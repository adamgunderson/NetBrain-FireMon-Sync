#!/usr/bin/env python3
# improved_upload_files.py
"""
Improved SFTP Upload Script for NetBrain-FireMon Sync Logs and Reports

Features:
- Better error handling and diagnostics
- Connection testing before uploads
- Proper timeout handling
- Improved logging
- Graceful termination of hanging processes
"""

import os
import sys
import subprocess
import logging
import time
import signal
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple, Any
from dotenv import load_dotenv

class CurlSFTPUploader:
    def __init__(self, hostname: str, username: str, password: str, 
                 port: int = 22, remote_base: str = None,
                 timeout: int = 60, max_retries: int = 3):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.remote_base = remote_base if remote_base else ''
        self.uploaded_files = set()
        self.failed_files = set()
        self.timeout = timeout
        self.max_retries = max_retries
        self._setup_logging()

    def _setup_logging(self):
        """Set up logging with enhanced formatting"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('sftp_upload.log')
            ]
        )

    def test_connection(self) -> bool:
        """Test SFTP connection before attempting uploads"""
        logging.info(f"Testing connection to {self.hostname}:{self.port}")
        
        # Create a test command to check connection but not transfer files
        curl_cmd = [
            'curl',
            '--insecure',
            '-v',
            '--disable-epsv',
            f'sftp://{self.hostname}:{self.port}/',
            '--list-only',
            '--connect-timeout', '10',
            '--max-time', '15',
            '--user', f'{self.username}:{self.password}',
            '--pubkey', ''  # Explicitly disable public key auth
        ]
        
        try:
            logging.info("Attempting to connect to SFTP server...")
            result = subprocess.run(
                curl_cmd,
                capture_output=True,
                text=True,
                timeout=20  # Process timeout
            )
            
            # Print verbose output for debugging
            for line in result.stderr.split('\n'):
                if any(x in line.lower() for x in ['connected', 'connection', 'auth', 'login', 'error']):
                    logging.info(f"CURL: {line.strip()}")
            
            if result.returncode == 0:
                logging.info("SFTP connection successful")
                return True
            else:
                logging.error(f"SFTP connection failed with exit code {result.returncode}")
                logging.error(f"Error message: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logging.error("Connection test timed out - check firewall rules or server availability")
            return False
        except Exception as e:
            logging.error(f"Connection test failed: {str(e)}")
            return False

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload a single file to SFTP server with improved error handling
        
        Args:
            local_path: Path to local file
            remote_path: Path on remote server
            
        Returns:
            Boolean indicating success
        """
        if not os.path.isfile(local_path):
            logging.error(f"Local file not found: {local_path}")
            self.failed_files.add(local_path)
            return False

        if not os.access(local_path, os.R_OK):
            logging.error(f"Local file not readable: {local_path}")
            self.failed_files.add(local_path)
            return False
            
        # Get file size for logging
        file_size = os.path.getsize(local_path)
        file_size_mb = file_size / (1024 * 1024)
        logging.info(f"Uploading {local_path} ({file_size_mb:.2f} MB) to {remote_path}")

        # Remove leading slash and normalize path
        remote_path = remote_path.lstrip('/')
        full_remote_url = f'sftp://{self.hostname}:{self.port}/{remote_path}'
        
        for attempt in range(1, self.max_retries + 1):
            try:
                # Set longer timeout for larger files
                dynamic_timeout = max(self.timeout, int(file_size_mb) * 10)
                
                curl_cmd = [
                    'curl',
                    '--insecure',
                    '-v',  # Verbose output
                    '--disable-epsv',
                    '--connect-timeout', '20',  # Connection timeout
                    '--max-time', str(dynamic_timeout),  # Transfer timeout
                    '--retry', '2',  # Retry failed operations
                    '--retry-delay', '5',  # Delay between retries
                    '--ftp-create-dirs',
                    '-T', local_path,
                    full_remote_url,
                    '--user', f'{self.username}:{self.password}',
                    '-k',
                    '--key', '/dev/null'  # Properly disable public key auth
                ]
                
                # Run curl with timeout to avoid hanging
                process = subprocess.Popen(
                    curl_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1  # Line buffered
                )
                
                # Track start time
                start_time = time.time()
                output_lines = []
                error_lines = []
                
                # Monitor the process with timeout
                while process.poll() is None:
                    # Check if process has been running too long
                    if time.time() - start_time > dynamic_timeout + 30:  # Adding 30s buffer
                        logging.warning(f"Upload process taking too long ({dynamic_timeout + 30}s), terminating...")
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        
                        logging.error(f"Upload of {local_path} timed out and was terminated")
                        break
                    
                    # Read output while waiting
                    stdout_line = process.stdout.readline() if process.stdout else ""
                    stderr_line = process.stderr.readline() if process.stderr else ""
                    
                    if stdout_line:
                        output_lines.append(stdout_line.strip())
                    if stderr_line:
                        error_lines.append(stderr_line.strip())
                        # Log important SFTP messages in real-time
                        if any(x in stderr_line.lower() for x in ['connected', 'auth', 'error', 'fail']):
                            logging.info(f"CURL: {stderr_line.strip()}")
                    
                    time.sleep(0.1)
                
                # Get remaining output
                stdout, stderr = process.communicate()
                if stdout:
                    output_lines.extend(stdout.splitlines())
                if stderr:
                    error_lines.extend(stderr.splitlines())
                
                result_code = process.returncode
                
                if result_code == 0:
                    logging.info(f"Successfully uploaded {local_path} (Attempt {attempt}/{self.max_retries})")
                    self.uploaded_files.add(local_path)
                    return True
                else:
                    # Log detailed error information
                    logging.error(f"Failed to upload {local_path}: Exit code {result_code} (Attempt {attempt}/{self.max_retries})")
                    
                    # Log important curl error messages
                    for line in error_lines:
                        if any(x in line.lower() for x in ['error', 'fail', 'denied', 'permission']):
                            logging.error(f"CURL error: {line}")
                    
                    if attempt < self.max_retries:
                        retry_delay = 5 * attempt  # Increase delay with each retry
                        logging.info(f"Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                    else:
                        self.failed_files.add(local_path)
                        return False
                        
            except Exception as e:
                logging.error(f"Error uploading {local_path} (Attempt {attempt}/{self.max_retries}): {str(e)}")
                if attempt < self.max_retries:
                    retry_delay = 5 * attempt
                    logging.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    self.failed_files.add(local_path)
                    return False
        
        # If we reach here, all retries failed
        self.failed_files.add(local_path)
        return False

    def _create_remote_directories(self, remote_path: str) -> bool:
        """Test that remote directories can be created"""
        try:
            remote_path = remote_path.lstrip('/')
            directory_url = f'sftp://{self.hostname}:{self.port}/{remote_path}/'
            
            curl_cmd = [
                'curl',
                '--insecure',
                '-v',
                '--disable-epsv',
                '--connect-timeout', '10',
                '--max-time', '20',
                '--ftp-create-dirs',
                directory_url,
                '--list-only',
                '--user', f'{self.username}:{self.password}',
                '-k',
                '--key', '/dev/null'  # Properly disable public key auth
            ]
            
            logging.info(f"Testing directory creation for: {remote_path}")
            result = subprocess.run(
                curl_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logging.info(f"Directory creation successful for: {remote_path}")
                return True
            else:
                logging.error(f"Directory creation failed for: {remote_path}")
                logging.error(f"Error: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Error creating directory {remote_path}: {str(e)}")
            return False

    def upload_directory(self, local_dir: str, remote_dir: str) -> List[str]:
        """
        Upload directory contents to SFTP with improved handling
        
        Args:
            local_dir: Path to local directory
            remote_dir: Path on remote server
            
        Returns:
            List of failed uploads
        """
        logging.info(f"Starting directory upload process:")
        logging.info(f"  Local directory: {local_dir}")
        logging.info(f"  Remote directory: {remote_dir}")
        logging.info(f"  SFTP Host: {self.hostname}")
        logging.info(f"  SFTP Port: {self.port}")
        logging.info(f"  Username: {self.username}")

        failed_uploads = []
        
        try:
            if not os.path.isdir(local_dir):
                logging.error(f"Local directory not found: {local_dir}")
                return [local_dir]

            # First, test directory creation on remote server
            if not self._create_remote_directories(remote_dir):
                logging.error(f"Cannot create or access remote directory: {remote_dir}")
                return [f"DIRECTORY: {remote_dir}"]
                
            local_dir = os.path.abspath(local_dir)
            remote_dir = remote_dir.strip('/')
            
            # First collect file list - sort by size ascending to upload small files first
            files_to_upload = []
            for root, dirs, files in os.walk(local_dir):
                # Calculate relative path
                rel_path = os.path.relpath(root, local_dir)
                current_remote_dir = remote_dir
                if rel_path != '.':
                    current_remote_dir = f"{remote_dir}/{rel_path}".replace('\\', '/')
                
                # Skip if no files to upload
                if not files:
                    continue
                
                # Add each file with size information
                for file in files:
                    local_path = os.path.join(root, file)
                    remote_path = f"{current_remote_dir}/{file}".replace('\\', '/')
                    
                    try:
                        file_size = os.path.getsize(local_path)
                        files_to_upload.append((local_path, remote_path, file_size))
                    except Exception as e:
                        logging.error(f"Error getting size for file {local_path}: {str(e)}")
                        failed_uploads.append(local_path)
            
            # Sort files by size (smallest first)
            files_to_upload.sort(key=lambda x: x[2])
            
            # Log upload plan
            total_size_mb = sum(item[2] for item in files_to_upload) / (1024 * 1024)
            logging.info(f"Planning to upload {len(files_to_upload)} files "
                       f"({total_size_mb:.2f} MB total)")
            
            # Upload each file
            for i, (local_path, remote_path, file_size) in enumerate(files_to_upload):
                logging.info(f"Uploading file {i+1}/{len(files_to_upload)}: "
                           f"{os.path.basename(local_path)} ({file_size/1024/1024:.2f} MB)")
                if not self.upload_file(local_path, remote_path):
                    failed_uploads.append(local_path)
                    logging.error(f"Failed to upload: {local_path}")
                else:
                    logging.info(f"Successfully uploaded: {local_path}")
                    
        except Exception as e:
            logging.error(f"Error uploading directory {local_dir}: {str(e)}")
            failed_uploads.append(local_dir)
            
        # Log all failures in one place
        if failed_uploads:
            logging.error(f"Failed to upload {len(failed_uploads)} files:")
            for failed in failed_uploads[:10]:
                logging.error(f"  - {failed}")
            if len(failed_uploads) > 10:
                logging.error(f"  ... and {len(failed_uploads) - 10} more")
                
        return failed_uploads

    def get_upload_stats(self) -> dict:
        """Get upload statistics"""
        return {
            'total_uploaded': len(self.uploaded_files),
            'total_failed': len(self.failed_files),
            'uploaded_files': sorted(list(self.uploaded_files)),
            'failed_files': sorted(list(self.failed_files))
        }

def main():
    """Main entry point with enhanced error handling"""
    start_time = time.time()
    
    # Load environment variables
    load_dotenv()
    
    # Get SFTP settings from environment
    hostname = os.getenv('SFTP_HOST')
    username = os.getenv('SFTP_USER')
    password = os.getenv('SFTP_PASS')
    port = int(os.getenv('SFTP_PORT', '22'))
    timeout = int(os.getenv('SFTP_TIMEOUT', '120'))
    
    # Debug environment variables
    logging.info(f"SFTP settings from environment:")
    logging.info(f"  Host: {hostname}")
    logging.info(f"  User: {username}")
    logging.info(f"  Password set: {'Yes' if password else 'No'}")
    logging.info(f"  Port: {port}")
    logging.info(f"  Timeout: {timeout}")
    
    # Validate settings
    if not hostname:
        logging.error("Missing SFTP_HOST environment variable")
        sys.exit(1)
    
    if not username:
        logging.error("Missing SFTP_USER environment variable")
        sys.exit(1)
    
    if not password:
        logging.warning("Missing SFTP_PASS environment variable - will try SSH keys or prompt for password")
    
    # Create timestamp for remote directory
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    remote_base = timestamp
    
    # Initialize uploader
    uploader = CurlSFTPUploader(
        hostname=hostname,
        username=username,
        password=password,
        port=port,
        remote_base=remote_base,
        timeout=timeout
    )
    
    failed_uploads = []
    uploaded_dirs = []
    
    try:
        # First test connection
        if not uploader.test_connection():
            logging.error("Connection test failed - check credentials and connectivity")
            sys.exit(1)
            
        cwd = os.getcwd()
        logging.info(f"Current working directory: {cwd}")
        
        # Check directories and list contents for logs
        logs_dir = os.path.join(cwd, 'logs')
        if os.path.exists(logs_dir) and os.path.isdir(logs_dir):
            # List directory contents
            log_files = os.listdir(logs_dir)
            log_files_info = []
            for file in log_files:
                full_path = os.path.join(logs_dir, file)
                if os.path.isfile(full_path):
                    size = os.path.getsize(full_path)
                    log_files_info.append((file, size))
            
            # Sort by size (largest first) for better debug visibility
            log_files_info.sort(key=lambda x: x[1], reverse=True)
            
            logging.info(f"Found {len(log_files_info)} files in logs directory:")
            for file_name, size in log_files_info[:10]:  # Show top 10 largest
                logging.info(f"  - {file_name} ({size/1024/1024:.2f} MB)")
            
            if len(log_files_info) > 10:
                logging.info(f"  ... and {len(log_files_info) - 10} more files")
                
            # Upload logs directory
            logging.info(f"Uploading logs directory: {logs_dir}")
            failed_logs = uploader.upload_directory(
                logs_dir,
                f'{remote_base}/logs'
            )
            failed_uploads.extend(failed_logs)
            if not failed_logs:
                uploaded_dirs.append('logs')
        else:
            logging.warning("Logs directory not found or empty")
        
        # Check reports directory
        reports_dir = os.path.join(cwd, 'reports')
        if os.path.exists(reports_dir) and os.path.isdir(reports_dir):
            # List directory contents
            report_files = os.listdir(reports_dir)
            report_files_info = []
            for file in report_files:
                full_path = os.path.join(reports_dir, file)
                if os.path.isfile(full_path):
                    size = os.path.getsize(full_path)
                    report_files_info.append((file, size))
            
            # Sort by size for better debug visibility
            report_files_info.sort(key=lambda x: x[1], reverse=True)
            
            logging.info(f"Found {len(report_files_info)} files in reports directory:")
            for file_name, size in report_files_info[:10]:  # Show top 10 largest
                logging.info(f"  - {file_name} ({size/1024/1024:.2f} MB)")
                
            if len(report_files_info) > 10:
                logging.info(f"  ... and {len(report_files_info) - 10} more files")
            
            # Upload reports directory
            logging.info(f"Uploading reports directory: {reports_dir}")
            failed_reports = uploader.upload_directory(
                reports_dir,
                f'{remote_base}/reports'
            )
            failed_uploads.extend(failed_reports)
            if not failed_reports:
                uploaded_dirs.append('reports')
        else:
            logging.warning("Reports directory not found or empty")
        
        # Get upload statistics
        stats = uploader.get_upload_stats()
        
        # Calculate execution time
        execution_time = time.time() - start_time
        
        # Report results
        logging.info(f"Upload process completed in {execution_time:.2f} seconds")
        
        if stats['total_uploaded'] > 0:
            logging.info(f"Successfully uploaded {stats['total_uploaded']} files")
            logging.info(f"Uploaded directories: {', '.join(uploaded_dirs)}")
        else:
            logging.error("No files were uploaded successfully")
            sys.exit(1)
            
        if stats['total_failed'] > 0:
            logging.warning(f"Failed to upload {stats['total_failed']} files")
            sys.exit(1)
        
    except KeyboardInterrupt:
        logging.warning("Upload interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Upload failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
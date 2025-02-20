# upload_files.py
"""
SFTP Upload Script using curl for Logs and Reports
Uploads contents of logs/ and reports/ directories to a remote SFTP server
Uses curl instead of paramiko for better compatibility

Key fixes:
- Proper path handling for remote directories
- Improved error handling and logging
- Verification of successful uploads
- Better file existence checks
- Proper curl command construction
- Added upload verification
"""

import os
import sys
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set
from dotenv import load_dotenv

class CurlSFTPUploader:
    def __init__(self, hostname: str, username: str, password: str, 
                 port: int = 22, remote_base: str = '/uploads'):
        """
        Initialize SFTP uploader using curl
        
        Args:
            hostname: SFTP server hostname
            username: SFTP username
            password: SFTP password
            port: SFTP port (default: 22)
            remote_base: Base remote directory for uploads
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.remote_base = remote_base.rstrip('/')
        
        # Track uploaded files
        self.uploaded_files = set()
        
        # Setup logging
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging for the uploader"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('sftp_upload.log')
            ]
        )

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload a single file using curl
        
        Args:
            local_path: Local file path
            remote_path: Remote file path
            
        Returns:
            bool: True if upload successful, False otherwise
        """
        try:
            # Verify local file exists and is readable
            if not os.path.isfile(local_path):
                logging.error(f"Local file not found: {local_path}")
                return False
                
            if not os.access(local_path, os.R_OK):
                logging.error(f"Local file not readable: {local_path}")
                return False

            # Normalize remote path
            remote_path = remote_path.lstrip('/')
            full_remote_url = f'sftp://{self.hostname}:{self.port}/{remote_path}'
            
            # Create parent directory structure
            remote_dir = os.path.dirname(remote_path)
            if remote_dir:
                self._ensure_remote_directory(remote_dir)
            
            # Construct curl command with proper escaping
            curl_cmd = [
                'curl',
                '--insecure',          # Skip SSL verification
                '-v',                  # Verbose output for debugging
                '--disable-epsv',      # Disable EPSV mode
                '--ftp-create-dirs',   # Create missing directories
                '-T', local_path,      # Upload file
                full_remote_url,
                '--user', f'{self.username}:{self.password}'
            ]
            
            logging.info(f"Uploading {local_path} to {remote_path}")
            
            # Log the exact curl command being executed
            logging.info("Executing curl command:")
            logging.info(" ".join(curl_cmd))
            
            # Run curl command and capture output
            result = subprocess.run(
                curl_cmd,
                capture_output=True,
                text=True
            )
            
            # Log the complete output
            logging.info("Curl stdout:")
            logging.info(result.stdout)
            logging.info("Curl stderr:")
            logging.info(result.stderr)
            
            # Check for successful upload
            if result.returncode == 0:
                # Verify upload by checking curl output
                if 'bytes uploaded' in result.stderr:
                    logging.info(f"Successfully uploaded {local_path}")
                    self.uploaded_files.add(local_path)
                    return True
                else:
                    logging.warning(f"Upload may have failed for {local_path}: No upload confirmation in output")
                    return False
            else:
                logging.error(f"Failed to upload {local_path}: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Error uploading {local_path}: {str(e)}")
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed error trace:")
            return False

    def _verify_directory_contents(self, dir_path: str) -> None:
        """
        Verify and log directory contents
        
        Args:
            dir_path: Directory path to check
        """
        try:
            if os.path.exists(dir_path):
                logging.info(f"Directory exists: {dir_path}")
                files = os.listdir(dir_path)
                logging.info(f"Directory contents ({len(files)} files):")
                for file in files:
                    full_path = os.path.join(dir_path, file)
                    size = os.path.getsize(full_path)
                    logging.info(f"  - {file} ({size} bytes)")
            else:
                logging.error(f"Directory does not exist: {dir_path}")
        except Exception as e:
            logging.error(f"Error checking directory {dir_path}: {str(e)}")

    def _ensure_remote_directory(self, remote_dir: str) -> bool:
        """
        Ensure remote directory exists
        
        Args:
            remote_dir: Remote directory path
            
        Returns:
            bool: True if directory exists or was created
        """
        try:
            # Build complete path for curl
            full_remote_url = f'sftp://{self.hostname}:{self.port}/{remote_dir}/'
            
            curl_cmd = [
                'curl',
                '--insecure',
                '-v',
                '--ftp-create-dirs',   # This flag should create parent directories
                full_remote_url,
                '--user', f'{self.username}:{self.password}',
                '-Q', 'MKD .'          # Try to create directory
            ]
            
            result = subprocess.run(curl_cmd, capture_output=True, text=True)
            
            # Check both for success and "already exists" responses
            if result.returncode == 0 or 'File exists' in result.stderr:
                logging.debug(f"Ensured remote directory exists: {remote_dir}")
                return True
            else:
                logging.error(f"Failed to create remote directory {remote_dir}: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Error creating remote directory {remote_dir}: {str(e)}")
            return False

    def upload_directory(self, local_dir: str, remote_dir: str) -> List[str]:
        """
        Upload entire directory
        
        Args:
            local_dir: Local directory path
            remote_dir: Remote directory path
            
        Returns:
            List of failed uploads
        """
        logging.info(f"Starting directory upload process:")
        logging.info(f"  Local directory: {local_dir}")
        logging.info(f"  Remote directory: {remote_dir}")
        logging.info(f"  SFTP Host: {self.hostname}")
        logging.info(f"  SFTP Port: {self.port}")
        logging.info(f"  Username: {self.username}")
        """
        Upload entire directory
        
        Args:
            local_dir: Local directory path
            remote_dir: Remote directory path
            
        Returns:
            List of failed uploads
        """
        failed_uploads = []
        
        try:
            # Verify local directory exists
            if not os.path.isdir(local_dir):
                logging.error(f"Local directory not found: {local_dir}")
                return [local_dir]
            
            # Normalize paths
            local_dir = os.path.abspath(local_dir)
            remote_dir = remote_dir.strip('/')
            
            # Create base remote directory
            if not self._ensure_remote_directory(remote_dir):
                logging.error(f"Could not create remote directory: {remote_dir}")
                return [local_dir]
            
            # Walk through local directory
            for root, dirs, files in os.walk(local_dir):
                # Calculate relative path
                rel_path = os.path.relpath(root, local_dir)
                current_remote_dir = os.path.join(remote_dir, rel_path).replace('\\', '/')
                
                # Skip if no files to upload
                if not files:
                    continue
                
                # Ensure remote directory exists for current level
                if not self._ensure_remote_directory(current_remote_dir):
                    logging.error(f"Failed to create remote directory: {current_remote_dir}")
                    continue
                
                # Upload each file
                for file in files:
                    local_path = os.path.join(root, file)
                    remote_path = os.path.join(current_remote_dir, file).replace('\\', '/')
                    
                    if not self.upload_file(local_path, remote_path):
                        failed_uploads.append(local_path)
                        logging.error(f"Failed to upload: {local_path}")
                    else:
                        logging.info(f"Successfully uploaded: {local_path}")
                        
        except Exception as e:
            logging.error(f"Error uploading directory {local_dir}: {str(e)}")
            failed_uploads.append(local_dir)
            
        return failed_uploads

    def get_upload_stats(self) -> dict:
        """Get statistics about uploaded files"""
        return {
            'total_uploaded': len(self.uploaded_files),
            'uploaded_files': sorted(list(self.uploaded_files))
        }

def main():
    """Main entry point for SFTP upload script"""
    # Load environment variables from .env file
    load_dotenv()
    
    # Get SFTP credentials from environment variables
    hostname = os.getenv('SFTP_HOST')
    username = os.getenv('SFTP_USER')
    password = os.getenv('SFTP_PASS')
    port = int(os.getenv('SFTP_PORT', '22'))
    
    # Verify credentials
    if not all([hostname, username, password]):
        logging.error("Missing required SFTP credentials in environment variables")
        sys.exit(1)
    
    # Create timestamp for remote directory
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    remote_base = f'/uploads/{timestamp}'
    
    # Initialize uploader
    uploader = CurlSFTPUploader(
        hostname=hostname,
        username=username,
        password=password,
        port=port,
        remote_base=remote_base
    )
    
    failed_uploads = []
    uploaded_dirs = []
    
    try:
        # Check and log current working directory
        cwd = os.getcwd()
        logging.info(f"Current working directory: {cwd}")
        
        # Upload logs directory if it exists
        logs_dir = os.path.join(os.getcwd(), 'logs')
        uploader._verify_directory_contents(logs_dir)
        if os.path.exists(logs_dir) and os.path.isdir(logs_dir):
            logging.info(f"Uploading logs directory: {logs_dir}")
            failed_logs = uploader.upload_directory(
                logs_dir,
                f'{remote_base}/logs'
            )
            failed_uploads.extend(failed_logs)
            if not failed_logs:
                uploaded_dirs.append('logs')
        else:
            logging.warning("Logs directory not found")
        
        # Upload reports directory if it exists
        reports_dir = os.path.join(os.getcwd(), 'reports')
        if os.path.exists(reports_dir) and os.path.isdir(reports_dir):
            logging.info(f"Uploading reports directory: {reports_dir}")
            failed_reports = uploader.upload_directory(
                reports_dir,
                f'{remote_base}/reports'
            )
            failed_uploads.extend(failed_reports)
            if not failed_reports:
                uploaded_dirs.append('reports')
        else:
            logging.warning("Reports directory not found")
        
        # Get upload statistics
        stats = uploader.get_upload_stats()
        
        # Report results
        if failed_uploads:
            logging.warning(f"Failed to upload {len(failed_uploads)} files:")
            for failed in failed_uploads:
                logging.warning(f"  - {failed}")
        
        if stats['total_uploaded'] > 0:
            logging.info(f"Successfully uploaded {stats['total_uploaded']} files")
            logging.info(f"Uploaded directories: {', '.join(uploaded_dirs)}")
        else:
            logging.error("No files were uploaded successfully")
            sys.exit(1)
        
    except Exception as e:
        logging.error(f"Upload failed: {str(e)}")
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.exception("Detailed error trace:")
        sys.exit(1)

if __name__ == "__main__":
    main()
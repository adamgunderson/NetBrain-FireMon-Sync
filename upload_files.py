# upload_files_curl.py
"""
SFTP Upload Script using curl for Logs and Reports
Uploads contents of logs/ and reports/ directories to a remote SFTP server
Uses curl instead of paramiko for better compatibility

Requirements:
- Python 3.9+
- curl installed on system
- python-dotenv
"""

import os
import sys
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional
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
        self.remote_base = remote_base
        
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
            # Construct curl command
            curl_cmd = [
                'curl',
                '--insecure',  # Skip SSL verification
                '-v',          # Verbose output for debugging
                '-T',          # Upload file
                local_path,    # Local file to upload
                f'sftp://{self.hostname}:{self.port}/{remote_path}',
                '--user',
                f'{self.username}:{self.password}'
            ]
            
            # Run curl command
            result = subprocess.run(
                curl_cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logging.info(f"Successfully uploaded {local_path} to {remote_path}")
                return True
            else:
                logging.error(f"Failed to upload {local_path}: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Error uploading {local_path}: {str(e)}")
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
        failed_uploads = []
        
        try:
            # Walk through local directory
            for root, dirs, files in os.walk(local_dir):
                # Calculate relative path
                rel_path = os.path.relpath(root, local_dir)
                current_remote_dir = os.path.join(remote_dir, rel_path).replace('\\', '/')
                
                # Create remote directory
                mkdir_cmd = [
                    'curl',
                    '--insecure',
                    '-v',
                    f'sftp://{self.hostname}:{self.port}/{current_remote_dir}/',
                    '--user',
                    f'{self.username}:{self.password}',
                    '-Q',       # Send custom command
                    'MKD .'     # Make directory command
                ]
                
                try:
                    subprocess.run(mkdir_cmd, capture_output=True, text=True)
                except Exception as e:
                    logging.warning(f"Error creating directory {current_remote_dir}: {str(e)}")
                
                # Upload each file
                for file in files:
                    local_path = os.path.join(root, file)
                    remote_path = os.path.join(current_remote_dir, file).replace('\\', '/')
                    
                    if not self.upload_file(local_path, remote_path):
                        failed_uploads.append(local_path)
                        
        except Exception as e:
            logging.error(f"Error uploading directory {local_dir}: {str(e)}")
            
        return failed_uploads

def main():
    """Main entry point for SFTP upload script"""
    # Load environment variables from .env file
    load_dotenv()
    
    # Get SFTP credentials from environment variables
    hostname = os.getenv('SFTP_HOST')
    username = os.getenv('SFTP_USER')
    password = os.getenv('SFTP_PASS')
    port = int(os.getenv('SFTP_PORT', '22'))
    
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
    
    try:
        # Upload logs directory
        if os.path.exists('logs'):
            logging.info("Uploading logs directory...")
            failed_logs = uploader.upload_directory(
                'logs',
                f'{remote_base}/logs'
            )
            failed_uploads.extend(failed_logs)
        
        # Upload reports directory
        if os.path.exists('reports'):
            logging.info("Uploading reports directory...")
            failed_reports = uploader.upload_directory(
                'reports',
                f'{remote_base}/reports'
            )
            failed_uploads.extend(failed_reports)
        
        # Report results
        if failed_uploads:
            logging.warning(f"Failed to upload {len(failed_uploads)} files:")
            for failed in failed_uploads:
                logging.warning(f"  - {failed}")
        else:
            logging.info("All files uploaded successfully")
        
    except Exception as e:
        logging.error(f"Upload failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
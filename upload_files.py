# upload_files.py
"""
SFTP Upload Script for Logs and Reports
Uploads contents of logs/ and reports/ directories to a remote SFTP server
Maintains directory structure and handles errors gracefully

Requirements for Python 3.9:
pip install paramiko python-dotenv

The script is compatible with all recent versions of these packages when using Python 3.9
"""

import os
import sys
import paramiko
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv

class SFTPUploader:
    def __init__(self, hostname: str, username: str, password: str, 
                 port: int = 22, remote_base: str = '/uploads'):
        """
        Initialize SFTP uploader
        
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
        self.transport = None
        self.sftp = None
        
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

    def connect(self) -> bool:
        """
        Establish SFTP connection
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.transport = paramiko.Transport((self.hostname, self.port))
            self.transport.connect(username=self.username, password=self.password)
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            logging.info(f"Successfully connected to {self.hostname}")
            return True
        except Exception as e:
            logging.error(f"Failed to connect to {self.hostname}: {str(e)}")
            return False

    def close(self):
        """Close SFTP connection"""
        try:
            if self.sftp:
                self.sftp.close()
            if self.transport:
                self.transport.close()
            logging.info("SFTP connection closed")
        except Exception as e:
            logging.error(f"Error closing connection: {str(e)}")

    def ensure_remote_dir(self, remote_path: str):
        """
        Ensure remote directory exists, create if needed
        
        Args:
            remote_path: Remote directory path
        """
        try:
            current_path = ''
            for part in remote_path.split('/'):
                if not part:
                    continue
                current_path += '/' + part
                try:
                    self.sftp.stat(current_path)
                except FileNotFoundError:
                    self.sftp.mkdir(current_path)
                    logging.debug(f"Created remote directory: {current_path}")
        except Exception as e:
            logging.error(f"Error creating remote directory {remote_path}: {str(e)}")
            raise

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload a single file to SFTP server with overwrite
        
        Args:
            local_path: Local file path
            remote_path: Remote file path
            
        Returns:
            bool: True if upload successful, False otherwise
        """
        try:
            # Ensure remote directory exists
            remote_dir = os.path.dirname(remote_path)
            self.ensure_remote_dir(remote_dir)
            
            # Remove existing file if it exists
            try:
                self.sftp.remove(remote_path)
                logging.debug(f"Removed existing file: {remote_path}")
            except FileNotFoundError:
                pass  # File doesn't exist, which is fine
            except Exception as e:
                logging.warning(f"Could not remove existing file {remote_path}: {str(e)}")
            
            # Upload file
            self.sftp.put(local_path, remote_path)
            logging.info(f"Successfully uploaded {local_path} to {remote_path}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to upload {local_path}: {str(e)}")
            return False

    def upload_directory(self, local_dir: str, remote_dir: str) -> List[str]:
        """
        Upload entire directory to SFTP server
        
        Args:
            local_dir: Local directory path
            remote_dir: Remote directory path
            
        Returns:
            List of failed uploads
        """
        failed_uploads = []
        try:
            # Ensure base remote directory exists
            self.ensure_remote_dir(remote_dir)
            
            # Walk through local directory
            for root, dirs, files in os.walk(local_dir):
                # Calculate relative path
                rel_path = os.path.relpath(root, local_dir)
                current_remote_dir = os.path.join(remote_dir, rel_path).replace('\\', '/')
                
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
    uploader = SFTPUploader(
        hostname=hostname,
        username=username,
        password=password,
        port=port,
        remote_base=remote_base
    )
    
    try:
        # Connect to SFTP server
        if not uploader.connect():
            sys.exit(1)
        
        failed_uploads = []
        
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
        
    finally:
        uploader.close()

if __name__ == "__main__":
    main()
# upload_files.py
"""
SFTP Upload Script using curl for Logs and Reports
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
                 port: int = 22, remote_base: str = None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.remote_base = remote_base if remote_base else ''
        self.uploaded_files = set()
        self._setup_logging()

    def _setup_logging(self):
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
        try:
            if not os.path.isfile(local_path):
                logging.error(f"Local file not found: {local_path}")
                return False

            if not os.access(local_path, os.R_OK):
                logging.error(f"Local file not readable: {local_path}")
                return False

            # Remove leading slash and normalize path
            remote_path = remote_path.lstrip('/')
            full_remote_url = f'sftp://{self.hostname}/{remote_path}'
            
            curl_cmd = [
                'curl',
                '--insecure',
                '-v',
                '--disable-epsv',
                '--ftp-create-dirs',
                '-T', local_path,
                full_remote_url,
                '--user', f'{self.username}:{self.password}',
                # Explicitly disable public key auth
                '--pubkey', ''
            ]
            
            logging.info(f"Uploading {local_path} to {remote_path}")
            
            result = subprocess.run(
                curl_cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logging.info(f"Successfully uploaded {local_path}")
                self.uploaded_files.add(local_path)
                return True
            else:
                logging.error(f"Failed to upload {local_path}: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Error uploading {local_path}: {str(e)}")
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed error trace:")
            return False

    def _verify_directory_contents(self, dir_path: str) -> None:
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

    def upload_directory(self, local_dir: str, remote_dir: str) -> List[str]:
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

            local_dir = os.path.abspath(local_dir)
            remote_dir = remote_dir.strip('/')
            
            # Walk through local directory
            for root, dirs, files in os.walk(local_dir):
                # Calculate relative path
                rel_path = os.path.relpath(root, local_dir)
                if rel_path == '.':
                    current_remote_dir = remote_dir
                else:
                    current_remote_dir = f"{remote_dir}/{rel_path}".replace('\\', '/')
                
                # Skip if no files to upload
                if not files:
                    continue
                
                # Upload each file
                for file in files:
                    local_path = os.path.join(root, file)
                    remote_path = f"{current_remote_dir}/{file}".replace('\\', '/')
                    
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
        return {
            'total_uploaded': len(self.uploaded_files),
            'uploaded_files': sorted(list(self.uploaded_files))
        }

def main():
    load_dotenv()
    
    hostname = os.getenv('SFTP_HOST')
    username = os.getenv('SFTP_USER')
    password = os.getenv('SFTP_PASS')
    port = int(os.getenv('SFTP_PORT', '22'))
    
    if not all([hostname, username, password]):
        logging.error("Missing required SFTP credentials in environment variables")
        sys.exit(1)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    remote_base = timestamp
    
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
        uploader._verify_directory_contents(reports_dir)
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
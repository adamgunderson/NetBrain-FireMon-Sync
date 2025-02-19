# update_code.py
"""
GitHub Code Update Script
Downloads and extracts the latest code from the NetBrain-FireMon-Sync repository.

Features:
- Downloads ZIP file from GitHub
- Creates backup of existing code
- Safely extracts and updates files
- Handles errors and cleanup
- Preserves local configuration files
"""

import os
import sys
import shutil
import tempfile
import zipfile
from datetime import datetime
import requests
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('update.log')
    ]
)

class CodeUpdater:
    def __init__(self):
        self.github_zip_url = "https://github.com/adamgunderson/NetBrain-FireMon-Sync/archive/refs/heads/main.zip"
        self.backup_dir = "backups"
        self.temp_dir = None
        
        # Files and directories to preserve during update
        self.preserve_files = [
            '.env',
            'sync-mappings.yaml',
            'config.yaml'
        ]
        
        # Directories to exclude from update process
        self.exclude_dirs = [
            'venv',
            'env',
            '.venv',
            '.env',
            '__pycache__'
        ]
        
    def create_backup(self) -> str:
        """
        Create backup of current code
        
        Returns:
            Path to backup directory
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(self.backup_dir, f'backup_{timestamp}')
        
        try:
            # Create backup directory
            os.makedirs(backup_path, exist_ok=True)
            
            # Copy all files except backups directory and excluded directories
            for item in os.listdir('.'):
                if (item != self.backup_dir and 
                    not item.startswith('.') and 
                    item not in self.exclude_dirs):
                    src = os.path.join('.', item)
                    dst = os.path.join(backup_path, item)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)
                        
            logging.info(f"Created backup at {backup_path}")
            return backup_path
            
        except Exception as e:
            logging.error(f"Backup failed: {str(e)}")
            raise
            
    def download_code(self) -> str:
        """
        Download ZIP file from GitHub
        
        Returns:
            Path to downloaded file
        """
        try:
            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(self.temp_dir, "update.zip")
            
            # Download the file
            logging.info("Downloading code from GitHub...")
            response = requests.get(self.github_zip_url, stream=True)
            response.raise_for_status()
            
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            logging.info("Download complete")
            return zip_path
            
        except Exception as e:
            logging.error(f"Download failed: {str(e)}")
            self.cleanup()
            raise
            
    def extract_code(self, zip_path: str) -> str:
        """
        Extract downloaded ZIP file
        
        Args:
            zip_path: Path to ZIP file
            
        Returns:
            Path to extracted directory
        """
        try:
            extract_path = os.path.join(self.temp_dir, "extracted")
            os.makedirs(extract_path, exist_ok=True)
            
            logging.info("Extracting files...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
                
            # Get the main directory from the ZIP (usually includes branch name)
            extracted_dirs = os.listdir(extract_path)
            if not extracted_dirs:
                raise Exception("No files found in ZIP archive")
                
            main_dir = os.path.join(extract_path, extracted_dirs[0])
            logging.info("Files extracted successfully")
            return main_dir
            
        except Exception as e:
            logging.error(f"Extraction failed: {str(e)}")
            self.cleanup()
            raise
            
    def preserve_local_files(self, target_dir: str):
        """
        Preserve local configuration files
        
        Args:
            target_dir: Directory containing new code
        """
        try:
            for filename in self.preserve_files:
                local_file = os.path.join('.', filename)
                if os.path.exists(local_file):
                    target_file = os.path.join(target_dir, filename)
                    if os.path.exists(target_file):
                        os.remove(target_file)
                    shutil.copy2(local_file, target_file)
                    logging.info(f"Preserved local file: {filename}")
                    
        except Exception as e:
            logging.error(f"Error preserving local files: {str(e)}")
            raise
            
    def update_code(self, source_dir: str):
        """
        Update code files
        
        Args:
            source_dir: Directory containing new code
        """
        try:
            # Preserve local files first
            self.preserve_local_files(source_dir)
            
            # Remove old files (except preserved ones, excluded dirs, and backups)
            for item in os.listdir('.'):
                if (item != self.backup_dir and 
                    not item.startswith('.') and 
                    item not in self.preserve_files and
                    item not in self.exclude_dirs):
                    path = os.path.join('.', item)
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                        
            # Copy new files
            for item in os.listdir(source_dir):
                src = os.path.join(source_dir, item)
                dst = os.path.join('.', item)
                # Skip excluded directories and preserved files
                if item not in self.exclude_dirs and item not in self.preserve_files:
                    if os.path.isdir(src):
                        if os.path.exists(dst):
                            shutil.rmtree(dst)
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)
                        
            logging.info("Code updated successfully")
            
        except Exception as e:
            logging.error(f"Update failed: {str(e)}")
            raise
            
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                logging.debug("Cleaned up temporary files")
            except Exception as e:
                logging.error(f"Cleanup failed: {str(e)}")
                
    def run(self):
        """Run the complete update process"""
        try:
            # Create backup first
            backup_path = self.create_backup()
            
            # Download and extract code
            zip_path = self.download_code()
            extracted_dir = self.extract_code(zip_path)
            
            # Update code
            self.update_code(extracted_dir)
            
            logging.info("Update completed successfully")
            logging.info(f"Backup available at: {backup_path}")
            
        except Exception as e:
            logging.error(f"Update process failed: {str(e)}")
            logging.info("Rolling back to backup...")
            try:
                if backup_path:
                    self.update_code(backup_path)
                    logging.info("Rollback successful")
            except Exception as rollback_error:
                logging.error(f"Rollback failed: {str(rollback_error)}")
            raise
            
        finally:
            self.cleanup()

def main():
    """Main entry point"""
    try:
        updater = CodeUpdater()
        updater.run()
    except Exception as e:
        logging.error(f"Update failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
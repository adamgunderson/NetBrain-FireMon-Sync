# lib/logger.py

import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional
from pathlib import Path

def setup_logging(level: Optional[str] = None) -> None:
    """
    Configure logging for the application
    
    Args:
        level: Optional log level override from command line
    """
    # Command line argument takes precedence over environment variable
    if level is None:
        level = os.getenv('LOG_LEVEL', 'INFO').upper()
    else:
        level = level.upper()

    # Get log settings from environment
    log_file = os.getenv('LOG_FILE', 'sync-service.log')
    log_dir = os.getenv('LOG_DIR', 'logs')
    max_bytes = int(os.getenv('LOG_MAX_BYTES', '10485760'))  # 10MB default
    backup_count = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Create log directory if it doesn't exist
    log_path = Path(log_dir) / log_file
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Remove any existing handlers
    logger = logging.getLogger()
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Set log level
    try:
        logger.setLevel(level)
    except (ValueError, TypeError):
        logger.setLevel(logging.INFO)
        logging.warning(f"Invalid log level '{level}', defaulting to INFO")
    
    # Enhanced format for debug logging
    if level == 'DEBUG':
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(funcName)s() - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Initial log messages
    logging.info(f"Logging initialized at {level} level")
    if level == 'DEBUG':
        logging.debug("Debug logging enabled with enhanced formatting")
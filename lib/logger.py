# lib/logger.py

"""
Logger configuration for the sync service
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional

def setup_logging(level: Optional[str] = None) -> None:
    """Configure logging for the application"""
    # Get log settings from environment or use defaults
    if level is None:
        level = os.getenv('LOG_LEVEL', 'INFO').upper()
    else:
        level = level.upper()

    log_file = os.getenv('LOG_FILE', 'sync-service.log')
    log_dir = 'logs'
    
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_path = os.path.join(log_dir, log_file)
    
    # Configure root logger
    logger = logging.getLogger()
    
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
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Initial log messages
    logging.info(f"Logging initialized at {level} level")
    if level == 'DEBUG':
        logging.debug("Debug logging enabled with enhanced formatting")
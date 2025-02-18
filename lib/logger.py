# lib/logger.py
"""
Logging configuration module
Handles setup of application logging with support for:
- Console output
- Main log file with rotation
- Separate debug log file for device/group details
- Separate debug log file for configuration content
- Multiple log levels
- Enhanced debug formatting
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional
from pathlib import Path

# Create custom loggers for detail tracking
debug_logger = logging.getLogger('debug_details')
config_logger = logging.getLogger('config_details')

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
    
    # Setup debug and config loggers if in DEBUG mode
    if level == 'DEBUG':
        # Debug details logger setup
        debug_log_path = Path(log_dir) / 'debug_details.log'
        debug_formatter = logging.Formatter(
            '%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        debug_handler = RotatingFileHandler(
            debug_log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        debug_handler.setFormatter(debug_formatter)
        debug_logger.addHandler(debug_handler)
        debug_logger.setLevel(logging.DEBUG)

        # Config details logger setup
        config_log_path = Path(log_dir) / 'config_details.log'
        config_formatter = logging.Formatter(
            '%(asctime)s - %(message)s\n',  # Add newline for better config readability
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        config_handler = RotatingFileHandler(
            config_log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        config_handler.setFormatter(config_formatter)
        config_logger.addHandler(config_handler)
        config_logger.setLevel(logging.DEBUG)
        
        logging.info(f"Debug details logging enabled to {debug_log_path}")
        logging.info(f"Config details logging enabled to {config_log_path}")
    
    # Initial log messages
    logging.info(f"Logging initialized at {level} level")
    if level == 'DEBUG':
        logging.debug("Debug logging enabled with enhanced formatting")

def log_device_details(devices: list) -> None:
    """
    Log detailed device information to debug log
    
    Args:
        devices: List of device dictionaries
    """
    if debug_logger.handlers:
        for device in devices:
            attrs = device.get('attributes', {})
            debug_logger.debug(
                f"Device: {device.get('hostname', 'N/A')} "
                f"ID: {device.get('id', 'N/A')} "
                f"IP: {device.get('mgmtIP', 'N/A')} "
                f"Site: {device.get('site', 'N/A')} "
                f"Type: {attrs.get('subTypeName', 'N/A')}"
            )

def log_group_details(groups: list) -> None:
    """
    Log detailed group information to debug log
    
    Args:
        groups: List of group dictionaries
    """
    if debug_logger.handlers:
        for group in groups:
            debug_logger.debug(
                f"Group: {group.get('name', 'N/A')} "
                f"ID: {group.get('id', 'N/A')} "
                f"Parent: {group.get('parentId', 'N/A')}"
            )

def log_config_details(hostname: str, configs: dict) -> None:
    """
    Log configuration content being uploaded to FireMon
    
    Args:
        hostname: Device hostname
        configs: Dictionary mapping filenames to config content
    """
    if config_logger.handlers:
        config_logger.debug(f"Configuration upload for device: {hostname}")
        config_logger.debug("=" * 80)
        
        for filename, content in configs.items():
            config_logger.debug(f"Filename: {filename}")
            config_logger.debug("-" * 40)
            config_logger.debug(content)
            config_logger.debug("=" * 80)
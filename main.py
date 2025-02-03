# main.py
"""
NetBrain to FireMon Synchronization Service
Main script that handles the sync process and scheduling

Key features:
- Environment configuration loading
- Command-line argument parsing
- Multiple sync modes: full, groups, licenses, configs, devices
- Dry run support
- Continuous sync capability
- Report generation in HTML/JSON formats
- Signal handling for graceful shutdown
- Comprehensive logging
- Error handling and validation
"""

import os
import sys
import time
import logging
import argparse
import signal
from typing import Dict, List, Any, Optional
from datetime import datetime
from dotenv import load_dotenv

from lib.netbrain import NetBrainClient
from lib.firemon import FireMonClient 
from lib.config import ConfigManager
from lib.sync_manager import SyncManager
from lib.group_hierarchy import GroupHierarchyManager
from lib.validation import ValidationManager
from lib.report import ReportManager
from lib.logger import setup_logging

def parse_args():
    """
    Parse command line arguments for sync service configuration
    
    Returns:
        Parsed argument namespace
    """
    parser = argparse.ArgumentParser(
        description='NetBrain to FireMon Device Synchronization Service'
    )
    
    # Sync mode options
    parser.add_argument(
        '--mode',
        choices=['full', 'groups', 'licenses', 'configs', 'devices'],
        help='Sync mode (overrides SYNC_MODE env var)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulation mode - no actual changes'
    )
    
    parser.add_argument(
        '--continuous',
        action='store_true',
        help='Run in continuous mode with interval (overrides CONTINUOUS_SYNC env var)'
    )
    
    parser.add_argument(
        '--report-file',
        type=str,
        help='Base output file path for sync report (without extension)'
    )
    
    parser.add_argument(
        '--report-format',
        choices=['json', 'html'],
        help='Report output format (overrides REPORT_FORMAT env var)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set logging level (overrides LOG_LEVEL env var)'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to sync mappings configuration file'
    )

    return parser.parse_args()

def setup_signal_handlers(sync_manager: SyncManager):
    """
    Setup handlers for graceful shutdown on signals
    
    Args:
        sync_manager: SyncManager instance to handle cleanup
    """
    def signal_handler(signum, frame):
        """Signal handler for graceful shutdown"""
        logging.info(f"Received signal {signum}, initiating graceful shutdown...")
        sync_manager.shutdown()
        logging.info("Shutdown complete")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def generate_report_filename(base_path: str, timestamp: str, mode: str, format: str) -> str:
    """
    Generate report filename with timestamp and mode
    
    Args:
        base_path: Base file path
        timestamp: Timestamp string
        mode: Sync mode (dry_run/full)
        format: Report format (html/json)
        
    Returns:
        Complete filename with path
    """
    # Create reports directory if it doesn't exist
    report_dir = os.path.dirname(base_path) if os.path.dirname(base_path) else 'reports'
    os.makedirs(report_dir, exist_ok=True)
    
    # Generate filename
    base_name = os.path.basename(base_path)
    return f"{os.path.join(report_dir, base_name)}_{timestamp}_{mode}.{format}"

def save_report(report: Dict[str, Any], report_manager: ReportManager, 
                filename: str, format: str) -> None:
    """
    Save sync report to file
    
    Args:
        report: Report data dictionary
        report_manager: ReportManager instance
        filename: Output filename
        format: Report format (html/json)
    """
    try:
        if format == 'html':
            report_content = report_manager.generate_html_report(report)
            with open(filename, 'w') as f:
                f.write(report_content)
        else:
            report_manager.save_report(report, filename)
        logging.info(f"Report saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving report to {filename}: {str(e)}")

def main():
    """Main entry point for sync service"""
    # Parse arguments
    args = parse_args()
    
    # Load environment variables first
    load_dotenv()
    
    # Initialize logging
    log_level = args.log_level or os.getenv('LOG_LEVEL', 'INFO')
    setup_logging(level=log_level)
    logging.info("Starting NetBrain to FireMon Sync Service")

    try:
        # Initialize configuration
        config_manager = ConfigManager(config_path=args.config)
        
        # Validate configuration
        config_issues = config_manager.validate_config()
        if any(issue['severity'] == 'error' for issue in config_issues):
            logging.error("Critical configuration issues found. Please fix before continuing.")
            for issue in config_issues:
                if issue['severity'] == 'error':
                    logging.error(f"Config Error: {issue['type']} - {issue.get('description', '')}")
            sys.exit(1)
        
        # Command line arguments override environment variables
        if args.mode:
            config_manager.sync_config.sync_mode = args.mode
        if args.dry_run:
            config_manager.sync_config.dry_run = True
        if args.continuous:
            config_manager.sync_config.continuous_sync = True
            
        # Initialize clients and managers
        try:
            netbrain_client = NetBrainClient(
                host=os.getenv('NETBRAIN_HOST'),
                username=os.getenv('NETBRAIN_USERNAME'),
                password=os.getenv('NETBRAIN_PASSWORD'),
                tenant=os.getenv('NETBRAIN_TENANT'),
                config_manager=config_manager
            )
        except Exception as e:
            logging.error(f"Failed to initialize NetBrain client: {str(e)}")
            sys.exit(1)

        try:
            firemon_client = FireMonClient(
                host=os.getenv('FIREMON_HOST'),
                username=os.getenv('FIREMON_USERNAME'),
                password=os.getenv('FIREMON_PASSWORD'),
                domain_id=int(os.getenv('FIREMON_DOMAIN_ID', 1))
            )
        except Exception as e:
            logging.error(f"Failed to initialize FireMon client: {str(e)}")
            sys.exit(1)

        group_manager = GroupHierarchyManager(firemon_client)
        report_manager = ReportManager()
        validation_manager = ValidationManager(
            netbrain_client, 
            firemon_client, 
            config_manager
        )
        
        sync_manager = SyncManager(
            netbrain_client, 
            firemon_client, 
            config_manager,
            group_manager=group_manager,
            validation_manager=validation_manager
        )

        # Setup signal handlers for graceful shutdown
        setup_signal_handlers(sync_manager)

        # Get report format from arguments or environment
        report_format = (args.report_format or 
                        os.getenv('REPORT_FORMAT', 'json')).lower()
        
        # Run initial sync
        logging.info(f"Starting sync in {config_manager.sync_config.sync_mode} mode "
                    f"(Dry Run: {config_manager.sync_config.dry_run})")
        
        initial_report = sync_manager.run_sync()
        
        # Generate and save report if requested
        if args.report_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            mode_suffix = 'dry_run' if config_manager.sync_config.dry_run else 'full'
            
            filename = generate_report_filename(
                args.report_file, 
                timestamp, 
                mode_suffix, 
                report_format
            )
            
            save_report(initial_report, report_manager, filename, report_format)
        
        # Print console summary
        print(report_manager.generate_console_summary(initial_report))
        
        # If continuous mode is enabled, start sync interval
        if config_manager.sync_config.continuous_sync and not config_manager.sync_config.dry_run:
            sync_interval = config_manager.sync_config.sync_interval_minutes
            logging.info(f"Starting continuous sync every {sync_interval} minutes")
            
            while True:
                time.sleep(sync_interval * 60)
                try:
                    report = sync_manager.run_sync()
                    print(report_manager.generate_console_summary(report))
                    
                    # Save continuous mode reports if requested
                    if args.report_file:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = generate_report_filename(
                            args.report_file,
                            timestamp,
                            'continuous',
                            report_format
                        )
                        
                        save_report(report, report_manager, filename, report_format)
                        
                except Exception as e:
                    logging.error(f"Error in continuous sync cycle: {str(e)}")
                    if log_level == 'DEBUG':
                        logging.exception("Detailed error trace:")
        else:
            logging.info("One-time sync completed")

    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt, shutting down...")
        sync_manager.shutdown()
        
    except Exception as e:
        logging.error(f"Fatal error in sync service: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
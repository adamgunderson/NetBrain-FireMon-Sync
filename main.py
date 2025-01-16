# main.py
"""
NetBrain to FireMon Synchronization Service
Main script that handles the sync process and scheduling
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
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='NetBrain to FireMon Device Synchronization Service'
    )
    
    # Sync mode options
    parser.add_argument(
        '--mode',
        choices=['full', 'groups', 'licenses', 'configs'],
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
        help='Output file for sync report'
    )
    
    parser.add_argument(
        '--report-format',
        choices=['json', 'html'],
        default='json',
        help='Report output format'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set logging level'
    )
    
    return parser.parse_args()

def main():
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
        config_manager = ConfigManager()
        
        # Command line arguments override environment variables
        if args.mode:
            config_manager.sync_config.sync_mode = args.mode
        if args.dry_run:
            config_manager.sync_config.dry_run = True
        if args.continuous:
            config_manager.sync_config.continuous_sync = True
            
        # Initialize clients and managers
        netbrain_client = NetBrainClient(
            host=os.getenv('NETBRAIN_HOST'),
            username=os.getenv('NETBRAIN_USERNAME'),
            password=os.getenv('NETBRAIN_PASSWORD'),
            tenant=os.getenv('NETBRAIN_TENANT'),
            config_manager=config_manager
        )

        firemon_client = FireMonClient(
            host=os.getenv('FIREMON_HOST'),
            username=os.getenv('FIREMON_USERNAME'),
            password=os.getenv('FIREMON_PASSWORD'),
            domain_id=int(os.getenv('FIREMON_DOMAIN_ID', 1))
        )

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

        # Run initial sync
        initial_report = sync_manager.run_sync()
        
        # Generate and save report if requested
        if args.report_file:
            if args.report_format == 'html':
                report_content = report_manager.generate_html_report(initial_report)
                filename = f"{args.report_file}.html"
            else:
                filename = f"{args.report_file}.json"
            
            report_manager.save_report(initial_report, filename)
        
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
                except Exception as e:
                    logging.error(f"Error in continuous sync cycle: {str(e)}")
        else:
            logging.info("One-time sync completed")

    except Exception as e:
        logging.error(f"Fatal error in sync service: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
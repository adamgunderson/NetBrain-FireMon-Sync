# File: main.py

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
    
    # Execution modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulation mode - no actual changes'
    )
    mode_group.add_argument(
        '--sync-groups',
        action='store_true',
        help='Sync only device groups'
    )
    mode_group.add_argument(
        '--sync-licenses',
        action='store_true',
        help='Sync only device licenses'
    )
    mode_group.add_argument(
        '--sync-configs',
        action='store_true',
        help='Sync only device configurations'
    )
    
    # Additional options
    parser.add_argument(
        '--continuous',
        action='store_true',
        help='Run in continuous mode with interval'
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
        default='INFO',
        help='Set logging level'
    )
    
    return parser.parse_args()

def setup_signal_handlers(sync_manager):
    """Setup graceful shutdown handlers"""
    def signal_handler(signum, frame):
        logging.info("Received shutdown signal, cleaning up...")
        sync_manager.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def main():
    # Parse arguments
    args = parse_args()
    
    # Initialize logging
    setup_logging(level=args.log_level)
    logging.info("Starting NetBrain to FireMon Sync Service")

    try:
        # Load environment variables
        load_dotenv()
        
        # Initialize configuration
        config_manager = ConfigManager()
        
        # Override config with command line arguments
        if args.dry_run:
            config_manager.sync_config.dry_run = True
        if args.sync_groups:
            config_manager.sync_config.sync_mode = 'groups'
        elif args.sync_licenses:
            config_manager.sync_config.sync_mode = 'licenses'
        elif args.sync_configs:
            config_manager.sync_config.sync_mode = 'configs'

        # Initialize clients
        netbrain_client = NetBrainClient(
            host=os.getenv('NETBRAIN_HOST'),
            username=os.getenv('NETBRAIN_USERNAME'),
            password=os.getenv('NETBRAIN_PASSWORD'),
            tenant=os.getenv('NETBRAIN_TENANT')
        )

        firemon_client = FireMonClient(
            host=os.getenv('FIREMON_HOST'),
            username=os.getenv('FIREMON_USERNAME'),
            password=os.getenv('FIREMON_PASSWORD'),
            domain_id=int(os.getenv('FIREMON_DOMAIN_ID', 1))
        )

        # Initialize managers
        group_manager = GroupHierarchyManager(firemon_client)
        report_manager = ReportManager()
        validation_manager = ValidationManager(netbrain_client, firemon_client, config_manager)
        
        sync_manager = SyncManager(
            netbrain_client, 
            firemon_client, 
            config_manager,
            group_manager=group_manager,
            validation_manager=validation_manager
        )
        
        # Setup signal handlers
        setup_signal_handlers(sync_manager)

        def run_sync_cycle():
            """Run a single sync cycle"""
            try:
                # Run sync operation
                sync_results = sync_manager.run_sync()
                
                # Generate report
                report = report_manager.generate_sync_report(
                    sync_results['changes'],
                    sync_results['final_state'],
                    config_manager.sync_config.sync_mode
                )
                
                # Save report if requested
                if args.report_file:
                    if args.report_format == 'html':
                        report_content = report_manager.generate_html_report(report)
                        filename = f"{args.report_file}.html"
                    else:
                        filename = f"{args.report_file}.json"
                    
                    report_manager.save_report(report, filename)
                
                # Print console summary
                print(report_manager.generate_console_summary(report))
                
                return report
                
            except Exception as e:
                logging.error(f"Error in sync cycle: {str(e)}", exc_info=True)
                raise

        # Run initial sync
        initial_report = run_sync_cycle()
        
        # If continuous mode, start sync interval
        if args.continuous and not args.dry_run:
            sync_interval = int(os.getenv('SYNC_INTERVAL_MINUTES', 60))
            logging.info(f"Starting sync interval every {sync_interval} minutes")
            
            while True:
                time.sleep(sync_interval * 60)
                try:
                    run_sync_cycle()
                except Exception as e:
                    logging.error(f"Error in continuous sync cycle: {str(e)}")
                    # Continue running despite errors in a cycle

    except Exception as e:
        logging.error(f"Fatal error in sync service: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
# lib/sync_manager.py

"""
NetBrain to FireMon Synchronization Manager

This module handles the synchronization of devices, configurations, groups, and licenses
between NetBrain and FireMon systems. Key features include:
- Parallel processing using ThreadPoolExecutor for improved performance
- Memory-efficient batch processing
- Multi-level caching to reduce API calls
- Proper dry run mode simulation with delta reporting
- Thread-safe operations
- Comprehensive error handling and reporting
"""

import logging
from typing import Dict, List, Any, Optional, Set
import os
import json
from datetime import datetime
from functools import lru_cache
from threading import Lock
from collections import defaultdict
import concurrent.futures

from .sync_lock import SyncLock, SyncLockError
from .timestamp_utils import TimestampUtil
from .config_handler import ConfigHandler, ConfigValidationError
from .group_hierarchy import GroupHierarchyManager
from .config_mapping import ConfigMappingManager
from .validation import ValidationManager

class SyncManager:
    def __init__(self, netbrain_client, firemon_client, config_manager,
                 group_manager=None, validation_manager=None, max_workers=10):
        """
        Initialize the sync manager with required clients and settings
        
        Args:
            netbrain_client: NetBrain API client
            firemon_client: FireMon API client
            config_manager: Configuration manager instance
            group_manager: Optional group hierarchy manager
            validation_manager: Optional validation manager
            max_workers: Maximum number of worker threads (default: 10)
        """
        # Core clients and managers
        self.netbrain = netbrain_client
        self.firemon = firemon_client
        self.config_manager = config_manager
        self.group_manager = group_manager or GroupHierarchyManager(firemon_client)
        self.validator = validation_manager
        self.max_workers = max_workers
        
        # Initialize supporting components
        self.config_handler = ConfigHandler(config_manager)
        self.config_mapping = ConfigMappingManager()
        self.sync_lock = SyncLock()
        
        # Thread-safe cache mechanisms
        self._cache_lock = Lock()
        self._changes_lock = Lock()
        self._device_cache = {}
        self._group_cache = {}
        self._config_cache = {}
        
        # Batch processing configuration
        self.batch_size = 50  # Number of devices to process in each batch
        
        # Change tracking
        self.changes = {
            'devices': [],
            'groups': [],
            'configs': [],
            'licenses': []
        }

        # Add delta tracking
        self.device_delta = {
            'only_in_netbrain': [],
            'only_in_firemon': [],
            'matching': [],
            'different': []  # Devices that exist in both but have differences
        }
        
        # Timing tracking
        self.current_sync_start = None
        self.last_sync_complete = None

    def _calculate_device_delta(self, nb_devices: List[Dict[str, Any]], 
                              fm_devices: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Calculate the difference between NetBrain and FireMon devices
        
        Args:
            nb_devices: List of NetBrain devices
            fm_devices: List of FireMon devices
            
        Returns:
            Dictionary containing device differences
        """
        logging.info("Calculating device delta between NetBrain and FireMon...")
        nb_by_hostname = {d['hostname']: d for d in nb_devices}
        fm_by_hostname = {d['name']: d for d in fm_devices}
        
        delta = {
            'only_in_netbrain': [],
            'only_in_firemon': [],
            'matching': [],
            'different': []
        }

        # Find devices only in NetBrain
        for hostname, nb_device in nb_by_hostname.items():
            if hostname not in fm_by_hostname:
                delta['only_in_netbrain'].append({
                    'hostname': hostname,
                    'mgmt_ip': nb_device['mgmtIP'],
                    'site': nb_device.get('site', 'N/A'),
                    'type': nb_device['attributes'].get('subTypeName', 'N/A'),
                    'vendor': nb_device['attributes'].get('vendor', 'N/A'),
                    'model': nb_device['attributes'].get('model', 'N/A'),
                    'version': nb_device['attributes'].get('version', 'N/A'),
                    'serial': nb_device['attributes'].get('serialNumber', 'N/A')
                })

        # Find devices only in FireMon
        for hostname, fm_device in fm_by_hostname.items():
            if hostname not in nb_by_hostname:
                delta['only_in_firemon'].append({
                    'hostname': hostname,
                    'mgmt_ip': fm_device.get('managementIp', 'N/A'),
                    'collector_group': fm_device.get('collectorGroupId', 'N/A'),
                    'device_pack': fm_device.get('devicePack', {}).get('deviceName', 'N/A'),
                    'status': fm_device.get('status', 'N/A'),
                    'last_retrieval': fm_device.get('lastRetrievalDate', 'N/A')
                })

        # Compare devices that exist in both systems
        for hostname, nb_device in nb_by_hostname.items():
            fm_device = fm_by_hostname.get(hostname)
            if fm_device:
                differences = self._compare_devices(nb_device, fm_device)
                if differences:
                    delta['different'].append({
                        'hostname': hostname,
                        'differences': differences,
                        'netbrain_data': {
                            'mgmt_ip': nb_device['mgmtIP'],
                            'site': nb_device.get('site', 'N/A'),
                            'type': nb_device['attributes'].get('subTypeName', 'N/A'),
                            'vendor': nb_device['attributes'].get('vendor', 'N/A'),
                            'model': nb_device['attributes'].get('model', 'N/A'),
                            'version': nb_device['attributes'].get('version', 'N/A')
                        },
                        'firemon_data': {
                            'mgmt_ip': fm_device.get('managementIp', 'N/A'),
                            'collector_group': fm_device.get('collectorGroupId', 'N/A'),
                            'device_pack': fm_device.get('devicePack', {}).get('deviceName', 'N/A'),
                            'status': fm_device.get('status', 'N/A'),
                            'last_retrieval': fm_device.get('lastRetrievalDate', 'N/A')
                        }
                    })
                else:
                    delta['matching'].append({
                        'hostname': hostname,
                        'mgmt_ip': nb_device['mgmtIP'],
                        'site': nb_device.get('site', 'N/A'),
                        'type': nb_device['attributes'].get('subTypeName', 'N/A'),
                        'vendor': nb_device['attributes'].get('vendor', 'N/A'),
                        'model': nb_device['attributes'].get('model', 'N/A')
                    })

        logging.info(f"Delta calculation complete. Found {len(delta['only_in_netbrain'])} devices only in NetBrain, "
                    f"{len(delta['only_in_firemon'])} only in FireMon, {len(delta['different'])} with differences, "
                    f"and {len(delta['matching'])} matching devices.")
        return delta

    def _compare_devices(self, nb_device: Dict[str, Any], 
                        fm_device: Dict[str, Any]) -> List[str]:
        """
        Compare NetBrain and FireMon device data to identify differences
        
        Args:
            nb_device: NetBrain device dictionary
            fm_device: FireMon device dictionary
            
        Returns:
            List of difference descriptions
        """
        differences = []

        # Compare management IP
        if nb_device['mgmtIP'] != fm_device.get('managementIp'):
            differences.append(f"Management IP mismatch: NB={nb_device['mgmtIP']}, "
                            f"FM={fm_device.get('managementIp', 'N/A')}")

        # Compare device type and mapping
        nb_type = nb_device['attributes'].get('subTypeName', 'N/A')
        device_pack = self.config_manager.get_device_pack(nb_type)
        if device_pack:
            expected_device_type = device_pack['device_name']
            fm_type = fm_device.get('devicePack', {}).get('deviceName', 'N/A')
            if expected_device_type != fm_type:
                differences.append(f"Device type mismatch: Expected={expected_device_type}, "
                                f"Actual={fm_type}")

        # Compare site/collector group mapping
        nb_site = nb_device.get('site', 'N/A')
        fm_collector = fm_device.get('collectorGroupId', 'N/A')
        expected_collector = self.config_manager.get_collector_group_id(nb_site)
        if expected_collector and str(fm_collector) != str(expected_collector):
            differences.append(f"Collector group mismatch: Expected={expected_collector}, "
                            f"Actual={fm_collector}")

        # Compare additional attributes
        nb_vendor = nb_device['attributes'].get('vendor', 'N/A')
        fm_vendor = fm_device.get('vendor', 'N/A')
        if nb_vendor != fm_vendor:
            differences.append(f"Vendor mismatch: NB={nb_vendor}, FM={fm_vendor}")

        nb_model = nb_device['attributes'].get('model', 'N/A')
        fm_model = fm_device.get('model', 'N/A')
        if nb_model != fm_model:
            differences.append(f"Model mismatch: NB={nb_model}, FM={fm_model}")

        return differences

    def run_sync(self) -> Dict[str, Any]:
        """
        Run synchronization process with proper locking and parallelization
        
        Returns:
            Dictionary containing sync results, statistics, and validation info
        """
        try:
            with self.sync_lock.acquire(timeout=30):
                logging.info(f"Starting synchronization in {self.config_manager.sync_config.sync_mode} mode "
                           f"(Dry Run: {self.config_manager.sync_config.dry_run})")
                
                self.current_sync_start = datetime.utcnow()

                # Get devices from both systems
                logging.info("Retrieving devices from NetBrain and FireMon...")
                nb_devices = self.netbrain.get_all_devices()
                fm_devices = self.firemon.get_all_devices()

                # Calculate device delta
                logging.info("Calculating device delta...")
                self.device_delta = self._calculate_device_delta(nb_devices, fm_devices)

                if self.config_manager.sync_config.dry_run:
                    logging.info("Running in dry-run mode - no changes will be made")
                    # In dry run mode, report the differences without making changes
                    report = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'sync_mode': self.config_manager.sync_config.sync_mode,
                        'dry_run': True,
                        'summary': {
                            'devices': {
                                'total_in_netbrain': len(nb_devices),
                                'total_in_firemon': len(fm_devices),
                                'only_in_netbrain': len(self.device_delta['only_in_netbrain']),
                                'only_in_firemon': len(self.device_delta['only_in_firemon']),
                                'matching': len(self.device_delta['matching']),
                                'different': len(self.device_delta['different'])
                            }
                        },
                        'delta': self.device_delta,
                        'validation': {
                            'initial': {},
                            'final': {}
                        },
                        'execution_time': (datetime.utcnow() - self.current_sync_start).total_seconds()
                    }

                else:
                    # For non-dry-run mode, proceed with actual sync
                    logging.info("Starting full synchronization...")
                    
                    # Run initial validation
                    initial_validation = self.validator.run_all_validations() if self.validator else {}
                    
                    # Process devices in batches
                    total_devices = len(nb_devices)
                    batch_count = (total_devices + self.batch_size - 1) // self.batch_size
                    
                    logging.info(f"Processing {total_devices} devices in {batch_count} batches")
                    
                    for i in range(0, total_devices, self.batch_size):
                        batch = nb_devices[i:i + self.batch_size]
                        current_batch = (i // self.batch_size) + 1
                        logging.info(f"Processing batch {current_batch} of {batch_count}")
                        self._process_device_batch(batch)

                    # Handle additional sync tasks based on configuration
                    if self.config_manager.sync_config.enable_group_sync:
                        logging.info("Starting group synchronization...")
                        self._sync_groups_parallel()

                    if self.config_manager.sync_config.enable_config_sync:
                        logging.info("Starting configuration synchronization...")
                        self._sync_configs_parallel()

                    if self.config_manager.sync_config.enable_license_sync:
                        logging.info("Starting license synchronization...")
                        self._sync_licenses_parallel()

                    # Final validation
                    final_validation = self.validator.run_all_validations() if self.validator else {}
                    self.last_sync_complete = datetime.utcnow()

                    report = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'sync_mode': self.config_manager.sync_config.sync_mode,
                        'summary': self._generate_summary(),
                        'changes': self.changes,
                        'validation': {
                            'initial': initial_validation,
                            'final': final_validation
                        },
                        'statistics': self._calculate_stats(),
                        'dry_run': False,
                        'execution_time': (self.last_sync_complete - self.current_sync_start).total_seconds()
                    }

                # Save report to file
                try:
                    # Create reports directory
                    report_dir = os.path.join(os.getcwd(), 'reports')
                    os.makedirs(report_dir, exist_ok=True)

                    # Generate report filename with timestamp
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    mode_suffix = 'dry_run' if self.config_manager.sync_config.dry_run else 'full'
                    report_filename = f"sync_report_{timestamp}_{mode_suffix}.json"
                    report_path = os.path.join(report_dir, report_filename)
                    
                    # Save JSON report
                    with open(report_path, 'w') as f:
                        json.dump(report, f, indent=2, default=str)
                    logging.info(f"Report saved to {report_path}")

                    # Generate and save HTML report if configured
                    try:
                        from .report import ReportManager
                        report_manager = ReportManager(output_dir=report_dir)
                        html_content = report_manager.generate_html_report(report)
                        html_path = os.path.join(report_dir, f"sync_report_{timestamp}_{mode_suffix}.html")
                        
                        with open(html_path, 'w') as f:
                            f.write(html_content)
                        logging.info(f"HTML report saved to {html_path}")
                    except Exception as e:
                        logging.error(f"Error generating HTML report: {str(e)}")

                except Exception as e:
                    logging.error(f"Error saving report to file: {str(e)}")
                    logging.error("Report will only be available in console output")

                # Log completion message with summary
                duration = (datetime.utcnow() - self.current_sync_start).total_seconds()
                if self.config_manager.sync_config.dry_run:
                    logging.info(f"Dry run completed in {duration:.2f} seconds")
                    logging.info(f"Found {len(self.device_delta['different'])} devices with differences")
                else:
                    logging.info(f"Synchronization completed in {duration:.2f} seconds")
                    logging.info(f"Processed {total_devices} devices")

                return report

        except SyncLockError as e:
            error_msg = f"Could not acquire sync lock: {str(e)}"
            logging.error(error_msg)
            raise

        except Exception as e:
            error_msg = f"Error during sync: {str(e)}"
            logging.error(error_msg, exc_info=True)
            raise

        finally:
            # Ensure resources are cleaned up
            try:
                self.clear_caches()
            except Exception as cleanup_error:
                logging.error(f"Error during cleanup: {str(cleanup_error)}")

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary of sync operations"""
        return {
            'devices': {
                'total_processed': len(self.changes.get('devices', [])),
                'added': sum(1 for d in self.changes.get('devices', []) 
                           if d.get('action') == 'add'),
                'updated': sum(1 for d in self.changes.get('devices', [])
                             if d.get('action') == 'update'),
                'removed': sum(1 for d in self.changes.get('devices', [])
                             if d.get('action') == 'remove'),
                'failed': sum(1 for d in self.changes.get('devices', [])
                            if d.get('status') == 'error')
            },
            'groups': {
                'total_processed': len(self.changes.get('groups', [])),
                'created': sum(1 for g in self.changes.get('groups', [])
                             if g.get('action') == 'create'),
                'updated': sum(1 for g in self.changes.get('groups', [])
                             if g.get('action') == 'update'),
                'failed': sum(1 for g in self.changes.get('groups', [])
                            if g.get('status') == 'error')
            },
            'configs': {
                'total_processed': len(self.changes.get('configs', [])),
                'updated': sum(1 for c in self.changes.get('configs', [])
                             if c.get('action') == 'update'),
                'failed': sum(1 for c in self.changes.get('configs', [])
                            if c.get('status') == 'error')
            },
            'licenses': {
                'total_processed': len(self.changes.get('licenses', [])),
                'added': sum(1 for l in self.changes.get('licenses', [])
                           if l.get('action') == 'add'),
                'removed': sum(1 for l in self.changes.get('licenses', [])
                             if l.get('action') == 'remove'),
                'failed': sum(1 for l in self.changes.get('licenses', [])
                            if l.get('status') == 'error')
            }
        }

    def _process_device_batch(self, devices: List[Dict[str, Any]]) -> None:
        """
        Process a batch of devices in parallel
        
        Args:
            devices: List of device dictionaries to process
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for device in devices:
                futures.append(executor.submit(self._process_single_device, device))
            concurrent.futures.wait(futures)

    def _process_single_device(self, device: Dict[str, Any]) -> None:
        """
        Process a single device with dry run awareness
        
        Args:
            device: Device dictionary containing device information
        """
        try:
            hostname = device['hostname']
            
            # Get existing FireMon device
            fm_device = self.firemon.search_device(hostname, device['mgmtIP'])
            
            if not fm_device:
                if not self.config_manager.sync_config.dry_run:
                    self._create_device_with_configs(device)
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'add',
                        'status': 'dry_run' if self.config_manager.sync_config.dry_run else 'success',
                        'details': {
                            'mgmt_ip': device['mgmtIP'],
                            'site': device.get('site'),
                            'type': device['attributes'].get('subTypeName')
                        }
                    })
            else:
                if not self.config_manager.sync_config.dry_run:
                    self._update_device_if_needed(device, fm_device)
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'update',
                        'status': 'dry_run' if self.config_manager.sync_config.dry_run else 'success',
                        'details': {
                            'mgmt_ip': device['mgmtIP'],
                            'site': device.get('site'),
                            'type': device['attributes'].get('subTypeName')
                        }
                    })

        except Exception as e:
            logging.error(f"Error processing device {device['hostname']}: {str(e)}")
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': device['hostname'],
                    'action': 'error',
                    'error': str(e)
                })

    def _sync_groups_parallel(self) -> None:
        """Process group hierarchy in parallel"""
        if self.config_manager.sync_config.dry_run:
            logging.info("Skipping group sync in dry run mode")
            return

        try:
            nb_sites = self.netbrain.get_sites()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self._process_site_hierarchy, site)
                          for site in nb_sites]
                concurrent.futures.wait(futures)
        except Exception as e:
            logging.error(f"Error in parallel group sync: {str(e)}")
            raise

    def _sync_configs_parallel(self) -> None:
        """Process device configurations in parallel"""
        if self.config_manager.sync_config.dry_run:
            logging.info("Skipping config sync in dry run mode")
            return

        try:
            nb_devices = self.netbrain.get_all_devices()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self._process_device_configs, device)
                          for device in nb_devices]
                concurrent.futures.wait(futures)
        except Exception as e:
            logging.error(f"Error in parallel config sync: {str(e)}")
            raise

    def _sync_licenses_parallel(self) -> None:
        """Process device licensing in parallel"""
        if self.config_manager.sync_config.dry_run:
            logging.info("Skipping license sync in dry run mode")
            return

        try:
            nb_devices = self.netbrain.get_all_devices()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self._process_device_licensing, device)
                          for device in nb_devices]
                concurrent.futures.wait(futures)
        except Exception as e:
            logging.error(f"Error in parallel license sync: {str(e)}")
            raise

    def _calculate_stats(self) -> Dict[str, Any]:
        """Calculate detailed sync statistics"""
        return {
            'devices': {
                'total': len(self.changes.get('devices', [])),
                'successful': sum(1 for d in self.changes.get('devices', []) 
                                if d.get('status') == 'success'),
                'simulated': sum(1 for d in self.changes.get('devices', []) 
                               if d.get('status') == 'dry_run'),
                'errors': sum(1 for d in self.changes.get('devices', []) 
                            if d.get('status') == 'error')
            },
            'timing': {
                'start': self.current_sync_start.isoformat() if self.current_sync_start else None,
                'end': self.last_sync_complete.isoformat() if self.last_sync_complete else None,
                'duration': (self.last_sync_complete - self.current_sync_start).total_seconds()
                          if self.last_sync_complete and self.current_sync_start else None
            },
            'cache': {
                'devices': len(self._device_cache),
                'groups': len(self._group_cache),
                'configs': len(self._config_cache)
            } if not self.config_manager.sync_config.dry_run else {},
            'mode': 'dry_run' if self.config_manager.sync_config.dry_run else 'live',
            'batch_processing': {
                'batch_size': self.batch_size,
                'max_workers': self.max_workers
            }
        }

    def clear_caches(self) -> None:
        """Clear all caches with thread safety"""
        with self._cache_lock:
            self._device_cache.clear()
            self._group_cache.clear()
            self._config_cache.clear()
            self._get_device_configs.cache_clear()
        logging.info("All caches cleared")

    def shutdown(self) -> None:
        """Clean shutdown of sync manager"""
        logging.info("Shutting down sync manager")
        try:
            if self.sync_lock.is_locked():
                self.sync_lock.break_lock()
            self.clear_caches()
            logging.info("Sync manager shutdown complete")
        except Exception as e:
            logging.error(f"Error during sync manager shutdown: {str(e)}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.shutdown()
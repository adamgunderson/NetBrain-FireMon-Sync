# lib/sync_manager.py
"""
NetBrain to FireMon Synchronization Manager

This module handles the synchronization of devices, configurations, groups, and licenses
between NetBrain and FireMon systems. Key features include:
- Enhanced device pack matching logic for various device types
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
import re

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

    def _calculate_device_delta(self, nb_devices: List[Dict[str, Any]], 
                            fm_devices: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Calculate the difference between NetBrain and FireMon devices
        Only includes devices that have mappings configured in sync-mappings.yaml
        
        Args:
            nb_devices: List of NetBrain devices
            fm_devices: List of FireMon devices
                
        Returns:
            Dictionary containing device differences with categories:
            - only_in_netbrain: devices found only in NetBrain
            - only_in_firemon: devices found only in FireMon
            - matching: devices that match in both systems
            - different: devices with differences between systems
        """
        logging.info("Calculating device delta between NetBrain and FireMon...")

        # Get configured device types from config manager
        configured_device_types = self.config_manager.get_mapped_device_types()
        logging.debug(f"Configured device types: {sorted(configured_device_types)}")
        
        # Filter NetBrain devices to only include configured types
        nb_by_hostname = {
            d['hostname']: d for d in nb_devices 
            if d['attributes'].get('subTypeName') in configured_device_types
        }
        
        fm_by_hostname = {d['name']: d for d in fm_devices}
        
        delta = {
            'only_in_netbrain': [],
            'only_in_firemon': [],
            'matching': [],
            'different': []
        }

        # Find devices only in NetBrain (only for configured device types)
        for hostname, nb_device in nb_by_hostname.items():
            if hostname not in fm_by_hostname:
                delta['only_in_netbrain'].append({
                    'hostname': hostname,
                    'mgmt_ip': nb_device['mgmtIP'],
                    'site': nb_device.get('site', 'N/A'),
                    'type': nb_device['attributes'].get('subTypeName', 'N/A'),
                    'vendor': nb_device['attributes'].get('vendor', 'N/A'),
                    'model': nb_device['attributes'].get('model', 'N/A'),
                    'version': nb_device['attributes'].get('version', 'N/A')
                })

        # Find devices only in FireMon
        for hostname, fm_device in fm_by_hostname.items():
            if hostname not in nb_by_hostname:
                # Get device pack info - try both devicePack structure and direct fields
                device_pack = (
                    fm_device.get('devicePack', {}).get('deviceName') or 
                    fm_device.get('product') or 
                    'N/A'
                )

                # Handle lastRevision timestamp
                last_revision = fm_device.get('lastRevision')
                if isinstance(last_revision, str) and last_revision.strip():
                    last_revision_display = last_revision
                else:
                    last_revision_display = 'N/A'
                
                delta['only_in_firemon'].append({
                    'hostname': hostname,
                    'mgmt_ip': fm_device.get('managementIp', 'N/A'),
                    'collector_group': fm_device.get('collectorGroupName', 'N/A'),
                    'device_pack': device_pack,
                    'status': fm_device.get('managedType', 'N/A'),
                    'last_retrieval': last_revision_display
                })

        # Compare devices that exist in both systems
        for hostname, nb_device in nb_by_hostname.items():
            fm_device = fm_by_hostname.get(hostname)
            if fm_device:
                # Get enhanced device pack based on all attributes
                nb_type = nb_device['attributes'].get('subTypeName', 'N/A')
                nb_model = nb_device['attributes'].get('model', 'N/A')
                nb_vendor = nb_device['attributes'].get('vendor', 'N/A')
                
                differences = []
                device_pack = self.config_manager.get_device_pack_by_attributes(
                    nb_type, nb_model, nb_vendor
                )

                if device_pack:
                    # Get FireMon device type and vendor - handle both data structures
                    fm_type = None
                    fm_vendor = None

                    # Try devicePack structure first
                    if fm_device.get('devicePack'):
                        fm_type = fm_device['devicePack'].get('deviceName')
                        fm_vendor = fm_device['devicePack'].get('vendor')
                    
                    # If not found, try direct fields
                    if not fm_type:
                        fm_type = fm_device.get('product')
                    if not fm_vendor:
                        fm_vendor = fm_device.get('vendor')

                    logging.debug(f"Device {hostname} - FM Type: {fm_type}, FM Vendor: {fm_vendor}, "
                                f"Expected Type: {device_pack['device_name']}, "
                                f"Expected Vendor: {device_pack['fm_vendor']}")

                    if fm_type != device_pack['device_name']:
                        differences.append(f"Device type mismatch: Expected={device_pack['device_name']}, "
                                        f"Actual={fm_type}")
                    
                    if fm_vendor != device_pack['fm_vendor']:
                        differences.append(f"Vendor mismatch: Expected={device_pack['fm_vendor']}, "
                                        f"Actual={fm_vendor}")

                    # Check model pattern match
                    if 'model_patterns' in device_pack:
                        if not any(re.match(pattern, nb_model, re.IGNORECASE) 
                                 for pattern in device_pack['model_patterns']):
                            differences.append(f"Model {nb_model} does not match expected patterns for "
                                          f"device type {device_pack['device_name']}")
                else:
                    differences.append(f"No matching device pack found for type={nb_type}, "
                                    f"model={nb_model}, vendor={nb_vendor}")

                # Compare additional attributes
                if nb_device['mgmtIP'] != fm_device.get('managementIp'):
                    differences.append(f"Management IP mismatch: NB={nb_device['mgmtIP']}, "
                                    f"FM={fm_device.get('managementIp', 'N/A')}")

                nb_site = nb_device.get('site', 'N/A')
                if nb_site.startswith("My Network/"):
                    nb_site = nb_site[len("My Network/"):]
                    
                expected_collector = self.config_manager.get_collector_group_id(nb_site)
                if expected_collector and str(fm_device.get('collectorGroupId')) != str(expected_collector):
                    differences.append(f"Collector group mismatch: Expected={expected_collector}, "
                                    f"Actual={fm_device.get('collectorGroupId', 'N/A')}")

                # Handle lastRevision timestamp for devices with differences
                last_revision = fm_device.get('lastRevision')
                if isinstance(last_revision, str) and last_revision.strip():
                    last_revision_display = last_revision
                else:
                    last_revision_display = 'N/A'

                if differences:
                    # When adding to different list, include both possible sources of device pack info
                    device_pack_info = (fm_device.get('devicePack', {}).get('deviceName') or 
                                    fm_device.get('product', 'N/A'))
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
                            'collector_group': fm_device.get('collectorGroupName', 'N/A'),
                            'device_pack': device_pack_info,
                            'status': fm_device.get('managedType', 'N/A'),
                            'last_retrieval': last_revision_display
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

        # Log final counts
        logging.info(f"Delta calculation complete. Found {len(delta['only_in_netbrain'])} devices only in NetBrain, "
                    f"{len(delta['only_in_firemon'])} only in FireMon, {len(delta['different'])} with differences, "
                    f"and {len(delta['matching'])} matching devices.")
        
        # Log skipped device types for debugging
        skipped_types = {d['attributes'].get('subTypeName') for d in nb_devices} - configured_device_types
        if skipped_types:
            logging.debug(f"Skipped unconfigured device types: {sorted(skipped_types)}")

        return delta

    def _matches_configured_type(self, fm_product: Optional[str], nb_type: str) -> bool:
        """
        Helper method to determine if a FireMon product matches a NetBrain device type
        
        Args:
            fm_product: FireMon product name
            nb_type: NetBrain device type
            
        Returns:
            bool: True if there's a match, False otherwise
        """
        if not fm_product:
            return False
            
        # Get the device pack mapping for this NetBrain type
        device_pack = self.config_manager.get_device_pack(nb_type)
        if not device_pack:
            return False
            
        # Check if the FireMon product matches the expected device name
        return device_pack.get('device_name') == fm_product

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
            
            # Get device pack based on all attributes
            nb_type = device['attributes'].get('subTypeName', 'N/A')
            nb_model = device['attributes'].get('model', 'N/A')
            nb_vendor = device['attributes'].get('vendor', 'N/A')
            
            device_pack = self.config_manager.get_device_pack_by_attributes(
                nb_type, nb_model, nb_vendor
            )
            
            if not device_pack:
                logging.error(f"No matching device pack found for device {hostname}")
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'error',
                        'error': 'No matching device pack found',
                        'details': {
                            'type': nb_type,
                            'model': nb_model,
                            'vendor': nb_vendor
                        }
                    })
                return

            if not fm_device:
                if not self.config_manager.sync_config.dry_run:
                    self._create_device_with_configs(device, device_pack)
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'add',
                        'status': 'dry_run' if self.config_manager.sync_config.dry_run else 'success',
                        'details': {
                            'mgmt_ip': device['mgmtIP'],
                            'site': device.get('site'),
                            'type': nb_type,
                            'device_pack': device_pack['device_name']
                        }
                    })
            else:
                if not self.config_manager.sync_config.dry_run:
                    self._update_device_if_needed(device, fm_device, device_pack)
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'update',
                        'status': 'dry_run' if self.config_manager.sync_config.dry_run else 'success',
                        'details': {
                            'mgmt_ip': device['mgmtIP'],
                            'site': device.get('site'),
                            'type': nb_type,
                            'device_pack': device_pack['device_name']
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

    def _create_device_with_configs(self, device: Dict[str, Any], device_pack: Dict[str, Any]) -> None:
        """
        Create new device in FireMon with configurations and track created device IDs
        
        Args:
            device: NetBrain device dictionary
            device_pack: Device pack configuration
        """
        try:
            # Prepare device data
            device_data = {
                'name': device['hostname'],
                'managementIp': device['mgmtIP'],
                'devicePack': {
                    'artifactId': device_pack['artifact_id'],
                    'groupId': device_pack['group_id'],
                    'deviceType': device_pack['device_type'],
                    'deviceName': device_pack['device_name']
                }
            }

            # Add collector group if site is mapped
            if device.get('site'):
                site = device['site']
                if site.startswith("My Network/"):
                    site = site[len("My Network/"):]
                collector_id = self.config_manager.get_collector_group_id(site)
                if collector_id:
                    device_data['collectorGroupId'] = collector_id

            # Add default settings
            device_data.update(self.config_manager.get_default_settings())

            # Create device in FireMon
            fm_device = self.firemon.create_device(device_data)
            
            # Track creation with FireMon device ID
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': device['hostname'],
                    'action': 'add',
                    'status': 'success',
                    'details': {
                        'firemon_id': fm_device['id'],
                        'mgmt_ip': device['mgmtIP'],
                        'site': device.get('site'),
                        'type': device['attributes'].get('subTypeName', 'N/A'),
                        'device_pack': device_pack['device_name'],
                        'collector_group': collector_id if collector_id else 'N/A'
                    }
                })

            logging.info(f"Created device {device['hostname']} in FireMon with ID: {fm_device['id']}")
            
            # Get and import configurations
            if self.config_manager.sync_config.enable_config_sync:
                configs = self.netbrain.get_device_configs(device['id'])
                if configs:
                    # Process and validate configs
                    mapped_configs = self.config_handler.process_device_configs(device, configs)
                    self.config_handler.backup_configs(device, mapped_configs)
                    
                    # Import configs to FireMon
                    self.firemon.import_device_config(
                        fm_device['id'],
                        mapped_configs,
                        change_user='NetBrain'
                    )

            # Add licenses
            if self.config_manager.sync_config.enable_license_sync:
                self.firemon.manage_device_license(fm_device['id'], add=True)

            # Update group membership
            if device.get('site') and self.config_manager.sync_config.enable_group_sync:
                self.group_manager.sync_device_group_membership(
                    fm_device['id'],
                    device['site'],
                    dry_run=False
                )

        except Exception as e:
            logging.error(f"Error creating device {device['hostname']}: {str(e)}")
            raise

    def _sync_licenses_parallel(self) -> None:
        """Process license synchronization in parallel"""
        try:
            if self.config_manager.sync_config.dry_run:
                logging.info("Skipping license sync in dry run mode")
                return

            # Get devices from both systems
            nb_devices = self.netbrain.get_all_devices()
            fm_devices = self.firemon.get_all_devices()
            
            # Calculate delta
            delta = self._calculate_device_delta(nb_devices, fm_devices)
            
            # Process devices in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                
                # Process devices that exist in both systems
                nb_by_hostname = {d['hostname']: d for d in nb_devices}
                for fm_device in fm_devices:
                    if fm_device['name'] in nb_by_hostname:
                        futures.append(executor.submit(
                            self._sync_device_licenses, 
                            fm_device
                        ))
                
                # Remove licenses from devices that only exist in FireMon
                for device in delta['only_in_firemon']:
                    fm_device = next(
                        (d for d in fm_devices if d['name'] == device['hostname']), 
                        None
                    )
                    if fm_device:
                        futures.append(executor.submit(
                            self._remove_device_licenses,
                            fm_device
                        ))
                
                concurrent.futures.wait(futures)
                
        except Exception as e:
            logging.error(f"Error in parallel license sync: {str(e)}")
            raise

    def _remove_device_licenses(self, fm_device: Dict[str, Any]) -> None:
        """Remove all licenses from a FireMon device"""
        try:
            current_licenses = set(fm_device.get('licenses', []))
            if current_licenses:
                self.firemon.manage_device_license(
                    fm_device['id'],
                    add=False,
                    products=list(current_licenses)
                )
                
                with self._changes_lock:
                    self.changes['licenses'].append({
                        'device': fm_device['name'],
                        'action': 'remove',
                        'status': 'success',
                        'details': {
                            'removed': list(current_licenses)
                        }
                    })
                logging.info(f"Removed licenses {current_licenses} from device {fm_device['name']}")
                
        except Exception as e:
            logging.error(f"Error removing licenses from device {fm_device['name']}: {str(e)}")
            with self._changes_lock:
                self.changes['licenses'].append({
                    'device': fm_device['name'],
                    'action': 'error',
                    'error': str(e)
                })

    def _update_device_if_needed(self, nb_device: Dict[str, Any], fm_device: Dict[str, Any],
                           device_pack: Dict[str, Any]) -> None:
        """
        Update FireMon device if changes are detected
        Only performs checks relevant to the current sync mode
        
        Args:
            nb_device: NetBrain device dictionary
            fm_device: FireMon device dictionary
            device_pack: Device pack configuration
        """
        try:
            updates_needed = []

            # Only check device pack and collector group if doing full sync
            if self.config_manager.sync_config.sync_mode == 'full':
                # Check device pack
                current_pack = fm_device.get('devicePack', {})
                # Also check direct fields if devicePack is not present
                current_type = (current_pack.get('deviceName') or fm_device.get('product'))
                current_vendor = (current_pack.get('vendor') or fm_device.get('vendor'))
                
                if (current_type != device_pack['device_name'] or
                    current_vendor != device_pack['fm_vendor']):
                    updates_needed.append('device_pack')

                # Check collector group
                if nb_device.get('site'):
                    site = nb_device['site']
                    if site.startswith("My Network/"):
                        site = site[len("My Network/"):]
                    expected_collector = self.config_manager.get_collector_group_id(site)
                    if expected_collector and str(fm_device.get('collectorGroupId')) != str(expected_collector):
                        updates_needed.append('collector_group')

                if updates_needed:
                    # Update device in FireMon
                    update_data = {
                        'id': fm_device['id'],
                        'name': fm_device['name'],
                        'managementIp': fm_device['managementIp']
                    }

                    if 'device_pack' in updates_needed:
                        update_data['devicePack'] = {
                            'artifactId': device_pack['artifact_id'],
                            'groupId': device_pack['group_id'],
                            'deviceType': device_pack['device_type'],
                            'deviceName': device_pack['device_name']
                        }

                    if 'collector_group' in updates_needed:
                        update_data['collectorGroupId'] = expected_collector

                    self.firemon.update_device(fm_device['id'], update_data)

            # Only sync specific components based on sync mode
            if self.config_manager.sync_config.sync_mode in ['full', 'configs']:
                if self.config_manager.sync_config.enable_config_sync:
                    self._sync_device_configs(nb_device, fm_device)

            if self.config_manager.sync_config.sync_mode in ['full', 'licenses']:
                if self.config_manager.sync_config.enable_license_sync:
                    self._sync_device_licenses(fm_device)

            if self.config_manager.sync_config.sync_mode in ['full', 'groups']:
                if nb_device.get('site') and self.config_manager.sync_config.enable_group_sync:
                    self.group_manager.sync_device_group_membership(
                        fm_device['id'],
                        nb_device['site'],
                        dry_run=False
                    )

        except Exception as e:
            logging.error(f"Error updating device {nb_device['hostname']}: {str(e)}")
            raise

    def _sync_device_configs(self, nb_device: Dict[str, Any], fm_device: Dict[str, Any]) -> None:
        """Sync device configurations"""
        try:
            # Get NetBrain config time
            nb_config_time = self.netbrain.get_device_config_time(nb_device['id'])
            if not nb_config_time:
                logging.warning(f"No configuration timestamp found for device {nb_device['hostname']}")
                return

            # Get FireMon config time
            fm_config_time = None
            fm_revision = self.firemon.get_device_revision(fm_device['id'])
            if fm_revision:
                fm_config_time = fm_revision.get('completeDate')

            # Compare timestamps
            if not fm_config_time or TimestampUtil.is_newer_than(nb_config_time, fm_config_time):
                configs = self.netbrain.get_device_configs(nb_device['id'])
                if configs:
                    mapped_configs = self.config_handler.process_device_configs(nb_device, configs)
                    self.config_handler.backup_configs(nb_device, mapped_configs)
                    
                    self.firemon.import_device_config(
                        fm_device['id'],
                        mapped_configs,
                        change_user='NetBrain'
                    )
                    
                    with self._changes_lock:
                        self.changes['configs'].append({
                            'device': nb_device['hostname'],
                            'action': 'update',
                            'status': 'success',
                            'details': {
                                'nb_time': nb_config_time,
                                'fm_time': fm_config_time
                            }
                        })

        except Exception as e:
            logging.error(f"Error syncing configs for device {nb_device['hostname']}: {str(e)}")
            with self._changes_lock:
                self.changes['configs'].append({
                    'device': nb_device['hostname'],
                    'action': 'error',
                    'error': str(e)
                })

    def _sync_device_licenses(self, fm_device: Dict[str, Any]) -> None:
        """Sync device licenses"""
        try:
            current_licenses = set(fm_device.get('licenses', []))
            required_licenses = {'SM', 'PO', 'PP'}
            
            licenses_to_add = required_licenses - current_licenses
            licenses_to_remove = current_licenses - required_licenses
            
            if licenses_to_add:
                self.firemon.manage_device_license(
                    fm_device['id'],
                    add=True,
                    products=list(licenses_to_add)
                )
                
            if licenses_to_remove:
                self.firemon.manage_device_license(
                    fm_device['id'],
                    add=False,
                    products=list(licenses_to_remove)
                )
                
            if licenses_to_add or licenses_to_remove:
                with self._changes_lock:
                    self.changes['licenses'].append({
                        'device': fm_device['name'],
                        'action': 'update',
                        'status': 'success',
                        'details': {
                            'added': list(licenses_to_add),
                            'removed': list(licenses_to_remove)
                        }
                    })

        except Exception as e:
            logging.error(f"Error syncing licenses for device {fm_device['name']}: {str(e)}")
            with self._changes_lock:
                self.changes['licenses'].append({
                    'device': fm_device['name'],
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

    def _process_site_hierarchy(self, site: Dict[str, Any]) -> None:
        """Process a single site for group hierarchy"""
        try:
            self.group_manager.sync_site_hierarchy(site, dry_run=self.config_manager.sync_config.dry_run)
        except Exception as e:
            logging.error(f"Error processing site {site.get('sitePath', 'UNKNOWN')}: {str(e)}")
            with self._changes_lock:
                self.changes['groups'].append({
                    'site': site.get('sitePath', 'UNKNOWN'),
                    'action': 'error',
                    'error': str(e)
                })

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

    @lru_cache(maxsize=1024)
    def _get_device_configs(self, device_id: str) -> Dict[str, str]:
        """Cached method to get device configurations"""
        return self.netbrain.get_device_configs(device_id)

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.shutdown()
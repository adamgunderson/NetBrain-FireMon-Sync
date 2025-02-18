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

        # Add reference to config sync method
        self._sync_configs_parallel = self.sync_configs_parallel

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
                    report = self._generate_dry_run_report(nb_devices, fm_devices)
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

    def sync_configs_parallel(self) -> None:
        """Process configuration synchronization in parallel"""
        try:
            if self.config_manager.sync_config.dry_run:
                logging.info("Skipping config sync in dry run mode")
                return

            # Get devices from both systems
            logging.info("Getting devices for config sync")
            nb_devices = self.netbrain.get_all_devices()
            fm_devices = self.firemon.get_all_devices()

            # Create lookup dict for FireMon devices
            fm_by_hostname = {d['name']: d for d in fm_devices}

            # Process configs in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                
                # Only process configs for devices that exist in both systems
                for nb_device in nb_devices:
                    hostname = nb_device['hostname']
                    fm_device = fm_by_hostname.get(hostname)
                    
                    if fm_device:
                        futures.append(executor.submit(
                            self._sync_device_configs,
                            nb_device,
                            fm_device
                        ))

                # Wait for all config syncs to complete
                concurrent.futures.wait(futures)
                
        except Exception as e:
            logging.error(f"Error in parallel config sync: {str(e)}")
            raise

    def _calculate_device_delta(self, nb_devices: List[Dict[str, Any]], 
                            fm_devices: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Calculate the difference between NetBrain and FireMon devices
        
        Args:
            nb_devices: List of NetBrain devices
            fm_devices: List of FireMon devices
                
        Returns:
            Dictionary containing device differences with categories
        """
        delta = {
            'only_in_netbrain': [],
            'only_in_firemon': [],
            'matching': [],
            'different': []
        }

        # Create case-insensitive lookup dictionaries
        nb_by_hostname = {d['hostname'].lower(): d for d in nb_devices}
        fm_by_hostname = {d['name'].lower(): d for d in fm_devices}

        # Find devices only in NetBrain
        for hostname_lower, nb_device in nb_by_hostname.items():
            if hostname_lower not in fm_by_hostname:
                delta['only_in_netbrain'].append({
                    'hostname': nb_device['hostname'],
                    'mgmt_ip': nb_device['mgmtIP'],
                    'site': nb_device.get('site', 'N/A'),
                    'type': nb_device['attributes'].get('subTypeName', 'N/A'),
                    'vendor': nb_device['attributes'].get('vendor', 'N/A'),
                    'model': nb_device['attributes'].get('model', 'N/A')
                })

        # Find devices only in FireMon
        for hostname_lower, fm_device in fm_by_hostname.items():
            if hostname_lower not in nb_by_hostname:
                delta['only_in_firemon'].append({
                    'hostname': fm_device['name'],
                    'mgmt_ip': fm_device.get('managementIp', 'N/A'),
                    'collector_group': fm_device.get('collectorGroupName', 'N/A'),
                    'device_pack': fm_device.get('devicePack', {}).get('deviceName', 'N/A')
                })

        # Compare devices that exist in both systems
        for hostname_lower, nb_device in nb_by_hostname.items():
            fm_device = fm_by_hostname.get(hostname_lower)
            if fm_device:
                differences = []
                
                # Compare attributes
                if nb_device['mgmtIP'] != fm_device.get('managementIp'):
                    differences.append('Management IP mismatch')

                # Get device pack details
                device_type = nb_device['attributes'].get('subTypeName')
                device_pack = self.config_manager.get_device_pack(device_type)
                
                if device_pack:
                    fm_pack = fm_device.get('devicePack', {})
                    if device_pack['device_name'] != fm_pack.get('deviceName'):
                        differences.append('Device pack mismatch')

                if differences:
                    delta['different'].append({
                        'hostname': nb_device['hostname'],
                        'differences': differences,
                        'netbrain_data': {
                            'mgmt_ip': nb_device['mgmtIP'],
                            'site': nb_device.get('site', 'N/A'),
                            'type': device_type,
                            'vendor': nb_device['attributes'].get('vendor', 'N/A')
                        },
                        'firemon_data': {
                            'mgmt_ip': fm_device.get('managementIp'),
                            'collector_group': fm_device.get('collectorGroupName'),
                            'device_pack': fm_device.get('devicePack', {}).get('deviceName')
                        }
                    })
                else:
                    delta['matching'].append({
                        'hostname': nb_device['hostname'],
                        'mgmt_ip': nb_device['mgmtIP'],
                        'type': device_type
                    })

        return delta

    def _process_device_batch(self, devices: List[Dict[str, Any]]) -> None:
        """Process a batch of devices with error handling"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for device in devices:
                futures.append(executor.submit(self._process_single_device, device))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error processing device batch: {str(e)}")

    def _process_single_device(self, device: Dict[str, Any]) -> None:
        """Process a single device with validation"""
        try:
            hostname = device['hostname']
            
            # Check if device exists in FireMon
            fm_device = self.firemon.search_device(hostname, device['mgmtIP'])
            
            # Get device pack based on attributes
            device_type = device['attributes'].get('subTypeName')
            device_pack = self.config_manager.get_device_pack(device_type)
            
            if not device_pack:
                error_msg = f"No matching device pack found for device {hostname}"
                logging.error(error_msg)
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'error',
                        'error': error_msg,
                        'details': {
                            'type': device_type,
                            'vendor': device['attributes'].get('vendor'),
                            'model': device['attributes'].get('model')
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
                            'type': device_type,
                            'device_pack': device_pack['device_name']
                        }
                    })
            else:
                self._update_device_if_needed(device, fm_device, device_pack)

        except Exception as e:
            logging.error(f"Error processing device {device['hostname']}: {str(e)}")
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': device['hostname'],
                    'action': 'error',
                    'error': str(e)
                })

    def _create_device_with_configs(self, device: Dict[str, Any], device_pack: Dict[str, Any]) -> None:
        """Create new device in FireMon with configurations"""
        try:
            device_data = {
                "name": device['hostname'],
                "managementIp": device['mgmtIP'],
                "domainId": self.firemon.domain_id,
                "devicePack": {
                    "artifactId": device_pack['artifact_id'],
                    "groupId": device_pack['group_id'],
                    "deviceType": device_pack['device_type'],
                    "deviceName": device_pack['device_name']
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
            
            # Import configs if enabled
            if self.config_manager.sync_config.enable_config_sync:
                configs = self.netbrain.get_device_configs(device['id'])
                if configs:
                    self.firemon.import_device_config(
                        fm_device['id'],
                        configs,
                        change_user='NetBrain'
                    )

            # Handle group membership
            if device.get('site'):
                self.group_manager.sync_device_group_membership(
                    fm_device['id'],
                    device['site']
                )

        except Exception as e:
            error_msg = f"Error creating device {device['hostname']}: {str(e)}"
            logging.error(error_msg)
            raise

    def _update_device_if_needed(self, nb_device: Dict[str, Any], fm_device: Dict[str, Any],
                                device_pack: Dict[str, Any]) -> None:
        """Update FireMon device if changes detected"""
        try:
            updates_needed = []
            changes_made = False

            # Check device pack
            current_pack = fm_device.get('devicePack', {})
            if (current_pack.get('deviceName') != device_pack['device_name'] or
                current_pack.get('artifactId') != device_pack['artifact_id']):
                updates_needed.append('device_pack')

            # Check collector group
            if nb_device.get('site'):
                site = nb_device['site']
                if site.startswith("My Network/"):
                    site = site[len("My Network/"):]
                expected_collector = self.config_manager.get_collector_group_id(site)
                if expected_collector and str(fm_device.get('collectorGroupId')) != str(expected_collector):
                    updates_needed.append('collector_group')

            if updates_needed and not self.config_manager.sync_config.dry_run:
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
                changes_made = True

            # Track changes
            if changes_made or updates_needed:
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': nb_device['hostname'],
                        'action': 'update',
                        'status': 'dry_run' if self.config_manager.sync_config.dry_run else 'success',
                        'details': {
                            'updates_made': updates_needed
                        }
                    })

        except Exception as e:
            error_msg = f"Error updating device {nb_device['hostname']}: {str(e)}"
            logging.error(error_msg)
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': nb_device['hostname'],
                    'action': 'error',
                    'error': error_msg
                })

    def _sync_device_configs(self, nb_device: Dict[str, Any], fm_device: Dict[str, Any]) -> None:
        """
        Sync device configurations between systems using hostname
        
        Args:
            nb_device: NetBrain device dictionary
            fm_device: FireMon device dictionary
        """
        try:
            hostname = nb_device['hostname']
            
            # Get device details from NetBrain with proper attributes
            device_details = self.netbrain.get_device_details(hostname)
            if not device_details:
                logging.warning(f"Could not get device details for {hostname}")
                return

            # Get config times 
            nb_config_time = device_details['attributes'].get('lDiscoveryTime')
            if not nb_config_time:
                logging.warning(f"No configuration timestamp found for device {hostname}")
                return

            fm_revision = self.firemon.get_device_revision(fm_device['id'])
            fm_config_time = fm_revision['completeDate'] if fm_revision else None

            # Compare timestamps
            if not fm_config_time or TimestampUtil.is_newer_than(nb_config_time, fm_config_time):
                logging.info(f"Configuration update needed for {hostname}")
                
                # Get configs from NetBrain
                device_type = device_details['attributes'].get('subTypeName')
                if not device_type:
                    logging.warning(f"No device type found for device {hostname}")
                    return

                command_mappings = self.config_manager.get_config_file_mapping(device_type)
                if not command_mappings:
                    logging.warning(f"No command mappings found for device type {device_type}")
                    return

                configs = {}
                for command in command_mappings.keys():
                    try:
                        # Use Device Raw Data API to get command output
                        url = urljoin(self.netbrain.host, '/ServicesAPI/API/V1/CMDB/Devices/DeviceRawData')
                        params = {
                            'hostname': hostname,
                            'dataType': 2,  # CLI command result
                            'cmd': command
                        }

                        response = self.netbrain._request('GET', url, params=params)
                        if response.get('statusCode') == 790200:  # Success
                            content = response.get('content', '')
                            if content:
                                configs[command] = self.netbrain._process_command_output(content, command)
                                logging.debug(f"Successfully retrieved command '{command}' for device {hostname}")
                            else:
                                logging.warning(f"Empty content received for command '{command}' on device {hostname}")
                        else:
                            logging.warning(f"Failed to get command '{command}' for device {hostname}: {response.get('statusDescription')}")

                    except Exception as e:
                        logging.error(f"Error getting command '{command}' for device {hostname}: {str(e)}")
                        continue

                if configs:
                    # Log configs being uploaded when in debug mode
                    from .logger import log_config_details
                    if logging.getLogger().isEnabledFor(logging.DEBUG):
                        log_config_details(hostname, configs)

                    # Import to FireMon
                    result = self.firemon.import_device_config(
                        fm_device['id'],
                        configs,
                        change_user='NetBrain'
                    )

                    with self._changes_lock:
                        self.changes['configs'].append({
                            'device': hostname,
                            'action': 'update',
                            'status': 'success',
                            'details': {
                                'nb_time': nb_config_time,
                                'fm_time': fm_config_time,
                                'files_updated': list(configs.keys())
                            }
                        })
                else:
                    logging.warning(f"No configurations retrieved for device {hostname}")

        except Exception as e:
            error_msg = f"Error syncing configs for device {hostname}: {str(e)}"
            logging.error(error_msg)
            with self._changes_lock:
                self.changes['configs'].append({
                    'device': hostname,
                    'action': 'error',
                    'error': error_msg
                })

    def _sync_device_licenses(self, fm_device: Dict[str, Any]) -> None:
        """Sync device licenses"""
        try:
            required_licenses = {'SM', 'PO', 'PP'}
            current_licenses = set(fm_device.get('licenses', []))
            
            licenses_to_add = required_licenses - current_licenses
            licenses_to_remove = current_licenses - required_licenses
            
            if not self.config_manager.sync_config.dry_run:
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
                        'status': 'dry_run' if self.config_manager.sync_config.dry_run else 'success',
                        'details': {
                            'added': list(licenses_to_add),
                            'removed': list(licenses_to_remove)
                        }
                    })

        except Exception as e:
            error_msg = f"Error syncing licenses for device {fm_device['name']}: {str(e)}"
            logging.error(error_msg)
            with self._changes_lock:
                self.changes['licenses'].append({
                    'device': fm_device['name'],
                    'action': 'error',
                    'error': error_msg
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
        """Process single site for group hierarchy"""
        try:
            self.group_manager.sync_site_hierarchy(
                site,
                dry_run=self.config_manager.sync_config.dry_run
            )
        except Exception as e:
            logging.error(f"Error processing site {site.get('sitePath', 'UNKNOWN')}: {str(e)}")
            with self._changes_lock:
                self.changes['groups'].append({
                    'site': site.get('sitePath', 'UNKNOWN'),
                    'action': 'error',
                    'error': str(e)
                })

    def _generate_dry_run_report(self, nb_devices: List[Dict[str, Any]], 
                             fm_devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate report for dry run mode"""
        return {
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
            'execution_time': (datetime.utcnow() - self.current_sync_start).total_seconds()
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary of sync operations"""
        return {
            'devices': {
                'total_processed': len(self.changes.get('devices', [])),
                'added': sum(1 for d in self.changes.get('devices', [])
                           if d.get('action') == 'add'),
                'updated': sum(1 for d in self.changes.get('devices', [])
                             if d.get('action') == 'update'),
                'failed': sum(1 for d in self.changes.get('devices', [])
                            if d.get('status') == 'error')
            },
            'configs': {
                'total_processed': len(self.changes.get('configs', [])),
                'updated': sum(1 for c in self.changes.get('configs', [])
                             if c.get('action') == 'update'),
                'failed': sum(1 for c in self.changes.get('configs', [])
                            if c.get('status') == 'error')
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
            'timing': {
                'start': self.current_sync_start.isoformat(),
                'end': self.last_sync_complete.isoformat(),
                'duration': (self.last_sync_complete - self.current_sync_start).total_seconds()
            },
            'devices': {
                'total': len(self.changes.get('devices', [])),
                'successful': sum(1 for d in self.changes.get('devices', []) 
                                if d.get('status') == 'success'),
                'simulated': sum(1 for d in self.changes.get('devices', []) 
                               if d.get('status') == 'dry_run'),
                'errors': sum(1 for d in self.changes.get('devices', []) 
                            if d.get('status') == 'error')
            },
            'cache': {
                'devices': len(self._device_cache),
                'groups': len(self._group_cache),
                'configs': len(self._config_cache)
            },
            'mode': self.config_manager.sync_config.sync_mode,
            'dry_run': self.config_manager.sync_config.dry_run,
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
            if hasattr(self, '_get_device_configs'):
                self._get_device_configs.cache_clear()
        logging.debug("Cleared all caches")

    def shutdown(self) -> None:
        """Clean shutdown of sync manager"""
        logging.info("Shutting down sync manager")
        try:
            if self.sync_lock.is_locked():
                self.sync_lock.break_lock()
            self.clear_caches()
            if hasattr(self, 'netbrain'):
                self.netbrain.session.close()
            if hasattr(self, 'firemon'):
                self.firemon.session.close()
            logging.info("Sync manager shutdown complete")
        except Exception as e:
            logging.error(f"Error during sync manager shutdown: {str(e)}")

    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status information"""
        return {
            'is_running': self.sync_lock.is_locked(),
            'start_time': self.current_sync_start.isoformat() if self.current_sync_start else None,
            'last_complete': self.last_sync_complete.isoformat() if self.last_sync_complete else None,
            'mode': self.config_manager.sync_config.sync_mode,
            'dry_run': self.config_manager.sync_config.dry_run,
            'changes': {
                'devices': len(self.changes.get('devices', [])),
                'configs': len(self.changes.get('configs', [])),
                'groups': len(self.changes.get('groups', [])),
                'licenses': len(self.changes.get('licenses', []))
            }
        }

    @property
    def is_running(self) -> bool:
        """Check if sync is currently running"""
        return self.sync_lock.is_locked()

    def validate_sync_config(self) -> List[Dict[str, Any]]:
        """Validate sync configuration"""
        issues = []
        
        # Validate sync mode
        valid_modes = {'full', 'groups', 'licenses', 'configs', 'devices'}
        if self.config_manager.sync_config.sync_mode not in valid_modes:
            issues.append({
                'type': 'invalid_sync_mode',
                'message': f"Invalid sync mode: {self.config_manager.sync_config.sync_mode}",
                'severity': 'error'
            })

        # Validate sync interval
        if self.config_manager.sync_config.continuous_sync:
            if self.config_manager.sync_config.sync_interval_minutes < 5:
                issues.append({
                    'type': 'invalid_sync_interval',
                    'message': "Sync interval must be at least 5 minutes",
                    'severity': 'error'
                })

        # Validate device mappings
        if not self.config_mapping.device_type_mappings:
            issues.append({
                'type': 'missing_device_mappings',
                'message': "No device type mappings configured",
                'severity': 'error'
            })

        # Validate command mappings
        if self.config_manager.sync_config.enable_config_sync:
            if not self.config_mapping.command_file_mappings:
                issues.append({
                    'type': 'missing_command_mappings',
                    'message': "No command file mappings configured",
                    'severity': 'error'
                })

        return issues

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.shutdown()
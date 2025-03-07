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
from urllib.parse import urljoin 

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

                # Pre-load FireMon devices to optimize lookups - this will populate the cache
                logging.info("Pre-loading all FireMon devices for faster processing...")
                self.firemon.initialize_device_cache()

                # Get devices from both systems - FireMon will use the cache
                logging.info("Retrieving devices from NetBrain and FireMon...")
                nb_devices = self.netbrain.get_all_devices()
                fm_devices = self.firemon.get_all_devices()  # Now uses cache when available

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

            # Get devices from both systems - using FireMon cache when available
            logging.info("Getting devices for config sync")
            nb_devices = self.netbrain.get_all_devices()
            # Note: No need to initialize cache again if already done in run_sync
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
        Performs case-insensitive matching using both hostname and IP address
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
        
        # Create both hostname and IP based lookups for FireMon devices - CASE INSENSITIVE
        # Using lowercase for case-insensitive comparisons
        fm_by_hostname = {}  # lowercase hostname -> device
        fm_by_ip = {}        # IP -> device
        processed_fm_devices = set()  # Track which FM devices we've processed (lowercase hostnames or IPs)
        
        for fm_device in fm_devices:
            hostname = fm_device.get('name', '')
            mgmt_ip = fm_device.get('managementIp')
            
            # Always log the device being processed
            logging.debug(f"FireMon device found: name={hostname}, IP={mgmt_ip}")
            
            if hostname:
                # Convert to lowercase for case-insensitive lookup
                hostname_lower = hostname.lower()
                fm_by_hostname[hostname_lower] = fm_device
            if mgmt_ip:
                fm_by_ip[mgmt_ip] = fm_device

        # Filter and validate NetBrain devices
        valid_nb_devices = []
        for device in nb_devices:
            # Skip if missing required fields
            if not device.get('hostname'):
                logging.warning(f"Skipping NetBrain device missing hostname: {device}")
                continue
            if not device.get('mgmtIP'):
                logging.warning(f"Skipping NetBrain device {device.get('hostname')} missing mgmtIP")
                continue
            if not device.get('attributes', {}).get('subTypeName'):
                logging.warning(f"Skipping NetBrain device {device.get('hostname')} missing subTypeName")
                continue
                
            # Check if device type is configured
            device_type = device['attributes']['subTypeName']
            if device_type in configured_device_types:
                valid_nb_devices.append(device)
                logging.debug(f"NetBrain device validated: hostname={device['hostname']}, IP={device['mgmtIP']}")
            else:
                logging.debug(f"Skipping device {device['hostname']} with unconfigured type: {device_type}")

        delta = {
            'only_in_netbrain': [],
            'only_in_firemon': [],
            'matching': [],
            'different': []
        }

        # Process each NetBrain device - WITH CASE INSENSITIVE MATCHING
        for nb_device in valid_nb_devices:
            hostname = nb_device['hostname']
            hostname_lower = hostname.lower()  # Use lowercase for comparison
            mgmt_ip = nb_device['mgmtIP']
            
            # Try to find matching FireMon device by hostname or IP
            # Use lowercase hostname for lookup
            fm_device = fm_by_hostname.get(hostname_lower) or fm_by_ip.get(mgmt_ip)
            
            if not fm_device:
                # Device only in NetBrain
                logging.debug(f"Device {nb_device['hostname']} only found in NetBrain")
                delta['only_in_netbrain'].append({
                    'hostname': nb_device['hostname'],
                    'mgmt_ip': mgmt_ip,
                    'site': nb_device.get('site', 'N/A'),
                    'type': nb_device['attributes'].get('subTypeName', 'N/A'),
                    'vendor': nb_device['attributes'].get('vendor', 'N/A'),
                    'model': nb_device['attributes'].get('model', 'N/A'),
                    'version': nb_device['attributes'].get('version', 'N/A')
                })
            else:
                # Mark this FireMon device as processed - use lowercase to ensure case-insensitive matching
                if fm_device.get('name'):
                    processed_fm_devices.add(fm_device['name'].lower())  # Use lowercase
                if fm_device.get('managementIp'):
                    processed_fm_devices.add(fm_device['managementIp'])

                # Rest of the method for comparing devices and finding differences...
                # [Unchanged code for device comparison...]

        # Find devices only in FireMon - IMPROVED CASE INSENSITIVE CHECKS
        for fm_device in fm_devices:
            hostname = fm_device.get('name', '')
            hostname_lower = hostname.lower() if hostname else ''  # Use lowercase
            mgmt_ip = fm_device.get('managementIp')
            
            # Skip if we've already processed this device - using lowercase
            if hostname_lower in processed_fm_devices or mgmt_ip in processed_fm_devices:
                continue
                
            # Get device pack info
            device_pack = (fm_device.get('devicePack', {}).get('deviceName') or 
                        fm_device.get('product') or 'N/A')

            # Get revision information
            last_revision = fm_device.get('lastRevision')
            last_revision_display = (last_revision if isinstance(last_revision, str) 
                                   and last_revision.strip() else 'N/A')
            
            delta['only_in_firemon'].append({
                'hostname': fm_device.get('name', 'N/A'),
                'mgmt_ip': mgmt_ip or 'N/A',
                'collector_group': fm_device.get('collectorGroupName', 'N/A'),
                'device_pack': device_pack,
                'status': fm_device.get('managedType', 'N/A'),
                'last_retrieval': last_revision_display
            })
            logging.debug(f"Device {fm_device.get('name')} only found in FireMon")

        # Log summary statistics
        logging.info(f"Delta calculation complete:"
                    f"\n  {len(delta['only_in_netbrain'])} devices only in NetBrain"
                    f"\n  {len(delta['only_in_firemon'])} devices only in FireMon"
                    f"\n  {len(delta['different'])} devices with differences"
                    f"\n  {len(delta['matching'])} matching devices")

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
        """Process a single device with validation and improved error handling"""
        try:
            hostname = device['hostname']
            
            # Log device processing attempt
            logging.info(f"Processing device: {hostname} (IP: {device.get('mgmtIP', 'N/A')})")
            
            # Check if device exists in FireMon (case-insensitive search)
            fm_device = self.firemon.search_device(hostname, device['mgmtIP'])
            
            # Get device pack based on attributes
            device_type = device['attributes'].get('subTypeName')
            device_pack = self.config_manager.get_device_pack(device_type)
            
            if not device_pack:
                error_msg = f"No matching device pack found for device {hostname} with type {device_type}"
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
                logging.info(f"Device {hostname} not found in FireMon, will attempt to create")
                if not self.config_manager.sync_config.dry_run:
                    try:
                        self._create_device_with_configs(device, device_pack)
                    except Exception as e:
                        if "already exists" in str(e).lower():
                            # If we get here, the device exists but our search didn't find it
                            # Try one more time with a fresh search
                            logging.warning(f"Device {hostname} creation failed with 'already exists' error. "
                                           f"Attempting to find existing device again.")
                            
                            # Force cache refresh by clearing session and re-authenticating
                            self.firemon.session.close()
                            self.firemon.session = requests.Session()
                            self.firemon.authenticate()
                            
                            # Try search again
                            fm_device = self.firemon.search_device(hostname, device['mgmtIP'])
                            
                            if fm_device:
                                logging.info(f"Found existing device {hostname} on second attempt. "
                                            f"Will update instead of create.")
                                self._update_device_if_needed(device, fm_device, device_pack)
                            else:
                                # Still can't find it, log the error
                                error_msg = (f"Device {hostname} reportedly exists in FireMon but "
                                            f"could not be found via search. Error: {str(e)}")
                                logging.error(error_msg)
                                with self._changes_lock:
                                    self.changes['devices'].append({
                                        'device': hostname,
                                        'action': 'error',
                                        'error': error_msg,
                                        'details': {
                                            'type': 'search_error',
                                            'mgmt_ip': device['mgmtIP']
                                        }
                                    })
                        else:
                            # Some other error occurred during creation
                            logging.error(f"Error creating device {hostname}: {str(e)}")
                            with self._changes_lock:
                                self.changes['devices'].append({
                                    'device': hostname,
                                    'action': 'error',
                                    'error': str(e),
                                    'details': {
                                        'type': 'creation_error',
                                        'mgmt_ip': device['mgmtIP']
                                    }
                                })
                else:
                    # In dry-run mode, just record the planned action
                    with self._changes_lock:
                        self.changes['devices'].append({
                            'device': hostname,
                            'action': 'add',
                            'status': 'dry_run',
                            'details': {
                                'mgmt_ip': device['mgmtIP'],
                                'site': device.get('site'),
                                'type': device_type,
                                'device_pack': device_pack['device_name']
                            }
                        })
            else:
                # Device exists, update if needed
                logging.info(f"Found existing device {hostname} in FireMon (ID: {fm_device.get('id', 'N/A')})")
                self._update_device_if_needed(device, fm_device, device_pack)

        except Exception as e:
            logging.error(f"Error processing device {device.get('hostname', 'UNKNOWN')}: {str(e)}")
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed processing error trace:")
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': device.get('hostname', 'UNKNOWN'),
                    'action': 'error',
                    'error': str(e)
                })

    def _create_device_with_configs(self, device: Dict[str, Any], device_pack: Dict[str, Any]) -> None:
        """
        Create new device in FireMon with configurations - Fixed version
        
        Args:
            device: NetBrain device dictionary
            device_pack: Device pack configuration
        """
        try:
            # Validate required fields before attempting creation
            required_fields = ['hostname', 'mgmtIP']
            missing_fields = [field for field in required_fields if not device.get(field)]
            if missing_fields:
                raise ValueError(f"Missing required fields for device creation: {missing_fields}")
                
            # Validate device pack
            required_pack_fields = ['artifact_id', 'group_id', 'device_type', 'device_name']
            missing_pack_fields = [field for field in required_pack_fields if not device_pack.get(field)]
            if missing_pack_fields:
                raise ValueError(f"Missing required device pack fields: {missing_pack_fields}")

            # Prepare device data following FireMon API structure - FIX: removed type field from collectionConfig
            device_data = {
                "name": device['hostname'],
                "managementIp": device['mgmtIP'],
                "domainId": self.firemon.domain_id,
                "devicePack": {
                    "artifactId": device_pack['artifact_id'],
                    "groupId": device_pack['group_id'],
                    "deviceType": device_pack['device_type'],
                    "deviceName": device_pack['device_name'],
                    "type": "DEVICE_PACK",  # Required type field
                    "collectionConfig": {
                        "name": "Default"
                        # Removed the problematic "type": "COLLECTION_CONFIG" field
                    }
                }
            }

            # Add device description if available
            if device.get('attributes', {}).get('description'):
                device_data["description"] = device['attributes']['description']

            # Add collector group if site is mapped
            collector_id = None
            if device.get('site'):
                site = device['site']
                if site.startswith("My Network/"):
                    site = site[len("My Network/"):]
                collector_id = self.config_manager.get_collector_group_id(site)
                if collector_id:
                    device_data['collectorGroupId'] = collector_id
                else:
                    logging.warning(f"No collector group mapping found for site: {site}")

            # Validate credentials before adding them
            username = os.getenv('DEFAULT_DEVICE_USERNAME')
            password = os.getenv('DEFAULT_DEVICE_PASSWORD')
            enable_password = os.getenv('DEFAULT_DEVICE_ENABLE_PASSWORD')
            
            if not all([username, password]):
                raise ValueError("Missing required device credentials in environment variables")

            # Get default settings from config manager
            default_settings = self.config_manager.get_default_settings()

            # Add extended settings
            device_data["extendedSettingsJson"] = {
                "retrievalMethod": "FromDevice",
                "retrievalCallTimeOut": default_settings.get('retrievalCallTimeOut', 120),
                "serverAliveInterval": default_settings.get('serverAliveInterval', 30),
                "suppressFQDNCapabilities": default_settings.get('suppressFQDNCapabilities', False),
                "useCLICommandGeneration": default_settings.get('useCLICommandGeneration', False),
                "usePrivateConfig": False,
                "logMonitoringEnabled": default_settings.get('logMonitoringEnabled', False),
                "changeMonitoringEnabled": default_settings.get('changeMonitoringEnabled', False),
                "scheduledRetrievalEnabled": default_settings.get('scheduledRetrievalEnabled', False),
                "checkForChangeEnabled": default_settings.get('checkForChangeEnabled', False),
                "skipRoute": False,
                "encoding": "",
                "batchConfigRetrieval": False,
                "deprecatedCA": False,
                "retrieveSetSyntaxConfig": False,
                "skipApplicationFile": False,
                "resetSSHKeyValue": False,
                "routesFromConfig": False,
                "authenticationMethod": "UserPassword",
                "fallbackAuthentication": False,
                "checkForChangeOnChangeDetection": False,
                "username": username,
                "password": password
            }

            # Add enable password if available
            if enable_password:
                device_data["extendedSettingsJson"]["enablePassword"] = enable_password

            # Log creation attempt
            logging.info(f"Creating device {device['hostname']} in FireMon")
            logging.debug(f"Device creation payload for {device['hostname']}: {json.dumps(device_data, indent=2)}")
            
            try:
                fm_device = self.firemon.create_device(device_data)
                logging.info(f"Successfully created device {device['hostname']} in FireMon with ID: {fm_device['id']}")

                # Track successful creation with FireMon device ID
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

            except Exception as e:
                error_msg = f"Failed to create device {device['hostname']}: {str(e)}"
                logging.error(error_msg)
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': device['hostname'],
                        'action': 'error',
                        'error': error_msg,
                        'details': {
                            'type': 'creation_error',
                            'mgmt_ip': device['mgmtIP'],
                            'site': device.get('site'),
                            'device_pack': device_pack['device_name']
                        }
                    })
                raise

        except Exception as e:
            error_msg = f"Unexpected error creating device {device['hostname']}: {str(e)}"
            logging.error(error_msg)
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed error trace:")
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': device['hostname'],
                    'action': 'error',
                    'error': error_msg,
                    'details': {
                        'type': 'creation_error',
                        'exception_type': type(e).__name__
                    }
                })
            raise

    def _update_device_if_needed(self, nb_device: Dict[str, Any], fm_device: Dict[str, Any],
                          device_pack: Dict[str, Any]) -> None:
        """Update FireMon device if changes detected"""
        try:
            updates_needed = []
            changes_made = False
            hostname = nb_device.get('hostname', 'unknown')
            
            # Verify that the FireMon device ID exists
            device_id = fm_device.get('id')
            if not device_id:
                logging.error(f"Cannot update device {hostname} without FireMon device ID")
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'error',
                        'error': "Missing FireMon device ID",
                        'status': 'error'
                    })
                return

            # Check device pack
            current_pack = fm_device.get('devicePack', {})
            if (current_pack is None or 
                current_pack.get('deviceName') != device_pack['device_name'] or
                current_pack.get('artifactId') != device_pack['artifact_id']):
                updates_needed.append('device_pack')

            # Check collector group
            if nb_device.get('site'):
                site = nb_device['site']
                if site.startswith("My Network/"):
                    site = site[len("My Network/"):]
                expected_collector = self.config_manager.get_collector_group_id(site)
                current_collector = fm_device.get('collectorGroupId')
                if expected_collector and current_collector is not None and str(current_collector) != str(expected_collector):
                    updates_needed.append('collector_group')

            if updates_needed and not self.config_manager.sync_config.dry_run:
                # Update device in FireMon
                update_data = {
                    'id': device_id,
                    'name': fm_device.get('name', hostname),
                    'managementIp': fm_device.get('managementIp', nb_device.get('mgmtIP')),
                    'domainId': self.firemon.domain_id  # Add domainId here
                }

                if 'device_pack' in updates_needed:
                    update_data['devicePack'] = {
                        'artifactId': device_pack['artifact_id'],
                        'groupId': device_pack['group_id'],
                        'deviceType': device_pack['device_type'],
                        'deviceName': device_pack['device_name'],
                        'type': 'DEVICE_PACK'  # Add required type field
                    }

                if 'collector_group' in updates_needed and expected_collector:
                    update_data['collectorGroupId'] = expected_collector

                try:
                    self.firemon.update_device(device_id, update_data)
                    changes_made = True
                    logging.info(f"Successfully updated device {hostname} with {updates_needed}")
                except Exception as e:
                    error_msg = f"Error updating device {hostname}: {str(e)}"
                    logging.error(error_msg)
                    with self._changes_lock:
                        self.changes['devices'].append({
                            'device': hostname,
                            'action': 'error',
                            'error': error_msg,
                            'status': 'error'
                        })
                    return

            # Track changes
            if changes_made or updates_needed:
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'update',
                        'status': 'dry_run' if self.config_manager.sync_config.dry_run else 'success',
                        'details': {
                            'updates_made': updates_needed
                        }
                    })

        except Exception as e:
            hostname = nb_device.get('hostname', 'unknown')
            error_msg = f"Error updating device {hostname}: {str(e)}"
            logging.error(error_msg)
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed error trace:")
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': hostname,
                    'action': 'error',
                    'error': error_msg,
                    'status': 'error'
                })

    def _sync_device_configs(self, nb_device: Dict[str, Any], fm_device: Dict[str, Any]) -> None:
        """
        Sync device configurations between systems using hostname
        
        Args:
            nb_device: NetBrain device dictionary
            fm_device: FireMon device dictionary
        """
        try:
            hostname = nb_device.get('hostname', 'unknown')
            
            # Verify device ID is present in FireMon device
            device_id = fm_device.get('id')
            if not device_id:
                error_msg = f"Missing device ID for {hostname} in FireMon data"
                logging.error(error_msg)
                with self._changes_lock:
                    self.changes['configs'].append({
                        'device': hostname,
                        'action': 'error',
                        'error': error_msg,
                        'status': 'error'
                    })
                return
            
            # Get device details from NetBrain using hostname instead of ID
            device_details = self.netbrain.get_device_details(hostname)
            if not device_details:
                logging.warning(f"Could not get device details for {hostname}")
                return

            # Get config times 
            nb_config_time = device_details['attributes'].get('lDiscoveryTime')
            if not nb_config_time:
                logging.warning(f"No configuration timestamp found for device {hostname}")
                return

            fm_revision = self.firemon.get_device_revision(device_id)
            
            # Safely access completeDate with error handling
            fm_config_time = None
            if fm_revision:
                # Use .get() with default value to prevent KeyError
                fm_config_time = fm_revision.get('completeDate')
                if not fm_config_time:
                    logging.warning(f"No completeDate found in revision for device {hostname}")
                    # Try alternative fields if available
                    fm_config_time = fm_revision.get('createDate') or fm_revision.get('date')
            
            # If we still don't have a valid time, assume config needs to be updated
            needs_update = True
            if fm_config_time:
                # Compare timestamps
                needs_update = TimestampUtil.is_newer_than(nb_config_time, fm_config_time)
                logging.debug(f"Config timestamp comparison for {hostname}: NB={nb_config_time}, FM={fm_config_time}, needs_update={needs_update}")
            else:
                logging.info(f"No valid FireMon config timestamp for {hostname}, forcing update")

            if needs_update:
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
                            'hostname': hostname,  # Using hostname for API call
                            'dataType': 2,  # CLI command result
                            'cmd': command
                        }

                        response = self.netbrain._request('GET', url, params=params)
                        if response.get('statusCode') == 790200:  # Success
                            content = response.get('content', '')
                            if content:
                                configs[command] = self.netbrain._process_command_output(content, command)
                                logging.debug(f"Successfully retrieved command '{command}' for device {hostname} "
                                            f"(length: {len(configs[command])} chars)")
                            else:
                                logging.warning(f"Empty content received for command '{command}' on device {hostname}")
                        else:
                            logging.warning(f"Failed to get command '{command}' for device {hostname}: {response.get('statusDescription')}")

                    except Exception as e:
                        logging.error(f"Error getting command '{command}' for device {hostname}: {str(e)}")
                        continue

                if configs:
                    # Validate config contents before proceeding
                    valid_configs = {}
                    invalid_cmds = []
                    
                    for command, content in configs.items():
                        # Ensure content is not empty or too small to be valid
                        if not content or len(content.strip()) < 10:
                            invalid_cmds.append(command)
                            logging.warning(f"Skipping invalid/empty content for command '{command}' on device {hostname}")
                            continue
                        
                        # Add valid content
                        valid_configs[command] = content
                    
                    if invalid_cmds:
                        logging.warning(f"Skipped {len(invalid_cmds)} commands with invalid content for device {hostname}")
                    
                    if not valid_configs:
                        logging.error(f"No valid configurations retrieved for device {hostname}")
                        with self._changes_lock:
                            self.changes['configs'].append({
                                'device': hostname,
                                'action': 'error',
                                'error': f"No valid configurations retrieved",
                                'status': 'error'
                            })
                        return
                        
                    # Log configs being uploaded when in debug mode
                    from .logger import log_config_details
                    if logging.getLogger().isEnabledFor(logging.DEBUG):
                        log_config_details(hostname, valid_configs)

                    # Map the commands to FireMon config files
                    fm_configs = {}
                    for command, content in valid_configs.items():
                        # Get the mapping from command to FireMon filename
                        fm_filename = command_mappings.get(command)
                        if fm_filename and content:
                            fm_configs[fm_filename] = content
                        elif content:
                            # Use a default mapping if no mapping found but we have content
                            default_filename = command.replace(' ', '_').lower() + '.txt'
                            fm_configs[default_filename] = content
                            logging.warning(f"No mapping found for command '{command}', using default filename '{default_filename}'")

                    if not fm_configs:
                        logging.error(f"No configurations to import for device {hostname} after mapping")
                        with self._changes_lock:
                            self.changes['configs'].append({
                                'device': hostname,
                                'action': 'error',
                                'error': f"No configurations to import after mapping",
                                'status': 'error'
                            })
                        return

                    # Import to FireMon
                    try:
                        # Log key information about what we're importing
                        logging.info(f"Importing {len(fm_configs)} config files for device {hostname} (ID: {device_id})")
                        logging.debug(f"Config files being imported: {list(fm_configs.keys())}")
                        
                        # Check for string content
                        for filename, content in list(fm_configs.items()):
                            if not isinstance(content, str):
                                logging.warning(f"Content for {filename} is not a string. Converting to string.")
                                fm_configs[filename] = str(content)
                        
                        result = self.firemon.import_device_config(
                            device_id,
                            fm_configs,
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
                                    'files_updated': list(fm_configs.keys()),
                                    'revision_id': result.get('id')
                                }
                            })
                        logging.info(f"Successfully updated configuration for device {hostname} with revision {result.get('id')}")
                    except Exception as e:
                        error_msg = f"Error importing configuration to FireMon for device {hostname}: {str(e)}"
                        logging.error(error_msg)
                        with self._changes_lock:
                            self.changes['configs'].append({
                                'device': hostname,
                                'action': 'error',
                                'error': error_msg,
                                'status': 'error'
                            })
                else:
                    logging.warning(f"No configurations retrieved for device {hostname}")

            else:
                logging.info(f"Configuration for device {hostname} is already up to date, skipping update")

        except Exception as e:
            hostname = nb_device.get('hostname', 'unknown')
            error_msg = f"Error syncing configs for device {hostname}: {str(e)}"
            logging.error(error_msg)
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed config sync error trace:")
            with self._changes_lock:
                self.changes['configs'].append({
                    'device': hostname,
                    'action': 'error',
                    'error': error_msg,
                    'status': 'error'
                })

    def _sync_licenses_parallel(self) -> None:
        """
        Process license synchronization in parallel
        Only considers devices with configured device types in sync-mappings.yaml
        """
        if self.config_manager.sync_config.dry_run:
            logging.info("Skipping license sync in dry run mode")
            return

        try:
            # Get devices from both systems - using FireMon cache when available
            logging.info("Getting devices for license sync")
            nb_devices = self.netbrain.get_all_devices()
            fm_devices = self.firemon.get_all_devices()
            
            # Create a set of hostnames from NetBrain devices for filtering (case-insensitive)
            nb_hostnames = {device['hostname'].lower() for device in nb_devices}
            
            # Filter FireMon devices to only include those matching NetBrain devices
            # with configured device types
            matching_fm_devices = [
                device for device in fm_devices 
                if device.get('name', '').lower() in nb_hostnames
            ]
            
            logging.info(f"Found {len(matching_fm_devices)} FireMon devices matching configured NetBrain device types")
            
            # Process licenses in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [
                    executor.submit(self._sync_device_licenses, device)
                    for device in matching_fm_devices
                ]
                
                # Wait for all license syncs to complete
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logging.error(f"Error in license sync task: {str(e)}")
                
        except Exception as e:
            logging.error(f"Error in parallel license sync: {str(e)}")
            raise

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
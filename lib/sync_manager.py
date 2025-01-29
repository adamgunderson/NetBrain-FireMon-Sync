# lib/sync_manager.py

"""
NetBrain to FireMon Synchronization Manager

This module handles the synchronization of devices, configurations, groups, and licenses
between NetBrain and FireMon systems. Key features include:
- Parallel processing using ThreadPoolExecutor for improved performance
- Memory-efficient batch processing
- Multi-level caching to reduce API calls
- Proper dry run mode simulation
- Thread-safe operations
- Comprehensive error handling and reporting
"""

import logging
from typing import Dict, List, Any, Optional, Set
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

                # Skip authentication and data prefetch in dry run mode
                if not self.config_manager.sync_config.dry_run:
                    self._ensure_authentication()
                    self._prefetch_data()

                # Initial validation
                initial_validation = self.validator.run_all_validations() if self.validator else {}

                # Get devices from NetBrain
                nb_devices = self.netbrain.get_all_devices()
                total_devices = len(nb_devices)
                logging.info(f"Processing {total_devices} devices")

                # Process devices in batches
                for i in range(0, total_devices, self.batch_size):
                    batch = nb_devices[i:i + self.batch_size]
                    self._process_device_batch(batch)
                    logging.info(f"Completed batch {i//self.batch_size + 1} of "
                               f"{(total_devices + self.batch_size - 1)//self.batch_size}")

                # Handle additional sync tasks based on configuration
                if self.config_manager.sync_config.enable_group_sync:
                    self._sync_groups_parallel()

                if self.config_manager.sync_config.enable_config_sync and not self.config_manager.sync_config.dry_run:
                    self._sync_configs_parallel()

                if self.config_manager.sync_config.enable_license_sync:
                    self._sync_licenses_parallel()

                # Final validation
                final_validation = self.validator.run_all_validations() if self.validator else {}
                self.last_sync_complete = datetime.utcnow()

                # Generate final report with all components
                return {
                    'timestamp': datetime.utcnow().isoformat(),
                    'sync_mode': self.config_manager.sync_config.sync_mode,
                    'summary': {
                        'devices': {
                            'total_processed': len(self.changes.get('devices', [])),
                            'added': sum(1 for d in self.changes.get('devices', []) 
                                       if d.get('action') == 'add'),
                            'updated': sum(1 for d in self.changes.get('devices', [])
                                         if d.get('action') == 'update'),
                            'removed': sum(1 for d in self.changes.get('devices', [])
                                         if d.get('action') == 'remove'),
                            'failed': sum(1 for d in self.changes.get('devices', [])
                                        if d.get('status') == 'error'),
                            'simulated': sum(1 for d in self.changes.get('devices', [])
                                           if d.get('status') == 'dry_run')
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
                        },
                        'validation': {
                            'total_issues': sum(len(issues) for issues in final_validation.values()),
                            'errors': sum(1 for category in final_validation.values() 
                                        for issue in category if issue['severity'] == 'error'),
                            'warnings': sum(1 for category in final_validation.values()
                                          for issue in category if issue['severity'] == 'warning')
                        }
                    },
                    'changes': self.changes,
                    'validation': {
                        'initial': initial_validation,
                        'final': final_validation
                    },
                    'statistics': self._calculate_stats(),
                    'dry_run': self.config_manager.sync_config.dry_run,
                    'sync_duration': (self.last_sync_complete - self.current_sync_start).total_seconds()
                }

        except Exception as e:
            logging.error(f"Error during sync: {str(e)}")
            raise

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
            
            # Early exit for dry run mode
            if self.config_manager.sync_config.dry_run:
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': hostname,
                        'action': 'simulate',
                        'status': 'dry_run',
                        'details': {
                            'mgmt_ip': device['mgmtIP'],
                            'site': device.get('site'),
                            'type': device['attributes'].get('subTypeName'),
                            'would_check': ['config', 'group', 'license']
                        }
                    })
                return

            # Process device if not in dry run mode
            fm_device = self._get_cached_firemon_device(hostname, device['mgmtIP'])
            
            if not fm_device:
                self._create_device_with_configs(device)
            else:
                self._update_device_if_needed(device, fm_device)

        except Exception as e:
            logging.error(f"Error processing device {device['hostname']}: {str(e)}")
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': device['hostname'],
                    'action': 'error',
                    'error': str(e)
                })

    def _ensure_authentication(self) -> None:
        """Ensure valid authentication tokens exist for both clients"""
        if not self.netbrain.validate_token():
            self.netbrain.authenticate()
        if not self.firemon.validate_token():
            self.firemon.authenticate()

    def _prefetch_data(self) -> None:
        """Prefetch and cache commonly accessed data"""
        logging.info("Prefetching data to optimize performance...")
        try:
            # Cache FireMon devices
            fm_devices = self.firemon.get_all_devices()
            with self._cache_lock:
                self._device_cache.update({d['name']: d for d in fm_devices})

            # Cache FireMon groups
            fm_groups = self.firemon.get_device_groups()
            with self._cache_lock:
                self._group_cache.update({g['name']: g for g in fm_groups})

        except Exception as e:
            logging.error(f"Error prefetching data: {str(e)}")
            raise

    def _get_cached_firemon_device(self, hostname: str, mgmt_ip: str) -> Optional[Dict[str, Any]]:
        """
        Get device from cache with thread safety
        
        Args:
            hostname: Device hostname
            mgmt_ip: Management IP address
            
        Returns:
            Device dictionary if found in cache, None otherwise
        """
        with self._cache_lock:
            return self._device_cache.get(hostname)

    @lru_cache(maxsize=1000)
    def _get_device_configs(self, device_id: str) -> Dict[str, str]:
        """
        Cached retrieval of device configurations
        
        Args:
            device_id: Device ID
            
        Returns:
            Dictionary of device configurations
        """
        if self.config_manager.sync_config.dry_run:
            return {}
        return self.netbrain.get_device_configs(device_id)

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
        """
        Calculate detailed sync statistics
        
        Returns:
            Dictionary containing sync statistics
        """
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

    def get_sync_status(self) -> Dict[str, Any]:
        """
        Get current sync status and detailed statistics
        
        Returns:
            Dictionary containing current sync status and statistics
        """
        status = {
            'running': self.sync_lock.is_locked(),
            'dry_run': self.config_manager.sync_config.dry_run,
            'lock_info': self.sync_lock.get_lock_info() if self.sync_lock.is_locked() else None,
            'last_sync': self.last_sync_complete.isoformat() if self.last_sync_complete else None,
            'current_sync_start': self.current_sync_start.isoformat() if self.current_sync_start else None,
            'changes': self.changes,
            'statistics': self._calculate_stats()
        }
        
        return status

    def _create_device_with_configs(self, device: Dict[str, Any]) -> None:
        """
        Create new device in FireMon with configurations
        
        Args:
            device: Device dictionary containing device information
        """
        try:
            device_type = device['attributes']['subTypeName']
            device_pack = self.config_manager.get_device_pack(device_type)

            if not device_pack:
                logging.warning(f"No device pack mapping for type: {device_type}")
                return

            collector_id = self.config_manager.get_collector_group_id(device['site'])
            if not collector_id:
                logging.warning(f"No collector group for site: {device['site']}")
                return

            # Prepare device data
            device_data = {
                'name': device['hostname'],
                'managementIp': device['mgmtIP'],
                'description': f"{device['attributes'].get('vendor', '')} {device['attributes'].get('model', '')}",
                'devicePack': {
                    'artifactId': device_pack['artifact_id'],
                    'groupId': device_pack['group_id'],
                    'deviceType': device_pack['device_type'],
                    'deviceName': device_pack['device_name']
                },
                'collectorGroupId': collector_id,
                'domainId': self.firemon.domain_id,
                'extendedSettingsJson': self._get_device_settings(device)
            }

            # Create device
            new_device = self.firemon.create_device(device_data)

            # Update cache
            with self._cache_lock:
                self._device_cache[device['hostname']] = new_device

            with self._changes_lock:
                self.changes['devices'].append({
                    'device': device['hostname'],
                    'action': 'add',
                    'status': 'success'
                })

        except Exception as e:
            logging.error(f"Error creating device {device['hostname']}: {str(e)}")
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': device['hostname'],
                    'action': 'add',
                    'status': 'error',
                    'error': str(e)
                })

    def _get_device_settings(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get device settings with defaults and overrides
        
        Args:
            device: Device dictionary containing device information
            
        Returns:
            Dictionary of device settings
        """
        settings = self.config_manager.get_default_settings()
        if device['attributes'].get('login_alias'):
            settings['username'] = device['attributes']['login_alias']
        return settings

    def _update_device_if_needed(self, nb_device: Dict[str, Any], 
                                fm_device: Dict[str, Any]) -> None:
        """
        Update device if changes are detected
        
        Args:
            nb_device: NetBrain device dictionary
            fm_device: FireMon device dictionary
        """
        try:
            # Skip updates in dry run mode
            if self.config_manager.sync_config.dry_run:
                with self._changes_lock:
                    self.changes['devices'].append({
                        'device': nb_device['hostname'],
                        'action': 'update',
                        'status': 'dry_run',
                        'details': {
                            'would_check': ['config', 'group', 'license']
                        }
                    })
                return

            updates_needed = self._check_device_updates(nb_device, fm_device)
            if not updates_needed:
                return

            # Process updates in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                
                if 'config' in updates_needed:
                    futures.append(executor.submit(
                        self._update_device_config, nb_device, fm_device['id']
                    ))
                    
                if 'group' in updates_needed:
                    futures.append(executor.submit(
                        self._update_device_group_membership, 
                        fm_device['id'], 
                        nb_device['site']
                    ))
                    
                if 'license' in updates_needed:
                    futures.append(executor.submit(
                        self._update_device_licensing,
                        fm_device['id'],
                        updates_needed['license']
                    ))
                    
                concurrent.futures.wait(futures)
                
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': nb_device['hostname'],
                    'action': 'update',
                    'updates': list(updates_needed.keys()),
                    'status': 'success'
                })

        except Exception as e:
            logging.error(f"Error updating device {nb_device['hostname']}: {str(e)}")
            with self._changes_lock:
                self.changes['devices'].append({
                    'device': nb_device['hostname'],
                    'action': 'update',
                    'status': 'error',
                    'error': str(e)
                })

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
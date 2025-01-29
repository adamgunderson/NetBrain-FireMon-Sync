# lib/sync_manager.py

"""
Optimized Sync Manager for NetBrain to FireMon synchronization
Key optimizations:
- Parallel processing using ThreadPoolExecutor
- Memory-efficient batch processing
- Multi-level caching (in-memory and function-level)
- Bulk data prefetching
- Optimized API calls
- Thread-safe operations
"""

import logging
import concurrent.futures
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from functools import lru_cache
from threading import Lock
from collections import defaultdict

from .sync_lock import SyncLock, SyncLockError
from .timestamp_utils import TimestampUtil
from .config_handler import ConfigHandler, ConfigValidationError
from .group_hierarchy import GroupHierarchyManager
from .config_mapping import ConfigMappingManager
from .validation import ValidationManager

class SyncManager:
    def __init__(self, netbrain_client, firemon_client, config_manager,
                 group_manager=None, validation_manager=None, max_workers=3):
        """
        Initialize sync manager with enhanced performance capabilities
        
        Args:
            netbrain_client: NetBrain API client
            firemon_client: FireMon API client
            config_manager: Configuration manager
            group_manager: Group hierarchy manager (optional)
            validation_manager: Validation manager (optional)
            max_workers: Maximum number of worker threads (default: 3)
        """
        self.netbrain = netbrain_client
        self.firemon = firemon_client
        self.config_manager = config_manager
        self.group_manager = group_manager or GroupHierarchyManager(firemon_client)
        self.validator = validation_manager
        self.max_workers = max_workers
        
        # Initialize handlers
        self.config_handler = ConfigHandler(config_manager)
        self.config_mapping = ConfigMappingManager()
        self.sync_lock = SyncLock()
        
        # Thread-safe caches with locks
        self._cache_lock = Lock()
        self._changes_lock = Lock()
        self._device_cache = {}
        self._group_cache = {}
        self._config_cache = {}
        
        # Batch processing settings
        self.batch_size = 50  # Configurable batch size
        
        # Change tracking
        self.changes = {
            'devices': [],
            'groups': [],
            'configs': [],
            'licenses': []
        }
        
        self.current_sync_start = None
        self.last_sync_complete = None

    def run_sync(self) -> Dict[str, Any]:
        """
        Run optimized synchronization with proper locking and parallel processing
        
        Returns:
            Dictionary containing sync results and statistics
        """
        try:
            with self.sync_lock.acquire(timeout=30):
                logging.info(f"Starting optimized synchronization in {self.config_manager.sync_config.sync_mode} mode")
                self.current_sync_start = datetime.utcnow()

                # Ensure valid authentication and prefetch data
                self._ensure_authentication()
                self._prefetch_data()

                # Initial validation
                initial_validation = self.validator.run_all_validations() if self.validator else {}

                # Parallel device processing if enabled
                if self.config_manager.sync_config.enable_device_sync:
                    self._sync_devices_parallel()

                # Parallel group sync if enabled
                if self.config_manager.sync_config.enable_group_sync:
                    self._sync_groups_parallel()

                # Parallel config sync if enabled
                if self.config_manager.sync_config.enable_config_sync:
                    self._sync_configs_parallel()

                # Parallel license sync if enabled
                if self.config_manager.sync_config.enable_license_sync:
                    self._sync_licenses_parallel()

                # Final validation
                final_validation = self.validator.run_all_validations() if self.validator else {}
                self.last_sync_complete = datetime.utcnow()

                return {
                    'initial_state': initial_validation,
                    'changes': self.changes,
                    'final_state': final_validation,
                    'unmapped_device_types': self.get_unmapped_device_types(),
                    'sync_duration': (self.last_sync_complete - self.current_sync_start).total_seconds(),
                    'statistics': self._calculate_stats()
                }

        except Exception as e:
            logging.error(f"Error during sync: {str(e)}")
            raise

    def _ensure_authentication(self) -> None:
        """Ensure valid authentication tokens"""
        if not self.netbrain.validate_token():
            self.netbrain.authenticate()
        if not self.firemon.validate_token():
            self.firemon.authenticate()

    def _prefetch_data(self) -> None:
        """Prefetch and cache frequently accessed data"""
        logging.info("Prefetching data to optimize performance...")
        try:
            # Prefetch FireMon devices
            fm_devices = self.firemon.get_all_devices()
            with self._cache_lock:
                self._device_cache.update({
                    d['name']: d for d in fm_devices
                })

            # Prefetch FireMon groups
            fm_groups = self.firemon.get_device_groups()
            with self._cache_lock:
                self._group_cache.update({
                    g['name']: g for g in fm_groups
                })

        except Exception as e:
            logging.error(f"Error prefetching data: {str(e)}")
            raise

    def _sync_devices_parallel(self) -> None:
        """Process devices in parallel using thread pool"""
        try:
            nb_devices = self.netbrain.get_all_devices()
            total_devices = len(nb_devices)
            logging.info(f"Processing {total_devices} devices in parallel batches")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Process devices in batches
                for i in range(0, total_devices, self.batch_size):
                    batch = nb_devices[i:i + self.batch_size]
                    futures = []
                    
                    for device in batch:
                        futures.append(executor.submit(
                            self._process_single_device, device
                        ))
                    
                    # Wait for batch completion
                    concurrent.futures.wait(futures)
                    logging.info(f"Completed batch {i//self.batch_size + 1} of {(total_devices + self.batch_size - 1)//self.batch_size}")

        except Exception as e:
            logging.error(f"Error in parallel device sync: {str(e)}")
            raise

    @lru_cache(maxsize=1000)
    def _get_device_configs(self, device_id: str) -> Dict[str, str]:
        """Cached retrieval of device configurations"""
        return self.netbrain.get_device_configs(device_id)

    def _process_single_device(self, device: Dict[str, Any]) -> None:
        """Process a single device with optimized API calls"""
        try:
            hostname = device['hostname']
            # Use cached FireMon device data
            fm_device = self._get_cached_firemon_device(hostname, device['mgmtIP'])

            if not fm_device:
                if not self.config_manager.sync_config.dry_run:
                    self._create_device_with_configs(device)
                else:
                    with self._changes_lock:
                        self.changes['devices'].append({
                            'device': hostname,
                            'action': 'add',
                            'status': 'dry_run',
                            'details': {
                                'mgmt_ip': device['mgmtIP'],
                                'site': device.get('site'),
                                'type': device['attributes'].get('subTypeName')
                            }
                        })
            else:
                if not self.config_manager.sync_config.dry_run:
                    self._update_device_if_needed(device, fm_device)
                else:
                    # In dry run mode, simulate changes without making API calls
                    with self._changes_lock:
                        self.changes['devices'].append({
                            'device': hostname,
                            'action': 'update',
                            'status': 'dry_run',
                            'details': {
                                'would_update': ['config', 'group', 'license']
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

    def _get_cached_firemon_device(self, hostname: str, mgmt_ip: str) -> Optional[Dict[str, Any]]:
        """Get device from cache with thread safety"""
        with self._cache_lock:
            return self._device_cache.get(hostname)

    def _create_device_with_configs(self, device: Dict[str, Any]) -> None:
        """Create new device with optimized config handling"""
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

            # Create device in FireMon
            device_data = self._prepare_device_data(device, device_pack, collector_id)
            new_device = self.firemon.create_device(device_data)

            # Handle configs and licensing in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                config_future = executor.submit(self._handle_device_configs, device, new_device['id'])
                license_future = executor.submit(self._handle_device_licensing, new_device['id'])
                
                concurrent.futures.wait([config_future, license_future])

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
            raise

    def _prepare_device_data(self, device: Dict[str, Any], device_pack: Dict[str, Any], 
                           collector_id: str) -> Dict[str, Any]:
        """Prepare device data for creation"""
        default_settings = self.config_manager.get_default_settings()
        if device['attributes'].get('login_alias'):
            default_settings['username'] = device['attributes']['login_alias']

        return {
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
            'extendedSettingsJson': default_settings
        }

    def _handle_device_configs(self, device: Dict[str, Any], device_id: int) -> None:
        """Handle device configuration import"""
        try:
            configs = self._get_device_configs(device['id'])
            if configs:
                mapped_configs = self.config_handler.process_device_configs(device, configs)
                self.firemon.import_device_config(device_id, mapped_configs, 'NetBrain')
        except Exception as e:
            logging.error(f"Error handling configs for {device['hostname']}: {str(e)}")
            raise

    def _handle_device_licensing(self, device_id: int) -> None:
        """Handle device licensing"""
        try:
            self.firemon.manage_device_license(device_id, add=True)
        except Exception as e:
            logging.error(f"Error handling licensing for device {device_id}: {str(e)}")
            raise

    def _sync_groups_parallel(self) -> None:
        """Parallel processing of group hierarchy"""
        try:
            nb_sites = self.netbrain.get_sites()
            hierarchy = self.group_manager.build_group_hierarchy(nb_sites)

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for site in nb_sites:
                    futures.append(executor.submit(
                        self._process_site_hierarchy, site, hierarchy
                    ))
                concurrent.futures.wait(futures)

        except Exception as e:
            logging.error(f"Error in parallel group sync: {str(e)}")
            raise

    def _sync_configs_parallel(self) -> None:
        """Parallel processing of device configurations"""
        if self.config_manager.sync_config.dry_run:
            logging.info("Skipping config sync in dry run mode")
            return

        try:
            nb_devices = self.netbrain.get_all_devices()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for device in nb_devices:
                    futures.append(executor.submit(
                        self._process_device_configs, device
                    ))
                concurrent.futures.wait(futures)
        except Exception as e:
            logging.error(f"Error in parallel config sync: {str(e)}")
            raise

    def _sync_licenses_parallel(self) -> None:
        """Parallel processing of device licensing"""
        try:
            nb_devices = self.netbrain.get_all_devices()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for device in nb_devices:
                    futures.append(executor.submit(
                        self._process_device_licensing, device
                    ))
                concurrent.futures.wait(futures)

        except Exception as e:
            logging.error(f"Error in parallel license sync: {str(e)}")
            raise

    def _calculate_stats(self) -> Dict[str, Any]:
        """Calculate detailed sync statistics"""
        return {
            'devices': {
                'total': len(self.changes['devices']),
                'successful': sum(1 for d in self.changes['devices'] if d['status'] == 'success'),
                'errors': sum(1 for d in self.changes['devices'] if d['status'] == 'error')
            },
            'groups': {
                'total': len(self.changes['groups']),
                'successful': sum(1 for g in self.changes['groups'] if g['status'] == 'success'),
                'errors': sum(1 for g in self.changes['groups'] if g['status'] == 'error')
            },
            'cache': {
                'devices': len(self._device_cache),
                'groups': len(self._group_cache),
                'configs': len(self._config_cache)
            },
            'timing': {
                'start': self.current_sync_start.isoformat() if self.current_sync_start else None,
                'end': self.last_sync_complete.isoformat() if self.last_sync_complete else None
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

    def get_unmapped_device_types(self) -> Dict[str, int]:
        """Get summary of device types without mappings"""
        unmapped = {}
        try:
            nb_devices = self.netbrain.get_all_devices()
            device_types = defaultdict(int)
            
            # Count device types in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                def count_device_type(device):
                    device_type = device.get('attributes', {}).get('subTypeName')
                    if device_type and not self.config_mapping.get_device_type_mapping(device_type):
                        return device_type
                    return None

                futures = [executor.submit(count_device_type, device) for device in nb_devices]
                for future in concurrent.futures.as_completed(futures):
                    device_type = future.result()
                    if device_type:
                        with self._changes_lock:
                            device_types[device_type] += 1

            unmapped = dict(device_types)
            if unmapped:
                logging.warning(f"Found {len(unmapped)} unmapped device types")
                
        except Exception as e:
            logging.error(f"Error getting unmapped device types: {str(e)}")
            
        return unmapped

    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status and statistics with enhanced metrics"""
        status = {
            'running': self.sync_lock.is_locked(),
            'lock_info': self.sync_lock.get_lock_info() if self.sync_lock.is_locked() else None,
            'last_sync': self.last_sync_complete.isoformat() if self.last_sync_complete else None,
            'current_sync_start': self.current_sync_start.isoformat() if self.current_sync_start else None,
            'changes': self.changes,
            'statistics': {
                'devices': {
                    'total': len(self.changes.get('devices', [])),
                    'success': sum(1 for d in self.changes.get('devices', []) 
                                 if d.get('status') == 'success'),
                    'errors': sum(1 for d in self.changes.get('devices', []) 
                                if d.get('status') == 'error')
                },
                'groups': {
                    'total': len(self.changes.get('groups', [])),
                    'success': sum(1 for g in self.changes.get('groups', []) 
                                 if g.get('status') == 'success'),
                    'errors': sum(1 for g in self.changes.get('groups', []) 
                                if g.get('status') == 'error')
                },
                'configs': {
                    'total': len(self.changes.get('configs', [])),
                    'success': sum(1 for c in self.changes.get('configs', []) 
                                 if c.get('status') == 'success'),
                    'errors': sum(1 for c in self.changes.get('configs', []) 
                                if c.get('status') == 'error')
                },
                'licenses': {
                    'total': len(self.changes.get('licenses', [])),
                    'success': sum(1 for l in self.changes.get('licenses', []) 
                                 if l.get('status') == 'success'),
                    'errors': sum(1 for l in self.changes.get('licenses', []) 
                                if l.get('status') == 'error')
                },
                'performance': {
                    'cache_stats': {
                        'device_cache_size': len(self._device_cache),
                        'group_cache_size': len(self._group_cache),
                        'config_cache_size': len(self._config_cache)
                    },
                    'batch_stats': {
                        'batch_size': self.batch_size,
                        'max_workers': self.max_workers
                    }
                }
            }
        }
        
        if self.validator:
            status['validation'] = self.validator.get_validation_summary()
            
        return status

    def _update_device_if_needed(self, nb_device: Dict[str, Any], 
                            fm_device: Dict[str, Any]) -> None:
        """Update device if changes detected"""
        try:
            # In dry run mode, skip actual update checks
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

    def _check_device_updates(self, nb_device: Dict[str, Any], 
                         fm_device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check what device aspects need updating"""
        updates = {}
        
        # Skip actual config checks in dry run mode
        if self.config_manager.sync_config.enable_config_sync and not self.config_manager.sync_config.dry_run:
            nb_config_time = self.netbrain.get_device_config_time(nb_device['id'])
            fm_config_time = self.firemon.get_device_revision(fm_device['id'])
            
            if nb_config_time and fm_config_time:
                if TimestampUtil.is_newer_than(nb_config_time, fm_config_time['completeDate']):
                    updates['config'] = True
        elif self.config_manager.sync_config.enable_config_sync and self.config_manager.sync_config.dry_run:
            # In dry run mode, just mark config as needing update for reporting
            updates['config'] = True
        
        # Check group membership
        if self.config_manager.sync_config.enable_group_sync:
            if not self.config_manager.sync_config.dry_run:
                current_groups = set(g['id'] for g in self.firemon.get_device_groups(fm_device['id']))
                target_groups = self._get_target_groups(nb_device['site'])
                
                if current_groups != target_groups:
                    updates['group'] = {'add': target_groups - current_groups,
                                      'remove': current_groups - target_groups}
            else:
                # In dry run mode, just mark group as needing update for reporting
                updates['group'] = {'add': set(), 'remove': set()}
        
        # Check licensing
        if self.config_manager.sync_config.enable_license_sync:
            if not self.config_manager.sync_config.dry_run:
                current_licenses = set(fm_device.get('licenses', []))
                required_licenses = {'SM', 'PO', 'PP'}
                
                missing_licenses = required_licenses - current_licenses
                if missing_licenses:
                    updates['license'] = {'add': missing_licenses}
            else:
                # In dry run mode, just mark licensing as needing update for reporting
                updates['license'] = {'add': {'SM', 'PO', 'PP'}}
        
        return updates if updates else None

    def _get_target_groups(self, site_path: str) -> Set[int]:
        """Get target group IDs for a site path"""
        target_groups = set()
        path_parts = site_path.split('/')
        current_path = ''
        
        for part in path_parts:
            if current_path:
                current_path += '/'
            current_path += part
            
            with self._cache_lock:
                group = self._group_cache.get(part)
                if group:
                    target_groups.add(group['id'])
        
        return target_groups

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
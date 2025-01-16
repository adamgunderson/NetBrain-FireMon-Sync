# lib/sync_manager.py

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from .sync_lock import SyncLock, SyncLockError
from .timestamp_utils import TimestampUtil  
from .config_handler import ConfigHandler, ConfigValidationError
from .group_hierarchy import GroupHierarchyManager
from .config_mapping import ConfigMappingManager
from .validation import ValidationManager

class SyncManager:
    def __init__(self, netbrain_client, firemon_client, config_manager,
                 group_manager=None, validation_manager=None):
        """Initialize sync manager with required clients and managers"""
        self.netbrain = netbrain_client
        self.firemon = firemon_client
        self.config_manager = config_manager
        self.group_manager = group_manager or GroupHierarchyManager(firemon_client)
        self.validator = validation_manager
        
        # Initialize handlers
        self.config_handler = ConfigHandler(config_manager)
        self.config_mapping = ConfigMappingManager()
        self.sync_lock = SyncLock()
        
        # Initialize change tracking
        self.changes = {
            'devices': [],
            'groups': [],
            'configs': [],
            'licenses': []
        }
        
        self.current_sync_start = None
        self.last_sync_complete = None

    def run_sync(self) -> Dict[str, Any]:
        """Run synchronization with proper locking"""
        try:
            with self.sync_lock.acquire(timeout=30):
                logging.info(f"Starting synchronization in {self.config_manager.sync_config.sync_mode} mode")
                self.current_sync_start = datetime.utcnow()

                # Ensure valid authentication
                if not self.netbrain.validate_token():
                    self.netbrain.authenticate()
                if not self.firemon.validate_token():
                    self.firemon.authenticate()

                # Initial validation
                initial_validation = self.validator.run_all_validations() if self.validator else {}

                # Perform device sync if enabled
                if self.config_manager.sync_config.enable_device_sync:
                    self._sync_devices()

                # Perform other syncs based on mode
                if self.config_manager.sync_config.enable_group_sync:
                    self._sync_device_groups()
                if self.config_manager.sync_config.enable_config_sync:
                    self._sync_configurations()
                if self.config_manager.sync_config.enable_license_sync:
                    self._sync_licenses()

                # Final validation
                final_validation = self.validator.run_all_validations() if self.validator else {}
                self.last_sync_complete = datetime.utcnow()

                return {
                    'initial_state': initial_validation,
                    'changes': self.changes,
                    'final_state': final_validation,
                    'unmapped_device_types': self.get_unmapped_device_types(),
                    'sync_duration': (self.last_sync_complete - self.current_sync_start).total_seconds()
                }

        except Exception as e:
            logging.error(f"Error during sync: {str(e)}")
            raise

    def _sync_devices(self) -> None:
        """Synchronize devices between NetBrain and FireMon"""
        try:
            logging.info("Starting device synchronization")
            
            # Get devices from both systems
            nb_devices = self.netbrain.get_all_devices()
            fm_devices = self.firemon.get_all_devices()
            
            # Create mappings for easier lookup
            nb_device_map = {d['hostname']: d for d in nb_devices}
            fm_device_map = {d['name']: d for d in fm_devices}
            
            # Find devices to add (in NetBrain but not in FireMon)
            devices_to_add = set(nb_device_map.keys()) - set(fm_device_map.keys())
            
            # Find devices to remove (in FireMon but not in NetBrain)
            devices_to_remove = set(fm_device_map.keys()) - set(nb_device_map.keys())
            
            # Process devices to add
            for hostname in devices_to_add:
                device = nb_device_map[hostname]
                if not self.config_manager.sync_config.dry_run:
                    try:
                        new_device = self._create_device_in_firemon(device)
                        if new_device:
                            self.changes['devices'].append({
                                'device': hostname,
                                'action': 'add',
                                'status': 'success'
                            })
                    except Exception as e:
                        logging.error(f"Error creating device {hostname}: {str(e)}")
                        self.changes['devices'].append({
                            'device': hostname,
                            'action': 'add',
                            'status': 'error',
                            'error': str(e)
                        })
                else:
                    # In dry run mode, just record what would be added
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
            
            # Process devices to remove if enabled
            if self.config_manager.sync_config.remove_missing_devices:
                for hostname in devices_to_remove:
                    device = fm_device_map[hostname]
                    if not self.config_manager.sync_config.dry_run:
                        try:
                            self.firemon.delete_device(device['id'])
                            self.changes['devices'].append({
                                'device': hostname,
                                'action': 'remove',
                                'status': 'success'
                            })
                        except Exception as e:
                            logging.error(f"Error removing device {hostname}: {str(e)}")
                            self.changes['devices'].append({
                                'device': hostname,
                                'action': 'remove',
                                'status': 'error',
                                'error': str(e)
                            })
                    else:
                        # In dry run mode, just record what would be removed
                        self.changes['devices'].append({
                            'device': hostname,
                            'action': 'remove',
                            'status': 'dry_run',
                            'details': {
                                'id': device['id'],
                                'mgmt_ip': device.get('managementIp')
                            }
                        })
            
            logging.info(f"Device sync summary - To Add: {len(devices_to_add)}, To Remove: {len(devices_to_remove)}")
            
        except Exception as e:
            logging.error(f"Error syncing devices: {str(e)}")
            raise

    def _sync_device_groups(self) -> None:
        """Synchronize device groups from NetBrain to FireMon"""
        try:
            logging.info("Starting device group synchronization")
            
            # Get NetBrain sites
            nb_sites = self.netbrain.get_sites()
            logging.debug(f"Retrieved {len(nb_sites)} sites from NetBrain")

            # Build hierarchy
            hierarchy = self.group_manager.build_group_hierarchy(nb_sites)
            
            # Get current FireMon groups for comparison
            current_groups = {g['name']: g for g in self.firemon.get_device_groups()}
            
            for site in nb_sites:
                try:
                    self._process_site_hierarchy(site, hierarchy, current_groups)
                except Exception as e:
                    logging.error(f"Error processing site {site['sitePath']}: {str(e)}")
                    self.changes['groups'].append({
                        'site': site['sitePath'],
                        'action': 'error',
                        'error': str(e)
                    })

        except Exception as e:
            logging.error(f"Error syncing device groups: {str(e)}")
            raise

    def _process_site_hierarchy(self, site: Dict[str, Any], hierarchy: Dict[str, Any], 
                              current_groups: Dict[str, Any]) -> None:
        """Process individual site for hierarchy sync"""
        site_path = site['sitePath']
        site_name = site_path.split('/')[-1]
        
        logging.debug(f"Processing site: {site_path}")
        
        if not self.config_manager.sync_config.dry_run:
            if site_name not in current_groups:
                # Create new group
                group_data = {
                    'name': site_name,
                    'description': f'NetBrain site: {site_path}',
                    'domainId': self.firemon.domain_id
                }
                
                # Add parent relationship if not top level
                parent_path = '/'.join(site_path.split('/')[:-1])
                if parent_path:
                    parent_name = parent_path.split('/')[-1]
                    if parent_name in current_groups:
                        group_data['parentId'] = current_groups[parent_name]['id']
                
                try:
                    new_group = self.firemon.create_device_group(group_data)
                    current_groups[site_name] = new_group
                    self.changes['groups'].append({
                        'site': site_path,
                        'action': 'create',
                        'status': 'success'
                    })
                except Exception as e:
                    logging.error(f"Error creating group for site {site_path}: {str(e)}")
                    self.changes['groups'].append({
                        'site': site_path,
                        'action': 'create',
                        'status': 'error',
                        'error': str(e)
                    })
            else:
                # Update existing group if needed
                existing_group = current_groups[site_name]
                updates_needed = self._check_group_updates(existing_group, site, hierarchy)
                
                if updates_needed:
                    try:
                        self.firemon.update_device_group(existing_group['id'], updates_needed)
                        self.changes['groups'].append({
                            'site': site_path,
                            'action': 'update',
                            'updates': list(updates_needed.keys()),
                            'status': 'success'
                        })
                    except Exception as e:
                        logging.error(f"Error updating group for site {site_path}: {str(e)}")
                        self.changes['groups'].append({
                            'site': site_path,
                            'action': 'update',
                            'status': 'error',
                            'error': str(e)
                        })

    def _sync_configurations(self) -> None:
        """Synchronize device configurations from NetBrain to FireMon"""
        try:
            logging.info("Starting configuration synchronization")
            processed_count = 0
            error_count = 0
            
            # Get all NetBrain devices
            nb_devices = self.netbrain.get_all_devices()
            logging.debug(f"Retrieved {len(nb_devices)} devices from NetBrain")

            for device in nb_devices:
                try:
                    logging.debug(f"Processing device: {device['hostname']}")
                    
                    # Check if device exists in FireMon
                    fm_device = self.firemon.search_device(
                        device['hostname'],
                        device['mgmtIP']
                    )
                    
                    if not fm_device:
                        logging.debug(f"Device {device['hostname']} not found in FireMon")
                        if not self.config_manager.sync_config.dry_run:
                            self._create_device_in_firemon(device)
                        continue

                    # Compare config timestamps
                    nb_config_time = self.netbrain.get_device_config_time(device['id'])
                    fm_config_time = self.firemon.get_device_revision(fm_device['id'])

                    if nb_config_time and fm_config_time:
                        if TimestampUtil.is_newer_than(nb_config_time, fm_config_time['completeDate']):
                            logging.debug(f"NetBrain has newer config for {device['hostname']}")
                            
                            if not self.config_manager.sync_config.dry_run:
                                try:
                                    self._update_device_config(device, fm_device['id'])
                                    processed_count += 1
                                except Exception as e:
                                    error_count += 1
                                    logging.error(f"Error updating config for {device['hostname']}: {str(e)}")
                        else:
                            logging.debug(f"FireMon config is current for {device['hostname']}")

                except Exception as e:
                    error_count += 1
                    logging.error(f"Error processing device {device['hostname']}: {str(e)}")
                    self.changes['configs'].append({
                        'device': device['hostname'],
                        'action': 'error',
                        'error': str(e)
                    })

            logging.info(f"Configuration sync complete - Processed: {processed_count}, Errors: {error_count}")

        except Exception as e:
            logging.error(f"Error syncing configurations: {str(e)}")
            raise

    def _update_device_config(self, device: Dict[str, Any], fm_device_id: int) -> None:
        """Update device configuration in FireMon"""
        try:
            # Get configurations from NetBrain
            configs = self.netbrain.get_device_configs(device['id'])
            
            # Process and map configurations
            mapped_configs = self.config_handler.process_device_configs(device, configs)
            
            # Backup existing configs before update
            self.config_handler.backup_configs(device, mapped_configs)
            
            # Import to FireMon
            self.firemon.import_device_config(
                fm_device_id,
                mapped_configs,
                'NetBrain'
            )
            
            self.changes['configs'].append({
                'device': device['hostname'],
                'action': 'update',
                'status': 'success'
            })
            
            logging.info(f"Successfully updated config for {device['hostname']}")
            
        except ConfigValidationError as e:
            logging.error(f"Config validation error for {device['hostname']}: {str(e)}")
            self.changes['configs'].append({
                'device': device['hostname'],
                'action': 'update',
                'status': 'error',
                'error': str(e)
            })
        except Exception as e:
            raise ConfigValidationError(f"Error updating config: {str(e)}")

    def _create_device_in_firemon(self, device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create new device in FireMon"""
        try:
            device_type = device['attributes']['subTypeName']
            device_pack = self.config_manager.get_device_pack(device_type)
            
            if not device_pack:
                logging.warning(f"No device pack mapping found for type: {device_type}")
                return None
                
            collector_id = self.config_manager.get_collector_group_id(device['site'])
            if not collector_id:
                logging.warning(f"No collector group found for site: {device['site']}")
                return None

            # Get default settings
            default_settings = self.config_manager.get_default_settings()
            
            # Override username if available in device attributes
            if device['attributes'].get('login_alias'):
                default_settings['username'] = device['attributes']['login_alias']

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
                'extendedSettingsJson': default_settings
            }

            new_device = self.firemon.create_device(device_data)
            
            # Process initial configuration and licensing
            configs = self.netbrain.get_device_configs(device['id'])
            if configs:
                mapped_configs = self.config_handler.process_device_configs(device, configs)
                self.firemon.import_device_config(new_device['id'], mapped_configs, 'NetBrain')

            # License the device
            self.firemon.manage_device_license(new_device['id'], add=True)
            
            # Update group membership
            if device.get('site'):
                self._update_device_group_membership(new_device['id'], device['site'])
                
            self.changes['devices'].append({
                'device': device['hostname'],
                'action': 'create',
                'status': 'success'
            })
            
            logging.info(f"Successfully created device {device['hostname']} in FireMon")
            return new_device
            
        except Exception as e:
            logging.error(f"Error creating device {device['hostname']}: {str(e)}")
            self.changes['devices'].append({
                'device': device['hostname'],
                'action': 'create',
                'status': 'error',
                'error': str(e)
            })
            return None

    def _sync_licenses(self) -> None:
        """Synchronize device licenses between NetBrain and FireMon"""
        try:
            logging.info("Starting license synchronization")
            
            # Get devices from both systems
            nb_devices = self.netbrain.get_all_devices()
            fm_devices = self.firemon.get_all_devices()
            
            nb_hostnames = {d['hostname'] for d in nb_devices}
            fm_hostnames = {d['name'] for d in fm_devices}
            
            # Track sync statistics
            license_added = 0
            license_removed = 0
            errors = 0
            
            # Process devices needing licenses
            for device in nb_devices:
                if device['hostname'] in fm_hostnames:
                    fm_device = next(d for d in fm_devices if d['name'] == device['hostname'])
                    if not any(product in fm_device.get('licenses', []) 
                             for product in ['SM', 'PO', 'PP']):
                        try:
                            if not self.config_manager.sync_config.dry_run:
                                self.firemon.manage_device_license(fm_device['id'], add=True)
                                self.changes['licenses'].append({
                                    'device': device['hostname'],
                                    'action': 'add',
                                    'status': 'success'
                                })
                                license_added += 1
                            else:
                                self.changes['licenses'].append({
                                    'device': device['hostname'],
                                    'action': 'add',
                                    'status': 'dry_run'
                                })
                        except Exception as e:
                            errors += 1
                            logging.error(f"Error adding license for {device['hostname']}: {str(e)}")
                            self.changes['licenses'].append({
                                'device': device['hostname'],
                                'action': 'add',
                                'status': 'error',
                                'error': str(e)
                            })
            
            # Handle devices not in NetBrain
            if self.config_manager.sync_config.unlicense_removed_devices:
                for device in fm_devices:
                    if device['name'] not in nb_hostnames:
                        if any(product in device.get('licenses', []) 
                              for product in ['SM', 'PO', 'PP']):
                            try:
                                if not self.config_manager.sync_config.dry_run:
                                    self.firemon.manage_device_license(device['id'], add=False)
                                    self.changes['licenses'].append({
                                        'device': device['name'],
                                        'action': 'remove',
                                        'status': 'success'
                                    })
                                    license_removed += 1
                                else:
                                    self.changes['licenses'].append({
                                        'device': device['name'],
                                        'action': 'remove',
                                        'status': 'dry_run'
                                    })
                            except Exception as e:
                                errors += 1
                                logging.error(f"Error removing license from {device['name']}: {str(e)}")
                                self.changes['licenses'].append({
                                    'device': device['name'],
                                    'action': 'remove',
                                    'status': 'error',
                                    'error': str(e)
                                })

            logging.info(f"License sync complete - Added: {license_added}, Removed: {license_removed}, Errors: {errors}")

        except Exception as e:
            logging.error(f"Error syncing licenses: {str(e)}")
            raise

    def _update_device_group_membership(self, device_id: int, site_path: str) -> None:
        """Update device group membership based on site path"""
        try:
            logging.debug(f"Updating group membership for device {device_id} to site {site_path}")
            
            # Get current and target groups
            current_groups = set()
            target_groups = set()
            
            fm_device_groups = self.firemon.get_device_groups(device_id)
            current_groups = {g['id'] for g in fm_device_groups}
            
            # Build target groups from site path
            path_parts = site_path.split('/')
            current_path = ''
            
            for part in path_parts:
                if current_path:
                    current_path += '/'
                current_path += part
                
                group = self.group_manager.get_group_by_path(current_path)
                if group:
                    target_groups.add(group['id'])
            
            # Calculate group changes
            groups_to_add = target_groups - current_groups
            groups_to_remove = current_groups - target_groups
            
            if not self.config_manager.sync_config.dry_run:
                # Add to new groups
                for group_id in groups_to_add:
                    try:
                        self.firemon.add_device_to_group(group_id, device_id)
                        logging.debug(f"Added device {device_id} to group {group_id}")
                    except Exception as e:
                        logging.error(f"Error adding device {device_id} to group {group_id}: {str(e)}")
                
                # Remove from old groups
                for group_id in groups_to_remove:
                    try:
                        self.firemon.remove_device_from_group(group_id, device_id)
                        logging.debug(f"Removed device {device_id} from group {group_id}")
                    except Exception as e:
                        logging.error(f"Error removing device {device_id} from group {group_id}: {str(e)}")
            
            self.changes['groups'].append({
                'device_id': device_id,
                'action': 'membership_update',
                'added_groups': len(groups_to_add),
                'removed_groups': len(groups_to_remove),
                'status': 'dry_run' if self.config_manager.sync_config.dry_run else 'success'
            })

        except Exception as e:
            logging.error(f"Error updating group membership for device {device_id}: {str(e)}")
            self.changes['groups'].append({
                'device_id': device_id,
                'action': 'membership_update',
                'status': 'error',
                'error': str(e)
            })

    def _check_group_updates(self, existing_group: Dict[str, Any], site: Dict[str, Any], 
                           hierarchy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if group needs updates"""
        updates = {}
        site_path = site['sitePath']
        
        # Check description
        expected_description = f'NetBrain site: {site_path}'
        if existing_group.get('description') != expected_description:
            updates['description'] = expected_description
            
        # Check parent relationship
        parent_path = '/'.join(site_path.split('/')[:-1])
        if parent_path:
            parent_node = hierarchy.get(parent_path)
            if parent_node and parent_node.get('id') != existing_group.get('parentId'):
                updates['parentId'] = parent_node['id']
                
        return updates if updates else None

    def get_unmapped_device_types(self) -> Dict[str, int]:
        """Get summary of device types without mappings"""
        unmapped = {}
        try:
            nb_devices = self.netbrain.get_all_devices()
            for device in nb_devices:
                device_type = device.get('attributes', {}).get('subTypeName')
                if device_type and not self.config_mapping.get_device_type_mapping(device_type):
                    unmapped[device_type] = unmapped.get(device_type, 0) + 1
                    logging.warning(f"No device pack mapping found for type: {device_type}")
        except Exception as e:
            logging.error(f"Error getting unmapped device types: {str(e)}")
        return unmapped

    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status and statistics"""
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
                }
            }
        }
        
        if self.validator:
            status['validation'] = self.validator.get_validation_summary()
            
        return status

    def clear_changes(self) -> None:
        """Clear tracked changes"""
        self.changes = {
            'devices': [],
            'groups': [],
            'configs': [],
            'licenses': []
        }

    def shutdown(self) -> None:
        """Clean shutdown of sync manager"""
        logging.info("Shutting down sync manager")
        try:
            if self.sync_lock.is_locked():
                self.sync_lock.break_lock()
            logging.info("Sync manager shutdown complete")
        except Exception as e:
            logging.error(f"Error during sync manager shutdown: {str(e)}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.shutdown()
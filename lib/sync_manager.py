# lib/sync_manager.py

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from .sync_lock import SyncLock, SyncLockError  
from .timestamp_utils import TimestampUtil
from .config_handler import ConfigHandler, ConfigValidationError
from .group_hierarchy import GroupHierarchyManager
from .config_mapping import ConfigMappingManager

class SyncManager:
    def __init__(self, netbrain_client, firemon_client, config_manager,
                 group_manager=None, validation_manager=None):
        self.netbrain = netbrain_client
        self.firemon = firemon_client
        self.config_manager = config_manager
        self.group_manager = group_manager
        self.validator = validation_manager
        
        # Initialize handlers
        self.config_handler = ConfigHandler(config_manager)
        self.config_mapping = ConfigMappingManager()
        self.sync_lock = SyncLock()
        
        self.changes = {
            'devices': [],
            'groups': [],
            'configs': [],
            'licenses': []
        }

    def run_sync(self) -> Dict[str, Any]:
        """Run synchronization with proper locking"""
        try:
            with self.sync_lock.acquire(timeout=30):
                logging.info(f"Starting synchronization in {self.config_manager.sync_config.sync_mode} mode")
                
                # Ensure authentication before starting sync
                self.netbrain.authenticate()
                self.firemon.authenticate()

                # Initial validation
                initial_validation = self.validator.run_all_validations() if self.validator else {}

                # Perform sync operations based on mode
                if self.config_manager.sync_config.sync_mode in ['full', 'groups']:
                    self._sync_device_groups()

                if self.config_manager.sync_config.sync_mode in ['full', 'configs']:
                    self._sync_configurations()

                if self.config_manager.sync_config.sync_mode in ['full', 'licenses']:
                    self._sync_licenses()

                # Get unmapped device types summary
                unmapped_types = self.get_unmapped_device_types()
                
                # Final validation
                final_validation = self.validator.run_all_validations() if self.validator else {}

                return {
                    'initial_state': initial_validation,
                    'changes': self.changes,
                    'final_state': final_validation,
                    'unmapped_device_types': unmapped_types
                }

        except Exception as e:
            logging.error(f"Error during sync: {str(e)}")
            raise

    def _sync_device_groups(self):
        """Synchronize device groups with improved hierarchy handling"""
        try:
            if self.group_manager:
                # Get NetBrain site hierarchy
                nb_sites = self.netbrain.get_sites()
                
                # Build and validate hierarchy
                hierarchy = self.group_manager.build_group_hierarchy(nb_sites)
                
                # Validate hierarchy before sync
                issues = self.group_manager.validate_hierarchy()
                if issues:
                    logging.warning(f"Found hierarchy issues: {issues}")
                    if any(i['severity'] == 'error' for i in issues):
                        raise ValueError("Critical hierarchy issues found")
                
                # Sync groups
                group_changes = self.group_manager.sync_group_hierarchy(
                    hierarchy,
                    self.config_manager.sync_config.dry_run
                )
                
                self.changes['groups'].extend(group_changes)
            else:
                logging.warning("Group manager not initialized, skipping group sync")

        except Exception as e:
            logging.error(f"Error syncing device groups: {str(e)}")
            raise

    def _process_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Process single device with improved error handling"""
        try:
            device_type = device['attributes']['subTypeName']
            
            # Validate device type mappings
            mapping_issues = self.config_mapping.validate_device_mappings(device_type)
            if mapping_issues:
                for issue in mapping_issues:
                    logging.warning(f"Mapping issue for {device['hostname']}: {issue}")
                if any(i['severity'] == 'error' for i in mapping_issues):
                    return {
                        'action': 'skip',
                        'device': device['hostname'],
                        'reason': 'mapping_issues',
                        'issues': mapping_issues,
                        'status': 'error'
                    }

            # Check if device exists in FireMon
            fm_device = self.firemon.search_device(
                device['hostname'],
                device['mgmtIP']
            )

            if not fm_device:
                if not self.config_manager.sync_config.dry_run:
                    # Create new device
                    collector_id = self.config_manager.get_collector_group_id(device['site'])
                    if not collector_id:
                        return {
                            'action': 'skip',
                            'device': device['hostname'],
                            'reason': 'no_collector_group',
                            'site': device['site'],
                            'status': 'warning'
                        }

                    device_data = {
                        'name': device['hostname'],
                        'managementIp': device['mgmtIP'],
                        'description': f"{device['attributes'].get('vendor', '')} {device['attributes'].get('model', '')}",
                        'devicePack': self.config_mapping.get_device_type_mapping(device_type),
                        'collectorGroupId': collector_id,
                        'domainId': self.firemon.domain_id,
                        'extendedSettingsJson': {
                            **self.config_manager.get_default_settings(),
                            'username': device['attributes'].get('login_alias', 'admin'),
                        }
                    }

                    new_device = self.firemon.create_device(device_data)
                    
                    try:
                        # Import configs
                        self._import_device_configs(device, new_device['id'])
                        
                        # License device
                        self.firemon.manage_device_license(new_device['id'], add=True)
                        
                        # Update group membership
                        if self.group_manager:
                            changes = self.group_manager.get_group_membership_changes(
                                new_device['id'],
                                device['site']
                            )
                            self._apply_group_changes(new_device['id'], changes)
                        
                        return {
                            'action': 'add',
                            'device': device['hostname'],
                            'device_id': new_device['id'],
                            'status': 'success'
                        }
                    
                    except Exception as e:
                        logging.error(f"Error setting up new device {device['hostname']}: {str(e)}")
                        # Try to cleanup
                        try:
                            self.firemon.delete_device(new_device['id'])
                        except:
                            pass
                        raise
                else:
                    return {
                        'action': 'add',
                        'device': device['hostname'],
                        'status': 'dry_run'
                    }
            else:
                updates = []
                
                # Check config updates
                if self.config_manager.sync_config.enable_config_sync:
                    config_change = self._import_device_configs(device, fm_device['id'])
                    if config_change:
                        updates.append('config')
                
                # Check group membership
                if self.group_manager:
                    group_changes = self.group_manager.get_group_membership_changes(
                        fm_device['id'],
                        device['site']
                    )
                    if group_changes['add'] or group_changes['remove']:
                        if not self.config_manager.sync_config.dry_run:
                            self._apply_group_changes(fm_device['id'], group_changes)
                            updates.append('groups')

                if updates:
                    return {
                        'action': 'update',
                        'device': device['hostname'],
                        'device_id': fm_device['id'],
                        'updates': updates,
                        'status': 'success' if not self.config_manager.sync_config.dry_run else 'dry_run'
                    }

            return None

        except Exception as e:
            logging.error(f"Error processing device {device['hostname']}: {str(e)}")
            return {
                'action': 'error',
                'device': device['hostname'],
                'error': str(e),
                'status': 'error'
            }

    def _import_device_configs(self, nb_device: Dict[str, Any], fm_device_id: int) -> Optional[Dict[str, Any]]:
        """Import device configurations with improved handling"""
        try:
            # Get configuration timestamps
            nb_config_time = self.netbrain.get_device_config_time(nb_device['id'])
            fm_config_time = self.firemon.get_device_revision(fm_device_id)
            
            if nb_config_time and fm_config_time:
                # Use timestamp utility for comparison
                if TimestampUtil.is_newer_than(nb_config_time, fm_config_time['completeDate']):
                    # Get and process configurations
                    configs = self.netbrain.get_device_configs(nb_device['id'])
                    
                    try:
                        # Process configs through handler
                        mapped_configs = self.config_handler.process_device_configs(nb_device, configs)
                        
                        if not self.config_manager.sync_config.dry_run:
                            # Backup existing configs
                            self.config_handler.backup_configs(nb_device, mapped_configs)
                            
                            # Import to FireMon
                            self.firemon.import_device_config(
                                fm_device_id,
                                mapped_configs,
                                'NetBrain'
                            )
                            return {
                                'type': 'config_update',
                                'device_id': fm_device_id,
                                'status': 'success'
                            }
                        else:
                            return {
                                'type': 'config_update',
                                'device_id': fm_device_id,
                                'status': 'dry_run'
                            }
                            
                    except ConfigValidationError as e:
                        logging.error(f"Config validation error for {nb_device['hostname']}: {str(e)}")
                        return {
                            'type': 'config_update',
                            'device_id': fm_device_id,
                            'error': str(e),
                            'status': 'error'
                        }

        except Exception as e:
            logging.error(f"Error importing configs for {nb_device['hostname']}: {str(e)}")
            return {
                'type': 'config_update',
                'device_id': fm_device_id,
                'error': str(e),
                'status': 'error'
            }

        return None

    def _apply_group_changes(self, device_id: int, changes: Dict[str, set]) -> None:
        """Apply group membership changes"""
        for group_id in changes['add']:
            try:
                self.firemon.add_device_to_group(group_id, device_id)
            except Exception as e:
                logging.error(f"Error adding device {device_id} to group {group_id}: {str(e)}")
                
        for group_id in changes['remove']:
            try:
                self.firemon.remove_device_from_group(group_id, device_id)
            except Exception as e:
                logging.error(f"Error removing device {device_id} from group {group_id}: {str(e)}")

    def _sync_licenses(self) -> None:
        """Synchronize device licenses with improved handling"""
        try:
            # Get devices from both systems
            nb_devices = self.netbrain.get_all_devices()
            fm_devices = self.firemon.get_all_devices()
            
            nb_hostnames = {d['hostname'] for d in nb_devices}
            fm_hostnames = {d['name'] for d in fm_devices}
            
            # Process devices in NetBrain but not licensed in FireMon
            for device in nb_devices:
                if device['hostname'] in fm_hostnames:
                    fm_device = next(d for d in fm_devices if d['name'] == device['hostname'])
                    if not any(product in fm_device.get('licenses', []) for product in ['SM', 'PO', 'PP']):
                        if not self.config_manager.sync_config.dry_run:
                            self.firemon.manage_device_license(fm_device['id'], add=True)
                            self.changes['licenses'].append({
                                'action': 'add',
                                'device': device['hostname'],
                                'status': 'success'
                            })
                        else:
                            self.changes['licenses'].append({
                                'action': 'add',
                                'device': device['hostname'],
                                'status': 'dry_run'
                            })
            
            # Handle devices not in NetBrain
            if self.config_manager.sync_config.unlicense_removed_devices:
                for device in fm_devices:
                    if device['name'] not in nb_hostnames:
                        if any(product in device.get('licenses', []) for product in ['SM', 'PO', 'PP']):
                            if not self.config_manager.sync_config.dry_run:
                                self.firemon.manage_device_license(device['id'], add=False)
                                self.changes['licenses'].append({
                                    'action': 'remove',
                                    'device': device['name'],
                                    'status': 'success'
                                })
                            else:
                                self.changes['licenses'].append({
                                    'action': 'remove',
                                    'device': device['name'],
                                    'status': 'dry_run'
                                })

        except Exception as e:
            logging.error(f"Error syncing licenses: {str(e)}")
            raise

    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status with lock information"""
        status = {
            'running': self.sync_lock.is_locked(),
            'changes': self.changes,
            'unmapped_types': self.get_unmapped_device_types()
        }
        
        if status['running']:
            status['lock_info'] = self.sync_lock.get_lock_info()
            
        if self.validator:
            status['validation'] = self.validator.get_validation_summary()
            
        return status

    def shutdown(self):
        """Clean shutdown of sync manager"""
        logging.info("Shutting down sync manager")
        if self.sync_lock.is_locked():
            self.sync_lock.break_lock()
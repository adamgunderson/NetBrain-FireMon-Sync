# lib/config.py

import os
import yaml
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class SyncConfig:
    """Configuration dataclass for sync settings"""
    dry_run: bool
    sync_mode: str
    enable_config_sync: bool
    enable_license_sync: bool 
    enable_group_sync: bool
    unlicense_removed_devices: bool

class ConfigManager:
    def __init__(self, config_path: str = 'sync-mappings.yaml'):
        self.config_path = config_path
        self.mappings = self._load_mappings()
        self.sync_config = self._init_sync_config()

    def _load_mappings(self) -> Dict[str, Any]:
        """Load the sync mappings from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load {self.config_path}: {str(e)}")

    def _init_sync_config(self) -> SyncConfig:
        """Initialize sync configuration from environment variables"""
        return SyncConfig(
            dry_run=os.getenv('DRY_RUN', 'false').lower() == 'true',
            sync_mode=os.getenv('SYNC_MODE', 'full'),
            enable_config_sync=os.getenv('ENABLE_CONFIG_SYNC', 'true').lower() == 'true',
            enable_license_sync=os.getenv('ENABLE_LICENSE_SYNC', 'true').lower() == 'true',
            enable_group_sync=os.getenv('ENABLE_GROUP_SYNC', 'true').lower() == 'true',
            unlicense_removed_devices=os.getenv('UNLICENSE_REMOVED_DEVICES', 'true').lower() == 'true'
        )

    def get_collector_group_id(self, site: str) -> Optional[str]:
        """Get FireMon collector group ID for a NetBrain site"""
        # Extract top-level site code (e.g., NA, EU, CN)
        site_code = site.split('/')[0].upper()
        return self.mappings['collector_mapping'].get(site_code)

    def get_device_pack(self, device_type: str) -> Optional[Dict[str, Any]]:
        """Get FireMon device pack config for a NetBrain device type"""
        return self.mappings['device_pack_mapping'].get(device_type)

    def get_config_file_mapping(self, device_type: str) -> Dict[str, str]:
        """Get config file mapping for a device type"""
        default_mapping = {
            'show configuration': 'config_xml',
            'show interfaces': 'interfaces_xml',
            'show version': 'version_xml'
        }
        return self.mappings['config_file_mapping'].get(device_type, default_mapping)

    def get_default_settings(self) -> Dict[str, Any]:
        """Get default device settings"""
        return self.mappings['default_settings']

    def map_netbrain_command_to_firemon_file(self, device_type: str, command: str) -> Optional[str]:
        """Map NetBrain command output to FireMon config filename"""
        mapping = self.get_config_file_mapping(device_type)
        
        # Handle complex mappings (e.g., Juniper route types)
        if isinstance(mapping.get(command), dict):
            return mapping[command]
        
        return mapping.get(command)

    def get_site_hierarchy_mapping(self) -> Dict[str, List[str]]:
        """Get mapping of parent-child relationships for site hierarchy"""
        return self.mappings.get('site_hierarchy', {})

    def get_validation_rules(self) -> Dict[str, Any]:
        """Get validation rules for sync operations"""
        return self.mappings.get('validation_rules', {})
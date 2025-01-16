# lib/config.py
"""
Configuration management for the NetBrain to FireMon sync service
Handles loading and validation of configuration from environment variables
"""

from dataclasses import dataclass
import os
import yaml
import logging
from typing import Dict, List, Any, Optional, Set

@dataclass
class SyncConfig:
    """Configuration dataclass for sync settings"""
    dry_run: bool
    sync_mode: str  # 'full', 'groups', 'licenses', 'configs', 'devices'
    sync_interval_minutes: int
    continuous_sync: bool
    remove_missing_devices: bool  # New flag to control device removal
    
    @classmethod
    def from_env(cls):
        """Create SyncConfig from environment variables"""
        sync_mode = os.getenv('SYNC_MODE', 'full').lower()
        if sync_mode not in ['full', 'groups', 'licenses', 'configs', 'devices']:
            logging.warning(f"Invalid SYNC_MODE '{sync_mode}', defaulting to 'full'")
            sync_mode = 'full'
            
        return cls(
            dry_run=os.getenv('DRY_RUN', 'false').lower() == 'true',
            sync_mode=sync_mode,
            sync_interval_minutes=int(os.getenv('SYNC_INTERVAL_MINUTES', '60')),
            continuous_sync=os.getenv('CONTINUOUS_SYNC', 'false').lower() == 'true',
            remove_missing_devices=os.getenv('REMOVE_MISSING_DEVICES', 'false').lower() == 'true'
        )
    
    @property
    def enable_config_sync(self) -> bool:
        """Determine if config sync is enabled based on sync mode"""
        return self.sync_mode in ['full', 'configs']
    
    @property
    def enable_license_sync(self) -> bool:
        """Determine if license sync is enabled based on sync mode"""
        return self.sync_mode in ['full', 'licenses']
    
    @property
    def enable_group_sync(self) -> bool:
        """Determine if group sync is enabled based on sync mode"""
        return self.sync_mode in ['full', 'groups']
    
    @property
    def enable_device_sync(self) -> bool:
        """Determine if device sync is enabled based on sync mode"""
        return self.sync_mode in ['full', 'devices']

class ConfigManager:
    def __init__(self, config_path: str = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to sync mappings YAML file, uses env var if not provided
        """
        self.config_path = config_path or os.getenv('SYNC_MAPPINGS_FILE', 'sync-mappings.yaml')
        self.mappings = self._load_mappings()
        self.sync_config = SyncConfig.from_env()
        self._device_type_cache = None

    def _load_mappings(self) -> Dict[str, Any]:
        """
        Load the sync mappings from YAML file
        
        Returns:
            Dictionary of configuration mappings
            
        Raises:
            RuntimeError: If config file cannot be loaded
        """
        try:
            with open(self.config_path, 'r') as f:
                mappings = yaml.safe_load(f)
                logging.debug(f"Loaded configuration from {self.config_path}")
                return mappings
        except Exception as e:
            error_msg = f"Failed to load {self.config_path}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)

    def get_mapped_device_types(self) -> Set[str]:
        """
        Get all device types that have mappings defined
        
        Returns:
            Set of device type strings
        """
        # Use cached value if available
        if self._device_type_cache is not None:
            return self._device_type_cache

        device_types = set()
        
        # Get device types from device pack mappings
        device_pack_mappings = self.mappings.get('device_pack_mapping', {})
        device_types.update(device_pack_mappings.keys())
        
        # Also check config file mappings for additional device types
        config_file_mappings = self.mappings.get('config_file_mapping', {})
        device_types.update(config_file_mappings.keys())
        
        # Cache the result
        self._device_type_cache = device_types
        
        logging.debug(f"Found {len(device_types)} mapped device types: {sorted(device_types)}")
        return device_types

    def get_collector_group_id(self, site: str) -> Optional[str]:
        """
        Get FireMon collector group ID for a NetBrain site
        
        Args:
            site: Site path (e.g., "My Network/NA/DC1")
            
        Returns:
            Collector group ID or None if not found
        """
        if not site:
            logging.warning("Empty site path provided")
            return None

        # Extract top-level site code (e.g., NA, EU, CN)
        site_parts = site.split('/')
        if len(site_parts) < 2:
            logging.warning(f"Invalid site path format: {site}")
            return None

        site_code = site_parts[1].upper()  # Skip "My Network" and use next level
        collector_id = self.mappings.get('collector_mapping', {}).get(site_code)
        
        if not collector_id:
            logging.warning(f"No collector mapping found for site code: {site_code}")
        
        return collector_id

    def get_device_pack(self, device_type: str) -> Optional[Dict[str, Any]]:
        """
        Get FireMon device pack config for a NetBrain device type
        
        Args:
            device_type: NetBrain device type
            
        Returns:
            Device pack configuration or None if not found
        """
        device_pack = self.mappings.get('device_pack_mapping', {}).get(device_type)
        
        if not device_pack:
            logging.warning(f"No device pack mapping found for device type: {device_type}")
            return None
        
        # Validate required fields
        required_fields = ['artifact_id', 'group_id', 'device_type', 'device_name']
        missing_fields = [field for field in required_fields if field not in device_pack]
        
        if missing_fields:
            logging.error(f"Device pack mapping for {device_type} missing required fields: {missing_fields}")
            return None
            
        return device_pack

    def get_config_file_mapping(self, device_type: str) -> Dict[str, str]:
        """
        Get config file mapping for a device type
        
        Args:
            device_type: NetBrain device type
            
        Returns:
            Dictionary mapping commands to file names
        """
        # Default mappings for common commands
        default_mapping = {
            'show configuration': 'config_xml',
            'show interfaces': 'interfaces_xml',
            'show version': 'version_xml'
        }
        
        # Get custom mappings for this device type
        custom_mapping = self.mappings.get('config_file_mapping', {}).get(device_type, {})
        
        # Merge default and custom mappings, with custom taking precedence
        mapping = {**default_mapping, **custom_mapping}
        logging.debug(f"Config file mapping for {device_type}: {mapping}")
        return mapping

    def get_default_settings(self) -> Dict[str, Any]:
        """
        Get default device settings, combining config file and environment variables
        
        Returns:
            Dictionary of default settings for device creation/management
        """
        # Get settings from config file
        config_settings = self.mappings.get('default_settings', {})
        
        # Get settings from environment variables
        env_settings = {
            'username': os.getenv('DEFAULT_DEVICE_USERNAME'),
            'password': os.getenv('DEFAULT_DEVICE_PASSWORD'),
            'enablePassword': os.getenv('DEFAULT_DEVICE_ENABLE_PASSWORD'),
            'port': int(os.getenv('DEFAULT_SSH_PORT', '22')),
            'retrievalCallTimeOut': int(os.getenv('DEFAULT_RETRIEVAL_TIMEOUT', '120')),
            'serverAliveInterval': int(os.getenv('DEFAULT_SERVER_ALIVE_INTERVAL', '30')),
            'retrievalMethod': 'FromDevice',
            'suppressFQDNCapabilities': False,
            'useCLICommandGeneration': False,
            'logMonitoringEnabled': True,
            'changeMonitoringEnabled': True,
            'scheduledRetrievalEnabled': False,
            'checkForChangeEnabled': False
        }
        
        # Merge settings, with environment variables taking precedence
        merged_settings = {**config_settings, **env_settings}
        
        # Remove None values
        return {k: v for k, v in merged_settings.items() if v is not None}

    def map_netbrain_command_to_firemon_file(self, device_type: str, command: str) -> Optional[str]:
        """
        Map NetBrain command output to FireMon config filename
        
        Args:
            device_type: NetBrain device type
            command: Command string
            
        Returns:
            FireMon filename or None if no mapping found
        """
        mapping = self.get_config_file_mapping(device_type)
        
        # Handle complex mappings (e.g., Juniper route types)
        if isinstance(mapping.get(command), dict):
            logging.debug(f"Complex mapping found for command '{command}' on device type {device_type}")
            return mapping[command]
        
        result = mapping.get(command)
        if not result:
            logging.debug(f"No file mapping found for command '{command}' on device type {device_type}")
            
        return result

    def get_site_hierarchy_mapping(self) -> Dict[str, List[str]]:
        """Get mapping of parent-child relationships for site hierarchy"""
        hierarchy = self.mappings.get('site_hierarchy', {})
        if not hierarchy:
            logging.warning("No site hierarchy mapping found in configuration")
        return hierarchy

    def get_validation_rules(self) -> Dict[str, Any]:
        """Get validation rules for sync operations"""
        rules = self.mappings.get('validation_rules', {})
        if not rules:
            logging.warning("No validation rules found in configuration")
        return rules

    def reload_config(self) -> None:
        """
        Reload configuration from file
        Useful for testing or dynamic config updates
        """
        self.mappings = self._load_mappings()
        self._device_type_cache = None  # Clear cache
        self.sync_config = SyncConfig.from_env()
        logging.info("Configuration reloaded")

    def validate_config(self) -> List[Dict[str, Any]]:
        """
        Validate configuration file and identify any issues
        
        Returns:
            List of validation issues found
        """
        issues = []
        
        # Check required top-level sections
        required_sections = {
            'collector_mapping': 'Collector mappings',
            'device_pack_mapping': 'Device pack mappings',
            'config_file_mapping': 'Config file mappings'
        }
        
        for section, description in required_sections.items():
            if section not in self.mappings:
                issues.append({
                    'type': 'missing_section',
                    'section': section,
                    'description': description,
                    'severity': 'error'
                })
        
        # Validate device pack mappings
        device_packs = self.mappings.get('device_pack_mapping', {})
        for device_type, pack in device_packs.items():
            required_fields = ['artifact_id', 'group_id', 'device_type', 'device_name']
            
            for field in required_fields:
                if field not in pack:
                    issues.append({
                        'type': 'missing_field',
                        'device_type': device_type,
                        'field': field,
                        'severity': 'error'
                    })

            # Validate device_type field values
            valid_device_types = {'FIREWALL', 'ROUTER_SWITCH', 'DEVICE_MGR'}
            if pack.get('device_type') not in valid_device_types:
                issues.append({
                    'type': 'invalid_value',
                    'device_type': device_type,
                    'field': 'device_type',
                    'value': pack.get('device_type'),
                    'valid_values': list(valid_device_types),
                    'severity': 'error'
                })

        # Validate required device settings
        required_device_settings = [
            ('DEFAULT_DEVICE_USERNAME', 'Device username'),
            ('DEFAULT_DEVICE_PASSWORD', 'Device password'),
            ('DEFAULT_DEVICE_ENABLE_PASSWORD', 'Device enable password')
        ]

        for env_var, description in required_device_settings:
            if not os.getenv(env_var):
                issues.append({
                    'type': 'missing_setting',
                    'setting': env_var,
                    'description': description,
                    'severity': 'error'
                })
        
        # Validate collector mappings
        collectors = self.mappings.get('collector_mapping', {})
        if not collectors:
            issues.append({
                'type': 'empty_section',
                'section': 'collector_mapping',
                'severity': 'warning'
            })
        
        # Validate config file mappings have corresponding device types
        config_mappings = self.mappings.get('config_file_mapping', {})
        for device_type in config_mappings:
            if device_type not in device_packs:
                issues.append({
                    'type': 'orphaned_config_mapping',
                    'device_type': device_type,
                    'severity': 'warning'
                })
        
        # Log validation results
        if issues:
            logging.warning(f"Found {len(issues)} configuration issues")
            for issue in issues:
                log_level = logging.ERROR if issue['severity'] == 'error' else logging.WARNING
                logging.log(log_level, f"Config issue: {issue['type']} - {issue.get('description', '')}")
        
        return issues
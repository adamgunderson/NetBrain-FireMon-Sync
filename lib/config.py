# lib/config.py
"""
Configuration management for the NetBrain to FireMon sync service
Handles loading and validation of configuration from environment variables
Includes enhanced handling of commented out device packs and mappings
"""

from dataclasses import dataclass
import os
import re
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
    remove_missing_devices: bool  # Flag to control device removal
    
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

    def is_device_pack_active(self, device_pack: Optional[Dict[str, Any]]) -> bool:
        """
        Check if a device pack mapping is active (not commented out)
        
        Args:
            device_pack: Device pack mapping dictionary
            
        Returns:
            bool: True if device pack is active, False if commented out
        """
        if not device_pack:
            return False
            
        # Check if any required fields have values
        required_fields = ['artifact_id', 'group_id', 'device_type', 'device_name']
        return any(device_pack.get(field) for field in required_fields)

    def get_mapped_device_types(self) -> Set[str]:
        """
        Get all device types that have active (non-commented) mappings defined
        
        Returns:
            Set of device type strings
        """
        # Use cached value if available
        if self._device_type_cache is not None:
            return self._device_type_cache

        device_types = set()
        
        # Get device types from device pack mappings that are not commented out
        device_pack_mappings = self.mappings.get('device_pack_mapping', {})
        for device_type, mapping in device_pack_mappings.items():
            if self.is_device_pack_active(mapping):
                device_types.add(device_type)
        
        # Cache the result
        self._device_type_cache = device_types
        
        logging.debug(f"Found {len(device_types)} active mapped device types: {sorted(device_types)}")
        return device_types

    def get_collector_group_id(self, site: str) -> Optional[str]:
        """
        Get FireMon collector group ID for a NetBrain site
        
        Args:
            site: Site path (e.g., "NA/DC1")
                
        Returns:
            Collector group ID or None if not found
        """
        if not site:
            logging.warning("Empty site path provided")
            return None

        # Normalize path separators
        site = site.replace('\\', '/')
        
        # Remove "My Network" prefix if present
        if site.lower().startswith("my network/"):
            site = site[len("my network/"):]
        
        # Extract top-level site code
        site_parts = site.split('/')
        if not site_parts:
            logging.warning(f"Invalid site path format: {site}")
            return None

        site_code = site_parts[0].upper()  # Convert to uppercase for consistent mapping
        collector_id = self.mappings.get('collector_mapping', {}).get(site_code)
        
        if not collector_id:
            logging.warning(f"No collector mapping found for site code: {site_code}")
        
        return collector_id

    def get_device_pack_by_attributes(self, device_type: str, model: str, vendor: str) -> Optional[Dict[str, Any]]:
        """
        Get device pack configuration based on device attributes
        
        Args:
            device_type: NetBrain device type (e.g. "Palo Alto Firewall") 
            model: Device model string (e.g. "PA-850")
            vendor: NetBrain vendor name (e.g. "Palo Alto Networks")
                
        Returns:
            Device pack configuration or None if no match found
        """
        try:
            # Skip lookup for non-mapped device types
            if device_type not in self.get_mapped_device_types():
                logging.debug(f"Device type {device_type} is not mapped or commented out")
                return None

            device_packs = self.mappings.get('device_pack_mapping', {})
            device_pack = device_packs.get(device_type)
            
            if not device_pack:
                # Add debug logging to help troubleshoot matches
                logging.debug(f"Device pack lookup for type={device_type}, model={model}, vendor={vendor}")
                logging.debug(f"Available device pack mappings: {list(device_packs.keys())}")
                logging.warning(f"No device pack mapping found for device type: {device_type}")
                return None
                    
            # Normalize vendor names for comparison
            nb_vendor_normalized = device_pack.get('nb_vendor', '').lower()
            vendor_normalized = vendor.lower()
            
            # Look for partial matches in vendor name
            if not (nb_vendor_normalized in vendor_normalized or 
                   vendor_normalized in nb_vendor_normalized):
                logging.warning(f"Vendor mismatch for device type {device_type}: "
                              f"expected {device_pack.get('nb_vendor')}, got {vendor}")
                return None
                    
            # If no model patterns defined, just return the device pack
            if 'model_patterns' not in device_pack:
                logging.debug(f"No model patterns defined for {device_type}, considering it a match")
                return device_pack
                    
            # Check if model matches any of the defined patterns
            for pattern in device_pack['model_patterns']:
                try:
                    if re.match(pattern, model, re.IGNORECASE):
                        logging.debug(f"Model {model} matches pattern {pattern} "
                                    f"for device type {device_type}")
                        return device_pack
                except re.error as e:
                    logging.error(f"Invalid regex pattern '{pattern}' for device type {device_type}: {str(e)}")
                    continue
                        
            logging.warning(f"Model {model} does not match any patterns for device type {device_type}")
            logging.debug(f"Available patterns: {device_pack['model_patterns']}")
            return None

        except Exception as e:
            logging.error(f"Error in device pack lookup: {str(e)}")
            return None

    def get_expected_firemon_vendor(self, netbrain_vendor: str) -> Optional[str]:
        """
        Get expected FireMon vendor name for a NetBrain vendor
        
        Args:
            netbrain_vendor: Vendor name from NetBrain
            
        Returns:
            Expected FireMon vendor name or None if not found
        """
        for device_pack in self.mappings.get('device_pack_mapping', {}).values():
            # Skip commented out device packs
            if not self.is_device_pack_active(device_pack):
                continue
            if device_pack.get('nb_vendor') == netbrain_vendor:
                return device_pack.get('fm_vendor')
        return None

    def get_device_pack(self, device_type: str) -> Optional[Dict[str, Any]]:
        """
        Get FireMon device pack config for a NetBrain device type
        Skip warning for commented out device packs
        
        Args:
            device_type: NetBrain device type
            
        Returns:
            Device pack configuration or None if not found or commented out
        """
        device_pack = self.mappings.get('device_pack_mapping', {}).get(device_type)
        
        # Skip warning if device pack is commented out
        if not self.is_device_pack_active(device_pack):
            logging.debug(f"Device pack for {device_type} is commented out or not configured")
            return None

        # For active device packs, validate required fields    
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
        # Only get mappings for active device types
        if device_type not in self.get_mapped_device_types():
            logging.debug(f"No config file mappings for commented out device type: {device_type}")
            return {}

        # Get custom mappings for this device type
        custom_mapping = self.mappings.get('config_file_mapping', {}).get(device_type, {})
        logging.debug(f"Config file mapping for {device_type}: {custom_mapping}")
        return custom_mapping

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
            # Skip validation for commented out device packs
            if not self.is_device_pack_active(pack):
                logging.debug(f"Skipping validation for commented out device pack: {device_type}")
                continue

            required_fields = [
                'artifact_id', 'group_id', 'device_type', 'device_name',
                'nb_vendor', 'fm_vendor', 'model_patterns'
            ]
            
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

            # Validate model patterns
            if 'model_patterns' in pack:
                if not isinstance(pack['model_patterns'], list):
                    issues.append({
                        'type': 'invalid_value',
                        'device_type': device_type,
                        'field': 'model_patterns',
                        'value': type(pack['model_patterns']).__name__,
                        'expected': 'list',
                        'severity': 'error'
                    })
                else:
                    # Validate each pattern is a valid regex
                    for pattern in pack['model_patterns']:
                        try:
                            re.compile(pattern)
                        except re.error:
                            issues.append({
                                'type': 'invalid_regex',
                                'device_type': device_type,
                                'pattern': pattern,
                                'severity': 'error'
                            })

        # Validate vendor mappings for active device packs
        for device_type, pack in device_packs.items():
            if not self.is_device_pack_active(pack):
                continue
                
            if 'nb_vendor' not in pack or 'fm_vendor' not in pack:
                issues.append({
                    'type': 'missing_vendor_mapping',
                    'device_type': device_type,
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
        
        # Validate config file mappings have corresponding active device types
        config_mappings = self.mappings.get('config_file_mapping', {})
        mapped_device_types = self.get_mapped_device_types()
        for device_type in config_mappings:
            if device_type not in mapped_device_types:
                issues.append({
                    'type': 'orphaned_config_mapping',
                    'device_type': device_type,
                    'severity': 'warning',
                    'message': 'Config mapping exists for non-active device type'
                })

        # Validate command mappings for active device types
        for device_type, commands in config_mappings.items():
            if device_type not in mapped_device_types:
                continue
                
            if not isinstance(commands, dict):
                issues.append({
                    'type': 'invalid_command_mapping',
                    'device_type': device_type,
                    'severity': 'error'
                })
            else:
                for command, filename in commands.items():
                    if not isinstance(command, str) or not isinstance(filename, str):
                        issues.append({
                            'type': 'invalid_command_mapping_type',
                            'device_type': device_type,
                            'command': command,
                            'filename': filename,
                            'severity': 'error'
                        })

        # Validate site hierarchy if present
        site_hierarchy = self.mappings.get('site_hierarchy', {})
        if site_hierarchy:
            # Check for circular references
            visited = set()
            path = []
            
            def check_circular(site):
                if site in path:
                    issues.append({
                        'type': 'circular_reference',
                        'site': site,
                        'path': '->'.join(path),
                        'severity': 'error'
                    })
                    return
                if site in visited:
                    return
                visited.add(site)
                path.append(site)
                for child in site_hierarchy.get(site, []):
                    check_circular(child)
                path.pop()

            for site in site_hierarchy:
                check_circular(site)
        
        # Log validation results
        if issues:
            logging.warning(f"Found {len(issues)} configuration issues")
            for issue in issues:
                log_level = logging.ERROR if issue['severity'] == 'error' else logging.WARNING
                logging.log(log_level, f"Config issue: {issue['type']} - {issue.get('description', '')}")
        
        return issues
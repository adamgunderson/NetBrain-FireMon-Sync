# lib/config_handler.py

import logging
from typing import Dict, Optional, List, Any
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

@dataclass
class ConfigFile:
    name: str
    content: str
    device_type: str
    command: str

class ConfigValidationError(Exception):
    pass

class ConfigHandler:
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.required_configs = {
            'Cisco IOS Switch': ['config_xml', 'interfaces_xml'],
            'Juniper SRX Firewall': ['config_xml', 'interfaces_xml', 'route_xml'],
            # Add other device types and their required configs
        }

    def process_device_configs(self, device: Dict[str, Any], configs: Dict[str, str]) -> Dict[str, str]:
        """
        Process and validate device configurations
        Returns mapped configurations or raises ConfigValidationError
        """
        try:
            device_type = device['attributes']['subTypeName']
            mapped_configs = {}
            missing_required = []
            
            # Get required configs for device type
            required_configs = self.required_configs.get(device_type, [])
            
            # Map commands to FireMon config files
            for command, content in configs.items():
                if not content or not content.strip():
                    logging.warning(f"Empty config content for command '{command}' on device {device['hostname']}")
                    continue
                    
                fm_filename = self.config_manager.map_netbrain_command_to_firemon_file(
                    device_type, 
                    command
                )
                
                if fm_filename:
                    mapped_configs[fm_filename] = content
            
            # Validate required configs
            for required_file in required_configs:
                if required_file not in mapped_configs:
                    missing_required.append(required_file)
            
            if missing_required:
                raise ConfigValidationError(
                    f"Missing required config files for {device['hostname']}: {missing_required}"
                )
            
            # Additional validation of config content
            invalid_configs = []
            for filename, content in mapped_configs.items():
                if not self._validate_config_content(filename, content):
                    invalid_configs.append(filename)
            
            if invalid_configs:
                raise ConfigValidationError(
                    f"Invalid config content for files: {invalid_configs}"
                )
            
            return mapped_configs
            
        except Exception as e:
            raise ConfigValidationError(f"Error processing configs: {str(e)}")

    def _validate_config_content(self, filename: str, content: str) -> bool:
        """Validate configuration content format"""
        try:
            if not content or len(content.strip()) < 10:
                return False
                
            if filename == 'config_xml':
                # Check for basic config structure
                required_sections = ['system', 'interfaces', 'routing-options']
                return any(section in content.lower() for section in required_sections)
                
            elif filename == 'interfaces_xml':
                # Check for interface definitions
                return 'interface' in content.lower()
                
            elif filename.startswith('route_'):
                # Check for routing information
                return 'route' in content.lower() or 'next-hop' in content.lower()
                
            return True
            
        except Exception as e:
            logging.error(f"Error validating config {filename}: {str(e)}")
            return False

    def backup_configs(self, device: Dict[str, Any], configs: Dict[str, str]) -> None:
        """Backup configuration files"""
        try:
            backup_dir = Path('backups') / device['hostname'] / datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            for filename, content in configs.items():
                backup_file = backup_dir / filename
                with open(backup_file, 'w') as f:
                    f.write(content)
                    
            logging.info(f"Backed up configs for {device['hostname']} to {backup_dir}")
            
        except Exception as e:
            logging.error(f"Error backing up configs for {device['hostname']}: {str(e)}")
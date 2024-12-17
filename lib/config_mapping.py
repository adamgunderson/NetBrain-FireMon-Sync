# lib/config_mapping.py

import logging
from typing import Dict, Any, Optional

class ConfigMappingManager:
    """Manages mappings between NetBrain device types and FireMon device packs"""
    
    def __init__(self):
        # Default device type mappings
        self.device_type_mappings = {
            "Cisco IOS Switch": {
                "device_pack_id": 25,
                "artifact_id": "cisco_ios",
                "group_id": "com.fm.sm.dp.cisco-ios",
                "device_type": "ROUTER_SWITCH",
                "device_name": "IOS"
            },
            "Juniper SRX Firewall": {
                "device_pack_id": 57,
                "artifact_id": "juniper_srx",
                "group_id": "com.fm.sm.dp.juniper_srx",
                "device_type": "FIREWALL",
                "device_name": "SRX"
            },
            # Add more device type mappings as needed
        }

        # Default command to file mappings
        self.command_file_mappings = {
            "Cisco IOS Switch": {
                "show running-config": "config_xml",
                "show interfaces": "interfaces_xml",
                "show version": "version_xml"
            },
            "Juniper SRX Firewall": {
                "show configuration | no-more": "config_xml",
                "show interfaces": "interfaces_xml",
                "show version": "version_xml",
                "show route": "route_xml"
            }
        }

    def get_device_type_mapping(self, device_type: str) -> Optional[Dict[str, Any]]:
        """Get FireMon device pack mapping for a NetBrain device type"""
        mapping = self.device_type_mappings.get(device_type)
        if not mapping:
            logging.warning(f"No device pack mapping found for device type: {device_type}")
        return mapping

    def validate_device_mappings(self, device_type: str) -> list:
        """Validate device type mappings and return any issues"""
        issues = []
        
        if device_type not in self.device_type_mappings:
            issues.append({
                'type': 'missing_device_mapping',
                'device_type': device_type,
                'severity': 'error',
                'message': f'No device pack mapping found for {device_type}'
            })
            return issues

        mapping = self.device_type_mappings[device_type]
        required_fields = [
            'device_pack_id', 
            'artifact_id', 
            'group_id', 
            'device_type', 
            'device_name'
        ]

        for field in required_fields:
            if field not in mapping:
                issues.append({
                    'type': 'incomplete_mapping',
                    'device_type': device_type,
                    'missing_field': field,
                    'severity': 'error',
                    'message': f'Missing required field {field} in device mapping'
                })

        # Validate command mappings
        if device_type not in self.command_file_mappings:
            issues.append({
                'type': 'missing_command_mapping',
                'device_type': device_type,
                'severity': 'warning',
                'message': f'No command file mappings found for {device_type}'
            })
        else:
            # Check for required config files
            required_files = {'config_xml', 'interfaces_xml'}
            mapped_files = set(self.command_file_mappings[device_type].values())
            missing_files = required_files - mapped_files
            
            if missing_files:
                issues.append({
                    'type': 'missing_required_files',
                    'device_type': device_type,
                    'missing_files': list(missing_files),
                    'severity': 'error',
                    'message': f'Missing required file mappings: {", ".join(missing_files)}'
                })

        return issues

    def get_command_file_mapping(self, device_type: str) -> Dict[str, str]:
        """Get command to file mappings for a device type"""
        return self.command_file_mappings.get(device_type, {})

    def add_device_type_mapping(self, device_type: str, mapping: Dict[str, Any]) -> None:
        """Add or update a device type mapping"""
        self.device_type_mappings[device_type] = mapping
        logging.info(f"Added/updated device type mapping for {device_type}")

    def add_command_file_mapping(self, device_type: str, mapping: Dict[str, str]) -> None:
        """Add or update command file mappings for a device type"""
        self.command_file_mappings[device_type] = mapping
        logging.info(f"Added/updated command file mappings for {device_type}")

    def remove_device_type_mapping(self, device_type: str) -> None:
        """Remove a device type mapping"""
        if device_type in self.device_type_mappings:
            del self.device_type_mappings[device_type]
            logging.info(f"Removed device type mapping for {device_type}")

    def remove_command_file_mapping(self, device_type: str) -> None:
        """Remove command file mappings for a device type"""
        if device_type in self.command_file_mappings:
            del self.command_file_mappings[device_type]
            logging.info(f"Removed command file mappings for {device_type}")
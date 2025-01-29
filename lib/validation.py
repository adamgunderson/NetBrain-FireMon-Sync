# lib/validation.py
"""
Validation Manager for NetBrain to FireMon synchronization
Handles validation of device groups, configurations, and licensing
Includes dry-run awareness to prevent unnecessary API calls
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

class ValidationManager:
    def __init__(self, netbrain_client, firemon_client, config_manager):
        self.netbrain = netbrain_client
        self.firemon = firemon_client
        self.config = config_manager
        self.validation_results = {}

    def validate_configs(self) -> List[Dict[str, Any]]:
        """
        Validate configuration imports
        Skips actual API calls in dry-run mode
        """
        issues = []
        try:
            # Skip config validation in dry-run mode
            if self.config.sync_config.dry_run:
                logging.debug("Skipping config validation in dry-run mode")
                issues.append({
                    'type': 'dry_run',
                    'message': 'Configuration validation skipped in dry-run mode',
                    'severity': 'info'
                })
                return issues

            # Get all devices in both systems
            nb_devices = self.netbrain.get_all_devices()
            
            for device in nb_devices:
                fm_device = self.firemon.search_device(
                    device['hostname'],
                    device['mgmtIP']
                )
                
                if fm_device:
                    # Compare configuration timestamps
                    nb_config_time = self.netbrain.get_device_config_time(device['id'])
                    fm_config_time = self.firemon.get_device_revision(fm_device['id'])
                    
                    if nb_config_time and fm_config_time:
                        nb_time = datetime.fromisoformat(nb_config_time.replace('Z', '+00:00'))
                        fm_time = datetime.fromisoformat(fm_config_time['completeDate'])
                        
                        if nb_time > fm_time:
                            issues.append({
                                'type': 'outdated_config',
                                'device': device['hostname'],
                                'nb_time': nb_time,
                                'fm_time': fm_time,
                                'severity': 'warning'
                            })

        except Exception as e:
            logging.error(f"Error validating configurations: {str(e)}")
            issues.append({
                'type': 'validation_error',
                'message': str(e),
                'severity': 'error'
            })

        self.validation_results['configs'] = issues
        return issues

    def validate_device_groups(self) -> List[Dict[str, Any]]:
        """
        Validate device group assignments
        Modified to handle dry-run mode
        """
        issues = []
        try:
            # Handle dry-run mode
            if self.config.sync_config.dry_run:
                logging.debug("Skipping device group validation in dry-run mode")
                issues.append({
                    'type': 'dry_run',
                    'message': 'Device group validation skipped in dry-run mode',
                    'severity': 'info'
                })
                return issues

            # Regular validation logic for non-dry-run mode
            fm_groups = self.firemon.get_device_groups()
            nb_sites = self.netbrain.get_sites()
            
            # Check each site has corresponding group
            for site in nb_sites:
                site_path = site['sitePath']
                matching_group = next(
                    (g for g in fm_groups if g['name'] == site_path.split('/')[-1]),
                    None
                )
                
                if not matching_group:
                    issues.append({
                        'type': 'missing_group',
                        'site': site_path,
                        'severity': 'error'
                    })
                else:
                    # Validate group hierarchy
                    if site['parentId']:
                        parent_site = next(
                            (s for s in nb_sites if s['siteId'] == site['parentId']),
                            None
                        )
                        if parent_site:
                            parent_group = next(
                                (g for g in fm_groups if g['name'] == parent_site['sitePath'].split('/')[-1]),
                                None
                            )
                            if parent_group and matching_group['parentId'] != parent_group['id']:
                                issues.append({
                                    'type': 'incorrect_hierarchy',
                                    'site': site_path,
                                    'expected_parent': parent_site['sitePath'],
                                    'severity': 'warning'
                                })

        except Exception as e:
            logging.error(f"Error validating device groups: {str(e)}")
            issues.append({
                'type': 'validation_error',
                'message': str(e),
                'severity': 'error'
            })

        self.validation_results['device_groups'] = issues
        return issues

    def validate_licensing(self) -> List[Dict[str, Any]]:
        """
        Validate device licensing status
        Modified to handle dry-run mode
        """
        issues = []
        try:
            # Handle dry-run mode
            if self.config.sync_config.dry_run:
                logging.debug("Skipping license validation in dry-run mode")
                issues.append({
                    'type': 'dry_run',
                    'message': 'License validation skipped in dry-run mode',
                    'severity': 'info'
                })
                return issues

            # Regular validation logic for non-dry-run mode
            nb_devices = self.netbrain.get_all_devices()
            fm_devices = self.firemon.get_all_devices()
            
            fm_hostnames = {d['name'] for d in fm_devices}
            nb_hostnames = {d['hostname'] for d in nb_devices}
            
            extra_fm_devices = fm_hostnames - nb_hostnames
            for hostname in extra_fm_devices:
                fm_device = next(d for d in fm_devices if d['name'] == hostname)
                if any(product in fm_device.get('licenses', []) for product in ['SM', 'PO', 'PP']):
                    issues.append({
                        'type': 'unnecessary_license',
                        'device': hostname,
                        'severity': 'warning'
                    })
            
            for hostname in nb_hostnames:
                fm_device = next((d for d in fm_devices if d['name'] == hostname), None)
                if fm_device and not any(product in fm_device.get('licenses', []) for product in ['SM', 'PO', 'PP']):
                    issues.append({
                        'type': 'missing_license',
                        'device': hostname,
                        'severity': 'error'
                    })

        except Exception as e:
            logging.error(f"Error validating licensing: {str(e)}")
            issues.append({
                'type': 'validation_error',
                'message': str(e),
                'severity': 'error'
            })

        self.validation_results['licensing'] = issues
        return issues

    def run_all_validations(self) -> Dict[str, List[Dict[str, Any]]]:
        """Run all validation checks with dry-run awareness"""
        if self.config.sync_config.dry_run:
            logging.info("Running validations in dry-run mode - API calls will be skipped")
            
        self.validate_device_groups()
        self.validate_configs()
        self.validate_licensing()
        return self.validation_results

    def get_validation_summary(self) -> Dict[str, Any]:
        """Generate validation summary"""
        summary = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_issues': 0,
            'error_count': 0,
            'warning_count': 0,
            'categories': {},
            'dry_run': self.config.sync_config.dry_run
        }
        
        for category, issues in self.validation_results.items():
            cat_summary = {
                'total': len(issues),
                'errors': len([i for i in issues if i['severity'] == 'error']),
                'warnings': len([i for i in issues if i['severity'] == 'warning'])
            }
            summary['categories'][category] = cat_summary
            summary['total_issues'] += cat_summary['total']
            summary['error_count'] += cat_summary['errors']
            summary['warning_count'] += cat_summary['warnings']
        
        return summary
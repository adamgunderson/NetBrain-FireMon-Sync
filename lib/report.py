# lib/report.py

"""
Report Manager for NetBrain to FireMon synchronization

Handles generation and formatting of sync reports including:
- Detailed sync operation summaries
- Device delta reporting with detailed device comparisons
- Configuration change tracking 
- Group hierarchy changes
- License status reports
- Validation results
- HTML and JSON report generation
- Console summary output
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass, asdict

@dataclass
class DeviceDelta:
    """Data structure for device delta information"""
    hostname: str
    mgmt_ip: str
    site: str = 'N/A'
    type: str = 'N/A'
    vendor: str = 'N/A'
    model: str = 'N/A'
    version: str = 'N/A'
    collector_group: Optional[str] = None
    device_pack: Optional[str] = None
    status: Optional[str] = None
    differences: Optional[List[str]] = None

class ReportManager:
    def __init__(self, output_dir: str = 'reports'):
        """
        Initialize the report manager
        
        Args:
            output_dir: Directory for report output files (default: 'reports')
        """
        self.output_dir = output_dir
        self._ensure_output_dir()

    def _ensure_output_dir(self) -> None:
        """Ensure output directory exists"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def generate_sync_report(self, 
                            changes: Dict[str, Any],
                            validation_results: Dict[str, Any],
                            sync_mode: str,
                            delta: Optional[Dict[str, Any]] = None,
                            dry_run: bool = False) -> Dict[str, Any]:
        """
        Generate comprehensive sync report
        
        Args:
            changes: Dictionary of sync changes
            validation_results: Dictionary of validation results
            sync_mode: Sync mode (full, groups, etc.)
            delta: Optional device delta information
            dry_run: Whether running in dry run mode
                
        Returns:
            Dictionary containing complete report
        """
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'sync_mode': sync_mode,
            'dry_run': dry_run,
            'summary': self._generate_summary(changes, validation_results, delta),
            'changes': changes,
            'validation': validation_results
        }
        
        if dry_run and delta:
            # For dry run mode, include delta information
            report['delta'] = delta
            report['summary']['delta'] = {
                'only_in_netbrain': len(delta.get('only_in_netbrain', [])),
                'only_in_firemon': len(delta.get('only_in_firemon', [])),
                'matching': len(delta.get('matching', [])),
                'different': len(delta.get('different', []))
            }
        
        # Add license analysis if appropriate
        if sync_mode in ['full', 'licenses']:
            report['license_analysis'] = self._analyze_license_requirements(changes)
            
        return report

    def _generate_summary(self, 
                         changes: Dict[str, Any],
                         validation_results: Dict[str, Any],
                         delta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate summary of sync operations
        
        Args:
            changes: Dictionary of sync changes
            validation_results: Dictionary of validation results
            delta: Optional device delta information
            
        Returns:
            Dictionary containing operation summary
        """
        summary = {
            'devices': {
                'total_processed': len(changes.get('devices', [])),
                'added': sum(1 for d in changes.get('devices', []) 
                           if d.get('action') == 'add'),
                'updated': sum(1 for d in changes.get('devices', [])
                             if d.get('action') == 'update'),
                'removed': sum(1 for d in changes.get('devices', [])
                             if d.get('action') == 'remove'),
                'failed': sum(1 for d in changes.get('devices', [])
                            if d.get('status') == 'error')
            },
            'groups': {
                'total_processed': len(changes.get('groups', [])),
                'created': sum(1 for g in changes.get('groups', [])
                             if g.get('action') == 'create'),
                'updated': sum(1 for g in changes.get('groups', [])
                             if g.get('action') == 'update'),
                'failed': sum(1 for g in changes.get('groups', [])
                            if g.get('status') == 'error')
            },
            'configs': {
                'total_processed': len(changes.get('configs', [])),
                'updated': sum(1 for c in changes.get('configs', [])
                             if c.get('action') == 'update'),
                'failed': sum(1 for c in changes.get('configs', [])
                            if c.get('status') == 'error')
            },
            'licenses': {
                'total_processed': len(changes.get('licenses', [])),
                'added': sum(1 for l in changes.get('licenses', [])
                           if l.get('action') == 'add'),
                'removed': sum(1 for l in changes.get('licenses', [])
                             if l.get('action') == 'remove'),
                'failed': sum(1 for l in changes.get('licenses', [])
                            if l.get('status') == 'error')
            },
            'validation': {
                'total_issues': sum(len(issues) for issues in validation_results.values()),
                'errors': sum(1 for category in validation_results.values() 
                            for issue in category if issue.get('severity') == 'error'),
                'warnings': sum(1 for category in validation_results.values()
                              for issue in category if issue.get('severity') == 'warning')
            }
        }

        # Add delta information if provided
        if delta:
            summary['delta'] = {
                'only_in_netbrain': len(delta.get('only_in_netbrain', [])),
                'only_in_firemon': len(delta.get('only_in_firemon', [])),
                'matching': len(delta.get('matching', [])),
                'different': len(delta.get('different', []))
            }
            
        return summary

    def _analyze_license_requirements(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze license requirements based on changes
        
        Args:
            changes: Dictionary of sync changes
            
        Returns:
            Dictionary containing license analysis
        """
        return {
            'current_licenses': {
                'SM': sum(1 for l in changes.get('licenses', [])
                         if l.get('product') == 'SM' and l.get('action') != 'remove'),
                'PO': sum(1 for l in changes.get('licenses', [])
                         if l.get('product') == 'PO' and l.get('action') != 'remove'),
                'PP': sum(1 for l in changes.get('licenses', [])
                         if l.get('product') == 'PP' and l.get('action') != 'remove')
            },
            'required_licenses': {
                'SM': sum(1 for d in changes.get('devices', [])
                         if d.get('action') in ['add', 'update']),
                'PO': sum(1 for d in changes.get('devices', [])
                         if d.get('action') in ['add', 'update']),
                'PP': sum(1 for d in changes.get('devices', [])
                         if d.get('action') in ['add', 'update'])
            },
            'additional_needed': {
                'SM': max(0, sum(1 for d in changes.get('devices', [])
                                if d.get('action') in ['add', 'update']) -
                         sum(1 for l in changes.get('licenses', [])
                             if l.get('product') == 'SM' and l.get('action') != 'remove')),
                'PO': max(0, sum(1 for d in changes.get('devices', [])
                                if d.get('action') in ['add', 'update']) -
                         sum(1 for l in changes.get('licenses', [])
                             if l.get('product') == 'PO' and l.get('action') != 'remove')),
                'PP': max(0, sum(1 for d in changes.get('devices', [])
                                if d.get('action') in ['add', 'update']) -
                         sum(1 for l in changes.get('licenses', [])
                             if l.get('product') == 'PP' and l.get('action') != 'remove'))
            }
        }

    def generate_console_summary(self, report: Dict[str, Any]) -> str:
        """
        Generate human-readable console summary based on sync mode
        Enhanced to show detailed group information in groups mode
        
        Args:
            report: Report dictionary
            
        Returns:
            Formatted string for console output
        """
        try:
            # Get common data
            summary = report.get('summary', {})
            execution_time = report.get('execution_time', 0)
            sync_mode = report.get('sync_mode', 'full')
            execution_time_str = f"{execution_time:.2f} seconds" if execution_time else "N/A"
            
            # Header section is common for all modes
            header = f"""
Sync Operation Summary ({sync_mode} mode{' - Dry Run' if report.get('dry_run') else ''})
================================================
Timestamp: {report['timestamp']}
Execution Time: {execution_time_str}
"""

            # Content varies based on sync mode and dry run status
            content = ""
            if report.get('dry_run'):
                if sync_mode == 'devices':
                    # Device mode content - unchanged
                    delta_stats = report.get('summary', {}).get('delta', {})
                    content = f"""
Device Analysis:
- Total in NetBrain: {delta_stats.get('total_in_netbrain', 0)}
- Total in FireMon: {delta_stats.get('total_in_firemon', 0)}
- Only in NetBrain: {delta_stats.get('only_in_netbrain', 0)}
- Only in FireMon: {delta_stats.get('only_in_firemon', 0)}
- Devices with Differences: {delta_stats.get('different', 0)}
"""
                elif sync_mode == 'groups':
                    # Enhanced group mode content
                    group_analysis = report.get('group_analysis', {})
                    groups_to_create = group_analysis.get('groups_to_create', [])
                    groups_to_update = group_analysis.get('groups_to_update', [])
                    orphaned_groups = group_analysis.get('orphaned_groups', [])
                    device_assignments = group_analysis.get('device_assignments', [])
                    
                    # Generate group summary
                    content = f"""
Group Synchronization Analysis:
- Groups to Create: {len(groups_to_create)}
- Groups to Update: {len(groups_to_update)}
- Orphaned Groups (will be preserved): {len(orphaned_groups)}
- Device Assignments to Process: {len(device_assignments)}
"""
                    
                    # Add details about groups to create (limit to 15 for readability)
                    if groups_to_create:
                        create_limit = min(15, len(groups_to_create))
                        content += "\nGroups That Will Be Created in FireMon:\n"
                        for i, group in enumerate(groups_to_create[:create_limit]):
                            content += f"  {i+1}. {group['name']} (Path: {group['path']})\n"
                        if len(groups_to_create) > create_limit:
                            content += f"  ... and {len(groups_to_create) - create_limit} more\n"
                    
                    # Add details about groups to update (limit to 10)
                    if groups_to_update:
                        update_limit = min(10, len(groups_to_update))
                        content += "\nGroups That Will Be Updated in FireMon:\n"
                        for i, group in enumerate(groups_to_update[:update_limit]):
                            content += f"  {i+1}. {group['name']} (Path: {group['path']})\n"
                        if len(groups_to_update) > update_limit:
                            content += f"  ... and {len(groups_to_update) - update_limit} more\n"
                    
                    # Add details about device assignments (limit to 15)
                    if device_assignments:
                        assign_limit = min(15, len(device_assignments))
                        content += "\nDevices That Will Be Assigned to Groups:\n"
                        for i, assignment in enumerate(device_assignments[:assign_limit]):
                            status = "Create group first" if not assignment['group_exists'] else "Ready"
                            content += f"  {i+1}. {assignment['device_name']} → {assignment['leaf_group']} ({status})\n"
                        if len(device_assignments) > assign_limit:
                            content += f"  ... and {len(device_assignments) - assign_limit} more\n"
                    
                    # Add details about orphaned groups (limit to 5)
                    if orphaned_groups:
                        orphan_limit = min(5, len(orphaned_groups))
                        content += "\nOrphaned Groups (Will Be Preserved):\n"
                        for i, group in enumerate(orphaned_groups[:orphan_limit]):
                            content += f"  {i+1}. {group['name']} (ID: {group['id']})\n"
                        if len(orphaned_groups) > orphan_limit:
                            content += f"  ... and {len(orphaned_groups) - orphan_limit} more\n"
                    
                elif sync_mode == 'licenses':
                    # License mode content - unchanged
                    content = f"""
License Analysis:
- Total Devices to Process: {summary.get('licenses', {}).get('total_processed', 0)}
- Licenses to Add: {summary.get('licenses', {}).get('to_add', 0)}
- Licenses to Remove: {summary.get('licenses', {}).get('to_remove', 0)}
"""
                elif sync_mode == 'configs':
                    # Config mode content - unchanged
                    content = f"""
Configuration Analysis:
- Total Devices to Check: {summary.get('configs', {}).get('total_processed', 0)}
- Configs Needing Update: {summary.get('configs', {}).get('to_update', 0)}
"""
                else:  # full mode
                    # Full mode content - unchanged
                    delta_stats = report.get('summary', {}).get('delta', {})
                    content = f"""
Full Sync Analysis:
Device Status:
- Total in NetBrain: {delta_stats.get('total_in_netbrain', 0)}
- Total in FireMon: {delta_stats.get('total_in_firemon', 0)}
- Only in NetBrain: {delta_stats.get('only_in_netbrain', 0)}
- Only in FireMon: {delta_stats.get('only_in_firemon', 0)}
- Devices with Differences: {delta_stats.get('different', 0)}

Group Status:
- Groups to Create/Update: {summary.get('groups', {}).get('to_update', 0)}

License Status:
- Licenses to Adjust: {summary.get('licenses', {}).get('to_update', 0)}

Config Status:
- Configs to Update: {summary.get('configs', {}).get('to_update', 0)}
"""
            else:
                # Non-dry run mode - show actual changes (no changes needed here)
                if sync_mode == 'devices':
                    device_summary = summary.get('devices', {})
                    content = f"""
Device Changes:
- Total Processed: {device_summary.get('total_processed', 0)}
- Added: {device_summary.get('added', 0)}
- Updated: {device_summary.get('updated', 0)}
- Failed: {device_summary.get('failed', 0)}
"""
                elif sync_mode == 'groups':
                    group_summary = summary.get('groups', {})
                    changes = report.get('changes', {})
                    
                    # Get detailed group changes from the changes list
                    created_groups = [g for g in changes.get('groups', []) if g.get('action') == 'create']
                    updated_groups = [g for g in changes.get('groups', []) if g.get('action') == 'update']
                    orphaned_groups = [g for g in changes.get('groups', []) if g.get('action') == 'orphaned']
                    error_groups = [g for g in changes.get('groups', []) if g.get('action') == 'error']
                    
                    # Prepare group details output
                    group_details = ""
                    if created_groups and len(created_groups) <= 10:
                        group_details += "\nCreated Groups:\n"
                        for g in created_groups:
                            group_details += f"  - {g.get('group')} (Path: {g.get('path', 'N/A')})\n"
                    
                    if updated_groups and len(updated_groups) <= 10:
                        group_details += "\nUpdated Groups:\n"
                        for g in updated_groups:
                            updates = ", ".join(g.get('updates', []))
                            group_details += f"  - {g.get('group')} (Updates: {updates})\n"
                    
                    if orphaned_groups and len(orphaned_groups) <= 10:
                        group_details += "\nPreserved Orphaned Groups:\n"
                        for g in orphaned_groups:
                            group_details += f"  - {g.get('group')} (ID: {g.get('id', 'N/A')})\n"
                    
                    content = f"""
Group Changes:
- Total Processed: {group_summary.get('total_processed', 0)}
- Created: {group_summary.get('created', 0)}
- Updated: {group_summary.get('updated', 0)}
- Preserved (Orphaned): {len(orphaned_groups)}
- Failed: {group_summary.get('failed', 0)}
{group_details}
"""
                elif sync_mode == 'licenses':
                    license_summary = summary.get('licenses', {})
                    content = f"""
License Changes:
- Total Processed: {license_summary.get('total_processed', 0)}
- Added: {license_summary.get('added', 0)}
- Removed: {license_summary.get('removed', 0)}
- Failed: {license_summary.get('failed', 0)}
"""
                elif sync_mode == 'configs':
                    config_summary = summary.get('configs', {})
                    content = f"""
Configuration Changes:
- Total Processed: {config_summary.get('total_processed', 0)}
- Updated: {config_summary.get('updated', 0)}
- Failed: {config_summary.get('failed', 0)}
"""
                else:  # full mode
                    content = f"""
Device Changes:
- Total Processed: {summary.get('devices', {}).get('total_processed', 0)}
- Added: {summary.get('devices', {}).get('added', 0)}
- Updated: {summary.get('devices', {}).get('updated', 0)}
- Failed: {summary.get('devices', {}).get('failed', 0)}

Group Changes:
- Total Processed: {summary.get('groups', {}).get('total_processed', 0)}
- Created: {summary.get('groups', {}).get('created', 0)}
- Updated: {summary.get('groups', {}).get('updated', 0)}
- Failed: {summary.get('groups', {}).get('failed', 0)}

License Changes:
- Total Processed: {summary.get('licenses', {}).get('total_processed', 0)}
- Added: {summary.get('licenses', {}).get('added', 0)}
- Removed: {summary.get('licenses', {}).get('removed', 0)}
- Failed: {summary.get('licenses', {}).get('failed', 0)}

Configuration Changes:
- Total Processed: {summary.get('configs', {}).get('total_processed', 0)}
- Updated: {summary.get('configs', {}).get('updated', 0)}
- Failed: {summary.get('configs', {}).get('failed', 0)}
"""

            # Footer is common for all modes
            footer = "\nFull details are available in the report file."

            return header + content + footer

        except Exception as e:
            logging.error(f"Error generating console summary: {str(e)}")
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed error trace for console summary:")
            return """
Error generating sync summary.
Please check the logs and report file for details.
"""

    def _format_device_list(self, devices: List[Dict[str, Any]], source: str) -> str:
        """
        Format device list for console output
        
        Args:
            devices: List of device dictionaries
            source: Device source ('netbrain' or 'firemon')
            
        Returns:
            Formatted string of device information
        """
        if not devices:
            return "  None\n"
            
        formatted = ""
        for device in devices:
            if source == 'netbrain':
                formatted += (f"  - {device['hostname']}\n"
                            f"    Management IP: {device['mgmt_ip']}\n"
                            f"    Site: {device['site']}\n"
                            f"    Type: {device['type']}\n"
                            f"    Model: {device.get('model', 'N/A')}\n"
                            f"    Vendor: {device.get('vendor', 'N/A')}\n"
                            f"    Version: {device.get('version', 'N/A')}\n")
            else:  # firemon
                formatted += (f"  - {device['hostname']}\n"
                            f"    Management IP: {device['mgmt_ip']}\n"
                            f"    Collector Group: {device['collector_group']}\n"
                            f"    Device Pack: {device['device_pack']}\n"
                            f"    Status: {device.get('status', 'N/A')}\n")
        return formatted

    def _format_different_devices(self, devices: List[Dict[str, Any]]) -> str:
        """
        Format device differences for console output
        
        Args:
            devices: List of device difference dictionaries
            
        Returns:
            Formatted string of device differences
        """
        if not devices:
            return "  None\n"
            
        formatted = ""
        for device in devices:
            formatted += f"  - {device['hostname']}:\n"
            
            # Format differences
            for diff in device['differences']:
                formatted += f"    * {diff}\n"
                
            # Format NetBrain data
            formatted += "    NetBrain Data:\n"
            nb_data = device['netbrain_data']
            formatted += (f"      Management IP: {nb_data['mgmt_ip']}\n"
                        f"      Site: {nb_data['site']}\n"
                        f"      Type: {nb_data['type']}\n"
                        f"      Vendor: {nb_data.get('vendor', 'N/A')}\n"
                        f"      Model: {nb_data.get('model', 'N/A')}\n"
                        f"      Version: {nb_data.get('version', 'N/A')}\n")
                        
            # Format FireMon data
            formatted += "    FireMon Data:\n"
            fm_data = device['firemon_data']
            formatted += (f"      Management IP: {fm_data['mgmt_ip']}\n"
                        f"      Collector Group: {fm_data['collector_group']}\n"
                        f"      Device Pack: {fm_data['device_pack']}\n"
                        f"      Status: {fm_data.get('status', 'N/A')}\n"
                        f"      Last Retrieval: {fm_data.get('last_retrieval', 'N/A')}\n")
        return formatted

    def save_report(self, report: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Save report to file
        
        Args:
            report: Report dictionary
            filename: Optional filename (default: auto-generated)
            
        Returns:
            Path to saved report file
            
        Raises:
            IOError: If unable to write report file
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"sync_report_{timestamp}.json"
        
        filepath = Path(self.output_dir) / filename
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            logging.info(f"Report saved to {filepath}")
            return str(filepath)
        except Exception as e:
            logging.error(f"Error saving report: {str(e)}")
            raise IOError(f"Failed to save report: {str(e)}")

    def generate_html_report(self, report: Dict[str, Any]) -> str:
        """
        Generate HTML report with enhanced group sync support
        
        Args:
            report: Report dictionary
            
        Returns:
            HTML string of report
        """
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sync Report - {timestamp}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ margin-bottom: 20px; }}
                .error {{ color: red; }}
                .warning {{ color: orange; }}
                .success {{ color: green; }}
                .info {{ color: blue; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .device-details {{ margin-left: 20px; }}
                .section {{ margin-bottom: 30px; }}
                .diff-highlight {{ background-color: #fff3cd; }}
                .group-section {{ margin-top: 20px; }}
            </style>
        </head>
        <body>
            <h1>Sync Operation Report</h1>
            <div class="section summary">
                {summary_html}
            </div>
            {delta_html}
            <div class="section changes">
                {changes_html}
            </div>
            <div class="section validation">
                {validation_html}
            </div>
        </body>
        </html>
        """
        
        # Generate HTML sections
        summary_html = self._generate_summary_html(report['summary'])
        
        # Handle delta and group analysis
        if report.get('dry_run'):
            delta_html = self._generate_delta_html(
                report.get('delta', {}), 
                report.get('group_analysis', {}) if report.get('sync_mode') == 'groups' else None
            )
        else:
            delta_html = ""
            
        changes_html = self._generate_changes_html(report['changes'])
        validation_html = self._generate_validation_html(report.get('validation', {}))
        
        return html_template.format(
            timestamp=report['timestamp'],
            summary_html=summary_html,
            delta_html=delta_html,
            changes_html=changes_html,
            validation_html=validation_html
        )

    def _generate_delta_html(self, delta: Dict[str, Any], group_analysis: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate HTML for delta section with improved group analysis support
        
        Args:
            delta: Dictionary containing device delta information
            group_analysis: Optional dictionary containing group analysis information
            
        Returns:
            HTML string
        """
        if not delta and not group_analysis:
            return ""
            
        html = ""
        
        # Add device delta section if available
        if delta:
            devices_nb = delta.get('only_in_netbrain', [])
            devices_fm = delta.get('only_in_firemon', [])
            devices_diff = delta.get('different', [])
            
            html += f"""
            <h2>Device Delta Analysis</h2>
            <div class="delta-section">
                <h3>Devices Only in NetBrain ({len(devices_nb)})</h3>
                {self._generate_device_table_html(devices_nb, 'netbrain')}
                
                <h3>Devices Only in FireMon ({len(devices_fm)})</h3>
                {self._generate_device_table_html(devices_fm, 'firemon')}
                
                <h3>Devices with Differences ({len(devices_diff)})</h3>
                {self._generate_differences_table_html(devices_diff)}
            </div>
            """
        
        # Add group analysis section if available
        if group_analysis:
            groups_to_create = group_analysis.get('groups_to_create', [])
            groups_to_update = group_analysis.get('groups_to_update', [])
            orphaned_groups = group_analysis.get('orphaned_groups', [])
            device_assignments = group_analysis.get('device_assignments', [])
            
            html += f"""
            <h2>Group Sync Analysis</h2>
            <div class="group-section">
                <h3>Groups to Create ({len(groups_to_create)})</h3>
                {self._generate_groups_table_html(groups_to_create, 'create')}
                
                <h3>Groups to Update ({len(groups_to_update)})</h3>
                {self._generate_groups_table_html(groups_to_update, 'update')}
                
                <h3>Orphaned Groups ({len(orphaned_groups)})</h3>
                {self._generate_groups_table_html(orphaned_groups, 'orphaned')}
                
                <h3>Device Group Assignments ({len(device_assignments)})</h3>
                {self._generate_assignments_table_html(device_assignments)}
            </div>
            """
            
        return html

    def _generate_groups_table_html(self, groups: List[Dict[str, Any]], mode: str) -> str:
        """
        Generate HTML table for group lists
        
        Args:
            groups: List of group dictionaries
            mode: Type of groups ('create', 'update', or 'orphaned')
            
        Returns:
            HTML string for the table
        """
        if not groups:
            return "<p>None</p>"
            
        # Define headers based on mode
        if mode == 'create':
            headers = ['Name', 'Path', 'Site ID']
        elif mode == 'update':
            headers = ['Name', 'Path', 'FireMon ID', 'Site ID']
        else:  # orphaned
            headers = ['Name', 'FireMon ID', 'Parent ID']
        
        html = """
        <table>
            <tr>
        """
        
        # Add headers
        for header in headers:
            html += f"<th>{header}</th>"
        html += "</tr>"
        
        # Add group rows
        for group in groups:
            html += "<tr>"
            if mode == 'create':
                html += f"""
                    <td>{group.get('name', 'N/A')}</td>
                    <td>{group.get('path', 'N/A')}</td>
                    <td>{group.get('site_id', 'N/A')}</td>
                """
            elif mode == 'update':
                html += f"""
                    <td>{group.get('name', 'N/A')}</td>
                    <td>{group.get('path', 'N/A')}</td>
                    <td>{group.get('firemon_id', 'N/A')}</td>
                    <td>{group.get('site_id', 'N/A')}</td>
                """
            else:  # orphaned
                html += f"""
                    <td>{group.get('name', 'N/A')}</td>
                    <td>{group.get('id', 'N/A')}</td>
                    <td>{group.get('parent_id', 'N/A')}</td>
                """
            html += "</tr>"
        
        html += "</table>"
        return html

    def _generate_assignments_table_html(self, assignments: List[Dict[str, Any]]) -> str:
        """
        Generate HTML table for device group assignments
        
        Args:
            assignments: List of device assignment dictionaries
            
        Returns:
            HTML string for the table
        """
        if not assignments:
            return "<p>None</p>"
            
        html = """
        <table>
            <tr>
                <th>Device Name</th>
                <th>IP Address</th>
                <th>Target Group</th>
                <th>Full Path</th>
                <th>Status</th>
            </tr>
        """
        
        for assignment in assignments:
            status_class = "error" if not assignment.get('group_exists') else "success"
            status_text = "Group needs creation" if not assignment.get('group_exists') else "Ready"
            
            html += f"""
            <tr>
                <td>{assignment.get('device_name', 'N/A')}</td>
                <td>{assignment.get('device_ip', 'N/A')}</td>
                <td>{assignment.get('leaf_group', 'N/A')}</td>
                <td>{assignment.get('full_path', 'N/A')}</td>
                <td class="{status_class}">{status_text}</td>
            </tr>
            """
        
        html += "</table>"
        return html

    def _generate_summary_html(self, summary: Dict[str, Any]) -> str:
        """Generate HTML for summary section"""
        return f"""
        <h2>Summary</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Total</th>
                <th>Success</th>
                <th>Failed</th>
            </tr>
            <tr>
                <td>Devices</td>
                <td>{summary.get('devices', {}).get('total_processed', 0)}</td>
                <td>{summary.get('devices', {}).get('added', 0) + summary.get('devices', {}).get('updated', 0)}</td>
                <td class="error">{summary.get('devices', {}).get('failed', 0)}</td>
            </tr>
            <tr>
                <td>Groups</td>
                <td>{summary.get('groups', {}).get('total_processed', 0)}</td>
                <td>{summary.get('groups', {}).get('created', 0) + summary.get('groups', {}).get('updated', 0)}</td>
                <td class="error">{summary.get('groups', {}).get('failed', 0)}</td>
            </tr>
            <tr>
                <td>Configurations</td>
                <td>{summary.get('configs', {}).get('total_processed', 0)}</td>
                <td>{summary.get('configs', {}).get('updated', 0)}</td>
                <td class="error">{summary.get('configs', {}).get('failed', 0)}</td>
            </tr>
        </table>
        """

    def _generate_device_table_html(self, devices: List[Dict[str, Any]], source: str) -> str:
        """Generate HTML table for device list"""
        if not devices:
            return "<p>None</p>"
            
        headers = {
            'netbrain': ['Hostname', 'Management IP', 'Site', 'Type', 'Model', 'Vendor', 'Version'],
            'firemon': ['Hostname', 'Management IP', 'Collector Group', 'Device Pack', 'Status']
        }
        
        html = """
        <table>
            <tr>
        """
        
        # Add headers
        for header in headers[source]:
            html += f"<th>{header}</th>"
        html += "</tr>"
        
        # Add device rows
        for device in devices:
            html += "<tr>"
            if source == 'netbrain':
                html += f"""
                    <td>{device['hostname']}</td>
                    <td>{device['mgmt_ip']}</td>
                    <td>{device['site']}</td>
                    <td>{device['type']}</td>
                    <td>{device.get('model', 'N/A')}</td>
                    <td>{device.get('vendor', 'N/A')}</td>
                    <td>{device.get('version', 'N/A')}</td>
                """
            else:  # firemon
                html += f"""
                    <td>{device['hostname']}</td>
                    <td>{device['mgmt_ip']}</td>
                    <td>{device['collector_group']}</td>
                    <td>{device['device_pack']}</td>
                    <td>{device.get('status', 'N/A')}</td>
                """
            html += "</tr>"
        
        html += "</table>"
        return html

    def _generate_differences_table_html(self, devices: List[Dict[str, Any]]) -> str:
        """Generate HTML table for device differences"""
        if not devices:
            return "<p>None</p>"
            
        html = """
        <table>
            <tr>
                <th>Hostname</th>
                <th>Differences</th>
                <th>NetBrain Data</th>
                <th>FireMon Data</th>
            </tr>
        """
        
        for device in devices:
            html += f"""
            <tr>
                <td>{device['hostname']}</td>
                <td>
                    <ul>
                        {''.join(f'<li>{diff}</li>' for diff in device['differences'])}
                    </ul>
                </td>
                <td>
                    <div class="device-details">
                        Management IP: {device['netbrain_data']['mgmt_ip']}<br>
                        Site: {device['netbrain_data']['site']}<br>
                        Type: {device['netbrain_data']['type']}<br>
                        Vendor: {device['netbrain_data'].get('vendor', 'N/A')}<br>
                        Model: {device['netbrain_data'].get('model', 'N/A')}<br>
                        Version: {device['netbrain_data'].get('version', 'N/A')}
                    </div>
                </td>
                <td>
                    <div class="device-details">
                        Management IP: {device['firemon_data']['mgmt_ip']}<br>
                        Collector Group: {device['firemon_data']['collector_group']}<br>
                        Device Pack: {device['firemon_data']['device_pack']}<br>
                        Status: {device['firemon_data'].get('status', 'N/A')}<br>
                        Last Retrieval: {device['firemon_data'].get('last_retrieval', 'N/A')}
                    </div>
                </td>
            </tr>
            """
        
        html += "</table>"
        return html

    def _generate_changes_html(self, changes: Dict[str, Any]) -> str:
        """Generate HTML for changes section"""
        return f"""
        <h2>Changes Detail</h2>
        <div class="changes-section">
            {self._generate_change_category_html('Device Changes', changes.get('devices', []))}
            {self._generate_change_category_html('Group Changes', changes.get('groups', []))}
            {self._generate_change_category_html('Config Changes', changes.get('configs', []))}
            {self._generate_change_category_html('License Changes', changes.get('licenses', []))}
        </div>
        """

    def _generate_change_category_html(self, title: str, items: List[Dict[str, Any]]) -> str:
        """Generate HTML for a change category"""
        if not items:
            return f"""
            <h3>{title}</h3>
            <p>No changes</p>
            """
            
        html = f"<h3>{title}</h3><table>"
        html += """
            <tr>
                <th>Item</th>
                <th>Action</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
        """
        
        for item in items:
            status_class = {
                'success': 'success',
                'error': 'error',
                'warning': 'warning',
                'dry_run': 'info'
            }.get(item.get('status', ''), '')
            
            html += f"""
            <tr>
                <td>{item.get('device', item.get('group', item.get('name', 'Unknown')))}</td>
                <td>{item.get('action', 'Unknown')}</td>
                <td class="{status_class}">{item.get('status', 'Unknown')}</td>
                <td>{self._format_details_html(item.get('details', {}))}</td>
            </tr>
            """
            
        html += "</table>"
        return html

    def _generate_validation_html(self, validation: Dict[str, Any]) -> str:
        """Generate HTML for validation section"""
        if not validation:
            return ""
            
        html = "<h2>Validation Results</h2>"
        
        for category, issues in validation.items():
            if not issues:
                continue
                
            html += f"<h3>{category.title()} Validation</h3>"
            html += """
            <table>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Message</th>
                    <th>Details</th>
                </tr>
            """
            
            for issue in issues:
                severity_class = 'error' if issue.get('severity') == 'error' else 'warning'
                html += f"""
                <tr>
                    <td>{issue.get('type', 'Unknown')}</td>
                    <td class="{severity_class}">{issue.get('severity', 'Unknown')}</td>
                    <td>{issue.get('message', 'No message')}</td>
                    <td>{self._format_details_html(issue.get('details', {}))}</td>
                </tr>
                """
                
            html += "</table>"
            
        return html

    def _format_details_html(self, details: Dict[str, Any]) -> str:
        """Format details dictionary as HTML"""
        if not details:
            return "No details"
            
        return "<br>".join(f"{k}: {v}" for k, v in details.items())
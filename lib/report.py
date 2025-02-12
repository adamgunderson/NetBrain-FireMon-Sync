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
        Shows relevant information based on the specific sync mode
        
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
            if report.get('dry_run'):
                if sync_mode == 'devices':
                    delta_stats = report.get('summary', {}).get('devices', {})
                    content = f"""
    Device Analysis:
    - Total in NetBrain: {delta_stats.get('total_in_netbrain', 0)}
    - Total in FireMon: {delta_stats.get('total_in_firemon', 0)}
    - Only in NetBrain: {delta_stats.get('only_in_netbrain', 0)}
    - Only in FireMon: {delta_stats.get('only_in_firemon', 0)}
    - Devices with Differences: {delta_stats.get('different', 0)}
    """
                elif sync_mode == 'groups':
                    content = f"""
    Group Analysis:
    - Total Groups in NetBrain: {summary.get('groups', {}).get('total_processed', 0)}
    - Groups to Create: {summary.get('groups', {}).get('to_create', 0)}
    - Groups to Update: {summary.get('groups', {}).get('to_update', 0)}
    """
                elif sync_mode == 'licenses':
                    content = f"""
    License Analysis:
    - Total Devices to Process: {summary.get('licenses', {}).get('total_processed', 0)}
    - Licenses to Add: {summary.get('licenses', {}).get('to_add', 0)}
    - Licenses to Remove: {summary.get('licenses', {}).get('to_remove', 0)}
    """
                elif sync_mode == 'configs':
                    content = f"""
    Configuration Analysis:
    - Total Devices to Check: {summary.get('configs', {}).get('total_processed', 0)}
    - Configs Needing Update: {summary.get('configs', {}).get('to_update', 0)}
    """
                else:  # full mode
                    delta_stats = report.get('summary', {}).get('devices', {})
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
                # Non-dry run mode - show actual changes
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
                    content = f"""
    Group Changes:
    - Total Processed: {group_summary.get('total_processed', 0)}
    - Created: {group_summary.get('created', 0)}
    - Updated: {group_summary.get('updated', 0)}
    - Failed: {group_summary.get('failed', 0)}
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
        Generate HTML report
        
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
        delta_html = self._generate_delta_html(report.get('delta', {})) if report.get('dry_run') else ""
        changes_html = self._generate_changes_html(report['changes'])
        validation_html = self._generate_validation_html(report.get('validation', {}))
        
        return html_template.format(
            timestamp=report['timestamp'],
            summary_html=summary_html,
            delta_html=delta_html,
            changes_html=changes_html,
            validation_html=validation_html
        )

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

    def _generate_delta_html(self, delta: Dict[str, Any]) -> str:
        """Generate HTML for delta section"""
        if not delta:
            return ""
            
        devices_nb = delta.get('only_in_netbrain', [])
        devices_fm = delta.get('only_in_firemon', [])
        devices_diff = delta.get('different', [])
        
        return f"""
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
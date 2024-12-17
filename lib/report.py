# lib/report.py

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

class ReportManager:
    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = output_dir
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        """Ensure output directory exists"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def generate_sync_report(self, 
                           changes: Dict[str, Any],
                           validation_results: Dict[str, Any],
                           sync_mode: str) -> Dict[str, Any]:
        """Generate comprehensive sync report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'sync_mode': sync_mode,
            'summary': self._generate_summary(changes, validation_results),
            'changes': changes,
            'validation': validation_results
        }
        
        # Add license requirements analysis if in appropriate mode
        if sync_mode in ['full', 'licenses']:
            report['license_analysis'] = self._analyze_license_requirements(changes)
        
        return report

    def _generate_summary(self, 
                         changes: Dict[str, Any],
                         validation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of sync operations"""
        return {
            'devices': {
                'total_processed': len(changes.get('devices', [])),
                'added': len([d for d in changes.get('devices', []) 
                            if d['action'] == 'add']),
                'updated': len([d for d in changes.get('devices', [])
                              if d['action'] == 'update']),
                'removed': len([d for d in changes.get('devices', [])
                              if d['action'] == 'remove']),
                'failed': len([d for d in changes.get('devices', [])
                             if d['status'] == 'error'])
            },
            'groups': {
                'total_processed': len(changes.get('groups', [])),
                'created': len([g for g in changes.get('groups', [])
                              if g['action'] == 'create']),
                'updated': len([g for g in changes.get('groups', [])
                              if g['action'] == 'update']),
                'failed': len([g for g in changes.get('groups', [])
                             if g['status'] == 'error'])
            },
            'configs': {
                'total_processed': len(changes.get('configs', [])),
                'updated': len([c for c in changes.get('configs', [])
                              if c['action'] == 'update']),
                'failed': len([c for c in changes.get('configs', [])
                             if c['status'] == 'error'])
            },
            'licenses': {
                'total_processed': len(changes.get('licenses', [])),
                'added': len([l for l in changes.get('licenses', [])
                            if l['action'] == 'add']),
                'removed': len([l for l in changes.get('licenses', [])
                              if l['action'] == 'remove']),
                'failed': len([l for l in changes.get('licenses', [])
                             if l['status'] == 'error'])
            },
            'validation': {
                'total_issues': sum(len(issues) for issues in validation_results.values()),
                'errors': sum(1 for category in validation_results.values() 
                            for issue in category if issue['severity'] == 'error'),
                'warnings': sum(1 for category in validation_results.values()
                              for issue in category if issue['severity'] == 'warning')
            }
        }

    def _analyze_license_requirements(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze license requirements based on changes"""
        return {
            'current_licenses': {
                'SM': sum(1 for l in changes.get('licenses', [])
                         if l.get('product') == 'SM' and l['action'] != 'remove'),
                'PO': sum(1 for l in changes.get('licenses', [])
                         if l.get('product') == 'PO' and l['action'] != 'remove'),
                'PP': sum(1 for l in changes.get('licenses', [])
                         if l.get('product') == 'PP' and l['action'] != 'remove')
            },
            'required_licenses': {
                'SM': sum(1 for d in changes.get('devices', [])
                         if d['action'] in ['add', 'update']),
                'PO': sum(1 for d in changes.get('devices', [])
                         if d['action'] in ['add', 'update']),
                'PP': sum(1 for d in changes.get('devices', [])
                         if d['action'] in ['add', 'update'])
            },
            'additional_needed': {
                'SM': max(0, sum(1 for d in changes.get('devices', [])
                                if d['action'] in ['add', 'update']) -
                         sum(1 for l in changes.get('licenses', [])
                             if l.get('product') == 'SM' and l['action'] != 'remove')),
                'PO': max(0, sum(1 for d in changes.get('devices', [])
                                if d['action'] in ['add', 'update']) -
                         sum(1 for l in changes.get('licenses', [])
                             if l.get('product') == 'PO' and l['action'] != 'remove')),
                'PP': max(0, sum(1 for d in changes.get('devices', [])
                                if d['action'] in ['add', 'update']) -
                         sum(1 for l in changes.get('licenses', [])
                             if l.get('product') == 'PP' and l['action'] != 'remove'))
            }
        }

    def save_report(self, report: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Save report to file"""
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
            raise

    def generate_console_summary(self, report: Dict[str, Any]) -> str:
        """Generate human-readable console summary"""
        summary = report['summary']
        
        return f"""
Sync Operation Summary
=====================
Timestamp: {report['timestamp']}
Mode: {report['sync_mode']}

Device Changes:
- Total Processed: {summary['devices']['total_processed']}
- Added: {summary['devices']['added']}
- Updated: {summary['devices']['updated']}
- Removed: {summary['devices']['removed']}
- Failed: {summary['devices']['failed']}

Group Changes:
- Total Processed: {summary['groups']['total_processed']}
- Created: {summary['groups']['created']}
- Updated: {summary['groups']['updated']}
- Failed: {summary['groups']['failed']}

Configuration Updates:
- Total Processed: {summary['configs']['total_processed']}
- Updated: {summary['configs']['updated']}
- Failed: {summary['configs']['failed']}

License Changes:
- Total Processed: {summary['licenses']['total_processed']}
- Added: {summary['licenses']['added']}
- Removed: {summary['licenses']['removed']}
- Failed: {summary['licenses']['failed']}

Validation Results:
- Total Issues: {summary['validation']['total_issues']}
- Errors: {summary['validation']['errors']}
- Warnings: {summary['validation']['warnings']}
"""

    def generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report"""
        # HTML template implementation
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
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Sync Operation Report</h1>
            <div class="summary">
                {summary_html}
            </div>
            <div class="changes">
                {changes_html}
            </div>
            <div class="validation">
                {validation_html}
            </div>
        </body>
        </html>
        """
        
        # Implementation details for HTML sections
        summary_html = self._generate_summary_html(report['summary'])
        changes_html = self._generate_changes_html(report['changes'])
        validation_html = self._generate_validation_html(report['validation'])
        
        return html_template.format(
            timestamp=report['timestamp'],
            summary_html=summary_html,
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
                <td>{summary['devices']['total_processed']}</td>
                <td>{summary['devices']['added'] + summary['devices']['updated']}</td>
                <td>{summary['devices']['failed']}</td>
            </tr>
            <!-- Add rows for other categories -->
        </table>
        """

    def _generate_changes_html(self, changes: Dict[str, Any]) -> str:
        """Generate HTML for changes section"""
        return f"""
        <h2>Changes Detail</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Item</th>
                <th>Action</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
            <!-- Add rows for each change -->
        </table>
        """

    def _generate_validation_html(self, validation: Dict[str, Any]) -> str:
        """Generate HTML for validation section"""
        return f"""
        <h2>Validation Results</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Severity</th>
                <th>Issue</th>
                <th>Details</th>
            </tr>
            <!-- Add rows for each validation issue -->
        </table>
        """
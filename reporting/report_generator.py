"""
Report generation module supporting multiple formats.
"""

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

from rich.console import Console
from rich.table import Table

from tdrf.core.logger import get_logger
from tdrf.core.config import config
from tdrf.core.database import get_database

logger = get_logger(__name__)
console = Console()


class ReportGenerator:
    """Generates security reports in various formats."""
    
    def __init__(self):
        """Initialize report generator."""
        self.db = get_database()
        self.output_dir = Path(config.get('reporting.output_dir', 'reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, format_type: str = 'console',
                       hours: int = 24) -> Optional[str]:
        """
        Generate a security report.
        
        Args:
            format_type: Report format (console, csv, json, html)
            hours: Number of hours to include in report
            
        Returns:
            Path to saved report file, or None for console output
        """
        # Gather data
        since = datetime.now() - timedelta(hours=hours)
        
        data = {
            'generated_at': datetime.now().isoformat(),
            'period_hours': hours,
            'events': self.db.get_events(since=since, limit=1000),
            'alerts': self.db.get_alerts(since=since, limit=500),
            'scan_results': self.db.get_scan_results(since=since, limit=1000),
            'statistics': self.db.get_statistics()
        }
        
        # Generate report based on format
        if format_type == 'console':
            self._generate_console_report(data)
            return None
        elif format_type == 'csv':
            return self._generate_csv_report(data)
        elif format_type == 'json':
            return self._generate_json_report(data)
        elif format_type == 'html':
            return self._generate_html_report(data)
        else:
            logger.error(f"Unknown report format: {format_type}")
            return None
    
    def _generate_console_report(self, data: Dict[str, Any]):
        """Generate console report."""
        console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]      TDRF Security Report[/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]\n")
        
        console.print(f"[bold]Generated:[/bold] {data['generated_at']}")
        console.print(f"[bold]Period:[/bold] Last {data['period_hours']} hours\n")
        
        # Statistics
        stats = data['statistics']
        console.print("[bold yellow]Summary Statistics:[/bold yellow]")
        console.print(f"  Total Events: {len(data['events'])}")
        console.print(f"  Total Alerts: {len(data['alerts'])}")
        console.print(f"  Open Ports Found: {len(data['scan_results'])}\n")
        
        # Alert severity breakdown
        if data['alerts']:
            console.print("[bold yellow]Alert Severity Breakdown:[/bold yellow]")
            severity_count = {}
            for alert in data['alerts']:
                sev = alert.get('severity', 'UNKNOWN')
                severity_count[sev] = severity_count.get(sev, 0) + 1
            
            for severity, count in sorted(severity_count.items(), reverse=True):
                console.print(f"  {severity}: {count}")
            console.print()
        
        # Recent alerts table
        if data['alerts']:
            table = Table(title="Recent Alerts")
            table.add_column("Time", style="cyan")
            table.add_column("Severity", style="yellow")
            table.add_column("Type", style="green")
            table.add_column("Description")
            
            for alert in data['alerts'][:10]:
                table.add_row(
                    str(alert.get('timestamp', ''))[:19],
                    alert.get('severity', 'INFO'),
                    alert.get('alert_type', 'unknown'),
                    str(alert.get('description', ''))[:50]
                )
            
            console.print(table)
            console.print()
        
        # Open ports table
        if data['scan_results']:
            table = Table(title="Open Ports Discovered")
            table.add_column("Target", style="cyan")
            table.add_column("Port", style="magenta")
            table.add_column("Service", style="green")
            
            for result in data['scan_results'][:20]:
                table.add_row(
                    result.get('target_ip', 'unknown'),
                    str(result.get('port', '?')),
                    result.get('service', 'unknown')
                )
            
            console.print(table)
    
    def _generate_csv_report(self, data: Dict[str, Any]) -> str:
        """Generate CSV report."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.output_dir / f"tdrf_report_{timestamp}.csv"
        
        with open(report_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['TDRF Security Report'])
            writer.writerow(['Generated', data['generated_at']])
            writer.writerow(['Period (hours)', data['period_hours']])
            writer.writerow([])
            
            # Alerts
            writer.writerow(['ALERTS'])
            writer.writerow(['Timestamp', 'Severity', 'Type', 'Source IP', 'Description'])
            
            for alert in data['alerts']:
                writer.writerow([
                    alert.get('timestamp', ''),
                    alert.get('severity', ''),
                    alert.get('alert_type', ''),
                    alert.get('source_ip', ''),
                    alert.get('description', '')
                ])
            
            writer.writerow([])
            
            # Scan results
            writer.writerow(['SCAN RESULTS'])
            writer.writerow(['Timestamp', 'Target', 'Port', 'State', 'Service'])
            
            for result in data['scan_results']:
                writer.writerow([
                    result.get('timestamp', ''),
                    result.get('target_ip', ''),
                    result.get('port', ''),
                    result.get('state', ''),
                    result.get('service', '')
                ])
        
        logger.info(f"CSV report saved to {report_path}")
        return str(report_path)
    
    def _generate_json_report(self, data: Dict[str, Any]) -> str:
        """Generate JSON report."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.output_dir / f"tdrf_report_{timestamp}.json"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to {report_path}")
        return str(report_path)
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.output_dir / f"tdrf_report_{timestamp}.html"
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>TDRF Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ background-color: #34495e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #3498db; }}
        .stat {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ TDRF Security Report</h1>
        <p>Generated: {data['generated_at']}</p>
        <p>Period: Last {data['period_hours']} hours</p>
    </div>
    
    <div class="section">
        <h2>📊 Summary Statistics</h2>
        <p>Total Events: <span class="stat">{len(data['events'])}</span></p>
        <p>Total Alerts: <span class="stat">{len(data['alerts'])}</span></p>
        <p>Open Ports Found: <span class="stat">{len(data['scan_results'])}</span></p>
    </div>
    
    <div class="section">
        <h2>🚨 Recent Alerts</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Source IP</th>
                <th>Description</th>
            </tr>
"""
        
        for alert in data['alerts'][:50]:
            severity = alert.get('severity', 'INFO').lower()
            html_content += f"""
            <tr>
                <td>{alert.get('timestamp', '')}</td>
                <td class="{severity}">{alert.get('severity', 'INFO')}</td>
                <td>{alert.get('alert_type', 'unknown')}</td>
                <td>{alert.get('source_ip', 'N/A')}</td>
                <td>{alert.get('description', '')}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>🔍 Open Ports Discovered</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Target IP</th>
                <th>Port</th>
                <th>Service</th>
            </tr>
"""
        
        for result in data['scan_results'][:50]:
            html_content += f"""
            <tr>
                <td>{result.get('timestamp', '')}</td>
                <td>{result.get('target_ip', 'unknown')}</td>
                <td>{result.get('port', '?')}</td>
                <td>{result.get('service', 'unknown')}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
</body>
</html>
"""
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {report_path}")
        return str(report_path)

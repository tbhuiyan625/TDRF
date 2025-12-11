"""
CLI interface for TDRF with interactive menu system.
"""

import cmd
import sys
from datetime import datetime, timedelta
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from tdrf.core.logger import get_logger
from tdrf.core.config import config
from tdrf.core.database import get_database
from tdrf.analyzers.log_analyzer import LogAnalyzer
from tdrf.scanners.port_scanner import PortScanner
from tdrf.scanners.banner_grabber import BannerGrabber
from tdrf.correlation.engine import CorrelationEngine
from tdrf.reporting.report_generator import ReportGenerator

logger = get_logger(__name__)
console = Console()


class TDRFShell(cmd.Cmd):
    """Interactive CLI shell for TDRF."""
    
    intro = """
╔═══════════════════════════════════════════════════════════╗
║   TDRF - Threat Detection/Response Framework v1.0.0      ║
║   Python Security Tool                                    ║
╚═══════════════════════════════════════════════════════════╝

Type 'help' or '?' to list commands.
Type 'exit' or 'quit' to leave.
"""
    
    prompt = '(tdrf) '
    
    def __init__(self):
        """Initialize CLI shell."""
        super().__init__()
        
        self.db = get_database()
        self.log_analyzer = LogAnalyzer()
        self.port_scanner = PortScanner()
        self.banner_grabber = BannerGrabber()
        self.correlation_engine = CorrelationEngine()
        self.report_generator = ReportGenerator()
        
        console.print("[bold green]TDRF initialized successfully![/bold green]")
    
    def do_analyze_logs(self, arg):
        """Analyze system logs for security events.
        Usage: analyze_logs [hours]
        Example: analyze_logs 24
        """
        try:
            hours = int(arg) if arg else 1
            since = datetime.now() - timedelta(hours=hours)
            
            console.print(f"[cyan]Analyzing logs from the last {hours} hour(s)...[/cyan]")
            
            results = self.log_analyzer.analyze_logs(since=since)
            
            # Display results
            console.print(f"\n[bold green]Analysis Complete![/bold green]")
            console.print(f"Duration: {results.get('duration', 0):.2f}s")
            console.print(f"Events found: {results.get('statistics', {}).get('total_events', 0)}")
            console.print(f"Alerts generated: {results.get('statistics', {}).get('total_alerts', 0)}")
            
            # Show alerts
            if results.get('alerts'):
                self._display_alerts(results['alerts'])
            
        except ValueError:
            console.print("[red]Error: Invalid hours value[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            logger.error(f"Log analysis error: {e}")
    
    def do_scan(self, arg):
        """Scan network ports.
        Usage: scan <target> <ports>
        Examples:
            scan 192.168.1.1 80,443
            scan 192.168.1.0/24 1-1000
            scan localhost 22,80,443,3306
        """
        try:
            parts = arg.split()
            if len(parts) < 2:
                console.print("[red]Usage: scan <target> <ports>[/red]")
                return
            
            target = parts[0]
            ports = parts[1]
            
            console.print(f"[cyan]Scanning {target} on ports {ports}...[/cyan]")
            
            results = self.port_scanner.scan(target, ports)
            
            if 'error' in results:
                console.print(f"[red]Error: {results['error']}[/red]")
                return
            
            # Display results
            console.print(f"\n[bold green]Scan Complete![/bold green]")
            console.print(f"Duration: {results['duration']:.2f}s")
            console.print(f"Open ports: {results['open_ports']}")
            
            if results['results']:
                self._display_scan_results(results['results'])
            else:
                console.print("[yellow]No open ports found[/yellow]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            logger.error(f"Scan error: {e}")
    
    def do_scan_profile(self, arg):
        """Run a predefined scan profile.
        Usage: scan_profile <target> [profile]
        Profiles: quick, standard, full
        Example: scan_profile 192.168.1.1 quick
        """
        try:
            parts = arg.split()
            if not parts:
                console.print("[red]Usage: scan_profile <target> [profile][/red]")
                return
            
            target = parts[0]
            profile = parts[1] if len(parts) > 1 else 'quick'
            
            console.print(f"[cyan]Running {profile} scan on {target}...[/cyan]")
            
            results = self.port_scanner.scan_profile(target, profile)
            
            if 'error' in results:
                console.print(f"[red]Error: {results['error']}[/red]")
                return
            
            console.print(f"\n[bold green]Scan Complete![/bold green]")
            console.print(f"Open ports: {results['open_ports']}")
            
            if results['results']:
                self._display_scan_results(results['results'])
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def do_grab_banner(self, arg):
        """Grab service banner from a port.
        Usage: grab_banner <target> <port>
        Example: grab_banner 192.168.1.1 22
        """
        try:
            parts = arg.split()
            if len(parts) < 2:
                console.print("[red]Usage: grab_banner <target> <port>[/red]")
                return
            
            target = parts[0]
            port = int(parts[1])
            
            console.print(f"[cyan]Grabbing banner from {target}:{port}...[/cyan]")
            
            result = self.banner_grabber.grab_banner(target, port)
            
            if result.get('banner'):
                console.print(f"\n[green]Banner:[/green] {result['banner']}")
                console.print(f"[green]Service:[/green] {result.get('service', 'unknown')}")
            else:
                console.print("[yellow]No banner received[/yellow]")
            
        except ValueError:
            console.print("[red]Error: Invalid port number[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def do_alerts(self, arg):
        """Show recent alerts.
        Usage: alerts [severity]
        Example: alerts HIGH
        """
        try:
            severity = arg.upper() if arg else None
            
            alerts = self.db.get_alerts(severity=severity, limit=50)
            
            if not alerts:
                console.print("[yellow]No alerts found[/yellow]")
                return
            
            self._display_alerts(alerts)
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def do_stats(self, arg):
        """Show system statistics."""
        try:
            console.print("\n[bold cyan]═══ TDRF Statistics ═══[/bold cyan]\n")
            
            db_stats = self.db.get_statistics()
            log_stats = self.log_analyzer.get_statistics()
            corr_stats = self.correlation_engine.get_statistics()
            
            # Database stats
            console.print("[bold]Database:[/bold]")
            console.print(f"  Total events: {db_stats.get('total_events', 0)}")
            console.print(f"  Total alerts: {db_stats.get('total_alerts', 0)}")
            console.print(f"  Scan results: {db_stats.get('total_scan_results', 0)}")
            
            # Recent activity
            console.print(f"\n[bold]Last 24 Hours:[/bold]")
            console.print(f"  Events: {db_stats.get('recent_events', 0)}")
            console.print(f"  Alerts: {db_stats.get('recent_alerts', 0)}")
            
            # Correlation stats
            console.print(f"\n[bold]Correlation Engine:[/bold]")
            console.print(f"  Events buffered: {corr_stats.get('events_buffered', 0)}")
            console.print(f"  Unique sources: {corr_stats.get('unique_sources', 0)}")
            console.print(f"  Active correlations: {corr_stats.get('active_correlations', 0)}")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def do_report(self, arg):
        """Generate a security report.
        Usage: report [format]
        Formats: console, csv, json, html
        Example: report html
        """
        try:
            format_type = arg.lower() if arg else 'console'
            
            console.print(f"[cyan]Generating {format_type} report...[/cyan]")
            
            report_path = self.report_generator.generate_report(format_type)
            
            if format_type == 'console':
                # Report already displayed
                pass
            else:
                console.print(f"[green]Report saved to: {report_path}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def do_clear(self, arg):
        """Clear the screen."""
        console.clear()
    
    def do_exit(self, arg):
        """Exit TDRF."""
        console.print("[yellow]Goodbye![/yellow]")
        return True
    
    def do_quit(self, arg):
        """Exit TDRF."""
        return self.do_exit(arg)
    
    def _display_alerts(self, alerts):
        """Display alerts in a table."""
        table = Table(title="Security Alerts")
        
        table.add_column("ID", style="cyan")
        table.add_column("Time", style="magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="green")
        table.add_column("Description")
        
        for alert in alerts[:20]:  # Limit to 20
            severity_style = self._get_severity_style(alert.get('severity', 'INFO'))
            
            table.add_row(
                str(alert.get('id', '?')),
                str(alert.get('timestamp', ''))[:19],
                f"[{severity_style}]{alert.get('severity', 'INFO')}[/{severity_style}]",
                alert.get('alert_type', 'unknown'),
                alert.get('description', '')[:60]
            )
        
        console.print(table)
    
    def _display_scan_results(self, results):
        """Display scan results in a table."""
        table = Table(title="Open Ports")
        
        table.add_column("Target", style="cyan")
        table.add_column("Port", style="magenta")
        table.add_column("State", style="green")
        table.add_column("Service")
        
        for result in results[:50]:  # Limit to 50
            table.add_row(
                result['target'],
                str(result['port']),
                result['state'],
                result.get('service', 'unknown')
            )
        
        console.print(table)
    
    def _get_severity_style(self, severity):
        """Get Rich style for severity level."""
        severity_styles = {
            'CRITICAL': 'bold red',
            'HIGH': 'red',
            'MEDIUM': 'yellow',
            'LOW': 'blue',
            'INFO': 'white'
        }
        return severity_styles.get(severity, 'white')


def main():
    """Main entry point for CLI."""
    try:
        shell = TDRFShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        logger.error(f"CLI error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

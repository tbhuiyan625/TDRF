"""
Main entry point for TDRF.
"""

import sys
import argparse
from pathlib import Path

from tdrf import __version__, logger
from tdrf.core.config import config


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='TDRF - Threat Detection/Response Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tdrf --cli                 Start CLI interface
  tdrf --gui                 Start GUI interface
  tdrf --analyze-logs        Analyze system logs
  tdrf --scan 192.168.1.1    Scan a target

For more information, visit: https://github.com/tdrf/tdrf
        """
    )
    
    parser.add_argument('--version', action='version', version=f'TDRF v{__version__}')
    parser.add_argument('--cli', action='store_true', help='Start CLI interface')
    parser.add_argument('--gui', action='store_true', help='Start GUI interface')
    parser.add_argument('--analyze-logs', action='store_true', help='Analyze system logs')
    parser.add_argument('--scan', metavar='TARGET', help='Scan a target (IP or hostname)')
    parser.add_argument('--ports', metavar='PORTS', default='80,443', help='Ports to scan')
    parser.add_argument('--report', metavar='FORMAT', help='Generate report (console, csv, json, html)')
    
    args = parser.parse_args()
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    try:
        # Start CLI
        if args.cli:
            from tdrf.interfaces.cli import main as cli_main
            cli_main()
        
        # Start GUI
        elif args.gui:
            from tdrf.interfaces.gui import main as gui_main
            gui_main()
        
        # Analyze logs
        elif args.analyze_logs:
            from tdrf.analyzers.log_analyzer import LogAnalyzer
            analyzer = LogAnalyzer()
            results = analyzer.analyze_logs()
            print(f"Analysis complete: {results['statistics']['total_events']} events, "
                  f"{results['statistics']['total_alerts']} alerts")
        
        # Scan target
        elif args.scan:
            from tdrf.scanners.port_scanner import PortScanner
            scanner = PortScanner()
            results = scanner.scan(args.scan, args.ports)
            print(f"Scan complete: {results['open_ports']} open ports found")
            for result in results['results']:
                print(f"  {result['target']}:{result['port']} - {result['state']}")
        
        # Generate report
        elif args.report:
            from tdrf.reporting.report_generator import ReportGenerator
            generator = ReportGenerator()
            report_path = generator.generate_report(args.report)
            if report_path:
                print(f"Report saved to: {report_path}")
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

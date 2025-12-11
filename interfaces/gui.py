"""
GUI interface for TDRF using customtkinter.
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox
import customtkinter as ctk
from datetime import datetime, timedelta
import threading

from tdrf.core.logger import get_logger
from tdrf.core.config import config
from tdrf.core.database import get_database
from tdrf.analyzers.log_analyzer import LogAnalyzer
from tdrf.scanners.port_scanner import PortScanner
from tdrf.correlation.engine import CorrelationEngine

logger = get_logger(__name__)


class TDRFGui:
    """GUI application for TDRF."""
    
    def __init__(self):
        """Initialize GUI."""
        # Set theme
        ctk.set_appearance_mode(config.get('ui.gui.theme', 'dark'))
        ctk.set_default_color_theme("blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("TDRF - Threat Detection/Response Framework v1.0.0")
        
        width = config.get('ui.gui.window_width', 1200)
        height = config.get('ui.gui.window_height', 800)
        self.root.geometry(f"{width}x{height}")
        
        # Initialize components
        self.db = get_database()
        self.log_analyzer = LogAnalyzer()
        self.port_scanner = PortScanner()
        self.correlation_engine = CorrelationEngine()
        
        # Setup UI
        self._setup_ui()
        
        # Auto-refresh
        if config.get('ui.gui.auto_refresh', True):
            self._start_auto_refresh()
    
    def _setup_ui(self):
        """Setup UI components."""
        # Create tabs
        self.tabview = ctk.CTkTabview(self.root)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Dashboard tab
        self.tab_dashboard = self.tabview.add("Dashboard")
        self._setup_dashboard_tab()
        
        # Log Analysis tab
        self.tab_logs = self.tabview.add("Log Analysis")
        self._setup_logs_tab()
        
        # Port Scanner tab
        self.tab_scanner = self.tabview.add("Port Scanner")
        self._setup_scanner_tab()
        
        # Alerts tab
        self.tab_alerts = self.tabview.add("Alerts")
        self._setup_alerts_tab()
        
        # Set default tab
        self.tabview.set("Dashboard")
    
    def _setup_dashboard_tab(self):
        """Setup dashboard tab."""
        # Statistics frame
        stats_frame = ctk.CTkFrame(self.tab_dashboard)
        stats_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(stats_frame, text="📊 System Statistics", 
                    font=("Arial", 20, "bold")).pack(pady=10)
        
        self.stats_text = ctk.CTkTextbox(stats_frame, height=200)
        self.stats_text.pack(fill="x", padx=10, pady=10)
        
        # Refresh button
        refresh_btn = ctk.CTkButton(stats_frame, text="Refresh Statistics",
                                    command=self._refresh_statistics)
        refresh_btn.pack(pady=10)
        
        # Recent alerts frame
        alerts_frame = ctk.CTkFrame(self.tab_dashboard)
        alerts_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(alerts_frame, text="🚨 Recent Alerts",
                    font=("Arial", 18, "bold")).pack(pady=10)
        
        self.dashboard_alerts = ctk.CTkTextbox(alerts_frame, height=300)
        self.dashboard_alerts.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Load initial data
        self._refresh_statistics()
    
    def _setup_logs_tab(self):
        """Setup log analysis tab."""
        # Control frame
        control_frame = ctk.CTkFrame(self.tab_logs)
        control_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(control_frame, text="Hours to analyze:").pack(side="left", padx=5)
        
        self.log_hours = ctk.CTkEntry(control_frame, width=100)
        self.log_hours.insert(0, "1")
        self.log_hours.pack(side="left", padx=5)
        
        analyze_btn = ctk.CTkButton(control_frame, text="Analyze Logs",
                                    command=self._analyze_logs)
        analyze_btn.pack(side="left", padx=5)
        
        # Results frame
        results_frame = ctk.CTkFrame(self.tab_logs)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.log_results = ctk.CTkTextbox(results_frame)
        self.log_results.pack(fill="both", expand=True, padx=10, pady=10)
    
    def _setup_scanner_tab(self):
        """Setup port scanner tab."""
        # Control frame
        control_frame = ctk.CTkFrame(self.tab_scanner)
        control_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(control_frame, text="Target:").pack(side="left", padx=5)
        
        self.scan_target = ctk.CTkEntry(control_frame, width=200)
        self.scan_target.insert(0, "127.0.0.1")
        self.scan_target.pack(side="left", padx=5)
        
        ctk.CTkLabel(control_frame, text="Ports:").pack(side="left", padx=5)
        
        self.scan_ports = ctk.CTkEntry(control_frame, width=150)
        self.scan_ports.insert(0, "80,443,22")
        self.scan_ports.pack(side="left", padx=5)
        
        scan_btn = ctk.CTkButton(control_frame, text="Scan",
                                command=self._run_scan)
        scan_btn.pack(side="left", padx=5)
        
        # Profile buttons
        profile_frame = ctk.CTkFrame(self.tab_scanner)
        profile_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(profile_frame, text="Quick Profiles:").pack(side="left", padx=5)
        
        ctk.CTkButton(profile_frame, text="Quick Scan", width=100,
                     command=lambda: self._run_profile_scan("quick")).pack(side="left", padx=5)
        
        ctk.CTkButton(profile_frame, text="Standard Scan", width=100,
                     command=lambda: self._run_profile_scan("standard")).pack(side="left", padx=5)
        
        # Results frame
        results_frame = ctk.CTkFrame(self.tab_scanner)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.scan_results = ctk.CTkTextbox(results_frame)
        self.scan_results.pack(fill="both", expand=True, padx=10, pady=10)
    
    def _setup_alerts_tab(self):
        """Setup alerts tab."""
        # Control frame
        control_frame = ctk.CTkFrame(self.tab_alerts)
        control_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(control_frame, text="Filter by severity:").pack(side="left", padx=5)
        
        self.alert_severity = ctk.CTkComboBox(control_frame,
                                              values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.alert_severity.set("ALL")
        self.alert_severity.pack(side="left", padx=5)
        
        refresh_alerts_btn = ctk.CTkButton(control_frame, text="Refresh Alerts",
                                          command=self._load_alerts)
        refresh_alerts_btn.pack(side="left", padx=5)
        
        # Alerts display
        alerts_frame = ctk.CTkFrame(self.tab_alerts)
        alerts_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.alerts_display = ctk.CTkTextbox(alerts_frame)
        self.alerts_display.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Load initial alerts
        self._load_alerts()
    
    def _refresh_statistics(self):
        """Refresh dashboard statistics."""
        try:
            self.stats_text.delete("0.0", "end")
            
            stats = self.db.get_statistics()
            
            stats_str = f"""
═══ TDRF Statistics ═══

Database:
  Total Events: {stats.get('total_events', 0)}
  Total Alerts: {stats.get('total_alerts', 0)}
  Scan Results: {stats.get('total_scan_results', 0)}

Last 24 Hours:
  Events: {stats.get('recent_events', 0)}
  Alerts: {stats.get('recent_alerts', 0)}

Alert Severity Breakdown:
"""
            
            for severity, count in stats.get('alert_severity', {}).items():
                stats_str += f"  {severity}: {count}\n"
            
            self.stats_text.insert("0.0", stats_str)
            
            # Load recent alerts
            self._load_dashboard_alerts()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load statistics: {e}")
            logger.error(f"Statistics error: {e}")
    
    def _load_dashboard_alerts(self):
        """Load recent alerts for dashboard."""
        try:
            self.dashboard_alerts.delete("0.0", "end")
            
            alerts = self.db.get_alerts(limit=10)
            
            if not alerts:
                self.dashboard_alerts.insert("0.0", "No recent alerts")
                return
            
            for alert in alerts:
                alert_str = f"""
[{alert.get('severity', 'INFO')}] {alert.get('timestamp', '')}
{alert.get('alert_type', 'unknown')}: {alert.get('description', '')}
---
"""
                self.dashboard_alerts.insert("end", alert_str)
                
        except Exception as e:
            logger.error(f"Error loading dashboard alerts: {e}")
    
    def _analyze_logs(self):
        """Analyze system logs."""
        def analyze():
            try:
                hours = int(self.log_hours.get())
                since = datetime.now() - timedelta(hours=hours)
                
                self.log_results.delete("0.0", "end")
                self.log_results.insert("0.0", f"Analyzing logs from last {hours} hour(s)...\n")
                
                results = self.log_analyzer.analyze_logs(since=since)
                
                result_str = f"""
Analysis Complete!
Duration: {results.get('duration', 0):.2f}s
Events found: {results.get('statistics', {}).get('total_events', 0)}
Alerts generated: {results.get('statistics', {}).get('total_alerts', 0)}

Event Types:
"""
                
                for event_type, count in results.get('statistics', {}).get('event_types', {}).items():
                    result_str += f"  {event_type}: {count}\n"
                
                if results.get('alerts'):
                    result_str += "\nGenerated Alerts:\n"
                    for alert in results['alerts'][:10]:
                        result_str += f"  [{alert.get('severity')}] {alert.get('description')}\n"
                
                self.log_results.delete("0.0", "end")
                self.log_results.insert("0.0", result_str)
                
            except ValueError:
                messagebox.showerror("Error", "Invalid hours value")
            except Exception as e:
                messagebox.showerror("Error", f"Analysis failed: {e}")
                logger.error(f"Log analysis error: {e}")
        
        # Run in thread to avoid blocking UI
        threading.Thread(target=analyze, daemon=True).start()
    
    def _run_scan(self):
        """Run port scan."""
        def scan():
            try:
                target = self.scan_target.get()
                ports = self.scan_ports.get()
                
                self.scan_results.delete("0.0", "end")
                self.scan_results.insert("0.0", f"Scanning {target} on ports {ports}...\n")
                
                results = self.port_scanner.scan(target, ports)
                
                if 'error' in results:
                    messagebox.showerror("Error", results['error'])
                    return
                
                result_str = f"""
Scan Complete!
Duration: {results['duration']:.2f}s
Targets scanned: {results['targets_scanned']}
Ports scanned: {results['ports_scanned']}
Open ports found: {results['open_ports']}

Open Ports:
"""
                
                for result in results['results']:
                    result_str += f"  {result['target']}:{result['port']} - {result['state']}\n"
                
                self.scan_results.delete("0.0", "end")
                self.scan_results.insert("0.0", result_str)
                
            except Exception as e:
                messagebox.showerror("Error", f"Scan failed: {e}")
                logger.error(f"Scan error: {e}")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def _run_profile_scan(self, profile: str):
        """Run a predefined scan profile."""
        def scan():
            try:
                target = self.scan_target.get()
                
                self.scan_results.delete("0.0", "end")
                self.scan_results.insert("0.0", f"Running {profile} scan on {target}...\n")
                
                results = self.port_scanner.scan_profile(target, profile)
                
                if 'error' in results:
                    messagebox.showerror("Error", results['error'])
                    return
                
                result_str = f"{profile.upper()} Scan Complete!\n"
                result_str += f"Open ports: {results['open_ports']}\n\n"
                
                for result in results['results']:
                    result_str += f"{result['target']}:{result['port']} - OPEN\n"
                
                self.scan_results.delete("0.0", "end")
                self.scan_results.insert("0.0", result_str)
                
            except Exception as e:
                messagebox.showerror("Error", f"Scan failed: {e}")
                logger.error(f"Profile scan error: {e}")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def _load_alerts(self):
        """Load alerts."""
        try:
            self.alerts_display.delete("0.0", "end")
            
            severity = self.alert_severity.get()
            if severity == "ALL":
                severity = None
            
            alerts = self.db.get_alerts(severity=severity, limit=100)
            
            if not alerts:
                self.alerts_display.insert("0.0", "No alerts found")
                return
            
            for alert in alerts:
                alert_str = f"""
ID: {alert.get('id')}
Time: {alert.get('timestamp', '')}
Severity: {alert.get('severity', 'INFO')}
Type: {alert.get('alert_type', 'unknown')}
Source: {alert.get('source_ip', 'N/A')}
Description: {alert.get('description', '')}
{'='*60}
"""
                self.alerts_display.insert("end", alert_str)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load alerts: {e}")
            logger.error(f"Alerts load error: {e}")
    
    def _start_auto_refresh(self):
        """Start auto-refresh timer."""
        interval = config.get('ui.gui.refresh_interval', 5) * 1000
        
        def refresh():
            if self.tabview.get() == "Dashboard":
                self._refresh_statistics()
            self.root.after(interval, refresh)
        
        self.root.after(interval, refresh)
    
    def run(self):
        """Run the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point for GUI."""
    try:
        app = TDRFGui()
        app.run()
    except Exception as e:
        logger.error(f"GUI error: {e}")
        messagebox.showerror("Fatal Error", f"Application failed to start: {e}")


if __name__ == '__main__':
    main()

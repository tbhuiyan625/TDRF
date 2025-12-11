"""
Main log analyzer that coordinates parsing and detection.
"""

import platform
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from tdrf.core.logger import get_logger
from tdrf.core.config import config
from tdrf.core.database import get_database
from tdrf.analyzers.linux_logs import LinuxLogParser
from tdrf.analyzers.windows_logs import WindowsLogParser
from tdrf.analyzers.patterns import PatternMatcher, BruteForceDetector

logger = get_logger(__name__)


class LogAnalyzer:
    """Main log analyzer coordinating all parsing and detection."""
    
    def __init__(self):
        """Initialize log analyzer."""
        self.db = get_database()
        self.pattern_matcher = PatternMatcher()
        self.brute_force_detector = BruteForceDetector()
        
        # Initialize platform-specific parsers
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        
        if self.is_linux:
            self.linux_parser = LinuxLogParser()
            logger.info("Linux log parser initialized")
        else:
            self.linux_parser = None
        
        if self.is_windows:
            self.windows_parser = WindowsLogParser()
            logger.info("Windows log parser initialized")
        else:
            self.windows_parser = None
        
        self.enabled = config.get('log_analysis.enabled', True)
    
    def analyze_logs(self, since: Optional[datetime] = None,
                     limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Analyze all available logs.
        
        Args:
            since: Only analyze events after this timestamp
            limit: Maximum number of events to analyze
            
        Returns:
            Analysis results dictionary
        """
        if not self.enabled:
            logger.warning("Log analysis is disabled")
            return {'events': [], 'alerts': [], 'error': 'Log analysis disabled'}
        
        results = {
            'events': [],
            'alerts': [],
            'statistics': {},
            'start_time': datetime.now(),
        }
        
        # Parse platform-specific logs
        if self.is_linux and self.linux_parser:
            logger.info("Analyzing Linux logs...")
            linux_events = self.linux_parser.parse_all_logs(since=since, limit=limit)
            results['events'].extend(linux_events)
            logger.info(f"Found {len(linux_events)} Linux events")
        
        if self.is_windows and self.windows_parser:
            logger.info("Analyzing Windows Event Logs...")
            max_per_log = limit if limit else 100
            windows_events = self.windows_parser.read_all_logs(
                max_events_per_log=max_per_log,
                since=since
            )
            results['events'].extend(windows_events)
            logger.info(f"Found {len(windows_events)} Windows events")
        
        # Store events in database
        for event in results['events']:
            try:
                self.db.add_event(
                    event_type=event.get('event_type', 'unknown'),
                    timestamp=event.get('timestamp'),
                    source_ip=event.get('source_ip'),
                    target_ip=event.get('target_ip'),
                    username=event.get('username'),
                    port=event.get('port'),
                    service=event.get('service'),
                    severity=event.get('severity', 'INFO'),
                    description=event.get('description', ''),
                    raw_data=event
                )
            except Exception as e:
                logger.debug(f"Error storing event: {e}")
        
        # Run brute-force detection
        logger.info("Running brute-force detection...")
        alerts = self.brute_force_detector.analyze_events(results['events'])
        results['alerts'] = alerts
        logger.info(f"Generated {len(alerts)} alerts")
        
        # Collect statistics
        results['statistics'] = {
            'total_events': len(results['events']),
            'total_alerts': len(alerts),
            'brute_force_stats': self.brute_force_detector.get_statistics(),
            'event_types': self._count_event_types(results['events']),
            'severity_breakdown': self._count_severity(results['events']),
        }
        
        results['end_time'] = datetime.now()
        results['duration'] = (results['end_time'] - results['start_time']).total_seconds()
        
        return results
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a specific log file.
        
        Args:
            file_path: Path to log file
            
        Returns:
            Analysis results
        """
        path = Path(file_path)
        
        if not path.exists():
            logger.error(f"Log file not found: {file_path}")
            return {'error': f'File not found: {file_path}'}
        
        results = {
            'events': [],
            'alerts': [],
            'file': str(path),
        }
        
        # Try parsing as Linux log
        if self.linux_parser:
            logger.info(f"Parsing {path} as Linux log...")
            events = self.linux_parser.parse_file(path)
            results['events'] = events
        
        # Run detection
        alerts = self.brute_force_detector.analyze_events(results['events'])
        results['alerts'] = alerts
        
        results['statistics'] = {
            'total_events': len(results['events']),
            'total_alerts': len(alerts),
        }
        
        return results
    
    def get_recent_events(self, minutes: int = 60,
                         event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent events from database.
        
        Args:
            minutes: Number of minutes to look back
            event_type: Filter by event type
            
        Returns:
            List of events
        """
        since = datetime.now() - timedelta(minutes=minutes)
        return self.db.get_events(event_type=event_type, since=since)
    
    def get_recent_alerts(self, minutes: int = 60,
                         severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent alerts from database.
        
        Args:
            minutes: Number of minutes to look back
            severity: Filter by severity
            
        Returns:
            List of alerts
        """
        since = datetime.now() - timedelta(minutes=minutes)
        return self.db.get_alerts(severity=severity, since=since)
    
    def _count_event_types(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count events by type."""
        counts = {}
        for event in events:
            event_type = event.get('event_type', 'unknown')
            counts[event_type] = counts.get(event_type, 0) + 1
        return counts
    
    def _count_severity(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count events by severity."""
        counts = {}
        for event in events:
            severity = event.get('severity', 'INFO')
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def tail_logs(self, lines: int = 100) -> List[Dict[str, Any]]:
        """
        Get the most recent log entries.
        
        Args:
            lines: Number of lines to read
            
        Returns:
            List of recent events
        """
        events = []
        
        if self.is_linux and self.linux_parser:
            for log_path in self.linux_parser.log_paths:
                log_events = self.linux_parser.tail_log(log_path, lines=lines)
                events.extend(log_events)
        
        if self.is_windows and self.windows_parser:
            events.extend(self.windows_parser.read_events(max_events=lines))
        
        # Sort by timestamp
        events.sort(key=lambda x: x.get('timestamp', datetime.now()), reverse=True)
        
        return events[:lines]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall statistics.
        
        Returns:
            Statistics dictionary
        """
        db_stats = self.db.get_statistics()
        bf_stats = self.brute_force_detector.get_statistics()
        
        return {
            'database': db_stats,
            'brute_force': bf_stats,
            'platform': platform.system(),
            'parsers_available': {
                'linux': self.linux_parser is not None,
                'windows': self.windows_parser is not None and self.windows_parser.available,
            }
        }

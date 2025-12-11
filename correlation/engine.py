"""
Event correlation engine for detecting attack patterns.
"""

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set

from tdrf.core.logger import get_logger
from tdrf.core.config import config
from tdrf.core.database import get_database
from tdrf.correlation.rules import RuleEngine
from tdrf.correlation.alert_manager import AlertManager

logger = get_logger(__name__)


class CorrelationEngine:
    """Correlates security events to detect attack patterns."""
    
    def __init__(self):
        """Initialize correlation engine."""
        self.db = get_database()
        self.rule_engine = RuleEngine()
        self.alert_manager = AlertManager()
        
        self.enabled = config.get('correlation.enabled', True)
        self.time_windows = config.get('correlation.time_windows', {
            'short': 300,
            'medium': 1800,
            'long': 3600
        })
        
        # Event storage for correlation
        self.event_buffer: List[Dict[str, Any]] = []
        self.event_by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.event_by_target: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.event_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        # Correlation state
        self.active_correlations: Dict[str, Dict[str, Any]] = {}
    
    def add_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Add event and check for correlations.
        
        Args:
            event: Event dictionary
            
        Returns:
            List of generated alerts
        """
        if not self.enabled:
            return []
        
        # Add event to buffer
        self.event_buffer.append(event)
        
        # Index event
        event_type = event.get('event_type', 'unknown')
        source_ip = event.get('source_ip')
        target_ip = event.get('target_ip')
        
        self.event_by_type[event_type].append(event)
        
        if source_ip:
            self.event_by_source[source_ip].append(event)
        
        if target_ip:
            self.event_by_target[target_ip].append(event)
        
        # Clean old events
        self._cleanup_old_events()
        
        # Run correlation rules
        alerts = self.rule_engine.evaluate_event(event, self)
        
        # Process alerts
        for alert in alerts:
            self.alert_manager.add_alert(alert)
        
        return alerts
    
    def add_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Add multiple events and check for correlations.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            List of all generated alerts
        """
        all_alerts = []
        
        for event in events:
            alerts = self.add_event(event)
            all_alerts.extend(alerts)
        
        return all_alerts
    
    def _cleanup_old_events(self):
        """Remove events outside the longest time window."""
        if not self.event_buffer:
            return
        
        max_window = max(self.time_windows.values())
        cutoff_time = datetime.now() - timedelta(seconds=max_window)
        
        # Filter event buffer
        self.event_buffer = [
            e for e in self.event_buffer
            if e.get('timestamp', datetime.now()) > cutoff_time
        ]
        
        # Rebuild indexes
        self.event_by_source.clear()
        self.event_by_target.clear()
        self.event_by_type.clear()
        
        for event in self.event_buffer:
            event_type = event.get('event_type', 'unknown')
            source_ip = event.get('source_ip')
            target_ip = event.get('target_ip')
            
            self.event_by_type[event_type].append(event)
            
            if source_ip:
                self.event_by_source[source_ip].append(event)
            
            if target_ip:
                self.event_by_target[target_ip].append(event)
    
    def get_events_by_source(self, source_ip: str,
                            event_types: Optional[List[str]] = None,
                            time_window: int = 300) -> List[Dict[str, Any]]:
        """
        Get events from a specific source.
        
        Args:
            source_ip: Source IP address
            event_types: Filter by event types
            time_window: Time window in seconds
            
        Returns:
            List of matching events
        """
        events = self.event_by_source.get(source_ip, [])
        
        # Filter by time window
        cutoff = datetime.now() - timedelta(seconds=time_window)
        events = [e for e in events if e.get('timestamp', datetime.now()) > cutoff]
        
        # Filter by event types
        if event_types:
            events = [e for e in events if e.get('event_type') in event_types]
        
        return events
    
    def get_events_by_target(self, target_ip: str,
                            event_types: Optional[List[str]] = None,
                            time_window: int = 300) -> List[Dict[str, Any]]:
        """
        Get events targeting a specific IP.
        
        Args:
            target_ip: Target IP address
            event_types: Filter by event types
            time_window: Time window in seconds
            
        Returns:
            List of matching events
        """
        events = self.event_by_target.get(target_ip, [])
        
        # Filter by time window
        cutoff = datetime.now() - timedelta(seconds=time_window)
        events = [e for e in events if e.get('timestamp', datetime.now()) > cutoff]
        
        # Filter by event types
        if event_types:
            events = [e for e in events if e.get('event_type') in event_types]
        
        return events
    
    def get_events_by_type(self, event_type: str, time_window: int = 300) -> List[Dict[str, Any]]:
        """
        Get events of a specific type.
        
        Args:
            event_type: Event type
            time_window: Time window in seconds
            
        Returns:
            List of matching events
        """
        events = self.event_by_type.get(event_type, [])
        
        # Filter by time window
        cutoff = datetime.now() - timedelta(seconds=time_window)
        events = [e for e in events if e.get('timestamp', datetime.now()) > cutoff]
        
        return events
    
    def correlate_reconnaissance_and_attack(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect reconnaissance followed by attack from same source.
        
        Args:
            event: Current event
            
        Returns:
            Alert dictionary if pattern detected
        """
        source_ip = event.get('source_ip')
        if not source_ip:
            return None
        
        # Look for port scans followed by failed logins
        time_window = self.time_windows.get('medium', 1800)
        source_events = self.get_events_by_source(source_ip, time_window=time_window)
        
        # Check for port scan events
        scan_events = [e for e in source_events if 'scan' in e.get('event_type', '')]
        
        # Check for attack events (failed logins)
        attack_events = [e for e in source_events if 'failed' in e.get('event_type', '')]
        
        if scan_events and attack_events:
            return {
                'alert_type': 'reconnaissance_and_attack',
                'severity': 'HIGH',
                'source_ip': source_ip,
                'timestamp': datetime.now(),
                'description': (
                    f"Reconnaissance and attack pattern detected from {source_ip}: "
                    f"{len(scan_events)} scan(s) followed by {len(attack_events)} attack(s)"
                ),
                'scan_count': len(scan_events),
                'attack_count': len(attack_events),
                'correlation_id': str(uuid.uuid4())
            }
        
        return None
    
    def correlate_distributed_attack(self, target_ip: str) -> Optional[Dict[str, Any]]:
        """
        Detect distributed attack against a target.
        
        Args:
            target_ip: Target IP address
            
        Returns:
            Alert dictionary if pattern detected
        """
        time_window = self.time_windows.get('short', 300)
        target_events = self.get_events_by_target(target_ip, time_window=time_window)
        
        # Get unique source IPs
        source_ips = set(e.get('source_ip') for e in target_events if e.get('source_ip'))
        
        # Check for distributed pattern
        if len(source_ips) >= 5 and len(target_events) >= 10:
            return {
                'alert_type': 'distributed_attack',
                'severity': 'CRITICAL',
                'target_ip': target_ip,
                'timestamp': datetime.now(),
                'description': (
                    f"Distributed attack detected against {target_ip}: "
                    f"{len(target_events)} events from {len(source_ips)} unique sources"
                ),
                'source_count': len(source_ips),
                'event_count': len(target_events),
                'sources': list(source_ips),
                'correlation_id': str(uuid.uuid4())
            }
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get correlation statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            'events_buffered': len(self.event_buffer),
            'unique_sources': len(self.event_by_source),
            'unique_targets': len(self.event_by_target),
            'event_types': len(self.event_by_type),
            'active_correlations': len(self.active_correlations),
            'total_alerts': self.alert_manager.get_alert_count()
        }
    
    def clear_buffer(self):
        """Clear event buffer and indexes."""
        self.event_buffer.clear()
        self.event_by_source.clear()
        self.event_by_target.clear()
        self.event_by_type.clear()
        logger.info("Cleared correlation buffer")

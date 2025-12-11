"""
Pattern matching and brute-force detection.
"""

from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

from tdrf.core.logger import get_logger
from tdrf.core.config import config
from tdrf.core.database import get_database

logger = get_logger(__name__)


class PatternMatcher:
    """Pattern matching for security events."""
    
    def __init__(self):
        """Initialize pattern matcher."""
        self.patterns = config.get_all_rules()
    
    def match_failed_login(self, event: Dict[str, Any]) -> bool:
        """Check if event matches failed login pattern."""
        failed_types = [
            'failed_password',
            'failed_password_invalid',
            'authentication_failure',
            'invalid_user'
        ]
        
        # Check event type
        if event.get('event_type') in failed_types:
            return True
        
        # Check Windows event IDs
        if event.get('event_id') in [4625, 4776]:
            return True
        
        return False
    
    def match_successful_login(self, event: Dict[str, Any]) -> bool:
        """Check if event matches successful login pattern."""
        success_types = [
            'accepted_password',
            'accepted_publickey',
            'session_opened'
        ]
        
        # Check event type
        if event.get('event_type') in success_types:
            return True
        
        # Check Windows event IDs
        if event.get('event_id') == 4624:
            return True
        
        return False
    
    def match_account_lockout(self, event: Dict[str, Any]) -> bool:
        """Check if event matches account lockout pattern."""
        # Windows event ID for account lockout
        if event.get('event_id') == 4740:
            return True
        
        return False
    
    def get_event_severity(self, event: Dict[str, Any]) -> str:
        """Determine event severity based on patterns."""
        # Check if severity already set
        if 'severity' in event:
            return event['severity']
        
        # Determine based on event type
        if self.match_account_lockout(event):
            return 'HIGH'
        elif self.match_failed_login(event):
            return 'MEDIUM'
        elif self.match_successful_login(event):
            return 'INFO'
        
        return 'LOW'


class BruteForceDetector:
    """Detects brute-force attacks from login patterns."""
    
    def __init__(self):
        """Initialize brute-force detector."""
        self.threshold = config.get('log_analysis.brute_force.failed_login_threshold', 5)
        self.time_window = config.get('log_analysis.brute_force.time_window_seconds', 300)
        self.alert_on_success = config.get('log_analysis.brute_force.alert_on_success_after_failures', True)
        
        # In-memory tracking (for session)
        self.failed_attempts: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
        self.successful_after_failed: List[Dict[str, Any]] = []
        
        self.db = get_database()
        self.pattern_matcher = PatternMatcher()
    
    def add_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process an event and detect brute-force patterns.
        
        Args:
            event: Event dictionary
            
        Returns:
            Alert dictionary if brute-force detected, None otherwise
        """
        source_ip = event.get('source_ip')
        username = event.get('username', 'unknown')
        timestamp = event.get('timestamp', datetime.now())
        
        if not source_ip:
            return None
        
        # Check if failed login
        if self.pattern_matcher.match_failed_login(event):
            return self._handle_failed_login(source_ip, username, timestamp, event)
        
        # Check if successful login
        elif self.pattern_matcher.match_successful_login(event):
            return self._handle_successful_login(source_ip, username, timestamp, event)
        
        return None
    
    def _handle_failed_login(self, source_ip: str, username: str,
                            timestamp: datetime, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle failed login event."""
        key = (source_ip, username)
        
        # Add to tracking
        self.failed_attempts[key].append(timestamp)
        
        # Clean old attempts outside time window
        cutoff_time = timestamp - timedelta(seconds=self.time_window)
        self.failed_attempts[key] = [
            t for t in self.failed_attempts[key] if t > cutoff_time
        ]
        
        # Check if threshold exceeded
        attempt_count = len(self.failed_attempts[key])
        
        if attempt_count >= self.threshold:
            # Generate alert
            alert = {
                'alert_type': 'brute_force_detected',
                'severity': 'HIGH',
                'source_ip': source_ip,
                'username': username,
                'timestamp': timestamp,
                'description': (
                    f"Brute-force attack detected: {attempt_count} failed login attempts "
                    f"for user '{username}' from {source_ip} in {self.time_window} seconds"
                ),
                'event_count': attempt_count,
                'time_window': self.time_window
            }
            
            # Store alert in database
            try:
                self.db.add_alert(
                    alert_type=alert['alert_type'],
                    severity=alert['severity'],
                    description=alert['description'],
                    timestamp=timestamp,
                    source_ip=source_ip
                )
            except Exception as e:
                logger.error(f"Failed to store alert: {e}")
            
            logger.warning(f"ALERT: {alert['description']}")
            return alert
        
        return None
    
    def _handle_successful_login(self, source_ip: str, username: str,
                                 timestamp: datetime, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle successful login event."""
        if not self.alert_on_success:
            return None
        
        key = (source_ip, username)
        
        # Check if there were recent failed attempts
        if key in self.failed_attempts:
            cutoff_time = timestamp - timedelta(seconds=self.time_window)
            recent_failures = [
                t for t in self.failed_attempts[key] if t > cutoff_time
            ]
            
            if len(recent_failures) >= 2:  # At least 2 failures before success
                # Generate alert
                alert = {
                    'alert_type': 'successful_brute_force',
                    'severity': 'CRITICAL',
                    'source_ip': source_ip,
                    'username': username,
                    'timestamp': timestamp,
                    'description': (
                        f"CRITICAL: Successful login for '{username}' from {source_ip} "
                        f"after {len(recent_failures)} failed attempts"
                    ),
                    'failed_attempts': len(recent_failures)
                }
                
                # Store alert
                try:
                    self.db.add_alert(
                        alert_type=alert['alert_type'],
                        severity=alert['severity'],
                        description=alert['description'],
                        timestamp=timestamp,
                        source_ip=source_ip
                    )
                except Exception as e:
                    logger.error(f"Failed to store alert: {e}")
                
                logger.critical(f"ALERT: {alert['description']}")
                
                # Clear failed attempts for this key
                del self.failed_attempts[key]
                
                return alert
        
        return None
    
    def analyze_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze a batch of events for brute-force patterns.
        
        Args:
            events: List of events to analyze
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        for event in events:
            alert = self.add_event(event)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            'tracked_sources': len(self.failed_attempts),
            'total_failed_attempts': sum(len(attempts) for attempts in self.failed_attempts.values()),
            'top_sources': []
        }
        
        # Get top sources by failed attempt count
        attempt_counts = {
            f"{ip}:{user}": len(attempts)
            for (ip, user), attempts in self.failed_attempts.items()
        }
        
        top_sources = sorted(attempt_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        stats['top_sources'] = [
            {'source': source, 'attempts': count}
            for source, count in top_sources
        ]
        
        return stats
    
    def clear_tracking(self):
        """Clear all tracking data."""
        self.failed_attempts.clear()
        self.successful_after_failed.clear()
        logger.info("Cleared brute-force tracking data")

"""
Alert manager for handling and storing security alerts.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import Counter

from tdrf.core.logger import get_logger
from tdrf.core.config import config
from tdrf.core.database import get_database

logger = get_logger(__name__)


class AlertManager:
    """Manages security alerts."""
    
    def __init__(self):
        """Initialize alert manager."""
        self.db = get_database()
        self.enabled = config.get('alerts.enabled', True)
        
        # Alert thresholds
        self.thresholds = config.get('alerts.thresholds', {
            'LOW': 1,
            'MEDIUM': 3,
            'HIGH': 5,
            'CRITICAL': 10
        })
        
        # Alert destinations
        self.console_enabled = config.get('alerts.console', True)
        self.file_enabled = config.get('alerts.file', True)
        
        # In-memory alert storage
        self.alerts: List[Dict[str, Any]] = []
    
    def add_alert(self, alert: Dict[str, Any]) -> int:
        """
        Add a new alert.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Alert ID
        """
        if not self.enabled:
            return -1
        
        # Ensure required fields
        alert.setdefault('timestamp', datetime.now())
        alert.setdefault('severity', 'MEDIUM')
        alert.setdefault('acknowledged', False)
        alert.setdefault('resolved', False)
        
        # Store in memory
        self.alerts.append(alert)
        
        # Store in database
        try:
            alert_id = self.db.add_alert(
                alert_type=alert.get('alert_type', 'unknown'),
                severity=alert['severity'],
                description=alert.get('description', ''),
                timestamp=alert['timestamp'],
                source_ip=alert.get('source_ip'),
                target_ip=alert.get('target_ip'),
                correlation_id=alert.get('correlation_id')
            )
        except Exception as e:
            logger.error(f"Error storing alert in database: {e}")
            alert_id = -1
        
        # Output to configured destinations
        if self.console_enabled:
            self._output_to_console(alert)
        
        if self.file_enabled:
            self._output_to_file(alert)
        
        return alert_id
    
    def _output_to_console(self, alert: Dict[str, Any]):
        """Output alert to console."""
        severity = alert.get('severity', 'INFO')
        description = alert.get('description', 'No description')
        timestamp = alert.get('timestamp', datetime.now())
        
        # Log based on severity
        if severity == 'CRITICAL':
            logger.critical(f"ALERT [{severity}] {description}")
        elif severity == 'HIGH':
            logger.error(f"ALERT [{severity}] {description}")
        elif severity == 'MEDIUM':
            logger.warning(f"ALERT [{severity}] {description}")
        else:
            logger.info(f"ALERT [{severity}] {description}")
    
    def _output_to_file(self, alert: Dict[str, Any]):
        """Output alert to file."""
        # Handled by logger file handler
        pass
    
    def get_alerts(self, severity: Optional[str] = None,
                  acknowledged: Optional[bool] = None,
                  limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get alerts from database.
        
        Args:
            severity: Filter by severity
            acknowledged: Filter by acknowledgment status
            limit: Maximum number of alerts to return
            
        Returns:
            List of alerts
        """
        return self.db.get_alerts(
            severity=severity,
            acknowledged=acknowledged,
            limit=limit
        )
    
    def get_recent_alerts(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """
        Get recent alerts.
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            List of recent alerts
        """
        from datetime import timedelta
        since = datetime.now() - timedelta(minutes=minutes)
        return self.db.get_alerts(since=since)
    
    def acknowledge_alert(self, alert_id: int):
        """
        Acknowledge an alert.
        
        Args:
            alert_id: Alert ID to acknowledge
        """
        # Update in database
        try:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                    (alert_id,)
                )
                logger.info(f"Acknowledged alert {alert_id}")
        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}")
    
    def resolve_alert(self, alert_id: int):
        """
        Mark an alert as resolved.
        
        Args:
            alert_id: Alert ID to resolve
        """
        try:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE alerts SET resolved = 1, acknowledged = 1 WHERE id = ?",
                    (alert_id,)
                )
                logger.info(f"Resolved alert {alert_id}")
        except Exception as e:
            logger.error(f"Error resolving alert: {e}")
    
    def get_alert_count(self, severity: Optional[str] = None) -> int:
        """
        Get count of alerts.
        
        Args:
            severity: Filter by severity (optional)
            
        Returns:
            Alert count
        """
        if severity:
            return len([a for a in self.alerts if a.get('severity') == severity])
        return len(self.alerts)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics.
        
        Returns:
            Statistics dictionary
        """
        # Severity breakdown
        severity_counts = Counter(a.get('severity') for a in self.alerts)
        
        # Alert type breakdown
        type_counts = Counter(a.get('alert_type') for a in self.alerts)
        
        # Acknowledgment status
        acknowledged = len([a for a in self.alerts if a.get('acknowledged')])
        unacknowledged = len(self.alerts) - acknowledged
        
        return {
            'total_alerts': len(self.alerts),
            'by_severity': dict(severity_counts),
            'by_type': dict(type_counts),
            'acknowledged': acknowledged,
            'unacknowledged': unacknowledged
        }
    
    def clear_alerts(self):
        """Clear in-memory alerts."""
        self.alerts.clear()
        logger.info("Cleared in-memory alerts")
    
    def get_top_sources(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get top alert sources.
        
        Args:
            limit: Number of top sources to return
            
        Returns:
            List of source information
        """
        source_counts = Counter(
            a.get('source_ip') for a in self.alerts
            if a.get('source_ip')
        )
        
        return [
            {'source_ip': ip, 'alert_count': count}
            for ip, count in source_counts.most_common(limit)
        ]

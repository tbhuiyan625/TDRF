"""
Rule engine for event correlation.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from tdrf.core.logger import get_logger
from tdrf.core.config import config

logger = get_logger(__name__)


class RuleEngine:
    """Rule-based correlation engine."""
    
    def __init__(self):
        """Initialize rule engine."""
        self.rules = self._load_rules()
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load correlation rules from configuration."""
        rules = config.get('correlation.rules', [])
        
        # Add default rules if none configured
        if not rules:
            rules = self._get_default_rules()
        
        logger.info(f"Loaded {len(rules)} correlation rules")
        return rules
    
    def _get_default_rules(self) -> List[Dict[str, Any]]:
        """Get default correlation rules."""
        return [
            {
                'name': 'Reconnaissance and Attack',
                'events': ['port_scan', 'failed_login'],
                'same_source': True,
                'time_window': 1800,
                'severity': 'HIGH'
            },
            {
                'name': 'Distributed Brute-Force',
                'events': ['failed_login'],
                'same_target': True,
                'different_sources': True,
                'count': 10,
                'time_window': 300,
                'severity': 'CRITICAL'
            },
            {
                'name': 'Suspicious Service Access',
                'events': ['port_scan', 'service_banner'],
                'suspicious_services': ['telnet', 'ftp', 'smb'],
                'severity': 'MEDIUM'
            }
        ]
    
    def evaluate_event(self, event: Dict[str, Any], correlation_engine) -> List[Dict[str, Any]]:
        """
        Evaluate an event against all rules.
        
        Args:
            event: Event to evaluate
            correlation_engine: CorrelationEngine instance for querying events
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        for rule in self.rules:
            alert = self._evaluate_rule(rule, event, correlation_engine)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _evaluate_rule(self, rule: Dict[str, Any], event: Dict[str, Any],
                      correlation_engine) -> Optional[Dict[str, Any]]:
        """
        Evaluate a single rule against an event.
        
        Args:
            rule: Rule dictionary
            event: Event to evaluate
            correlation_engine: CorrelationEngine instance
            
        Returns:
            Alert dictionary if rule matches, None otherwise
        """
        rule_name = rule.get('name', 'Unknown Rule')
        required_events = rule.get('events', [])
        time_window = rule.get('time_window', 300)
        severity = rule.get('severity', 'MEDIUM')
        
        # Check if current event type is in required events
        current_type = event.get('event_type', '')
        if not any(req in current_type for req in required_events):
            return None
        
        # Check same source rule
        if rule.get('same_source'):
            source_ip = event.get('source_ip')
            if not source_ip:
                return None
            
            # Get events from same source
            source_events = correlation_engine.get_events_by_source(
                source_ip,
                time_window=time_window
            )
            
            # Check if all required event types are present
            event_types_found = set(e.get('event_type', '') for e in source_events)
            
            # Fuzzy match event types
            matches = 0
            for req_type in required_events:
                if any(req_type in et for et in event_types_found):
                    matches += 1
            
            if matches >= len(required_events):
                return {
                    'alert_type': 'rule_match',
                    'rule_name': rule_name,
                    'severity': severity,
                    'source_ip': source_ip,
                    'timestamp': datetime.now(),
                    'description': f"Rule matched: {rule_name} - {source_ip}",
                    'correlation_id': str(uuid.uuid4()),
                    'matched_events': len(source_events)
                }
        
        # Check same target rule
        if rule.get('same_target'):
            target_ip = event.get('target_ip')
            if not target_ip:
                return None
            
            # Get events targeting same IP
            target_events = correlation_engine.get_events_by_target(
                target_ip,
                time_window=time_window
            )
            
            # Check event count threshold
            min_count = rule.get('count', 1)
            if len(target_events) >= min_count:
                # Check for different sources
                if rule.get('different_sources'):
                    unique_sources = len(set(e.get('source_ip') for e in target_events
                                           if e.get('source_ip')))
                    min_sources = rule.get('unique_sources_min', 2)
                    
                    if unique_sources >= min_sources:
                        return {
                            'alert_type': 'rule_match',
                            'rule_name': rule_name,
                            'severity': severity,
                            'target_ip': target_ip,
                            'timestamp': datetime.now(),
                            'description': (
                                f"Rule matched: {rule_name} - {unique_sources} sources "
                                f"targeting {target_ip}"
                            ),
                            'correlation_id': str(uuid.uuid4()),
                            'matched_events': len(target_events),
                            'unique_sources': unique_sources
                        }
        
        # Check suspicious services
        if rule.get('suspicious_services'):
            service = event.get('service', '').lower()
            suspicious = rule.get('suspicious_services', [])
            
            if service in suspicious:
                return {
                    'alert_type': 'suspicious_service',
                    'rule_name': rule_name,
                    'severity': severity,
                    'source_ip': event.get('source_ip'),
                    'target_ip': event.get('target_ip'),
                    'service': service,
                    'port': event.get('port'),
                    'timestamp': datetime.now(),
                    'description': f"Suspicious service detected: {service}",
                    'correlation_id': str(uuid.uuid4())
                }
        
        return None
    
    def add_rule(self, rule: Dict[str, Any]):
        """
        Add a new correlation rule.
        
        Args:
            rule: Rule dictionary
        """
        self.rules.append(rule)
        logger.info(f"Added new rule: {rule.get('name', 'Unnamed')}")
    
    def remove_rule(self, rule_name: str) -> bool:
        """
        Remove a correlation rule by name.
        
        Args:
            rule_name: Name of rule to remove
            
        Returns:
            True if rule was removed, False otherwise
        """
        initial_count = len(self.rules)
        self.rules = [r for r in self.rules if r.get('name') != rule_name]
        
        if len(self.rules) < initial_count:
            logger.info(f"Removed rule: {rule_name}")
            return True
        
        return False
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """
        Get all correlation rules.
        
        Returns:
            List of rules
        """
        return self.rules.copy()

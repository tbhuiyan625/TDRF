"""
Windows Event Log parser for security events.
Parses Security, System, and Application event logs.
"""

import platform
from datetime import datetime
from typing import Dict, List, Optional, Any

from tdrf.core.logger import get_logger
from tdrf.core.config import config

logger = get_logger(__name__)

# Platform-specific imports
if platform.system() == 'Windows':
    try:
        import win32evtlog
        import win32evtlogutil
        import win32security
        import win32con
        WINDOWS_AVAILABLE = True
    except ImportError:
        logger.warning("pywin32 not available. Windows event log parsing disabled.")
        WINDOWS_AVAILABLE = False
else:
    WINDOWS_AVAILABLE = False


class WindowsLogParser:
    """Parser for Windows Event Logs."""
    
    # Important Security Event IDs
    EVENT_IDS = {
        4624: {'name': 'Successful Logon', 'severity': 'INFO'},
        4625: {'name': 'Failed Logon', 'severity': 'MEDIUM'},
        4634: {'name': 'Logoff', 'severity': 'INFO'},
        4648: {'name': 'Explicit Credentials Logon', 'severity': 'LOW'},
        4672: {'name': 'Special Privileges Assigned', 'severity': 'LOW'},
        4720: {'name': 'User Account Created', 'severity': 'MEDIUM'},
        4726: {'name': 'User Account Deleted', 'severity': 'MEDIUM'},
        4740: {'name': 'Account Lockout', 'severity': 'HIGH'},
        4767: {'name': 'Account Unlocked', 'severity': 'LOW'},
        4776: {'name': 'Failed Credential Validation', 'severity': 'MEDIUM'},
        4778: {'name': 'Session Reconnected', 'severity': 'INFO'},
        4779: {'name': 'Session Disconnected', 'severity': 'INFO'},
    }
    
    def __init__(self):
        """Initialize Windows log parser."""
        self.available = WINDOWS_AVAILABLE
        
        if not self.available:
            logger.warning("Windows Event Log parsing not available on this platform")
            return
        
        self.log_types = config.get('log_analysis.windows_logs', ['Security', 'System'])
    
    def _parse_event(self, event) -> Optional[Dict[str, Any]]:
        """
        Parse a Windows event object.
        
        Args:
            event: Windows event object
            
        Returns:
            Parsed event dictionary or None
        """
        if not self.available:
            return None
        
        try:
            event_id = event.EventID & 0xFFFF  # Mask to get actual event ID
            event_category = event.EventCategory
            time_generated = event.TimeGenerated
            source_name = event.SourceName
            
            # Get event data
            event_data = win32evtlogutil.SafeFormatMessage(event, 'Security')
            
            # Build base event
            parsed_event = {
                'timestamp': time_generated,
                'event_id': event_id,
                'event_type': 'windows_event',
                'source': source_name,
                'category': event_category,
                'raw_data': event_data,
            }
            
            # Add metadata for known event IDs
            if event_id in self.EVENT_IDS:
                event_info = self.EVENT_IDS[event_id]
                parsed_event['event_name'] = event_info['name']
                parsed_event['severity'] = event_info['severity']
            else:
                parsed_event['event_name'] = f"Event {event_id}"
                parsed_event['severity'] = 'INFO'
            
            # Extract specific data based on event ID
            if event_id == 4625:  # Failed logon
                parsed_event = self._parse_failed_logon(parsed_event, event_data)
            elif event_id == 4624:  # Successful logon
                parsed_event = self._parse_successful_logon(parsed_event, event_data)
            elif event_id == 4740:  # Account lockout
                parsed_event = self._parse_account_lockout(parsed_event, event_data)
            elif event_id == 4776:  # Failed credential validation
                parsed_event = self._parse_credential_validation(parsed_event, event_data)
            
            return parsed_event
            
        except Exception as e:
            logger.debug(f"Error parsing Windows event: {e}")
            return None
    
    def _parse_failed_logon(self, event: Dict, event_data: str) -> Dict[str, Any]:
        """Extract data from failed logon event (4625)."""
        # Parse event_data string to extract fields
        # Event 4625 contains: Account Name, Source Network Address, Logon Type, etc.
        
        lines = event_data.split('\n')
        for line in lines:
            if 'Account Name:' in line and 'username' not in event:
                event['username'] = line.split(':', 1)[1].strip()
            elif 'Source Network Address:' in line:
                event['source_ip'] = line.split(':', 1)[1].strip()
            elif 'Failure Reason:' in line:
                event['failure_reason'] = line.split(':', 1)[1].strip()
        
        event['description'] = f"Failed logon attempt for {event.get('username', 'unknown')}"
        return event
    
    def _parse_successful_logon(self, event: Dict, event_data: str) -> Dict[str, Any]:
        """Extract data from successful logon event (4624)."""
        lines = event_data.split('\n')
        for line in lines:
            if 'Account Name:' in line and 'username' not in event:
                event['username'] = line.split(':', 1)[1].strip()
            elif 'Source Network Address:' in line:
                event['source_ip'] = line.split(':', 1)[1].strip()
            elif 'Logon Type:' in line:
                event['logon_type'] = line.split(':', 1)[1].strip()
        
        event['description'] = f"Successful logon for {event.get('username', 'unknown')}"
        return event
    
    def _parse_account_lockout(self, event: Dict, event_data: str) -> Dict[str, Any]:
        """Extract data from account lockout event (4740)."""
        lines = event_data.split('\n')
        for line in lines:
            if 'Account Name:' in line:
                event['username'] = line.split(':', 1)[1].strip()
            elif 'Caller Computer Name:' in line:
                event['source_ip'] = line.split(':', 1)[1].strip()
        
        event['description'] = f"Account lockout for {event.get('username', 'unknown')}"
        return event
    
    def _parse_credential_validation(self, event: Dict, event_data: str) -> Dict[str, Any]:
        """Extract data from credential validation event (4776)."""
        lines = event_data.split('\n')
        for line in lines:
            if 'Account Name:' in line:
                event['username'] = line.split(':', 1)[1].strip()
            elif 'Source Workstation:' in line:
                event['source_ip'] = line.split(':', 1)[1].strip()
        
        event['description'] = f"Failed credential validation for {event.get('username', 'unknown')}"
        return event
    
    def read_events(self, log_type: str = 'Security', max_events: int = 100,
                   since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Read events from Windows Event Log.
        
        Args:
            log_type: Type of log (Security, System, Application)
            max_events: Maximum number of events to read
            since: Only return events after this timestamp
            
        Returns:
            List of parsed events
        """
        if not self.available:
            logger.warning("Windows Event Log reading not available")
            return []
        
        events = []
        
        try:
            # Open event log
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            total_events = win32evtlog.GetNumberOfEventLogRecords(hand)
            logger.debug(f"Total events in {log_type} log: {total_events}")
            
            # Read events
            event_count = 0
            while event_count < max_events:
                events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
                
                if not events_batch:
                    break
                
                for event in events_batch:
                    # Filter by timestamp if specified
                    if since and event.TimeGenerated < since:
                        continue
                    
                    parsed = self._parse_event(event)
                    if parsed:
                        events.append(parsed)
                        event_count += 1
                        
                        if event_count >= max_events:
                            break
            
            win32evtlog.CloseEventLog(hand)
            logger.info(f"Read {len(events)} events from {log_type} log")
            
        except Exception as e:
            logger.error(f"Error reading Windows Event Log {log_type}: {e}")
        
        return events
    
    def read_all_logs(self, max_events_per_log: int = 100,
                     since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Read events from all configured Windows Event Logs.
        
        Args:
            max_events_per_log: Maximum events to read from each log
            since: Only return events after this timestamp
            
        Returns:
            List of all parsed events
        """
        if not self.available:
            return []
        
        all_events = []
        
        for log_type in self.log_types:
            events = self.read_events(log_type, max_events=max_events_per_log, since=since)
            all_events.extend(events)
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events
    
    def monitor_events(self, log_type: str = 'Security',
                      event_ids: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """
        Monitor for specific event IDs in real-time.
        
        Args:
            log_type: Type of log to monitor
            event_ids: List of event IDs to filter (None = all)
            
        Returns:
            List of matching events
        """
        if not self.available:
            return []
        
        # For simplicity, this reads recent events
        # True real-time monitoring would require event subscriptions
        events = self.read_events(log_type, max_events=50)
        
        if event_ids:
            events = [e for e in events if e.get('event_id') in event_ids]
        
        return events

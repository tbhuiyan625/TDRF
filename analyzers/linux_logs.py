"""
Linux log parser for authentication logs.
Parses /var/log/auth.log, /var/log/secure, and related files.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from tdrf.core.logger import get_logger
from tdrf.core.config import config

logger = get_logger(__name__)


class LinuxLogParser:
    """Parser for Linux authentication logs."""
    
    # Common Linux auth log patterns
    PATTERNS = {
        'failed_password': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)'
        ),
        'failed_password_invalid': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)'
        ),
        'accepted_password': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)'
        ),
        'accepted_publickey': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted publickey for (\w+) from (\d+\.\d+\.\d+\.\d+)'
        ),
        'authentication_failure': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)(?:.*user=(\w+))?'
        ),
        'invalid_user': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)'
        ),
        'connection_closed': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*Connection closed by (?:authenticating user \w+ )?(\d+\.\d+\.\d+\.\d+)'
        ),
        'session_opened': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*session opened for user (\w+)'
        ),
        'session_closed': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*session closed for user (\w+)'
        ),
        'sudo_command': re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*(\w+) : TTY=\w+ ; PWD=.* ; USER=(\w+) ; COMMAND=(.+)'
        ),
    }
    
    def __init__(self):
        """Initialize Linux log parser."""
        self.log_paths = self._get_log_paths()
    
    def _get_log_paths(self) -> List[Path]:
        """Get list of Linux log file paths to monitor."""
        default_paths = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/syslog',
        ]
        
        # Get paths from config
        config_paths = config.get('log_analysis.linux_logs', default_paths)
        
        # Filter to existing paths
        paths = []
        for path_str in config_paths:
            path = Path(path_str)
            if path.exists():
                paths.append(path)
            else:
                logger.debug(f"Log file not found: {path_str}")
        
        if not paths:
            logger.warning("No Linux log files found. Running on Windows or logs not accessible.")
        
        return paths
    
    def _parse_timestamp(self, timestamp_str: str, log_file: Path) -> datetime:
        """
        Parse timestamp from log entry.
        
        Args:
            timestamp_str: Timestamp string from log
            log_file: Path to log file (for getting year from file metadata)
            
        Returns:
            Parsed datetime object
        """
        try:
            # Linux auth logs typically don't include year
            # Use current year or file modification year
            current_year = datetime.now().year
            
            # Try parsing with current year
            try:
                dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            except ValueError:
                # Fallback to simpler parsing
                dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
                dt = dt.replace(year=current_year)
            
            # If timestamp is in future, it's probably from last year
            if dt > datetime.now():
                dt = dt.replace(year=current_year - 1)
            
            return dt
        except Exception as e:
            logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return datetime.now()
    
    def parse_line(self, line: str, log_file: Path) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line.
        
        Args:
            line: Log line to parse
            log_file: Path to log file
            
        Returns:
            Parsed event dictionary or None
        """
        line = line.strip()
        if not line:
            return None
        
        # Try each pattern
        for event_type, pattern in self.PATTERNS.items():
            match = pattern.search(line)
            if match:
                groups = match.groups()
                
                # Parse timestamp
                timestamp = self._parse_timestamp(groups[0], log_file)
                
                # Build event based on type
                event = {
                    'timestamp': timestamp,
                    'event_type': event_type,
                    'raw_line': line,
                    'source': str(log_file)
                }
                
                if event_type == 'failed_password':
                    event['username'] = groups[1]
                    event['source_ip'] = groups[2]
                    event['severity'] = 'MEDIUM'
                    event['description'] = f"Failed password for {groups[1]} from {groups[2]}"
                
                elif event_type == 'failed_password_invalid':
                    event['username'] = groups[1]
                    event['source_ip'] = groups[2]
                    event['severity'] = 'HIGH'
                    event['description'] = f"Failed password for invalid user {groups[1]} from {groups[2]}"
                
                elif event_type == 'accepted_password':
                    event['username'] = groups[1]
                    event['source_ip'] = groups[2]
                    event['severity'] = 'INFO'
                    event['description'] = f"Successful login for {groups[1]} from {groups[2]}"
                
                elif event_type == 'accepted_publickey':
                    event['username'] = groups[1]
                    event['source_ip'] = groups[2]
                    event['severity'] = 'INFO'
                    event['description'] = f"Successful publickey login for {groups[1]} from {groups[2]}"
                
                elif event_type == 'authentication_failure':
                    event['source_ip'] = groups[1]
                    event['username'] = groups[2] if len(groups) > 2 and groups[2] else 'unknown'
                    event['severity'] = 'MEDIUM'
                    event['description'] = f"Authentication failure from {groups[1]}"
                
                elif event_type == 'invalid_user':
                    event['username'] = groups[1]
                    event['source_ip'] = groups[2]
                    event['severity'] = 'MEDIUM'
                    event['description'] = f"Invalid user {groups[1]} from {groups[2]}"
                
                elif event_type == 'session_opened':
                    event['username'] = groups[1]
                    event['severity'] = 'INFO'
                    event['description'] = f"Session opened for {groups[1]}"
                
                elif event_type == 'session_closed':
                    event['username'] = groups[1]
                    event['severity'] = 'INFO'
                    event['description'] = f"Session closed for {groups[1]}"
                
                elif event_type == 'sudo_command':
                    event['username'] = groups[1]
                    event['target_user'] = groups[2]
                    event['command'] = groups[3]
                    event['severity'] = 'LOW'
                    event['description'] = f"Sudo command by {groups[1]} as {groups[2]}"
                
                return event
        
        return None
    
    def parse_file(self, log_file: Path, since: Optional[datetime] = None,
                   limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Parse entire log file.
        
        Args:
            log_file: Path to log file
            since: Only return events after this timestamp
            limit: Maximum number of events to return
            
        Returns:
            List of parsed events
        """
        events = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if limit and len(events) >= limit:
                        break
                    
                    event = self.parse_line(line, log_file)
                    if event:
                        # Filter by timestamp if specified
                        if since and event['timestamp'] < since:
                            continue
                        
                        events.append(event)
            
            logger.info(f"Parsed {len(events)} events from {log_file}")
        except Exception as e:
            logger.error(f"Error parsing log file {log_file}: {e}")
        
        return events
    
    def parse_all_logs(self, since: Optional[datetime] = None,
                       limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Parse all available log files.
        
        Args:
            since: Only return events after this timestamp
            limit: Maximum number of events to return (per file)
            
        Returns:
            List of all parsed events
        """
        all_events = []
        
        for log_path in self.log_paths:
            events = self.parse_file(log_path, since=since, limit=limit)
            all_events.extend(events)
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events
    
    def tail_log(self, log_file: Path, lines: int = 100) -> List[Dict[str, Any]]:
        """
        Parse the last N lines of a log file.
        
        Args:
            log_file: Path to log file
            lines: Number of lines to read from end
            
        Returns:
            List of parsed events
        """
        events = []
        
        try:
            # Read last N lines efficiently
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Seek to end and read backwards
                f.seek(0, 2)  # Go to end
                file_size = f.tell()
                
                # Approximate line size and calculate starting position
                estimated_line_size = 150
                start_pos = max(0, file_size - (lines * estimated_line_size))
                f.seek(start_pos)
                
                # Skip partial first line
                if start_pos > 0:
                    f.readline()
                
                # Read remaining lines
                last_lines = f.readlines()
                
                # Parse last N lines
                for line in last_lines[-lines:]:
                    event = self.parse_line(line, log_file)
                    if event:
                        events.append(event)
        
        except Exception as e:
            logger.error(f"Error tailing log file {log_file}: {e}")
        
        return events

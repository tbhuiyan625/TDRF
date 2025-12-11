"""
Database management for TDRF.
Handles storage and retrieval of events, alerts, and scan results.
"""

import sqlite3
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from contextlib import contextmanager

from tdrf.core.logger import get_logger

logger = get_logger(__name__)


class Database:
    """SQLite database manager for TDRF."""
    
    def __init__(self, db_path: str = "data/tdrf.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    target_ip TEXT,
                    username TEXT,
                    port INTEGER,
                    service TEXT,
                    severity TEXT,
                    description TEXT,
                    raw_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    target_ip TEXT,
                    description TEXT NOT NULL,
                    correlation_id TEXT,
                    acknowledged BOOLEAN DEFAULT 0,
                    resolved BOOLEAN DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Scan results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    target_ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    service TEXT,
                    banner TEXT,
                    scan_type TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Failed login tracking table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS failed_logins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    username TEXT,
                    attempt_count INTEGER DEFAULT 1,
                    last_attempt TEXT NOT NULL,
                    window_start TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Correlation state table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS correlation_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    correlation_id TEXT UNIQUE NOT NULL,
                    rule_id TEXT NOT NULL,
                    event_ids TEXT,
                    timestamp TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                ON events(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_source_ip 
                ON events(source_ip)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
                ON alerts(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_results_target 
                ON scan_results(target_ip, port)
            """)
            
            logger.info(f"Database initialized at {self.db_path}")
    
    def add_event(self, event_type: str, timestamp: Optional[datetime] = None,
                  source_ip: Optional[str] = None, target_ip: Optional[str] = None,
                  username: Optional[str] = None, port: Optional[int] = None,
                  service: Optional[str] = None, severity: str = "INFO",
                  description: str = "", raw_data: Optional[Dict] = None) -> int:
        """
        Add an event to the database.
        
        Returns:
            Event ID
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events 
                (timestamp, event_type, source_ip, target_ip, username, port, 
                 service, severity, description, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp.isoformat(),
                event_type,
                source_ip,
                target_ip,
                username,
                port,
                service,
                severity,
                description,
                json.dumps(raw_data) if raw_data else None
            ))
            
            return cursor.lastrowid
    
    def add_alert(self, alert_type: str, severity: str, description: str,
                  timestamp: Optional[datetime] = None,
                  source_ip: Optional[str] = None, target_ip: Optional[str] = None,
                  correlation_id: Optional[str] = None) -> int:
        """
        Add an alert to the database.
        
        Returns:
            Alert ID
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts 
                (timestamp, alert_type, severity, source_ip, target_ip, 
                 description, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp.isoformat(),
                alert_type,
                severity,
                source_ip,
                target_ip,
                description,
                correlation_id
            ))
            
            return cursor.lastrowid
    
    def add_scan_result(self, target_ip: str, port: int, state: str,
                       service: Optional[str] = None, banner: Optional[str] = None,
                       scan_type: str = "tcp", timestamp: Optional[datetime] = None) -> int:
        """
        Add a scan result to the database.
        
        Returns:
            Scan result ID
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_results 
                (timestamp, target_ip, port, state, service, banner, scan_type)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp.isoformat(),
                target_ip,
                port,
                state,
                service,
                banner,
                scan_type
            ))
            
            return cursor.lastrowid
    
    def get_events(self, event_type: Optional[str] = None,
                   source_ip: Optional[str] = None,
                   since: Optional[datetime] = None,
                   limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve events from database.
        
        Args:
            event_type: Filter by event type
            source_ip: Filter by source IP
            since: Filter events since this timestamp
            limit: Maximum number of events to return
            
        Returns:
            List of event dictionaries
        """
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        
        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_alerts(self, severity: Optional[str] = None,
                   acknowledged: Optional[bool] = None,
                   since: Optional[datetime] = None,
                   limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve alerts from database.
        
        Returns:
            List of alert dictionaries
        """
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if acknowledged is not None:
            query += " AND acknowledged = ?"
            params.append(1 if acknowledged else 0)
        
        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_scan_results(self, target_ip: Optional[str] = None,
                        state: str = "open",
                        since: Optional[datetime] = None,
                        limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Retrieve scan results from database.
        
        Returns:
            List of scan result dictionaries
        """
        query = "SELECT * FROM scan_results WHERE 1=1"
        params = []
        
        if target_ip:
            query += " AND target_ip = ?"
            params.append(target_ip)
        
        if state:
            query += " AND state = ?"
            params.append(state)
        
        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def cleanup_old_data(self, retention_days: int = 30):
        """
        Remove data older than retention period.
        
        Args:
            retention_days: Number of days to retain data
        """
        cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_date,))
            events_deleted = cursor.rowcount
            
            cursor.execute("DELETE FROM alerts WHERE timestamp < ? AND resolved = 1", 
                         (cutoff_date,))
            alerts_deleted = cursor.rowcount
            
            cursor.execute("DELETE FROM scan_results WHERE timestamp < ?", 
                         (cutoff_date,))
            scans_deleted = cursor.rowcount
            
            logger.info(f"Cleaned up old data: {events_deleted} events, "
                       f"{alerts_deleted} alerts, {scans_deleted} scan results")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dictionary with statistics
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Total counts
            cursor.execute("SELECT COUNT(*) FROM events")
            stats['total_events'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts")
            stats['total_alerts'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scan_results")
            stats['total_scan_results'] = cursor.fetchone()[0]
            
            # Recent counts (last 24 hours)
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            
            cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", 
                         (yesterday,))
            stats['recent_events'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", 
                         (yesterday,))
            stats['recent_alerts'] = cursor.fetchone()[0]
            
            # Alert severity breakdown
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM alerts 
                WHERE timestamp >= ? 
                GROUP BY severity
            """, (yesterday,))
            stats['alert_severity'] = {row['severity']: row['count'] 
                                      for row in cursor.fetchall()}
            
            return stats


# Global database instance
_db_instance: Optional[Database] = None


def get_database(db_path: Optional[str] = None) -> Database:
    """
    Get or create global database instance.
    
    Args:
        db_path: Path to database file (only used on first call)
        
    Returns:
        Database instance
    """
    global _db_instance
    
    if _db_instance is None:
        if db_path is None:
            from tdrf.core.config import config
            db_path = config.database_path
        _db_instance = Database(db_path)
    
    return _db_instance

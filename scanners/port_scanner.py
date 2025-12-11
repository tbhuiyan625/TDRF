"""
Port scanner with async TCP connect scanning.
"""

import socket
import asyncio
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network

from tdrf.core.logger import get_logger
from tdrf.core.config import config
from tdrf.core.database import get_database

logger = get_logger(__name__)


class PortScanner:
    """Asynchronous TCP port scanner."""
    
    def __init__(self):
        """Initialize port scanner."""
        self.db = get_database()
        self.timeout = config.get('port_scanner.default_timeout', 2)
        self.max_concurrent = config.get('port_scanner.max_concurrent_connections', 100)
        self.enabled = config.get('port_scanner.enabled', True)
        
        # Scan results
        self.results: List[Dict[str, Any]] = []
    
    def _parse_port_spec(self, port_spec: str) -> List[int]:
        """
        Parse port specification string.
        
        Args:
            port_spec: Port specification (e.g., "80", "1-1000", "80,443,8080")
            
        Returns:
            List of port numbers
        """
        ports = []
        
        # Handle comma-separated ports
        if ',' in port_spec:
            for part in port_spec.split(','):
                ports.extend(self._parse_port_spec(part.strip()))
            return sorted(set(ports))
        
        # Handle range
        if '-' in port_spec:
            try:
                start, end = port_spec.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                
                if start_port < 1 or end_port > 65535:
                    logger.warning(f"Invalid port range: {port_spec}")
                    return []
                
                return list(range(start_port, end_port + 1))
            except ValueError:
                logger.error(f"Invalid port range format: {port_spec}")
                return []
        
        # Single port
        try:
            port = int(port_spec)
            if 1 <= port <= 65535:
                return [port]
            else:
                logger.warning(f"Port out of range: {port}")
                return []
        except ValueError:
            logger.error(f"Invalid port specification: {port_spec}")
            return []
    
    def _parse_targets(self, target_spec: str) -> List[str]:
        """
        Parse target specification.
        
        Args:
            target_spec: Target IP or CIDR (e.g., "192.168.1.1" or "192.168.1.0/24")
            
        Returns:
            List of IP addresses
        """
        targets = []
        
        # Check if CIDR notation
        if '/' in target_spec:
            try:
                network = ip_network(target_spec, strict=False)
                targets = [str(ip) for ip in network.hosts()]
                
                # Limit to reasonable size
                if len(targets) > 256:
                    logger.warning(f"Large network {target_spec}, limiting to first 256 hosts")
                    targets = targets[:256]
            except ValueError as e:
                logger.error(f"Invalid network specification: {target_spec} - {e}")
                return []
        else:
            # Single IP or hostname
            try:
                # Validate IP address
                ip_address(target_spec)
                targets = [target_spec]
            except ValueError:
                # Might be a hostname
                try:
                    resolved = socket.gethostbyname(target_spec)
                    targets = [resolved]
                    logger.info(f"Resolved {target_spec} to {resolved}")
                except socket.gaierror:
                    logger.error(f"Could not resolve hostname: {target_spec}")
                    return []
        
        return targets
    
    async def _scan_port(self, target: str, port: int, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Scan a single port on a target.
        
        Args:
            target: Target IP address
            port: Port number
            timeout: Connection timeout in seconds
            
        Returns:
            Scan result dictionary
        """
        if timeout is None:
            timeout = self.timeout
        
        result = {
            'target': target,
            'port': port,
            'state': 'closed',
            'timestamp': datetime.now()
        }
        
        try:
            # Attempt TCP connection
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            
            result['state'] = 'open'
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            result['state'] = 'filtered'
        except ConnectionRefusedError:
            result['state'] = 'closed'
        except OSError as e:
            result['state'] = 'error'
            result['error'] = str(e)
        except Exception as e:
            logger.debug(f"Error scanning {target}:{port} - {e}")
            result['state'] = 'error'
            result['error'] = str(e)
        
        return result
    
    async def _scan_target_ports(self, target: str, ports: List[int],
                                 timeout: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Scan multiple ports on a single target.
        
        Args:
            target: Target IP address
            ports: List of ports to scan
            timeout: Connection timeout
            
        Returns:
            List of scan results
        """
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_with_semaphore(port):
            async with semaphore:
                return await self._scan_port(target, port, timeout)
        
        # Scan all ports concurrently
        tasks = [scan_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        return results
    
    def scan(self, targets: str, ports: str, timeout: Optional[float] = None,
             store_results: bool = True) -> Dict[str, Any]:
        """
        Scan targets and ports.
        
        Args:
            targets: Target specification (IP, hostname, or CIDR)
            ports: Port specification (single, range, or comma-separated)
            timeout: Connection timeout in seconds
            store_results: Whether to store results in database
            
        Returns:
            Scan summary dictionary
        """
        if not self.enabled:
            logger.warning("Port scanner is disabled")
            return {'error': 'Port scanner disabled'}
        
        start_time = datetime.now()
        
        # Parse targets and ports
        target_list = self._parse_targets(targets)
        port_list = self._parse_port_spec(ports)
        
        if not target_list:
            return {'error': 'No valid targets specified'}
        
        if not port_list:
            return {'error': 'No valid ports specified'}
        
        logger.info(f"Scanning {len(target_list)} target(s) on {len(port_list)} port(s)")
        
        # Run scan
        all_results = []
        
        try:
            for target in target_list:
                logger.info(f"Scanning {target}...")
                results = asyncio.run(self._scan_target_ports(target, port_list, timeout))
                all_results.extend(results)
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {'error': str(e)}
        
        # Filter open ports
        open_ports = [r for r in all_results if r['state'] == 'open']
        
        # Store results
        if store_results:
            for result in all_results:
                try:
                    self.db.add_scan_result(
                        target_ip=result['target'],
                        port=result['port'],
                        state=result['state'],
                        timestamp=result['timestamp']
                    )
                except Exception as e:
                    logger.debug(f"Error storing scan result: {e}")
        
        # Build summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        summary = {
            'start_time': start_time,
            'end_time': end_time,
            'duration': duration,
            'targets_scanned': len(target_list),
            'ports_scanned': len(port_list),
            'total_scans': len(all_results),
            'open_ports': len(open_ports),
            'results': open_ports,
            'all_results': all_results
        }
        
        logger.info(f"Scan complete: {len(open_ports)} open ports found in {duration:.2f}s")
        
        self.results = all_results
        return summary
    
    def scan_profile(self, targets: str, profile: str = 'quick') -> Dict[str, Any]:
        """
        Scan using a predefined profile.
        
        Args:
            targets: Target specification
            profile: Profile name (quick, standard, full)
            
        Returns:
            Scan summary
        """
        profiles = config.get('port_scanner.profiles', {})
        
        if profile not in profiles:
            logger.warning(f"Profile '{profile}' not found, using quick scan")
            profile = 'quick'
        
        profile_config = profiles.get(profile, {})
        ports = profile_config.get('ports', '80,443')
        timeout = profile_config.get('timeout', self.timeout)
        
        logger.info(f"Running {profile} scan profile")
        return self.scan(targets, ports, timeout=timeout)
    
    def get_open_ports(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get open ports from database.
        
        Args:
            target: Filter by target IP (None = all)
            
        Returns:
            List of open ports
        """
        return self.db.get_scan_results(target_ip=target, state='open')
    
    def get_common_ports(self) -> List[int]:
        """Get list of commonly scanned ports."""
        return [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
        ]

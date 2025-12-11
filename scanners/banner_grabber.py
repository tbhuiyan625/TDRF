"""
Banner grabbing for service identification.
"""

import socket
import asyncio
import re
from typing import Dict, Optional, Any
from datetime import datetime

from tdrf.core.logger import get_logger
from tdrf.core.config import config

logger = get_logger(__name__)


class BannerGrabber:
    """Service banner grabbing for identification."""
    
    # Common service probes
    SERVICE_PROBES = {
        21: b'',  # FTP - server sends banner immediately
        22: b'',  # SSH - server sends banner immediately
        23: b'',  # Telnet - server sends banner immediately
        25: b'EHLO example.com\r\n',  # SMTP
        80: b'HEAD / HTTP/1.0\r\n\r\n',  # HTTP
        110: b'',  # POP3 - server sends banner immediately
        143: b'',  # IMAP - server sends banner immediately
        443: b'',  # HTTPS - requires TLS
        3306: b'',  # MySQL - server sends banner immediately
        5432: b'',  # PostgreSQL
        6379: b'PING\r\n',  # Redis
        8080: b'HEAD / HTTP/1.0\r\n\r\n',  # HTTP Alt
    }
    
    # Service identification patterns
    SERVICE_PATTERNS = {
        'ssh': re.compile(rb'SSH-[\d.]+-', re.IGNORECASE),
        'ftp': re.compile(rb'220.*FTP', re.IGNORECASE),
        'http': re.compile(rb'HTTP/[\d.]+', re.IGNORECASE),
        'smtp': re.compile(rb'220.*SMTP|220.*ESMTP', re.IGNORECASE),
        'pop3': re.compile(rb'\+OK.*POP3', re.IGNORECASE),
        'imap': re.compile(rb'\* OK.*IMAP', re.IGNORECASE),
        'mysql': re.compile(rb'[\x00-\xFF]*mysql', re.IGNORECASE),
        'postgresql': re.compile(rb'PostgreSQL', re.IGNORECASE),
        'redis': re.compile(rb'\+PONG', re.IGNORECASE),
        'telnet': re.compile(rb'telnet|login:', re.IGNORECASE),
    }
    
    def __init__(self):
        """Initialize banner grabber."""
        self.timeout = config.get('port_scanner.banner_grabbing.timeout', 3)
        self.max_banner_size = config.get('port_scanner.banner_grabbing.max_banner_size', 1024)
        self.enabled = config.get('port_scanner.banner_grabbing.enabled', True)
    
    async def grab_banner_async(self, target: str, port: int,
                               timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Asynchronously grab banner from a service.
        
        Args:
            target: Target IP address
            port: Port number
            timeout: Connection timeout
            
        Returns:
            Banner information dictionary
        """
        if timeout is None:
            timeout = self.timeout
        
        result = {
            'target': target,
            'port': port,
            'banner': None,
            'service': None,
            'timestamp': datetime.now()
        }
        
        try:
            # Open connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )
            
            # Send probe if available
            probe = self.SERVICE_PROBES.get(port, b'')
            if probe:
                writer.write(probe)
                await writer.drain()
            
            # Read banner
            banner_data = await asyncio.wait_for(
                reader.read(self.max_banner_size),
                timeout=timeout
            )
            
            # Clean banner
            banner = banner_data.decode('utf-8', errors='ignore').strip()
            result['banner'] = banner
            
            # Identify service
            result['service'] = self._identify_service(banner_data, port)
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            logger.debug(f"Banner grab timeout for {target}:{port}")
        except ConnectionRefusedError:
            logger.debug(f"Connection refused for {target}:{port}")
        except Exception as e:
            logger.debug(f"Error grabbing banner from {target}:{port} - {e}")
        
        return result
    
    def grab_banner(self, target: str, port: int,
                   timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Synchronously grab banner from a service.
        
        Args:
            target: Target IP address
            port: Port number
            timeout: Connection timeout
            
        Returns:
            Banner information dictionary
        """
        if not self.enabled:
            return {'error': 'Banner grabbing disabled'}
        
        return asyncio.run(self.grab_banner_async(target, port, timeout))
    
    async def grab_multiple_banners(self, targets_ports: list) -> list:
        """
        Grab banners from multiple targets/ports concurrently.
        
        Args:
            targets_ports: List of (target, port) tuples
            
        Returns:
            List of banner results
        """
        tasks = [
            self.grab_banner_async(target, port)
            for target, port in targets_ports
        ]
        
        results = await asyncio.gather(*tasks)
        return results
    
    def _identify_service(self, banner_data: bytes, port: int) -> Optional[str]:
        """
        Identify service from banner data.
        
        Args:
            banner_data: Raw banner data
            port: Port number
            
        Returns:
            Service name or None
        """
        # Try pattern matching
        for service_name, pattern in self.SERVICE_PATTERNS.items():
            if pattern.search(banner_data):
                return service_name
        
        # Fallback to common port mapping
        common_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            445: 'smb',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            6379: 'redis',
            8080: 'http-proxy',
            8443: 'https-alt',
        }
        
        return common_services.get(port, 'unknown')
    
    def get_service_info(self, service_name: str) -> Dict[str, Any]:
        """
        Get information about a service.
        
        Args:
            service_name: Name of service
            
        Returns:
            Service information dictionary
        """
        service_info = {
            'ssh': {
                'name': 'SSH (Secure Shell)',
                'description': 'Secure remote access protocol',
                'security_note': 'Generally secure if using key-based auth'
            },
            'ftp': {
                'name': 'FTP (File Transfer Protocol)',
                'description': 'File transfer protocol',
                'security_note': 'Unencrypted - use SFTP instead'
            },
            'telnet': {
                'name': 'Telnet',
                'description': 'Remote terminal protocol',
                'security_note': 'Highly insecure - credentials sent in cleartext'
            },
            'http': {
                'name': 'HTTP',
                'description': 'Web server protocol',
                'security_note': 'Unencrypted - use HTTPS when possible'
            },
            'https': {
                'name': 'HTTPS',
                'description': 'Secure web server protocol',
                'security_note': 'Encrypted HTTP, check certificate validity'
            },
            'smtp': {
                'name': 'SMTP (Simple Mail Transfer Protocol)',
                'description': 'Email transmission protocol',
                'security_note': 'Check if STARTTLS is supported'
            },
            'mysql': {
                'name': 'MySQL Database',
                'description': 'MySQL database server',
                'security_note': 'Should not be exposed to internet'
            },
            'postgresql': {
                'name': 'PostgreSQL Database',
                'description': 'PostgreSQL database server',
                'security_note': 'Should not be exposed to internet'
            },
            'redis': {
                'name': 'Redis',
                'description': 'In-memory data store',
                'security_note': 'Often misconfigured without authentication'
            },
            'rdp': {
                'name': 'RDP (Remote Desktop Protocol)',
                'description': 'Windows remote desktop',
                'security_note': 'Common brute-force target, use strong passwords'
            },
            'smb': {
                'name': 'SMB (Server Message Block)',
                'description': 'Windows file sharing protocol',
                'security_note': 'Common ransomware vector, keep patched'
            },
        }
        
        return service_info.get(service_name, {
            'name': service_name.upper(),
            'description': 'Unknown service',
            'security_note': 'Unable to determine security implications'
        })
    
    def check_suspicious_service(self, port: int, service: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Check if a service is considered suspicious.
        
        Args:
            port: Port number
            service: Service name (optional)
            
        Returns:
            Suspicious service info or None
        """
        suspicious_services = config.get_rule('suspicious_services', [])
        
        for svc in suspicious_services:
            if svc.get('port') == port:
                return {
                    'port': port,
                    'service': svc.get('service'),
                    'severity': svc.get('severity'),
                    'reason': svc.get('reason')
                }
        
        return None

"""
Network validation and utility functions.
"""

import socket
import ipaddress
from typing import Optional


def validate_ip(ip_str: str) -> bool:
    """
    Validate IP address.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    Validate port number.
    
    Args:
        port: Port number
        
    Returns:
        True if valid, False otherwise
    """
    return 1 <= port <= 65535


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address string or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is private.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if private, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

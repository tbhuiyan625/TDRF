"""
Input validation utilities.
"""

import re
from typing import Optional


def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR notation.
    
    Args:
        cidr: CIDR string (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid, False otherwise
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    return bool(re.match(pattern, cidr))


def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        input_str: Input string
        
    Returns:
        Sanitized string
    """
    # Remove potentially dangerous characters
    dangerous_chars = ['|', '&', ';', '$', '`', '\n', '\r']
    
    for char in dangerous_chars:
        input_str = input_str.replace(char, '')
    
    return input_str.strip()


def validate_path(path_str: str) -> bool:
    """
    Validate file path to prevent traversal attacks.
    
    Args:
        path_str: Path string
        
    Returns:
        True if safe, False otherwise
    """
    # Check for path traversal patterns
    dangerous_patterns = ['../', '..\\', '%2e%2e']
    
    path_lower = path_str.lower()
    for pattern in dangerous_patterns:
        if pattern in path_lower:
            return False
    
    return True

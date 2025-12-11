"""
Python Threat Detection/Response Framework (TDRF)

A comprehensive security tool for analyzing system logs, detecting threats,
scanning networks, and responding to security incidents.
"""

__version__ = "1.0.0"
__author__ = "TDRF Team"
__license__ = "MIT"

from tdrf.core.config import Config
from tdrf.core.logger import setup_logger

# Initialize default logger
logger = setup_logger()

__all__ = ["Config", "logger", "__version__"]

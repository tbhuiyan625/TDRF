"""
Core configuration management module.
Handles loading and accessing configuration from YAML files.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional


class Config:
    """Configuration manager for TDRF."""
    
    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}
    _rules: Dict[str, Any] = {}
    
    def __new__(cls):
        """Singleton pattern to ensure single config instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize configuration manager."""
        if not self._config:
            self.reload()
    
    def reload(self):
        """Reload configuration from files."""
        # Determine config directory
        config_dir = self._get_config_dir()
        
        # Load main configuration
        config_path = config_dir / "config.yaml"
        if config_path.exists():
            with open(config_path, 'r') as f:
                self._config = yaml.safe_load(f) or {}
        else:
            self._config = self._get_default_config()
        
        # Load rules configuration
        rules_path = config_dir / "rules.yaml"
        if rules_path.exists():
            with open(rules_path, 'r') as f:
                self._rules = yaml.safe_load(f) or {}
        else:
            self._rules = {}
    
    def _get_config_dir(self) -> Path:
        """Get configuration directory path."""
        # Try to find config directory relative to this file
        current_file = Path(__file__)
        project_root = current_file.parent.parent.parent
        config_dir = project_root / "config"
        
        if not config_dir.exists():
            config_dir.mkdir(parents=True, exist_ok=True)
        
        return config_dir
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'general': {
                'app_name': 'TDRF',
                'version': '1.0.0',
                'debug': False,
                'log_level': 'INFO'
            },
            'database': {
                'path': 'data/tdrf.db',
                'retention_days': 30
            },
            'log_analysis': {
                'enabled': True,
                'scan_interval': 60,
                'brute_force': {
                    'failed_login_threshold': 5,
                    'time_window_seconds': 300
                }
            },
            'port_scanner': {
                'enabled': True,
                'default_timeout': 2,
                'max_concurrent_connections': 100
            },
            'correlation': {
                'enabled': True,
                'time_windows': {
                    'short': 300,
                    'medium': 1800,
                    'long': 3600
                }
            },
            'alerts': {
                'enabled': True,
                'console': True,
                'file': True
            },
            'reporting': {
                'enabled': True,
                'output_dir': 'reports'
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key.
        
        Args:
            key: Configuration key in dot notation (e.g., 'general.debug')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_rule(self, key: str, default: Any = None) -> Any:
        """
        Get rule configuration value by dot-notation key.
        
        Args:
            key: Rule key in dot notation
            default: Default value if key not found
            
        Returns:
            Rule value or default
        """
        keys = key.split('.')
        value = self._rules
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration."""
        return self._config.copy()
    
    def get_all_rules(self) -> Dict[str, Any]:
        """Get all rules configuration."""
        return self._rules.copy()
    
    @property
    def debug(self) -> bool:
        """Check if debug mode is enabled."""
        return self.get('general.debug', False)
    
    @property
    def log_level(self) -> str:
        """Get logging level."""
        return self.get('general.log_level', 'INFO')
    
    @property
    def database_path(self) -> str:
        """Get database path."""
        return self.get('database.path', 'data/tdrf.db')
    
    @property
    def log_analysis_enabled(self) -> bool:
        """Check if log analysis is enabled."""
        return self.get('log_analysis.enabled', True)
    
    @property
    def port_scanner_enabled(self) -> bool:
        """Check if port scanner is enabled."""
        return self.get('port_scanner.enabled', True)
    
    @property
    def correlation_enabled(self) -> bool:
        """Check if event correlation is enabled."""
        return self.get('correlation.enabled', True)


# Global config instance
config = Config()

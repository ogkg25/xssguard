"""
Configuration management for XSSGuard
"""

import copy
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class Config:
    """Configuration manager for XSSGuard framework."""
    
    DEFAULT_CONFIG = {
        "global": {
            "output_format": "console",
            "verbosity": "normal",
            "color": True
        },
        "whitebox": {
            "extensions": [".js", ".jsx", ".ts", ".tsx", ".py", ".html", ".vue", ".php"],
            "exclude_dirs": ["node_modules", "__pycache__", ".git", "vendor", "dist", "build"],
            "min_severity": "medium",
            "frameworks": {
                "react": True,
                "vue": True,
                "angular": True
            }
        },
        "blackbox": {
            "timeout": 10,
            "max_redirects": 5,
            "verify_ssl": True,
            "crawl": {
                "enabled": True,
                "max_depth": 3,
                "max_pages": 100,
                "same_domain_only": True
            },
            "verification": {
                "headless": False,
                "browser": "chromium",
                "wait_time": 2000
            }
        },
        "sanitizer": {
            "policy": {
                "tags": [
                    "b",
                    "i",
                    "u",
                    "em",
                    "strong",
                    "p",
                    "br",
                    "ul",
                    "ol",
                    "li",
                    "a",
                    "code",
                    "pre"
                ],
                "attributes": {
                    "a": ["href", "title", "rel", "target"]
                },
                "protocols": ["http", "https", "mailto"],
                "strip": True,
                "strip_comments": True
            }
        }
    }
    
    def __init__(self, config_file: Optional[str] = None, data: Optional[Dict] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Optional path to YAML configuration file
        """
        self.config = copy.deepcopy(self.DEFAULT_CONFIG)

        if data:
            self._merge_config(self.config, data)
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)

    @classmethod
    def load(cls, config_file: Optional[str] = None) -> "Config":
        """Load configuration from file or default locations."""
        resolved = config_file or os.environ.get("XSSGUARD_CONFIG")
        if not resolved:
            default_path = Path.cwd() / "xssguard.yaml"
            if default_path.exists():
                resolved = str(default_path)
        return cls(config_file=resolved)
    
    def load_from_file(self, config_file: str):
        """Load configuration from YAML file."""
        with open(config_file, 'r') as f:
            user_config = yaml.safe_load(f)
            self._merge_config(self.config, user_config)
    
    def _merge_config(self, base: Dict, override: Dict):
        """Recursively merge configuration dictionaries."""
        if not override:
            return
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default=None):
        """Get configuration value by dot-notation key."""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default

    def get_section(self, key: str) -> Dict[str, Any]:
        """Return a dictionary for a configuration section."""
        value = self.get(key, {})
        return value if isinstance(value, dict) else {}

    def set(self, key: str, value: Any) -> None:
        """Set configuration value by dot-notation key."""
        keys = key.split('.')
        data = self.config
        for k in keys[:-1]:
            if k not in data or not isinstance(data[k], dict):
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value

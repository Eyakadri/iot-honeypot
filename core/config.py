#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration module for the Advanced IoT Honeypot.
Handles loading and validation of configuration settings.
"""

import os
import json
import logging
import ipaddress
from typing import Dict, Any, List, Optional, Union

# Default configuration
DEFAULT_CONFIG = {
    "general": {
        "log_level": "INFO",
        "log_dir": "/var/log/advanced_honeypot",
        "data_dir": "/var/lib/advanced_honeypot",
        "pid_file": "/var/run/advanced_honeypot.pid",
    },
    "network": {
        "bind_ip": "0.0.0.0",
        "telnet_port": 2323,
        "ssh_port": 2222,
        "http_port": 8080,
        "https_port": 8443,
        "mqtt_port": 1883,
    },
    "protocols": {
        "telnet": {
            "enabled": True,
            "max_connections": 50,
            "timeout": 300,
            "banner": "Welcome to IoT Device Management Console",
        },
        "ssh": {
            "enabled": True,
            "max_connections": 50,
            "timeout": 300,
            "server_version": "SSH-2.0-OpenSSH_7.2p2",
            "keys_dir": "/etc/advanced_honeypot/ssh_keys",
        },
        "http": {
            "enabled": True,
            "max_connections": 100,
            "timeout": 300,
            "server_header": "nginx/1.14.0",
        },
        "https": {
            "enabled": True,
            "max_connections": 100,
            "timeout": 300,
            "cert_file": "/etc/advanced_honeypot/ssl/cert.pem",
            "key_file": "/etc/advanced_honeypot/ssl/key.pem",
        },
        "mqtt": {
            "enabled": False,
            "max_connections": 50,
            "timeout": 300,
        },
    },
    "devices": {
        "ip_camera": {
            "enabled": True,
            "brand": "Generic",
            "model": "IP-CAM-2000",
            "firmware": "v2.4.6",
        },
        "router": {
            "enabled": True,
            "brand": "NetLink",
            "model": "WR-3000",
            "firmware": "v1.2.8",
        },
        "dvr": {
            "enabled": True,
            "brand": "SecureView",
            "model": "DVR-8CH",
            "firmware": "v3.1.0",
        },
    },
    "database": {
        "type": "elasticsearch",
        "host": "localhost",
        "port": 9200,
        "index_prefix": "honeypot",
        "username": "",
        "password": "",
    },
    "malware": {
        "capture_dir": "/var/lib/advanced_honeypot/malware",
        "max_size": 10485760,  # 10MB
        "sandbox_enabled": False,
    },
    "visualization": {
        "enabled": True,
        "web_port": 8000,
        "web_host": "localhost",
    },
}


class Config:
    """Configuration handler for the Advanced IoT Honeypot."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration handler.
        
        Args:
            config_path: Path to the configuration file. If None, uses default config.
        """
        self.logger = logging.getLogger("honeypot.config")
        self.config = DEFAULT_CONFIG.copy()
        
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
        
        self._validate_config()
        self._setup_directories()
    
    def _load_config(self, config_path: str) -> None:
        """
        Load configuration from a JSON file.
        
        Args:
            config_path: Path to the configuration file.
        """
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
            
            # Merge user config with default config
            self._merge_configs(self.config, user_config)
            self.logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to load configuration from {config_path}: {e}")
            self.logger.warning("Using default configuration")
    
    def _merge_configs(self, default_config: Dict[str, Any], user_config: Dict[str, Any]) -> None:
        """
        Recursively merge user configuration into default configuration.
        
        Args:
            default_config: Default configuration dictionary.
            user_config: User configuration dictionary.
        """
        for key, value in user_config.items():
            if key in default_config:
                if isinstance(value, dict) and isinstance(default_config[key], dict):
                    self._merge_configs(default_config[key], value)
                else:
                    default_config[key] = value
            else:
                default_config[key] = value
    
    def _validate_config(self) -> None:
        """Validate the configuration settings."""
        # Validate network settings
        try:
            ipaddress.ip_address(self.config["network"]["bind_ip"])
        except ValueError:
            self.logger.warning(f"Invalid bind_ip: {self.config['network']['bind_ip']}, using 0.0.0.0")
            self.config["network"]["bind_ip"] = "0.0.0.0"
        
        # Validate ports
        for protocol in ["telnet", "ssh", "http", "https", "mqtt"]:
            port_key = f"{protocol}_port"
            if port_key in self.config["network"]:
                port = self.config["network"][port_key]
                if not isinstance(port, int) or port < 1 or port > 65535:
                    self.logger.warning(f"Invalid {port_key}: {port}, using default")
                    self.config["network"][port_key] = DEFAULT_CONFIG["network"][port_key]
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.config["general"]["log_level"] not in valid_log_levels:
            self.logger.warning(f"Invalid log_level: {self.config['general']['log_level']}, using INFO")
            self.config["general"]["log_level"] = "INFO"
    
    def _setup_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        directories = [
            self.config["general"]["log_dir"],
            self.config["general"]["data_dir"],
            self.config["malware"]["capture_dir"],
        ]
        
        for directory in directories:
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory, exist_ok=True)
                    self.logger.info(f"Created directory: {directory}")
                except Exception as e:
                    self.logger.error(f"Failed to create directory {directory}: {e}")
    
    def get(self, section: str, key: Optional[str] = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            section: Configuration section.
            key: Configuration key within the section. If None, returns the entire section.
            
        Returns:
            Configuration value or section.
        """
        if section not in self.config:
            return None
        
        if key is None:
            return self.config[section]
        
        if key not in self.config[section]:
            return None
        
        return self.config[section][key]
    
    def get_protocol_config(self, protocol: str) -> Dict[str, Any]:
        """
        Get configuration for a specific protocol.
        
        Args:
            protocol: Protocol name (telnet, ssh, http, etc.).
            
        Returns:
            Protocol configuration dictionary.
        """
        return self.config["protocols"].get(protocol, {})
    
    def get_device_config(self, device_type: str) -> Dict[str, Any]:
        """
        Get configuration for a specific device type.
        
        Args:
            device_type: Device type (ip_camera, router, dvr, etc.).
            
        Returns:
            Device configuration dictionary.
        """
        return self.config["devices"].get(device_type, {})
    
    def is_protocol_enabled(self, protocol: str) -> bool:
        """
        Check if a protocol is enabled.
        
        Args:
            protocol: Protocol name.
            
        Returns:
            True if the protocol is enabled, False otherwise.
        """
        protocol_config = self.get_protocol_config(protocol)
        return protocol_config.get("enabled", False)
    
    def is_device_enabled(self, device_type: str) -> bool:
        """
        Check if a device type is enabled.
        
        Args:
            device_type: Device type.
            
        Returns:
            True if the device type is enabled, False otherwise.
        """
        device_config = self.get_device_config(device_type)
        return device_config.get("enabled", False)
    
    def get_enabled_protocols(self) -> List[str]:
        """
        Get a list of enabled protocols.
        
        Returns:
            List of enabled protocol names.
        """
        return [p for p in self.config["protocols"] if self.is_protocol_enabled(p)]
    
    def get_enabled_devices(self) -> List[str]:
        """
        Get a list of enabled device types.
        
        Returns:
            List of enabled device type names.
        """
        return [d for d in self.config["devices"] if self.is_device_enabled(d)]


# Singleton instance
_config_instance = None


def get_config(config_path: Optional[str] = None) -> Config:
    """
    Get the configuration instance.
    
    Args:
        config_path: Path to the configuration file.
        
    Returns:
        Configuration instance.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
    return _config_instance

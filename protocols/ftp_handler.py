#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FTP protocol handler for the Advanced IoT Honeypot.
Implements a realistic FTP server emulating IoT device file systems.
"""

import os
import socket
import threading
import time
import datetime
from typing import Dict, Any, Optional, List, Tuple, Union, Callable
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import ThreadedFTPServer

from .base_protocol import BaseProtocolHandler
from core.logger import get_logger
from core.config import get_config

class CustomFTPHandler(FTPHandler):
    """Custom FTP handler with enhanced logging and vulnerability simulation."""
    
    def __init__(self, *args, **kwargs):
        self.honeypot_handler = kwargs.pop('honeypot_handler', None)
        super().__init__(*args, **kwargs)
    
    def on_connect(self):
        """Called when client connects."""
        super().on_connect()
        if self.honeypot_handler:
            client_address = self.addr
            self.honeypot_handler.logger.info(
                f"FTP connection from {client_address[0]}:{client_address[1]}",
                src_ip=client_address[0],
                src_port=client_address[1],
                protocol="ftp"
            )
    
    def on_disconnect(self):
        """Called when client disconnects."""
        super().on_disconnect()
        if self.honeypot_handler:
            client_address = self.addr
            self.honeypot_handler.logger.info(
                f"FTP disconnection from {client_address[0]}:{client_address[1]}",
                src_ip=client_address[0],
                src_port=client_address[1],
                protocol="ftp"
            )
    
    def on_login(self, username):
        """Called when user logs in."""
        super().on_login(username)
        if self.honeypot_handler:
            client_address = self.addr
            self.honeypot_handler.logger.log_login_attempt(
                src_ip=client_address[0],
                username=username,
                password="<hidden>",  # Password already verified by authorizer
                success=True,
                protocol="ftp"
            )
    
    def on_login_failed(self, username, password):
        """Called when login fails."""
        super().on_login_failed(username, password)
        if self.honeypot_handler:
            client_address = self.addr
            self.honeypot_handler.logger.log_login_attempt(
                src_ip=client_address[0],
                username=username,
                password=password,
                success=False,
                protocol="ftp"
            )
    
    def on_file_sent(self, file):
        """Called when a file has been sent."""
        super().on_file_sent(file)
        if self.honeypot_handler:
            client_address = self.addr
            self.honeypot_handler.logger.info(
                f"FTP file download: {file} by {client_address[0]}",
                src_ip=client_address[0],
                file=file,
                username=self.username,
                protocol="ftp",
                event_type="file_download"
            )
    
    def on_file_received(self, file):
        """Called when a file has been received."""
        super().on_file_received(file)
        if self.honeypot_handler:
            client_address = self.addr
            self.honeypot_handler.logger.info(
                f"FTP file upload: {file} by {client_address[0]}",
                src_ip=client_address[0],
                file=file,
                username=self.username,
                protocol="ftp",
                event_type="file_upload"
            )
            
            # Check for malware
            self.honeypot_handler._check_uploaded_file(file, client_address[0])
    
    def ftp_RETR(self, path):
        """Handle file download with vulnerability simulation."""
        if self.honeypot_handler and self.honeypot_handler._check_path_traversal(path, self.addr[0]):
            # Path traversal vulnerability detected, but still allow the command
            # to see what files the attacker is trying to access
            pass
        return super().ftp_RETR(path)
    
    def ftp_STOR(self, path):
        """Handle file upload with vulnerability simulation."""
        if self.honeypot_handler and self.honeypot_handler._check_path_traversal(path, self.addr[0]):
            # Path traversal vulnerability detected, but still allow the command
            # to capture potential malware
            pass
        return super().ftp_STOR(path)
    
    def ftp_SITE(self, line):
        """Handle SITE command with vulnerability simulation."""
        if self.honeypot_handler:
            client_address = self.addr
            self.honeypot_handler.logger.info(
                f"FTP SITE command: {line} from {client_address[0]}",
                src_ip=client_address[0],
                command=f"SITE {line}",
                username=self.username,
                protocol="ftp"
            )
            
            # Check for command injection
            if self.honeypot_handler._check_command_injection(line, client_address[0]):
                # Command injection vulnerability detected
                # In a real vulnerable system, this might execute the command
                # Here we'll just pretend it worked
                self.respond('200 SITE command executed.')
                return
        
        return super().ftp_SITE(line)

class FTPHandler(BaseProtocolHandler):
    """FTP protocol handler for IoT device file system emulation."""

    def __init__(self):
        """Initialize the FTP protocol handler."""
        super().__init__("ftp")
        
        # Load device profiles
        self.device_profiles = {}
        self._load_device_profiles()
        
        # FTP server settings
        self.banner = self.protocol_config.get("banner", "FTP Server Ready")
        self.max_connections = self.protocol_config.get("max_connections", 10)
        self.timeout = self.protocol_config.get("timeout", 300)
        
        # FTP server instance
        self.server = None
        self.authorizer = None
        
        # Virtual file systems for each device type
        self.virtual_filesystems = {}
        self._setup_virtual_filesystems()
        
        # Vulnerabilities
        self.vulnerabilities = self._get_vulnerabilities()

    def _load_device_profiles(self) -> None:
        """Load device profiles from configuration."""
        config = get_config()
        
        # Get enabled device types
        enabled_devices = config.get_enabled_devices()
        
        for device_type in enabled_devices:
            device_config = config.get_device_config(device_type)
            
            if not device_config:
                continue
            
            # Create device profile
            profile = {
                "type": device_type,
                "brand": device_config.get("brand", "Generic"),
                "model": device_config.get("model", "Unknown"),
                "firmware": device_config.get("firmware", "1.0.0"),
                "ftp_username": device_config.get("ftp_username", "admin"),
                "ftp_password": device_config.get("ftp_password", "admin"),
                "anonymous": device_config.get("ftp_anonymous", False),
            }
            
            self.device_profiles[device_type] = profile
            self.logger.info(f"Loaded FTP device profile: {device_type} ({profile['brand']} {profile['model']})")

    def _setup_virtual_filesystems(self) -> None:
        """Set up virtual file systems for each device type."""
        base_dir = "/home/ubuntu/advanced_honeypot/virtual_fs"
        os.makedirs(base_dir, exist_ok=True)
        
        for device_type, profile in self.device_profiles.items():
            device_dir = os.path.join(base_dir, device_type)
            os.makedirs(device_dir, exist_ok=True)
            
            # Create basic directory structure
            for subdir in ["etc", "var", "tmp", "home", "mnt"]:
                os.makedirs(os.path.join(device_dir, subdir), exist_ok=True)
            
            # Create device-specific files
            if device_type == "ip_camera":
                self._create_camera_files(device_dir, profile)
            elif device_type == "router":
                self._create_router_files(device_dir, profile)
            elif device_type == "dvr":
                self._create_dvr_files(device_dir, profile)
            
            # Store virtual filesystem path
            self.virtual_filesystems[device_type] = device_dir

    def _create_camera_files(self, base_dir: str, profile: Dict[str, Any]) -> None:
        """Create files for IP camera virtual filesystem."""
        # Create config file
        config_dir = os.path.join(base_dir, "etc")
        with open(os.path.join(config_dir, "camera.conf"), "w") as f:
            f.write(f"""# Camera Configuration
brand={profile['brand']}
model={profile['model']}
firmware={profile['firmware']}
resolution=1080p
framerate=30
motion_detection=enabled
recording=continuous
""")
        
        # Create password file (with fake hashed passwords)
        with open(os.path.join(config_dir, "passwd"), "w") as f:
            f.write(f"""admin:x:1000:1000:Administrator:/home/admin:/bin/sh
user:x:1001:1001:Regular User:/home/user:/bin/sh
""")
        
        # Create log file
        log_dir = os.path.join(base_dir, "var", "log")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "camera.log"), "w") as f:
            f.write(f"""2025-05-20 08:00:00 System booted
2025-05-20 08:00:05 Camera service started
2025-05-20 08:01:00 Motion detection enabled
2025-05-20 09:15:22 Motion detected: Zone 1
2025-05-20 10:30:45 Recording started
2025-05-20 12:45:30 Firmware update available: v{float(profile['firmware'])+0.1:.1f}
""")
        
        # Create sample images directory
        images_dir = os.path.join(base_dir, "mnt", "sdcard", "images")
        os.makedirs(images_dir, exist_ok=True)
        
        # Create placeholder image files
        for i in range(1, 4):
            with open(os.path.join(images_dir, f"snapshot_{i}.jpg"), "w") as f:
                f.write(f"PLACEHOLDER IMAGE {i}")

    def _create_router_files(self, base_dir: str, profile: Dict[str, Any]) -> None:
        """Create files for router virtual filesystem."""
        # Create config file
        config_dir = os.path.join(base_dir, "etc")
        with open(os.path.join(config_dir, "router.conf"), "w") as f:
            f.write(f"""# Router Configuration
brand={profile['brand']}
model={profile['model']}
firmware={profile['firmware']}
wan_type=dhcp
lan_ip=192.168.1.1
lan_netmask=255.255.255.0
dhcp_enabled=true
dhcp_start=192.168.1.100
dhcp_end=192.168.1.200
wireless_enabled=true
wireless_ssid=Router_SSID
wireless_channel=6
wireless_security=WPA2-PSK
wireless_password=password123
""")
        
        # Create password file (with fake hashed passwords)
        with open(os.path.join(config_dir, "passwd"), "w") as f:
            f.write(f"""admin:x:1000:1000:Administrator:/home/admin:/bin/sh
user:x:1001:1001:Regular User:/home/user:/bin/sh
""")
        
        # Create log file
        log_dir = os.path.join(base_dir, "var", "log")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "router.log"), "w") as f:
            f.write(f"""2025-05-20 08:00:00 System booted
2025-05-20 08:00:05 WAN interface up, IP: 203.0.113.45
2025-05-20 08:00:10 LAN interface up, IP: 192.168.1.1
2025-05-20 08:00:15 Wireless interface up, SSID: Router_SSID
2025-05-20 08:01:00 DHCP server started
2025-05-20 09:15:22 DHCP request from 00:11:22:33:44:55, assigned 192.168.1.100
2025-05-20 10:30:45 DNS request for example.com from 192.168.1.100
2025-05-20 12:45:30 Firmware update available: v{float(profile['firmware'])+0.1:.1f}
""")
        
        # Create backup directory
        backup_dir = os.path.join(base_dir, "mnt", "backup")
        os.makedirs(backup_dir, exist_ok=True)
        
        # Create backup file
        with open(os.path.join(backup_dir, "router_backup.bin"), "w") as f:
            f.write("PLACEHOLDER ROUTER BACKUP FILE")

    def _create_dvr_files(self, base_dir: str, profile: Dict[str, Any]) -> None:
        """Create files for DVR virtual filesystem."""
        # Create config file
        config_dir = os.path.join(base_dir, "etc")
        with open(os.path.join(config_dir, "dvr.conf"), "w") as f:
            f.write(f"""# DVR Configuration
brand={profile['brand']}
model={profile['model']}
firmware={profile['firmware']}
channels=8
resolution=1080p
framerate=30
recording_mode=continuous
motion_detection=enabled
storage_device=/dev/sda1
storage_capacity=2TB
""")
        
        # Create password file (with fake hashed passwords)
        with open(os.path.join(config_dir, "passwd"), "w") as f:
            f.write(f"""admin:x:1000:1000:Administrator:/home/admin:/bin/sh
user:x:1001:1001:Regular User:/home/user:/bin/sh
""")
        
        # Create log file
        log_dir = os.path.join(base_dir, "var", "log")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "dvr.log"), "w") as f:
            f.write(f"""2025-05-20 08:00:00 System booted
2025-05-20 08:00:05 DVR service started
2025-05-20 08:00:10 Storage mounted: /dev/sda1
2025-05-20 08:01:00 Recording started on channels 1-8
2025-05-20 09:15:22 Motion detected: Channel 2
2025-05-20 10:30:45 Storage usage: 68%
2025-05-20 12:45:30 Firmware update available: v{float(profile['firmware'])+0.1:.1f}
""")
        
        # Create recordings directory
        recordings_dir = os.path.join(base_dir, "mnt", "hdd1", "recordings")
        os.makedirs(recordings_dir, exist_ok=True)
        
        # Create placeholder recording files
        for i in range(1, 4):
            with open(os.path.join(recordings_dir, f"channel1_recording_{i}.mp4"), "w") as f:
                f.write(f"PLACEHOLDER RECORDING {i}")

    def _get_vulnerabilities(self) -> Dict[str, Dict[str, Any]]:
        """
        Get vulnerabilities for the FTP server.
        
        Returns:
            Dictionary of vulnerability_id -> vulnerability info
        """
        return {
            "anonymous_access": {
                "type": "authentication",
                "description": "FTP server allows anonymous access",
                "enabled": True,
            },
            "default_credentials": {
                "type": "authentication",
                "description": "FTP server uses default credentials",
                "enabled": True,
            },
            "path_traversal": {
                "type": "injection",
                "description": "Path traversal vulnerability in FTP commands",
                "enabled": True,
            },
            "command_injection": {
                "type": "injection",
                "description": "Command injection vulnerability in SITE command",
                "enabled": True,
            },
            "clear_text": {
                "type": "encryption",
                "description": "Credentials and data transmitted in clear text",
                "enabled": True,
            },
        }

    def start(self) -> None:
        """Start the FTP server."""
        # Create authorizer
        self.authorizer = DummyAuthorizer()
        
        # Add users for each device profile
        for device_type, profile in self.device_profiles.items():
            # Add user with write permissions
            self.authorizer.add_user(
                profile["ftp_username"],
                profile["ftp_password"],
                self.virtual_filesystems[device_type],
                perm="elradfmwMT"  # Full permissions
            )
            
            # Add anonymous user if enabled
            if profile["anonymous"] or self.vulnerabilities["anonymous_access"]["enabled"]:
                self.authorizer.add_anonymous(
                    self.virtual_filesystems[device_type],
                    perm="elr"  # Read-only permissions
                )
        
        # Create handler
        handler = CustomFTPHandler
        handler.authorizer = self.authorizer
        handler.banner = self.banner
        handler.honeypot_handler = self
        
        # Create server
        self.server = ThreadedFTPServer((self.bind_ip, self.port), handler)
        self.server.max_cons = self.max_connections
        self.server.max_cons_per_ip = 5
        
        # Start server in a separate thread
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        self.logger.info(f"FTP server started on {self.bind_ip}:{self.port}")

    def stop(self) -> None:
        """Stop the FTP server."""
        if self.server:
            self.server.close_all()
            self.logger.info("FTP server stopped")

    def _check_path_traversal(self, path: str, client_ip: str) -> bool:
        """
        Check for path traversal attempts.
        
        Args:
            path: Requested path
            client_ip: Client IP address
            
        Returns:
            True if path traversal detected, False otherwise
        """
        if not self.vulnerabilities["path_traversal"]["enabled"]:
            return False
        
        # Check for path traversal patterns
        traversal_patterns = ["../", "..\\", "%2e%2e/", "%2e%2e\\"]
        if any(pattern in path for pattern in traversal_patterns):
            self.logger.warning(
                f"Path traversal attempt detected: {path} from {client_ip}",
                src_ip=client_ip,
                path=path,
                protocol="ftp",
                event_type="path_traversal"
            )
            return True
        
        return False

    def _check_command_injection(self, command: str, client_ip: str) -> bool:
        """
        Check for command injection attempts.
        
        Args:
            command: SITE command
            client_ip: Client IP address
            
        Returns:
            True if command injection detected, False otherwise
        """
        if not self.vulnerabilities["command_injection"]["enabled"]:
            return False
        
        # Check for command injection patterns
        injection_patterns = [";", "|", "`", "$", "(", ")", "&", "&&", "||"]
        if any(pattern in command for pattern in injection_patterns):
            self.logger.warning(
                f"Command injection attempt detected: {command} from {client_ip}",
                src_ip=client_ip,
                command=command,
                protocol="ftp",
                event_type="command_injection"
            )
            return True
        
        return False

    def _check_uploaded_file(self, file_path: str, client_ip: str) -> None:
        """
        Check uploaded file for potential malware.
        
        Args:
            file_path: Path to uploaded file
            client_ip: Client IP address
        """
        try:
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Log file details
            self.logger.info(
                f"Analyzing uploaded file: {file_path} ({file_size} bytes) from {client_ip}",
                src_ip=client_ip,
                file=file_path,
                file_size=file_size,
                file_ext=file_ext,
                protocol="ftp",
                event_type="file_analysis"
            )
            
            # Check file type
            suspicious = False
            reason = []
            
            # Check for executable files
            if file_ext in [".exe", ".dll", ".so", ".bin", ".sh", ".py", ".pl", ".php"]:
                suspicious = True
                reason.append(f"Suspicious file extension: {file_ext}")
            
            # Check file content (simple check)
            with open(file_path, "rb") as f:
                content = f.read(4096)  # Read first 4KB
                
                # Check for shell scripts
                if content.startswith(b"#!/bin/") or content.startswith(b"#!/usr/bin/"):
                    suspicious = True
                    reason.append("File contains shell script header")
                
                # Check for ELF header (Linux executables)
                if content.startswith(b"\x7fELF"):
                    suspicious = True
                    reason.append("File is an ELF executable")
                
                # Check for PE header (Windows executables)
                if b"MZ" in content[:2] and b"PE\0\0" in content:
                    suspicious = True
                    reason.append("File is a PE executable")
            
            if suspicious:
                # Log suspicious file
                self.logger.warning(
                    f"Suspicious file uploaded: {file_path} from {client_ip}. Reasons: {', '.join(reason)}",
                    src_ip=client_ip,
                    file=file_path,
                    reasons=reason,
                    protocol="ftp",
                    event_type="suspicious_file"
                )
                
                # Copy file to malware directory for further analysis
                malware_dir = "/home/ubuntu/advanced_honeypot/malware"
                os.makedirs(malware_dir, exist_ok=True)
                
                # Create a unique filename
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                malware_file = os.path.join(
                    malware_dir,
                    f"{timestamp}_{os.path.basename(file_path)}"
                )
                
                # Copy file
                import shutil
                shutil.copy2(file_path, malware_file)
                
                self.logger.info(
                    f"Copied suspicious file to malware directory: {malware_file}",
                    src_ip=client_ip,
                    original_file=file_path,
                    malware_file=malware_file,
                    protocol="ftp",
                    event_type="malware_capture"
                )
        
        except Exception as e:
            self.logger.error(
                f"Error analyzing uploaded file {file_path}: {e}",
                error=str(e),
                file=file_path,
                protocol="ftp"
            )

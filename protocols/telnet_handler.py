#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telnet protocol handler for the Advanced IoT Honeypot.
Implements a realistic Telnet server emulating IoT devices.
"""

import re
import time
import socket
import threading
from typing import Dict, Any, Optional, List, Tuple

from advanced_honeypot.protocols.base_protocol import BaseProtocolHandler
from advanced_honeypot.core.logger import get_logger
from advanced_honeypot.core.config import get_config


class TelnetHandler(BaseProtocolHandler):
    """Telnet protocol handler for IoT device emulation."""

    # Telnet protocol constants
    IAC = bytes([255])  # Interpret As Command
    DONT = bytes([254])
    DO = bytes([253])
    WONT = bytes([252])
    WILL = bytes([251])
    SB = bytes([250])  # Subnegotiation Begin
    SE = bytes([240])  # Subnegotiation End
    
    # Telnet options
    OPT_ECHO = bytes([1])
    OPT_SGA = bytes([3])  # Suppress Go Ahead
    OPT_TTYPE = bytes([24])  # Terminal Type
    OPT_NAWS = bytes([31])  # Negotiate About Window Size
    OPT_TSPEED = bytes([32])  # Terminal Speed
    OPT_LFLOW = bytes([33])  # Remote Flow Control
    OPT_LINEMODE = bytes([34])  # Linemode
    OPT_NEW_ENVIRON = bytes([39])  # New Environment
    
    def __init__(self):
        """Initialize the Telnet protocol handler."""
        super().__init__("telnet")
        
        # Load device profiles
        self.device_profiles = {}
        self._load_device_profiles()
        
        # Authentication settings
        self.auth_attempts = {}  # session_id -> count
        self.max_auth_attempts = 3
        
        # Command handlers
        self.command_handlers = {
            "help": self._handle_help,
            "ls": self._handle_ls,
            "cd": self._handle_cd,
            "cat": self._handle_cat,
            "echo": self._handle_echo,
            "ps": self._handle_ps,
            "wget": self._handle_wget,
            "curl": self._handle_curl,
            "uname": self._handle_uname,
            "id": self._handle_id,
            "passwd": self._handle_passwd,
            "reboot": self._handle_reboot,
            "shutdown": self._handle_shutdown,
            "exit": self._handle_exit,
            "logout": self._handle_exit,
            "busybox": self._handle_busybox,
        }
        
        # Banner message
        self.banner = self.protocol_config.get("banner", "Welcome to IoT Device Management Console")
    
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
                "prompt": f"{device_config.get('brand', 'device')}> ",
                "filesystem": self._get_default_filesystem(device_type),
                "commands": self._get_device_commands(device_type),
                "users": self._get_device_users(device_type),
            }
            
            self.device_profiles[device_type] = profile
            self.logger.info(f"Loaded device profile: {device_type} ({profile['brand']} {profile['model']})")
    
    def _get_default_filesystem(self, device_type: str) -> Dict[str, Any]:
        """
        Get the default filesystem for a device type.
        
        Args:
            device_type: Device type
            
        Returns:
            Filesystem structure
        """
        # Common directories for all devices
        fs = {
            "/": {"type": "dir", "content": {}},
            "/bin": {"type": "dir", "content": {}},
            "/etc": {"type": "dir", "content": {}},
            "/tmp": {"type": "dir", "content": {}},
            "/var": {"type": "dir", "content": {}},
            "/var/log": {"type": "dir", "content": {}},
            "/proc": {"type": "dir", "content": {}},
            "/dev": {"type": "dir", "content": {}},
        }
        
        # Common files
        fs["/etc/passwd"] = {
            "type": "file",
            "content": "root:x:0:0:root:/root:/bin/sh\n"
                      "admin:x:1000:1000:admin:/home/admin:/bin/sh\n"
                      "user:x:1001:1001:user:/home/user:/bin/sh\n"
        }
        
        fs["/etc/shadow"] = {
            "type": "file",
            "content": "root:$1$salt$hashedpassword:18000:0:99999:7:::\n"
                      "admin:$1$salt$hashedpassword:18000:0:99999:7:::\n"
                      "user:$1$salt$hashedpassword:18000:0:99999:7:::\n"
        }
        
        fs["/etc/hosts"] = {
            "type": "file",
            "content": "127.0.0.1 localhost\n"
        }
        
        # Device-specific files
        if device_type == "ip_camera":
            fs["/etc/config"] = {
                "type": "file",
                "content": "# IP Camera Configuration\n"
                          "RESOLUTION=1080p\n"
                          "FRAMERATE=30\n"
                          "RTSP_PORT=554\n"
                          "HTTP_PORT=80\n"
                          "USERNAME=admin\n"
                          "PASSWORD=admin\n"
            }
            
            fs["/var/www"] = {"type": "dir", "content": {}}
            fs["/var/www/html"] = {"type": "dir", "content": {}}
            fs["/var/www/html/index.html"] = {
                "type": "file",
                "content": "<html><head><title>IP Camera Web Interface</title></head>"
                          "<body><h1>IP Camera Web Interface</h1></body></html>"
            }
            
        elif device_type == "router":
            fs["/etc/config"] = {
                "type": "file",
                "content": "# Router Configuration\n"
                          "WAN_INTERFACE=eth0\n"
                          "LAN_INTERFACE=eth1\n"
                          "WIFI_ENABLED=1\n"
                          "WIFI_SSID=Router_SSID\n"
                          "WIFI_PASSWORD=password123\n"
                          "DHCP_ENABLED=1\n"
            }
            
            fs["/etc/network"] = {"type": "dir", "content": {}}
            fs["/etc/network/interfaces"] = {
                "type": "file",
                "content": "auto lo\n"
                          "iface lo inet loopback\n\n"
                          "auto eth0\n"
                          "iface eth0 inet dhcp\n\n"
                          "auto eth1\n"
                          "iface eth1 inet static\n"
                          "  address 192.168.1.1\n"
                          "  netmask 255.255.255.0\n"
            }
            
        elif device_type == "dvr":
            fs["/etc/config"] = {
                "type": "file",
                "content": "# DVR Configuration\n"
                          "CHANNELS=8\n"
                          "RECORDING_QUALITY=HIGH\n"
                          "MOTION_DETECTION=1\n"
                          "STORAGE_PATH=/media/hdd1\n"
                          "REMOTE_ACCESS=1\n"
            }
            
            fs["/media"] = {"type": "dir", "content": {}}
            fs["/media/hdd1"] = {"type": "dir", "content": {}}
            fs["/media/hdd1/recordings"] = {"type": "dir", "content": {}}
            
        return fs
    
    def _get_device_commands(self, device_type: str) -> Dict[str, str]:
        """
        Get device-specific command responses.
        
        Args:
            device_type: Device type
            
        Returns:
            Dictionary of command -> response
        """
        commands = {}
        
        # Common commands for all devices
        commands["busybox"] = "BusyBox v1.31.1 multi-call binary.\n" \
                             "Usage: busybox [function] [arguments]...\n" \
                             "   or: busybox --list[-full]\n" \
                             "   or: function [arguments]...\n\n" \
                             "        BusyBox is a multi-call binary that combines many common Unix\n" \
                             "        utilities into a single executable.\n"
        
        # Device-specific commands
        if device_type == "ip_camera":
            commands["get_status"] = "Camera Status:\n" \
                                    "Resolution: 1080p\n" \
                                    "Framerate: 30fps\n" \
                                    "Recording: Active\n" \
                                    "Storage: 68% used\n"
            
            commands["set_resolution"] = "Usage: set_resolution [720p|1080p|4K]\n"
            
        elif device_type == "router":
            commands["get_clients"] = "Connected Clients:\n" \
                                     "192.168.1.100 - 00:11:22:33:44:55 - Android-Phone\n" \
                                     "192.168.1.101 - AA:BB:CC:DD:EE:FF - Windows-PC\n" \
                                     "192.168.1.102 - 11:22:33:44:55:66 - Smart-TV\n"
            
            commands["get_wan_status"] = "WAN Status:\n" \
                                        "IP: 203.0.113.45\n" \
                                        "Mask: 255.255.255.0\n" \
                                        "Gateway: 203.0.113.1\n" \
                                        "DNS: 8.8.8.8, 8.8.4.4\n"
            
        elif device_type == "dvr":
            commands["get_recordings"] = "Recent Recordings:\n" \
                                        "CH1_20250520_083000.mp4 - 256MB\n" \
                                        "CH2_20250520_090000.mp4 - 128MB\n" \
                                        "CH3_20250520_100000.mp4 - 512MB\n"
            
            commands["start_recording"] = "Usage: start_recording [channel] [duration]\n"
            
        return commands
    
    def _get_device_users(self, device_type: str) -> Dict[str, str]:
        """
        Get device-specific user credentials.
        
        Args:
            device_type: Device type
            
        Returns:
            Dictionary of username -> password
        """
        # Common default credentials
        users = {
            "root": "root",
            "admin": "admin",
            "user": "user",
        }
        
        # Device-specific credentials
        if device_type == "ip_camera":
            users.update({
                "admin": "admin1234",
                "operator": "operator",
            })
            
        elif device_type == "router":
            users.update({
                "admin": "password",
                "support": "support",
            })
            
        elif device_type == "dvr":
            users.update({
                "admin": "123456",
                "supervisor": "supervisor",
            })
            
        return users
    
    def _handle_client(self, session_id: str) -> None:
        """
        Handle a Telnet client connection.
        
        Args:
            session_id: Session identifier
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        
        # Initialize session state
        session["state"] = "init"
        session["authenticated"] = False
        session["username"] = None
        session["device_type"] = None
        session["current_dir"] = "/"
        session["terminal_type"] = "unknown"
        session["window_size"] = (80, 24)
        
        # Select a device profile
        device_types = list(self.device_profiles.keys())
        if device_types:
            # For now, randomly select a device type
            import random
            device_type = random.choice(device_types)
            session["device_type"] = device_type
            session["device_profile"] = self.device_profiles[device_type]
            session["filesystem"] = self.device_profiles[device_type]["filesystem"].copy()
            
            self.logger.info(
                f"Selected device profile for {client_address[0]}: {device_type}",
                device_type=device_type,
                session_id=session_id
            )
        else:
            self.logger.error(f"No device profiles available")
            self.close_session(session_id)
            return
        
        try:
            # Perform Telnet negotiation
            self._telnet_negotiation(session_id)
            
            # Send banner
            self.send_data(session_id, f"\r\n{self.banner}\r\n".encode())
            
            # Authenticate user
            if not self._authenticate_user(session_id):
                self.close_session(session_id)
                return
            
            # Main command loop
            self._command_loop(session_id)
            
        except Exception as e:
            self.logger.error(
                f"Error handling Telnet client {client_address[0]}: {e}",
                error=str(e),
                session_id=session_id
            )
            self.close_session(session_id)
    
    def _telnet_negotiation(self, session_id: str) -> None:
        """
        Perform Telnet option negotiation.
        
        Args:
            session_id: Session identifier
        """
        # Send initial negotiation
        # WILL ECHO, WILL SGA
        self.send_data(session_id, self.IAC + self.WILL + self.OPT_ECHO)
        self.send_data(session_id, self.IAC + self.WILL + self.OPT_SGA)
        
        # DO TTYPE, DO NAWS
        self.send_data(session_id, self.IAC + self.DO + self.OPT_TTYPE)
        self.send_data(session_id, self.IAC + self.DO + self.OPT_NAWS)
        
        # Process client responses
        # We'll give the client a short time to respond to our negotiation
        time.sleep(0.5)
        
        # Read any pending data (negotiation responses)
        data = self.receive_data(session_id, 1024)
        if data:
            self._process_telnet_commands(session_id, data)
    
    def _process_telnet_commands(self, session_id: str, data: bytes) -> bytes:
        """
        Process Telnet commands in the data stream.
        
        Args:
            session_id: Session identifier
            data: Raw data from client
            
        Returns:
            Data with Telnet commands removed
        """
        if session_id not in self.sessions:
            return b''
        
        session = self.sessions[session_id]
        
        # Process IAC sequences
        i = 0
        result = bytearray()
        
        while i < len(data):
            if data[i:i+1] == self.IAC:
                if i + 1 >= len(data):
                    break
                
                command = data[i+1:i+2]
                
                if command in (self.WILL, self.WONT, self.DO, self.DONT):
                    if i + 2 >= len(data):
                        break
                    
                    option = data[i+2:i+3]
                    
                    # Process specific options
                    if command == self.WILL:
                        if option == self.OPT_TTYPE:
                            # Client is willing to send terminal type
                            # Send SB TTYPE SEND
                            self.send_data(
                                session_id, 
                                self.IAC + self.SB + self.OPT_TTYPE + bytes([1]) + self.IAC + self.SE
                            )
                        elif option == self.OPT_NAWS:
                            # Client is willing to send window size
                            pass
                    
                    # Skip the IAC command
                    i += 3
                    
                elif command == self.SB:
                    # Subnegotiation
                    se_pos = data.find(self.IAC + self.SE, i)
                    if se_pos == -1:
                        break
                    
                    subneg_data = data[i+2:se_pos]
                    
                    # Process specific subnegotiations
                    if subneg_data and subneg_data[0:1] == self.OPT_TTYPE and subneg_data[1:2] == bytes([0]):
                        # Terminal type response
                        terminal_type = subneg_data[2:].decode('ascii', errors='ignore')
                        session["terminal_type"] = terminal_type
                        self.logger.debug(
                            f"Client terminal type: {terminal_type}",
                            terminal_type=terminal_type,
                            session_id=session_id
                        )
                    
                    elif subneg_data and subneg_data[0:1] == self.OPT_NAWS:
                        # Window size
                        if len(subneg_data) >= 5:
                            width = (subneg_data[1] << 8) | subneg_data[2]
                            height = (subneg_data[3] << 8) | subneg_data[4]
                            session["window_size"] = (width, height)
                            self.logger.debug(
                                f"Client window size: {width}x{height}",
                                width=width,
                                height=height,
                                session_id=session_id
                            )
                    
                    # Skip the subnegotiation
                    i = se_pos + 2
                    
                else:
                    # Skip other commands (IAC + command)
                    i += 2
            else:
                # Regular data
                result.append(data[i])
                i += 1
        
        return bytes(result)
    
    def _authenticate_user(self, session_id: str) -> bool:
        """
        Authenticate a user.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if authenticated, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        client_address = session["address"]
        device_profile = session["device_profile"]
        
        # Initialize authentication attempts
        self.auth_attempts[session_id] = 0
        
        while self.auth_attempts[session_id] < self.max_auth_attempts:
            # Send login prompt
            self.send_data(session_id, b"\r\nlogin: ")
            
            # Get username
            username_data = self.receive_data(session_id)
            if not username_data:
                return False
            
            username = username_data.decode('utf-8', errors='ignore').strip()
            
            # Send password prompt
            self.send_data(session_id, b"Password: ")
            
            # Get password
            password_data = self.receive_data(session_id)
            if not password_data:
                return False
            
            password = password_data.decode('utf-8', errors='ignore').strip()
            
            # Check credentials
            valid_users = device_profile["users"]
            
            if username in valid_users and valid_users[username] == password:
                # Successful login
                session["authenticated"] = True
                session["username"] = username
                
                # Log login attempt
                self.logger.log_login_attempt(
                    src_ip=client_address[0],
                    username=username,
                    password=password,
                    success=True,
                    session_id=session_id
                )
                
                # Send welcome message
                brand = device_profile["brand"]
                model = device_profile["model"]
                firmware = device_profile["firmware"]
                
                welcome_msg = (
                    f"\r\n"
                    f"Welcome to {brand} {model}\r\n"
                    f"Firmware version: {firmware}\r\n"
                    f"\r\n"
                )
                
                self.send_data(session_id, welcome_msg.encode())
                
                return True
            else:
                # Failed login
                self.auth_attempts[session_id] += 1
                
                # Log login attempt
                self.logger.log_login_attempt(
                    src_ip=client_address[0],
                    username=username,
                    password=password,
                    success=False,
                    session_id=session_id
                )
                
                # Send failure message
                self.send_data(session_id, b"\r\nLogin incorrect\r\n")
        
        # Max authentication attempts reached
        self.send_data(session_id, b"\r\nMaximum login attempts exceeded\r\n")
        return False
    
    def _command_loop(self, session_id: str) -> None:
        """
        Main command processing loop.
        
        Args:
            session_id: Session identifier
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        device_profile = session["device_profile"]
        
        # Command history
        session["history"] = []
        
        while session_id in self.sessions:
            # Send prompt
            prompt = device_profile["prompt"]
            self.send_data(session_id, f"\r\n{prompt}".encode())
            
            # Get command
            cmd_data = self.receive_data(session_id)
            if not cmd_data:
                break
            
            # Process command
            cmd_str = cmd_data.decode('utf-8', errors='ignore').strip()
            
            # Skip empty commands
            if not cmd_str:
                continue
            
            # Add to history
            session["history"].append(cmd_str)
            
            # Log command
            self.logger.log_command(
                src_ip=client_address[0],
                command=cmd_str,
                session_id=session_id
            )
            
            # Process command
            self._process_command(session_id, cmd_str)
    
    def _process_command(self, session_id: str, command: str) -> None:
        """
        Process a command.
        
        Args:
            session_id: Session identifier
            command: Command string
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        # Split command and arguments
        parts = command.split(None, 1)
        cmd = parts[0] if parts else ""
        args = parts[1] if len(parts) > 1 else ""
        
        # Check for device-specific commands
        device_commands = device_profile["commands"]
        if cmd in device_commands:
            response = device_commands[cmd]
            self.send_data(session_id, f"\r\n{response}".encode())
            return
        
        # Check for built-in command handlers
        if cmd in self.command_handlers:
            self.command_handlers[cmd](session_id, args)
            return
        
        # Unknown command
        self.send_data(session_id, f"\r\n{cmd}: command not found".encode())
    
    # Command handlers
    
    def _handle_help(self, session_id: str, args: str) -> None:
        """Handle the 'help' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        # Basic help message
        help_msg = (
            "Available commands:\r\n"
            "  help       - Show this help message\r\n"
            "  ls         - List directory contents\r\n"
            "  cd         - Change directory\r\n"
            "  cat        - Display file contents\r\n"
            "  echo       - Display a message\r\n"
            "  ps         - Show process status\r\n"
            "  wget       - Download file from network\r\n"
            "  curl       - Transfer data from or to a server\r\n"
            "  uname      - Print system information\r\n"
            "  id         - Print user identity\r\n"
            "  passwd     - Change user password\r\n"
            "  reboot     - Reboot the system\r\n"
            "  shutdown   - Shut down the system\r\n"
            "  exit       - Exit the session\r\n"
            "  busybox    - Show BusyBox help\r\n"
        )
        
        # Add device-specific commands
        device_commands = device_profile["commands"]
        if device_commands:
            help_msg += "\r\nDevice-specific commands:\r\n"
            for cmd in sorted(device_commands.keys()):
                help_msg += f"  {cmd}\r\n"
        
        self.send_data(session_id, f"\r\n{help_msg}".encode())
    
    def _handle_ls(self, session_id: str, args: str) -> None:
        """Handle the 'ls' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        filesystem = session["filesystem"]
        current_dir = session["current_dir"]
        
        # Parse arguments
        show_all = "-a" in args
        long_format = "-l" in args
        
        # Get target directory
        target_dir = current_dir
        args_parts = args.split()
        for arg in args_parts:
            if not arg.startswith("-"):
                if arg.startswith("/"):
                    target_dir = arg
                else:
                    target_dir = self._resolve_path(current_dir, arg)
                break
        
        # Ensure target_dir ends with /
        if not target_dir.endswith("/"):
            target_dir += "/"
        
        # Get directory contents
        contents = []
        for path, info in filesystem.items():
            if path.startswith(target_dir) and path != target_dir:
                # Get the relative path
                rel_path = path[len(target_dir):]
                
                # Only include direct children
                if "/" not in rel_path:
                    contents.append((rel_path, info))
        
        # Filter hidden files
        if not show_all:
            contents = [(name, info) for name, info in contents if not name.startswith(".")]
        
        # Format output
        if long_format:
            result = ""
            for name, info in sorted(contents):
                file_type = "d" if info["type"] == "dir" else "-"
                permissions = "rwxr-xr-x" if info["type"] == "dir" else "rw-r--r--"
                owner = "root"
                group = "root"
                size = 4096 if info["type"] == "dir" else len(info.get("content", ""))
                date = "May 20 10:00"
                
                result += f"{file_type}{permissions} 1 {owner} {group} {size} {date} {name}\r\n"
        else:
            result = "  ".join(name for name, _ in sorted(contents))
        
        self.send_data(session_id, f"\r\n{result}".encode())
    
    def _handle_cd(self, session_id: str, args: str) -> None:
        """Handle the 'cd' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        filesystem = session["filesystem"]
        current_dir = session["current_dir"]
        
        # Default to home directory if no args
        if not args:
            session["current_dir"] = "/"
            return
        
        # Resolve the target path
        target_path = self._resolve_path(current_dir, args)
        
        # Ensure path exists and is a directory
        if target_path not in filesystem:
            self.send_data(session_id, f"\r\ncd: {args}: No such file or directory".encode())
            return
        
        if filesystem[target_path]["type"] != "dir":
            self.send_data(session_id, f"\r\ncd: {args}: Not a directory".encode())
            return
        
        # Update current directory
        session["current_dir"] = target_path
    
    def _handle_cat(self, session_id: str, args: str) -> None:
        """Handle the 'cat' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        filesystem = session["filesystem"]
        current_dir = session["current_dir"]
        
        if not args:
            self.send_data(session_id, b"\r\nUsage: cat [file]")
            return
        
        # Resolve the target path
        target_path = self._resolve_path(current_dir, args)
        
        # Check if file exists
        if target_path not in filesystem:
            self.send_data(session_id, f"\r\ncat: {args}: No such file or directory".encode())
            return
        
        # Check if it's a file
        if filesystem[target_path]["type"] != "file":
            self.send_data(session_id, f"\r\ncat: {args}: Is a directory".encode())
            return
        
        # Display file content
        content = filesystem[target_path].get("content", "")
        self.send_data(session_id, f"\r\n{content}".encode())
    
    def _handle_echo(self, session_id: str, args: str) -> None:
        """Handle the 'echo' command."""
        self.send_data(session_id, f"\r\n{args}".encode())
    
    def _handle_ps(self, session_id: str, args: str) -> None:
        """Handle the 'ps' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        # Generate fake process list based on device type
        device_type = device_profile["type"]
        
        processes = [
            "    1 root     1200 S    init",
            "    2 root        0 SW   [kthreadd]",
            "    3 root        0 SW   [ksoftirqd/0]",
            "   10 root        0 SW   [kworker/0:1]",
            "   11 root        0 SW   [kworker/u:1]",
            "  312 root     1300 S    /sbin/udhcpc -i eth0",
            "  423 root     2100 S    /usr/sbin/dropbear",
            "  567 root     1100 S    /sbin/syslogd -n",
            "  568 root     1100 S    /sbin/klogd -n",
        ]
        
        # Add device-specific processes
        if device_type == "ip_camera":
            processes.extend([
                "  789 root     5200 S    /usr/bin/camera_service",
                "  790 root     3100 S    /usr/bin/rtsp_server",
                "  791 root     2800 S    /usr/bin/motion_detection",
                "  792 root     1900 S    /usr/bin/web_server",
            ])
        elif device_type == "router":
            processes.extend([
                "  789 root     3200 S    /usr/sbin/dnsmasq",
                "  790 root     2100 S    /usr/sbin/hostapd",
                "  791 root     1800 S    /usr/sbin/httpd",
                "  792 root     1500 S    /usr/sbin/firewall",
            ])
        elif device_type == "dvr":
            processes.extend([
                "  789 root     6200 S    /usr/bin/recording_service",
                "  790 root     4100 S    /usr/bin/video_encoder",
                "  791 root     3800 S    /usr/bin/stream_server",
                "  792 root     2900 S    /usr/bin/web_interface",
            ])
        
        # Add the current shell
        processes.append(f"{1000 + len(processes)} {session['username']}     1400 S    -sh")
        
        # Format output
        header = "  PID USER     VSZ STAT COMMAND"
        result = header + "\r\n" + "\r\n".join(processes)
        
        self.send_data(session_id, f"\r\n{result}".encode())
    
    def _handle_wget(self, session_id: str, args: str) -> None:
        """Handle the 'wget' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        
        if not args:
            self.send_data(session_id, b"\r\nUsage: wget [URL]")
            return
        
        # Extract URL
        url_match = re.search(r'(https?://\S+)', args)
        if not url_match:
            self.send_data(session_id, b"\r\nwget: missing URL")
            return
        
        url = url_match.group(1)
        
        # Log download attempt
        self.logger.info(
            f"Download attempt from {client_address[0]}: wget {url}",
            event_type="download_attempt",
            src_ip=client_address[0],
            url=url,
            command=f"wget {args}",
            session_id=session_id
        )
        
        # Simulate download
        self.send_data(session_id, f"\r\nConnecting to {url.split('/')[2]}... connected.".encode())
        self.send_data(session_id, b"\r\nHTTP request sent, awaiting response... 200 OK")
        self.send_data(session_id, b"\r\nLength: 12345 (12K) [text/plain]")
        self.send_data(session_id, b"\r\nSaving to: 'malware.bin'")
        self.send_data(session_id, b"\r\n\r\n     0K .......... ..         100%  102K=0.1s")
        self.send_data(session_id, b"\r\n\r\n2025-05-25 19:30:00 (102 KB/s) - 'malware.bin' saved [12345/12345]")
    
    def _handle_curl(self, session_id: str, args: str) -> None:
        """Handle the 'curl' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        
        if not args:
            self.send_data(session_id, b"\r\nUsage: curl [options] [URL]")
            return
        
        # Extract URL
        url_match = re.search(r'(https?://\S+)', args)
        if not url_match:
            self.send_data(session_id, b"\r\ncurl: try 'curl --help' for more information")
            return
        
        url = url_match.group(1)
        
        # Log download attempt
        self.logger.info(
            f"Download attempt from {client_address[0]}: curl {url}",
            event_type="download_attempt",
            src_ip=client_address[0],
            url=url,
            command=f"curl {args}",
            session_id=session_id
        )
        
        # Check for output option
        output_file = "malware.bin"
        output_match = re.search(r'-[Oo] (\S+)', args)
        if output_match:
            output_file = output_match.group(1)
        
        # Simulate download
        self.send_data(session_id, f"\r\n  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current".encode())
        self.send_data(session_id, f"\r\n                                 Dload  Upload   Total   Spent    Left  Speed".encode())
        self.send_data(session_id, f"\r\n100 12345  100 12345    0     0   102k      0  0:00:01  0:00:01 --:--:--  102k".encode())
    
    def _handle_uname(self, session_id: str, args: str) -> None:
        """Handle the 'uname' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        # Generate uname output based on device type
        if "-a" in args:
            result = f"Linux {device_profile['brand'].lower()} 3.10.14 #1 Tue May 20 10:35:24 UTC 2025 armv7l GNU/Linux"
        else:
            result = "Linux"
        
        self.send_data(session_id, f"\r\n{result}".encode())
    
    def _handle_id(self, session_id: str, args: str) -> None:
        """Handle the 'id' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        username = session["username"]
        
        if username == "root":
            result = "uid=0(root) gid=0(root) groups=0(root)"
        else:
            result = f"uid=1000({username}) gid=1000({username}) groups=1000({username})"
        
        self.send_data(session_id, f"\r\n{result}".encode())
    
    def _handle_passwd(self, session_id: str, args: str) -> None:
        """Handle the 'passwd' command."""
        self.send_data(session_id, b"\r\nChanging password for root")
        self.send_data(session_id, b"\r\nNew password: ")
        
        # Receive password
        password_data = self.receive_data(session_id)
        if not password_data:
            return
        
        self.send_data(session_id, b"\r\nRetype new password: ")
        
        # Receive confirmation
        confirm_data = self.receive_data(session_id)
        if not confirm_data:
            return
        
        # Log password change attempt
        if session_id in self.sessions:
            session = self.sessions[session_id]
            client_address = session["address"]
            password = password_data.decode('utf-8', errors='ignore').strip()
            
            self.logger.info(
                f"Password change attempt from {client_address[0]}: {password}",
                event_type="password_change",
                src_ip=client_address[0],
                password=password,
                session_id=session_id
            )
        
        # Always succeed
        self.send_data(session_id, b"\r\npasswd: password updated successfully")
    
    def _handle_reboot(self, session_id: str, args: str) -> None:
        """Handle the 'reboot' command."""
        self.send_data(session_id, b"\r\nThe system is going down for reboot NOW!")
        
        # Close the session after a short delay
        time.sleep(1)
        self.close_session(session_id)
    
    def _handle_shutdown(self, session_id: str, args: str) -> None:
        """Handle the 'shutdown' command."""
        self.send_data(session_id, b"\r\nThe system is going down for system halt NOW!")
        
        # Close the session after a short delay
        time.sleep(1)
        self.close_session(session_id)
    
    def _handle_exit(self, session_id: str, args: str) -> None:
        """Handle the 'exit' command."""
        self.send_data(session_id, b"\r\nConnection closed.")
        self.close_session(session_id)
    
    def _handle_busybox(self, session_id: str, args: str) -> None:
        """Handle the 'busybox' command."""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        if "--help" in args or not args:
            # Show BusyBox help
            busybox_help = device_profile["commands"].get("busybox", "")
            self.send_data(session_id, f"\r\n{busybox_help}".encode())
        elif "--list" in args:
            # Show list of BusyBox applets
            applets = [
                "ash", "cat", "chmod", "cp", "date", "dd", "df", "dmesg", "echo", "egrep",
                "false", "fgrep", "grep", "gunzip", "gzip", "halt", "ifconfig", "kill",
                "ln", "login", "ls", "mkdir", "mknod", "mount", "mv", "netstat", "ping",
                "ps", "pwd", "reboot", "rm", "rmdir", "sed", "sh", "sleep", "sync", "tar",
                "touch", "true", "umount", "uname", "wget", "zcat"
            ]
            
            result = "\r\n".join(applets)
            self.send_data(session_id, f"\r\n{result}".encode())
        else:
            # Try to execute the applet
            applet = args.split()[0]
            applet_args = " ".join(args.split()[1:])
            
            # Map applet to command handler
            applet_map = {
                "ls": self._handle_ls,
                "cat": self._handle_cat,
                "echo": self._handle_echo,
                "ps": self._handle_ps,
                "uname": self._handle_uname,
            }
            
            if applet in applet_map:
                applet_map[applet](session_id, applet_args)
            else:
                self.send_data(session_id, f"\r\nbusybox: applet not found: {applet}".encode())
    
    def _resolve_path(self, current_dir: str, path: str) -> str:
        """
        Resolve a path relative to the current directory.
        
        Args:
            current_dir: Current directory
            path: Path to resolve
            
        Returns:
            Absolute path
        """
        # Handle absolute paths
        if path.startswith("/"):
            resolved = path
        else:
            # Handle relative paths
            if not current_dir.endswith("/"):
                current_dir += "/"
            resolved = current_dir + path
        
        # Normalize path
        parts = resolved.split("/")
        normalized = []
        
        for part in parts:
            if part == "" or part == ".":
                continue
            elif part == "..":
                if normalized:
                    normalized.pop()
            else:
                normalized.append(part)
        
        # Ensure path starts with /
        result = "/" + "/".join(normalized)
        
        # Special case for root directory
        if result == "":
            result = "/"
        
        return result

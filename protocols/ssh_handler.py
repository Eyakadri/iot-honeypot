#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH protocol handler for the Advanced IoT Honeypot.
Implements a realistic SSH server emulating IoT device shells.
"""

import os
import socket
import threading
import time
import paramiko
from typing import Dict, Any, Optional, List, Tuple, Union, Callable

from advanced_honeypot.protocols.base_protocol import BaseProtocolHandler
from advanced_honeypot.core.logger import get_logger
from advanced_honeypot.core.config import get_config

# Generate a host key if it doesn't exist
HOST_KEY_PATH = "/home/ubuntu/advanced_honeypot/core/ssh_host_key"
if not os.path.exists(HOST_KEY_PATH):
    try:
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
        print(f"Generated new SSH host key: {HOST_KEY_PATH}")
    except Exception as e:
        print(f"Error generating SSH host key: {e}")
        # Handle error appropriately, maybe exit or use a default key

class SSHHandler(BaseProtocolHandler):
    """SSH protocol handler for IoT device shell emulation."""

    def __init__(self):
        """Initialize the SSH protocol handler."""
        super().__init__("ssh")
        
        # Load device profiles
        self.device_profiles = {}
        self._load_device_profiles()
        
        # SSH server settings
        self.host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)
        self.server_banner = self.protocol_config.get("server_banner", "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3")
        
        # SSH sessions
        self.ssh_sessions = {}

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
                "default_username": device_config.get("ssh_username", "root"),
                "default_password": device_config.get("ssh_password", "root"),
                "shell_prompt": device_config.get("ssh_prompt", "# "),
                "commands": self._get_device_commands(device_type),
                "vulnerabilities": self._get_device_vulnerabilities(device_type),
            }
            
            self.device_profiles[device_type] = profile
            self.logger.info(f"Loaded SSH device profile: {device_type} ({profile['brand']} {profile['model']})")

    def _get_device_commands(self, device_type: str) -> Dict[str, Union[str, Callable]]:
        """
        Get shell commands for a device type.
        
        Args:
            device_type: Device type
            
        Returns:
            Dictionary of command -> response or handler function
        """
        commands = {
            # Common commands
            "help": "Available commands:\n  help, exit, ls, pwd, uname, reboot, cat, echo",
            "exit": lambda session_id, args: self.close_session(session_id),
            "pwd": "/root",
            "uname": "Linux GenericDevice 2.6.32 #1 SMP PREEMPT Tue May 10 15:01:58 CST 2025 mips",
            "uname -a": "Linux GenericDevice 2.6.32 #1 SMP PREEMPT Tue May 10 15:01:58 CST 2025 mips GNU/Linux",
            "reboot": lambda session_id, args: self._handle_reboot(session_id),
            "ls": "bin  dev  etc  home  lib  mnt  proc  root  sbin  tmp  usr  var",
            "ls -la": "total 0\ndrwxr-xr-x    1 root     root            0 May 25 19:50 .\ndrwxr-xr-x    1 root     root            0 May 25 19:50 ..",
            "cat /proc/version": "Linux version 2.6.32 (builder@buildhost) (gcc version 4.8.3 (Buildroot 2015.02)) #1 SMP PREEMPT Tue May 10 15:01:58 CST 2025",
            "echo $SHELL": "/bin/sh",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh",
            "cat /etc/shadow": "root:$1$abcdefgh$IJKLMNOPQRSTUVWXYZ012345:18000:0:99999:7:::\nadmin:$1$ijklmnop$QRSTUVWXYZ0123456789abcd:18000:0:99999:7:::",
        }
        
        # Device-specific commands
        if device_type == "ip_camera":
            commands.update({
                "uname": "Linux IPCam 3.10.14 #1 PREEMPT Wed Apr 1 10:00:00 CST 2025 armv7l",
                "uname -a": "Linux IPCam 3.10.14 #1 PREEMPT Wed Apr 1 10:00:00 CST 2025 armv7l GNU/Linux",
                "cat /proc/version": "Linux version 3.10.14 (builder@buildhost) (gcc version 4.9.4 (Buildroot 2016.11.1)) #1 PREEMPT Wed Apr 1 10:00:00 CST 2025",
                "ls /mnt": "sdcard",
                "cat /etc/passwd": "root:x:0:0:root:/root:/bin/sh\ncamera:x:1001:1001:camera:/home/camera:/bin/false",
            })
        elif device_type == "router":
            commands.update({
                "uname": "Linux Router 4.1.27 #2 SMP Tue Mar 15 14:30:00 UTC 2025 mips",
                "uname -a": "Linux Router 4.1.27 #2 SMP Tue Mar 15 14:30:00 UTC 2025 mips GNU/Linux",
                "cat /proc/version": "Linux version 4.1.27 (builder@buildhost) (gcc version 5.2.0 (OpenWrt GCC 5.2.0 r49389)) #2 SMP Tue Mar 15 14:30:00 UTC 2025",
                "nvram show": "wan_ipaddr=203.0.113.45\nlan_ipaddr=192.168.1.1\n...",
                "cat /etc/passwd": "root:x:0:0:root:/root:/bin/ash\nadmin:x:1000:1000:admin:/home/admin:/bin/ash",
            })
        elif device_type == "dvr":
            commands.update({
                "uname": "Linux DVR 3.4.35 #1 SMP Mon Feb 10 11:20:00 CST 2025 armv7l",
                "uname -a": "Linux DVR 3.4.35 #1 SMP Mon Feb 10 11:20:00 CST 2025 armv7l GNU/Linux",
                "cat /proc/version": "Linux version 3.4.35 (builder@buildhost) (gcc version 4.7.2 (Buildroot 2013.08.1)) #1 SMP Mon Feb 10 11:20:00 CST 2025",
                "ls /mnt": "hdd1",
                "cat /etc/passwd": "root:x:0:0:root:/root:/bin/sh\ndvr:x:1002:1002:dvr:/home/dvr:/bin/false",
            })
        
        return commands

    def _get_device_vulnerabilities(self, device_type: str) -> Dict[str, Dict[str, Any]]:
        """
        Get vulnerabilities for a device type.
        
        Args:
            device_type: Device type
            
        Returns:
            Dictionary of vulnerability_id -> vulnerability info
        """
        vulnerabilities = {
            "default_credentials": {
                "type": "authentication",
                "description": "Device uses default SSH credentials",
                "enabled": True,
            },
            "weak_crypto": {
                "type": "encryption",
                "description": "Supports weak SSH algorithms (e.g., diffie-hellman-group1-sha1)",
                "enabled": True,
            },
            "command_injection": {
                "type": "injection",
                "description": "Command injection vulnerability in a specific command",
                "enabled": True,
                "command": "ping",
            },
        }
        
        # Device-specific vulnerabilities
        if device_type == "ip_camera":
            vulnerabilities.update({
                "root_access": {
                    "type": "privilege_escalation",
                    "description": "Allows direct root login via SSH",
                    "enabled": True,
                },
            })
        elif device_type == "router":
            vulnerabilities.update({
                "info_leak": {
                    "type": "information_disclosure",
                    "description": "NVRAM variables accessible via shell",
                    "enabled": True,
                },
            })
        elif device_type == "dvr":
            vulnerabilities.update({
                "backdoor_account": {
                    "type": "authentication",
                    "description": "Hidden backdoor SSH account",
                    "enabled": True,
                    "username": "support",
                    "password": "DVRsupport2025",
                },
            })
        
        return vulnerabilities

    def _handle_client(self, session_id: str) -> None:
        """
        Handle an SSH client connection using Paramiko's server interface.
        
        Args:
            session_id: Session identifier
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_socket = session["socket"]
        client_address = session["address"]
        
        try:
            # Create Paramiko transport
            transport = paramiko.Transport(client_socket)
            transport.local_version = self.server_banner
            transport.add_server_key(self.host_key)
            
            # Create server interface
            server_interface = SSHServerInterface(session_id, self)
            
            # Start SSH server
            transport.start_server(server=server_interface)
            
            # Accept channel requests
            while transport.is_active():
                channel = transport.accept(timeout=1)
                if channel is None:
                    continue
                
                # Start channel handler thread
                thread = threading.Thread(target=self._handle_channel, args=(session_id, channel))
                thread.daemon = True
                thread.start()
                
        except paramiko.SSHException as e:
            self.logger.warning(f"SSH negotiation failed for {client_address[0]}: {e}", session_id=session_id)
        except Exception as e:
            self.logger.error(f"Error handling SSH client {client_address[0]}: {e}", error=str(e), session_id=session_id)
        finally:
            self.close_session(session_id)

    def _handle_channel(self, session_id: str, channel: paramiko.Channel) -> None:
        """
        Handle an SSH channel (e.g., shell, exec).
        
        Args:
            session_id: Session identifier
            channel: Paramiko channel object
        """
        if session_id not in self.sessions:
            channel.close()
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        device_profile = session["device_profile"]
        commands = device_profile["commands"]
        prompt = device_profile["shell_prompt"]
        
        try:
            # Wait for channel request (e.g., 'shell', 'exec')
            channel.accept() # Accept the channel request
            
            # Handle shell request
            if channel.get_pty():
                self.logger.info(f"Shell requested by {client_address[0]}", session_id=session_id)
                
                # Send welcome message
                channel.send(f"Welcome to {device_profile['brand']} {device_profile['model']} ({device_profile['type']})\n")
                channel.send(prompt)
                
                # Interactive shell loop
                command_buffer = ""
                while channel.active:
                    data = channel.recv(1024)
                    if not data:
                        break
                    
                    # Handle special characters (e.g., backspace, Ctrl+C)
                    if data == b'\x03': # Ctrl+C
                        channel.send("\n" + prompt)
                        command_buffer = ""
                        continue
                    elif data == b'\x7f' or data == b'\x08': # Backspace
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            channel.send(b'\x08 \x08') # Erase character on terminal
                        continue
                    elif data == b'\r' or data == b'\n': # Enter
                        channel.send("\r\n")
                        command = command_buffer.strip()
                        command_buffer = ""
                        
                        if command:
                            self.logger.log_command(client_address[0], command, session_id)
                            
                            # Handle command
                            response = self._handle_shell_command(session_id, command)
                            if response is not None:
                                channel.send(response.replace("\n", "\r\n") + "\r\n")
                        
                        channel.send(prompt)
                    else:
                        # Echo printable characters
                        try:
                            char = data.decode('utf-8')
                            if char.isprintable():
                                command_buffer += char
                                channel.send(data)
                        except UnicodeDecodeError:
                            # Ignore non-printable characters
                            pass
            
            # Handle exec request
            else:
                # Get command from channel request (not directly supported by default Interface)
                # This requires a custom ServerInterface or inspecting internal state
                # For simplicity, we'll assume the command is sent immediately after channel open
                command = channel.recv(1024).decode('utf-8', errors='ignore').strip()
                self.logger.info(f"Exec request from {client_address[0]}: {command}", session_id=session_id)
                self.logger.log_command(client_address[0], command, session_id)
                
                # Handle command
                response = self._handle_shell_command(session_id, command)
                if response is not None:
                    channel.send(response + "\n")
                
                # Send exit status
                channel.send_exit_status(0)
                
        except Exception as e:
            self.logger.error(f"Error handling SSH channel for {client_address[0]}: {e}", error=str(e), session_id=session_id)
        finally:
            channel.close()

    def _handle_shell_command(self, session_id: str, command: str) -> Optional[str]:
        """
        Handle a shell command.
        
        Args:
            session_id: Session identifier
            command: Command string
            
        Returns:
            Command response or None
        """
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        device_commands = device_profile["commands"]
        
        # Split command and arguments
        parts = command.split()
        cmd = parts[0] if parts else ""
        args = parts[1:]
        
        # Check for command injection vulnerability
        vuln = device_profile["vulnerabilities"].get("command_injection", {})
        if vuln.get("enabled", False) and cmd == vuln.get("command"):
            # Simulate command injection
            if any(c in command for c in [';', '|', '`', '$', '(', ')']):
                self.logger.warning(
                    f"Potential command injection attempt: {command}",
                    event_type="command_injection",
                    src_ip=session["address"][0],
                    command=command,
                    session_id=session_id
                )
                # Simulate execution (e.g., return error or partial output)
                return f"sh: {cmd}: Invalid argument"
        
        # Find command handler
        handler = device_commands.get(command) # Check full command first
        if not handler:
            handler = device_commands.get(cmd) # Check base command
        
        if handler:
            if callable(handler):
                # Call handler function
                result = handler(session_id, args)
                return result
            else:
                # Return static response
                return str(handler)
        else:
            # Command not found
            return f"sh: {cmd}: command not found"

    def _handle_reboot(self, session_id: str) -> str:
        """
        Handle the reboot command.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Response string
        """
        response = "Rebooting system..."
        
        # Close session after a delay
        def delayed_close():
            time.sleep(1)
            self.close_session(session_id)
            
        thread = threading.Thread(target=delayed_close)
        thread.daemon = True
        thread.start()
        
        return response

    def authenticate(self, session_id: str, username: str, password: str) -> bool:
        """
        Authenticate a user.
        
        Args:
            session_id: Session identifier
            username: Username
            password: Password
            
        Returns:
            True if authenticated, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        client_address = session["address"]
        
        # Select a device profile (if not already selected)
        if "device_profile" not in session:
            device_types = list(self.device_profiles.keys())
            if device_types:
                import random
                device_type = random.choice(device_types)
                session["device_type"] = device_type
                session["device_profile"] = self.device_profiles[device_type]
                self.logger.info(
                    f"Selected SSH device profile for {client_address[0]}: {device_type}",
                    device_type=device_type,
                    session_id=session_id
                )
            else:
                self.logger.error(f"No SSH device profiles available")
                return False
        
        device_profile = session["device_profile"]
        authenticated = False
        
        # Check for backdoor account (if enabled)
        backdoor = device_profile["vulnerabilities"].get("backdoor_account", {})
        if backdoor.get("enabled", False) and username == backdoor.get("username", "") and password == backdoor.get("password", ""):
            authenticated = True
        
        # Check default credentials
        elif username == device_profile["default_username"] and password == device_profile["default_password"]:
            authenticated = True
            
        # Check root access vulnerability
        elif device_profile["vulnerabilities"].get("root_access", {}).get("enabled", False) and username == "root":
            # Allow any password for root if vulnerability is enabled
            authenticated = True
        
        # Log login attempt
        self.logger.log_login_attempt(
            src_ip=client_address[0],
            username=username,
            password=password,
            success=authenticated,
            session_id=session_id
        )
        
        if authenticated:
            session["username"] = username
            
        return authenticated


class SSHServerInterface(paramiko.ServerInterface):
    """Custom Paramiko server interface to handle authentication and channel requests."""

    def __init__(self, session_id: str, handler: SSHHandler):
        self.session_id = session_id
        self.handler = handler
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Check if a channel request (e.g., 'session') is allowed."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """Check password authentication."""
        if self.handler.authenticate(self.session_id, username, password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """Check public key authentication (not supported)."""
        # For simplicity, we don't support public key auth
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        """Return allowed authentication methods."""
        return "password"

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        """Check if a shell request is allowed."""
        self.event.set()
        return True

    def check_channel_pty_request(self, channel: paramiko.Channel, term: str, width: int, height: int, pixelwidth: int, pixelheight: int, modes: bytes) -> bool:
        """Check if a PTY request is allowed."""
        # Store PTY info if needed
        if self.session_id in self.handler.sessions:
            self.handler.sessions[self.session_id]["pty"] = {
                "term": term,
                "width": width,
                "height": height,
            }
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        """Check if an exec request is allowed."""
        # Store command if needed (though typically handled after channel open)
        if self.session_id in self.handler.sessions:
            self.handler.sessions[self.session_id]["exec_command"] = command.decode('utf-8', errors='ignore')
        self.event.set()
        return True
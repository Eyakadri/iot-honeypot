#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP protocol handler for the Advanced IoT Honeypot.
Implements a realistic HTTP server emulating IoT device web interfaces.
"""

import os
import re
import json
import time
import socket
import threading
import urllib.parse
from typing import Dict, Any, Optional, List, Tuple, Union, Callable

from advanced_honeypot.protocols.base_protocol import BaseProtocolHandler
from advanced_honeypot.core.logger import get_logger
from advanced_honeypot.core.config import get_config


class HTTPHandler(BaseProtocolHandler):
    """HTTP protocol handler for IoT device web interface emulation."""

    def __init__(self):
        """Initialize the HTTP protocol handler."""
        super().__init__("http")
        
        # Load device profiles
        self.device_profiles = {}
        self._load_device_profiles()
        
        # HTTP server settings
        self.server_header = self.protocol_config.get("server_header", "nginx/1.14.0")
        self.max_request_size = self.protocol_config.get("max_request_size", 65536)
        
        # Request handlers
        self.request_handlers = {
            "GET": self._handle_get_request,
            "POST": self._handle_post_request,
            "HEAD": self._handle_head_request,
        }
        
        # Content type mappings
        self.content_types = {
            ".html": "text/html",
            ".htm": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".json": "application/json",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".ico": "image/x-icon",
            ".xml": "application/xml",
            ".txt": "text/plain",
        }
        
        # Session storage
        self.http_sessions = {}
    
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
                "web_title": f"{device_config.get('brand', 'Generic')} {device_config.get('model', 'Device')} - Web Management",
                "login_required": True,
                "default_username": "admin",
                "default_password": "admin",
                "web_pages": self._get_device_web_pages(device_type),
                "api_endpoints": self._get_device_api_endpoints(device_type),
                "vulnerabilities": self._get_device_vulnerabilities(device_type),
            }
            
            self.device_profiles[device_type] = profile
            self.logger.info(f"Loaded HTTP device profile: {device_type} ({profile['brand']} {profile['model']})")
    
    def _get_device_web_pages(self, device_type: str) -> Dict[str, Dict[str, Any]]:
        """
        Get web pages for a device type.
        
        Args:
            device_type: Device type
            
        Returns:
            Dictionary of path -> page info
        """
        pages = {
            # Common pages for all devices
            "/": {
                "title": "Login",
                "template": "login.html",
                "auth_required": False,
            },
            "/login.cgi": {
                "title": "Login Process",
                "template": None,  # Handled by POST handler
                "auth_required": False,
            },
            "/logout.cgi": {
                "title": "Logout",
                "template": None,  # Handled by special handler
                "auth_required": True,
            },
        }
        
        # Device-specific pages
        if device_type == "ip_camera":
            pages.update({
                "/index.html": {
                    "title": "Home",
                    "template": "camera_home.html",
                    "auth_required": True,
                },
                "/live.html": {
                    "title": "Live View",
                    "template": "camera_live.html",
                    "auth_required": True,
                },
                "/settings.html": {
                    "title": "Camera Settings",
                    "template": "camera_settings.html",
                    "auth_required": True,
                },
                "/network.html": {
                    "title": "Network Settings",
                    "template": "camera_network.html",
                    "auth_required": True,
                },
                "/users.html": {
                    "title": "User Management",
                    "template": "camera_users.html",
                    "auth_required": True,
                },
                "/maintenance.html": {
                    "title": "Maintenance",
                    "template": "camera_maintenance.html",
                    "auth_required": True,
                },
                "/api/snapshot.jpg": {
                    "title": "Camera Snapshot",
                    "template": "camera_snapshot.jpg",
                    "auth_required": True,
                    "content_type": "image/jpeg",
                },
            })
        elif device_type == "router":
            pages.update({
                "/index.html": {
                    "title": "Dashboard",
                    "template": "router_home.html",
                    "auth_required": True,
                },
                "/status.html": {
                    "title": "Status",
                    "template": "router_status.html",
                    "auth_required": True,
                },
                "/wireless.html": {
                    "title": "Wireless Settings",
                    "template": "router_wireless.html",
                    "auth_required": True,
                },
                "/network.html": {
                    "title": "Network Settings",
                    "template": "router_network.html",
                    "auth_required": True,
                },
                "/security.html": {
                    "title": "Security Settings",
                    "template": "router_security.html",
                    "auth_required": True,
                },
                "/admin.html": {
                    "title": "Administration",
                    "template": "router_admin.html",
                    "auth_required": True,
                },
            })
        elif device_type == "dvr":
            pages.update({
                "/index.html": {
                    "title": "Dashboard",
                    "template": "dvr_home.html",
                    "auth_required": True,
                },
                "/live.html": {
                    "title": "Live View",
                    "template": "dvr_live.html",
                    "auth_required": True,
                },
                "/playback.html": {
                    "title": "Playback",
                    "template": "dvr_playback.html",
                    "auth_required": True,
                },
                "/config.html": {
                    "title": "Configuration",
                    "template": "dvr_config.html",
                    "auth_required": True,
                },
                "/storage.html": {
                    "title": "Storage Management",
                    "template": "dvr_storage.html",
                    "auth_required": True,
                },
                "/system.html": {
                    "title": "System Settings",
                    "template": "dvr_system.html",
                    "auth_required": True,
                },
            })
        
        return pages
    
    def _get_device_api_endpoints(self, device_type: str) -> Dict[str, Dict[str, Any]]:
        """
        Get API endpoints for a device type.
        
        Args:
            device_type: Device type
            
        Returns:
            Dictionary of path -> endpoint info
        """
        endpoints = {
            # Common endpoints for all devices
            "/api/login": {
                "method": "POST",
                "handler": self._api_login,
                "auth_required": False,
            },
            "/api/logout": {
                "method": "POST",
                "handler": self._api_logout,
                "auth_required": True,
            },
            "/api/system_info": {
                "method": "GET",
                "handler": self._api_system_info,
                "auth_required": True,
            },
        }
        
        # Device-specific endpoints
        if device_type == "ip_camera":
            endpoints.update({
                "/api/get_video_settings": {
                    "method": "GET",
                    "handler": self._api_camera_video_settings,
                    "auth_required": True,
                },
                "/api/set_video_settings": {
                    "method": "POST",
                    "handler": self._api_camera_set_video_settings,
                    "auth_required": True,
                },
                "/api/get_network_settings": {
                    "method": "GET",
                    "handler": self._api_camera_network_settings,
                    "auth_required": True,
                },
                "/api/set_network_settings": {
                    "method": "POST",
                    "handler": self._api_camera_set_network_settings,
                    "auth_required": True,
                },
                "/api/reboot": {
                    "method": "POST",
                    "handler": self._api_reboot,
                    "auth_required": True,
                },
                "/api/firmware_upgrade": {
                    "method": "POST",
                    "handler": self._api_firmware_upgrade,
                    "auth_required": True,
                },
            })
        elif device_type == "router":
            endpoints.update({
                "/api/get_wan_status": {
                    "method": "GET",
                    "handler": self._api_router_wan_status,
                    "auth_required": True,
                },
                "/api/get_wireless_settings": {
                    "method": "GET",
                    "handler": self._api_router_wireless_settings,
                    "auth_required": True,
                },
                "/api/set_wireless_settings": {
                    "method": "POST",
                    "handler": self._api_router_set_wireless_settings,
                    "auth_required": True,
                },
                "/api/get_clients": {
                    "method": "GET",
                    "handler": self._api_router_clients,
                    "auth_required": True,
                },
                "/api/reboot": {
                    "method": "POST",
                    "handler": self._api_reboot,
                    "auth_required": True,
                },
                "/api/firmware_upgrade": {
                    "method": "POST",
                    "handler": self._api_firmware_upgrade,
                    "auth_required": True,
                },
            })
        elif device_type == "dvr":
            endpoints.update({
                "/api/get_recording_status": {
                    "method": "GET",
                    "handler": self._api_dvr_recording_status,
                    "auth_required": True,
                },
                "/api/get_channels": {
                    "method": "GET",
                    "handler": self._api_dvr_channels,
                    "auth_required": True,
                },
                "/api/get_recordings": {
                    "method": "GET",
                    "handler": self._api_dvr_recordings,
                    "auth_required": True,
                },
                "/api/start_recording": {
                    "method": "POST",
                    "handler": self._api_dvr_start_recording,
                    "auth_required": True,
                },
                "/api/stop_recording": {
                    "method": "POST",
                    "handler": self._api_dvr_stop_recording,
                    "auth_required": True,
                },
                "/api/reboot": {
                    "method": "POST",
                    "handler": self._api_reboot,
                    "auth_required": True,
                },
                "/api/firmware_upgrade": {
                    "method": "POST",
                    "handler": self._api_firmware_upgrade,
                    "auth_required": True,
                },
            })
        
        return endpoints
    
    def _get_device_vulnerabilities(self, device_type: str) -> Dict[str, Dict[str, Any]]:
        """
        Get vulnerabilities for a device type.
        
        Args:
            device_type: Device type
            
        Returns:
            Dictionary of vulnerability_id -> vulnerability info
        """
        vulnerabilities = {
            # Common vulnerabilities for all devices
            "default_credentials": {
                "type": "authentication",
                "description": "Device uses default credentials",
                "enabled": True,
            },
            "session_hijacking": {
                "type": "session",
                "description": "Weak session management allows session hijacking",
                "enabled": True,
            },
            "command_injection": {
                "type": "injection",
                "description": "Command injection in diagnostic tools",
                "enabled": True,
                "endpoint": "/api/diagnostics",
                "parameter": "host",
            },
        }
        
        # Device-specific vulnerabilities
        if device_type == "ip_camera":
            vulnerabilities.update({
                "rtsp_bypass": {
                    "type": "authentication",
                    "description": "RTSP stream accessible without authentication",
                    "enabled": True,
                },
                "snapshot_bypass": {
                    "type": "authentication",
                    "description": "Camera snapshot accessible with direct URL",
                    "enabled": True,
                },
                "firmware_extraction": {
                    "type": "information_disclosure",
                    "description": "Firmware can be downloaded without authentication",
                    "enabled": True,
                    "endpoint": "/api/firmware_download",
                },
            })
        elif device_type == "router":
            vulnerabilities.update({
                "csrf": {
                    "type": "csrf",
                    "description": "No CSRF protection on configuration changes",
                    "enabled": True,
                },
                "upnp_exposure": {
                    "type": "misconfiguration",
                    "description": "UPnP enabled and exposed to WAN",
                    "enabled": True,
                },
                "weak_wifi": {
                    "type": "encryption",
                    "description": "Weak WiFi encryption (WEP/WPA)",
                    "enabled": True,
                },
            })
        elif device_type == "dvr":
            vulnerabilities.update({
                "backdoor_account": {
                    "type": "authentication",
                    "description": "Hidden backdoor account",
                    "enabled": True,
                    "username": "maintenance",
                    "password": "DVR2025",
                },
                "unauthenticated_streaming": {
                    "type": "authentication",
                    "description": "Video streams accessible without authentication",
                    "enabled": True,
                },
                "path_traversal": {
                    "type": "injection",
                    "description": "Path traversal in recording playback",
                    "enabled": True,
                    "endpoint": "/api/play_recording",
                    "parameter": "file",
                },
            })
        
        return vulnerabilities
    
    def _handle_client(self, session_id: str) -> None:
        """
        Handle an HTTP client connection.
        
        Args:
            session_id: Session identifier
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        
        # Select a device profile
        device_types = list(self.device_profiles.keys())
        if device_types:
            # For now, randomly select a device type
            import random
            device_type = random.choice(device_types)
            session["device_type"] = device_type
            session["device_profile"] = self.device_profiles[device_type]
            
            self.logger.info(
                f"Selected HTTP device profile for {client_address[0]}: {device_type}",
                device_type=device_type,
                session_id=session_id
            )
        else:
            self.logger.error(f"No HTTP device profiles available")
            self.close_session(session_id)
            return
        
        try:
            # Read HTTP request
            request_data = self._read_http_request(session_id)
            if not request_data:
                self.close_session(session_id)
                return
            
            # Parse HTTP request
            request = self._parse_http_request(request_data)
            if not request:
                self._send_http_response(session_id, 400, "Bad Request")
                self.close_session(session_id)
                return
            
            # Log HTTP request
            self.logger.log_http_request(
                src_ip=client_address[0],
                method=request["method"],
                path=request["path"],
                user_agent=request["headers"].get("User-Agent", ""),
                session_id=session_id
            )
            
            # Handle HTTP request
            self._handle_http_request(session_id, request)
            
            # Close connection if not keep-alive
            if request["headers"].get("Connection", "").lower() != "keep-alive":
                self.close_session(session_id)
            
        except Exception as e:
            self.logger.error(
                f"Error handling HTTP client {client_address[0]}: {e}",
                error=str(e),
                session_id=session_id
            )
            self.close_session(session_id)
    
    def _read_http_request(self, session_id: str) -> Optional[bytes]:
        """
        Read an HTTP request from the client.
        
        Args:
            session_id: Session identifier
            
        Returns:
            HTTP request data or None if error
        """
        if session_id not in self.sessions:
            return None
        
        # Read headers
        header_data = bytearray()
        content_length = 0
        headers_complete = False
        
        while not headers_complete and len(header_data) < self.max_request_size:
            chunk = self.receive_data(session_id)
            if not chunk:
                return None
            
            header_data.extend(chunk)
            
            # Check if headers are complete
            if b"\r\n\r\n" in header_data:
                headers_complete = True
                
                # Split headers and body
                headers_end = header_data.find(b"\r\n\r\n") + 4
                headers = header_data[:headers_end].decode("utf-8", errors="ignore")
                
                # Extract Content-Length
                match = re.search(r"Content-Length:\s*(\d+)", headers, re.IGNORECASE)
                if match:
                    content_length = int(match.group(1))
                
                # Check if we already have the complete body
                body_received = len(header_data) - headers_end
                if body_received >= content_length:
                    # We have the complete request
                    return header_data[:headers_end + content_length]
                
                # Need to read more data for the body
                body_data = header_data[headers_end:]
                remaining = content_length - len(body_data)
                
                # Read the rest of the body
                while remaining > 0:
                    chunk = self.receive_data(session_id)
                    if not chunk:
                        return None
                    
                    body_data.extend(chunk)
                    remaining = content_length - len(body_data)
                
                # Combine headers and body
                return header_data[:headers_end] + body_data[:content_length]
        
        # Headers too large or incomplete
        return None
    
    def _parse_http_request(self, request_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse an HTTP request.
        
        Args:
            request_data: HTTP request data
            
        Returns:
            Parsed HTTP request or None if error
        """
        try:
            # Split headers and body
            headers_end = request_data.find(b"\r\n\r\n")
            if headers_end == -1:
                return None
            
            headers_data = request_data[:headers_end].decode("utf-8", errors="ignore")
            body_data = request_data[headers_end + 4:]
            
            # Parse request line
            lines = headers_data.split("\r\n")
            if not lines:
                return None
            
            request_line = lines[0].split(" ")
            if len(request_line) != 3:
                return None
            
            method, path, version = request_line
            
            # Parse query parameters
            path_parts = path.split("?", 1)
            base_path = path_parts[0]
            query_string = path_parts[1] if len(path_parts) > 1 else ""
            
            query_params = {}
            if query_string:
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        query_params[key] = urllib.parse.unquote_plus(value)
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            
            # Parse cookies
            cookies = {}
            if "Cookie" in headers:
                for cookie in headers["Cookie"].split(";"):
                    if "=" in cookie:
                        key, value = cookie.strip().split("=", 1)
                        cookies[key] = value
            
            # Parse body based on content type
            body = None
            content_type = headers.get("Content-Type", "")
            
            if "application/x-www-form-urlencoded" in content_type:
                body = {}
                if body_data:
                    body_str = body_data.decode("utf-8", errors="ignore")
                    for param in body_str.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            body[key] = urllib.parse.unquote_plus(value)
            
            elif "application/json" in content_type:
                if body_data:
                    body_str = body_data.decode("utf-8", errors="ignore")
                    body = json.loads(body_str)
            
            elif "multipart/form-data" in content_type:
                # Basic multipart form parsing
                body = {}
                if body_data:
                    # Get boundary
                    boundary_match = re.search(r"boundary=([^;]+)", content_type)
                    if boundary_match:
                        boundary = boundary_match.group(1)
                        # Parse multipart form data (simplified)
                        parts = body_data.split(f"--{boundary}".encode())
                        for part in parts:
                            if b"\r\n\r\n" in part:
                                part_headers, part_content = part.split(b"\r\n\r\n", 1)
                                part_headers = part_headers.decode("utf-8", errors="ignore")
                                # Extract name
                                name_match = re.search(r'name="([^"]+)"', part_headers)
                                if name_match:
                                    name = name_match.group(1)
                                    # Remove trailing boundary marker if present
                                    if part_content.endswith(b"--\r\n"):
                                        part_content = part_content[:-4]
                                    elif part_content.endswith(b"\r\n"):
                                        part_content = part_content[:-2]
                                    
                                    # Check if this is a file upload
                                    filename_match = re.search(r'filename="([^"]+)"', part_headers)
                                    if filename_match:
                                        filename = filename_match.group(1)
                                        body[name] = {
                                            "filename": filename,
                                            "content": part_content,
                                        }
                                    else:
                                        # Regular form field
                                        body[name] = part_content.decode("utf-8", errors="ignore")
            else:
                # Raw body
                body = body_data
            
            return {
                "method": method,
                "path": path,
                "base_path": base_path,
                "query_params": query_params,
                "version": version,
                "headers": headers,
                "cookies": cookies,
                "body": body,
                "raw_body": body_data,
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing HTTP request: {e}")
            return None
    
    def _handle_http_request(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle an HTTP request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        # Check if this is an API endpoint
        if request["base_path"].startswith("/api/"):
            self._handle_api_request(session_id, request)
            return
        
        # Check if this is a static file
        if self._is_static_file(request["base_path"]):
            self._serve_static_file(session_id, request)
            return
        
        # Check if this is a known page
        web_pages = device_profile["web_pages"]
        if request["base_path"] in web_pages:
            page_info = web_pages[request["base_path"]]
            
            # Check if authentication is required
            if page_info["auth_required"] and not self._is_authenticated(session_id, request):
                # Redirect to login page
                self._send_redirect(session_id, "/")
                return
            
            # Handle special pages
            if request["base_path"] == "/logout.cgi":
                self._handle_logout(session_id, request)
                return
            
            # Serve the page
            if page_info["template"]:
                self._serve_template(session_id, request, page_info["template"])
                return
        
        # Handle request based on method
        if request["method"] in self.request_handlers:
            self.request_handlers[request["method"]](session_id, request)
            return
        
        # Method not allowed
        self._send_http_response(session_id, 405, "Method Not Allowed")
    
    def _handle_api_request(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle an API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        # Check if this is a known API endpoint
        api_endpoints = device_profile["api_endpoints"]
        if request["base_path"] in api_endpoints:
            endpoint_info = api_endpoints[request["base_path"]]
            
            # Check if method is allowed
            if request["method"] != endpoint_info["method"]:
                self._send_http_response(session_id, 405, "Method Not Allowed")
                return
            
            # Check if authentication is required
            if endpoint_info["auth_required"] and not self._is_authenticated(session_id, request):
                self._send_json_response(session_id, 401, {"error": "Authentication required"})
                return
            
            # Call the handler
            if "handler" in endpoint_info and callable(endpoint_info["handler"]):
                endpoint_info["handler"](session_id, request)
                return
        
        # API endpoint not found
        self._send_json_response(session_id, 404, {"error": "API endpoint not found"})
    
    def _handle_get_request(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle a GET request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Default behavior for GET requests
        self._send_http_response(session_id, 404, "Not Found")
    
    def _handle_post_request(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle a POST request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Handle login form submission
        if request["base_path"] == "/login.cgi":
            self._handle_login(session_id, request)
            return
        
        # Default behavior for POST requests
        self._send_http_response(session_id, 404, "Not Found")
    
    def _handle_head_request(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle a HEAD request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Similar to GET but without body
        self._send_http_response(session_id, 404, "Not Found", include_body=False)
    
    def _handle_login(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle a login request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        client_address = session["address"]
        
        # Get credentials from form data
        username = ""
        password = ""
        
        if isinstance(request["body"], dict):
            username = request["body"].get("username", "")
            password = request["body"].get("password", "")
        
        # Check credentials
        authenticated = False
        
        # Check for backdoor account (if enabled)
        backdoor = device_profile["vulnerabilities"].get("backdoor_account", {})
        if backdoor.get("enabled", False) and username == backdoor.get("username", "") and password == backdoor.get("password", ""):
            authenticated = True
        
        # Check default credentials
        elif username == device_profile["default_username"] and password == device_profile["default_password"]:
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
            # Create HTTP session
            http_session_id = self._create_http_session(session_id, username)
            
            # Set session cookie
            cookie = f"session={http_session_id}; Path=/; HttpOnly"
            
            # Redirect to index page
            self._send_redirect(session_id, "/index.html", cookie)
        else:
            # Redirect back to login page with error
            self._send_redirect(session_id, "/?error=1")
    
    def _handle_logout(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle a logout request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Get HTTP session ID from cookie
        http_session_id = self._get_session_id_from_request(request)
        
        # Invalidate HTTP session
        if http_session_id and http_session_id in self.http_sessions:
            del self.http_sessions[http_session_id]
        
        # Clear session cookie
        cookie = "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        
        # Redirect to login page
        self._send_redirect(session_id, "/", cookie)
    
    def _create_http_session(self, session_id: str, username: str) -> str:
        """
        Create an HTTP session.
        
        Args:
            session_id: Session identifier
            username: Authenticated username
            
        Returns:
            HTTP session ID
        """
        # Generate HTTP session ID
        import uuid
        http_session_id = str(uuid.uuid4())
        
        # Create session
        self.http_sessions[http_session_id] = {
            "username": username,
            "created": time.time(),
            "last_activity": time.time(),
            "session_id": session_id,
        }
        
        return http_session_id
    
    def _is_authenticated(self, session_id: str, request: Dict[str, Any]) -> bool:
        """
        Check if a request is authenticated.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
            
        Returns:
            True if authenticated, False otherwise
        """
        # Get HTTP session ID from cookie
        http_session_id = self._get_session_id_from_request(request)
        
        # Check if session exists and is valid
        if http_session_id and http_session_id in self.http_sessions:
            # Update last activity
            self.http_sessions[http_session_id]["last_activity"] = time.time()
            return True
        
        return False
    
    def _get_session_id_from_request(self, request: Dict[str, Any]) -> Optional[str]:
        """
        Get HTTP session ID from request.
        
        Args:
            request: Parsed HTTP request
            
        Returns:
            HTTP session ID or None if not found
        """
        # Check cookies
        if "session" in request["cookies"]:
            return request["cookies"]["session"]
        
        return None
    
    def _is_static_file(self, path: str) -> bool:
        """
        Check if a path refers to a static file.
        
        Args:
            path: Request path
            
        Returns:
            True if static file, False otherwise
        """
        # Check file extension
        for ext in self.content_types:
            if path.endswith(ext):
                return True
        
        return False
    
    def _serve_static_file(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Serve a static file.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Get file extension
        path = request["base_path"]
        _, ext = os.path.splitext(path)
        
        # Get content type
        content_type = self.content_types.get(ext, "application/octet-stream")
        
        # For now, just return a placeholder response
        # In a real implementation, this would serve actual static files
        if ext in [".jpg", ".jpeg", ".png", ".gif"]:
            # Placeholder image data (1x1 transparent pixel)
            content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x00\x00\x02\x00\x01\xe5\'\xde\xe2\x00\x00\x00\x00IEND\xaeB`\x82"
        else:
            # Placeholder text content
            content = f"This is a placeholder for {path}".encode()
        
        # Send response
        self._send_http_response(
            session_id,
            200,
            "OK",
            headers={"Content-Type": content_type},
            body=content
        )
    
    def _serve_template(self, session_id: str, request: Dict[str, Any], template_name: str) -> None:
        """
        Serve a template page.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
            template_name: Template name
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        # Get template content based on device type and template name
        content = self._get_template_content(device_profile["type"], template_name)
        
        # Send response
        self._send_http_response(
            session_id,
            200,
            "OK",
            headers={"Content-Type": "text/html"},
            body=content.encode()
        )
    
    def _get_template_content(self, device_type: str, template_name: str) -> str:
        """
        Get template content.
        
        Args:
            device_type: Device type
            template_name: Template name
            
        Returns:
            Template content
        """
        # For now, return placeholder templates
        # In a real implementation, this would load actual template files
        
        if template_name == "login.html":
            return self._get_login_template()
        
        elif template_name.startswith("camera_"):
            return self._get_camera_template(template_name)
        
        elif template_name.startswith("router_"):
            return self._get_router_template(template_name)
        
        elif template_name.startswith("dvr_"):
            return self._get_dvr_template(template_name)
        
        # Default template
        return f"<html><body><h1>Template: {template_name}</h1></body></html>"
    
    def _get_login_template(self) -> str:
        """
        Get login template.
        
        Returns:
            Login template content
        """
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Device Login</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f0f0f0;
                    margin: 0;
                    padding: 0;
                }
                .login-container {
                    width: 300px;
                    margin: 100px auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }
                h1 {
                    text-align: center;
                    color: #333;
                }
                .error {
                    color: red;
                    text-align: center;
                    margin-bottom: 15px;
                    display: none;
                }
                input[type="text"], input[type="password"] {
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 3px;
                    box-sizing: border-box;
                }
                input[type="submit"] {
                    width: 100%;
                    padding: 10px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 3px;
                    cursor: pointer;
                }
                input[type="submit"]:hover {
                    background-color: #45a049;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>Device Login</h1>
                <div id="error-message" class="error">Invalid username or password</div>
                <form action="/login.cgi" method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <input type="submit" value="Login">
                </form>
            </div>
            <script>
                // Show error message if login failed
                if (window.location.search.includes('error=1')) {
                    document.getElementById('error-message').style.display = 'block';
                }
            </script>
        </body>
        </html>
        """
    
    def _get_camera_template(self, template_name: str) -> str:
        """
        Get camera template.
        
        Args:
            template_name: Template name
            
        Returns:
            Template content
        """
        if template_name == "camera_home.html":
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>IP Camera - Dashboard</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f0f0f0;
                    }
                    .header {
                        background-color: #333;
                        color: white;
                        padding: 10px 20px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .header h1 {
                        margin: 0;
                        font-size: 24px;
                    }
                    .header a {
                        color: white;
                        text-decoration: none;
                    }
                    .container {
                        display: flex;
                        min-height: calc(100vh - 60px);
                    }
                    .sidebar {
                        width: 200px;
                        background-color: #333;
                        color: white;
                        padding: 20px 0;
                    }
                    .sidebar ul {
                        list-style-type: none;
                        padding: 0;
                        margin: 0;
                    }
                    .sidebar li {
                        padding: 10px 20px;
                    }
                    .sidebar li:hover {
                        background-color: #444;
                    }
                    .sidebar a {
                        color: white;
                        text-decoration: none;
                        display: block;
                    }
                    .content {
                        flex: 1;
                        padding: 20px;
                    }
                    .dashboard {
                        display: grid;
                        grid-template-columns: repeat(2, 1fr);
                        gap: 20px;
                    }
                    .card {
                        background-color: white;
                        border-radius: 5px;
                        padding: 20px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    .card h2 {
                        margin-top: 0;
                        color: #333;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>IP Camera Dashboard</h1>
                    <a href="/logout.cgi">Logout</a>
                </div>
                <div class="container">
                    <div class="sidebar">
                        <ul>
                            <li><a href="/index.html">Dashboard</a></li>
                            <li><a href="/live.html">Live View</a></li>
                            <li><a href="/settings.html">Camera Settings</a></li>
                            <li><a href="/network.html">Network Settings</a></li>
                            <li><a href="/users.html">User Management</a></li>
                            <li><a href="/maintenance.html">Maintenance</a></li>
                        </ul>
                    </div>
                    <div class="content">
                        <div class="dashboard">
                            <div class="card">
                                <h2>Camera Status</h2>
                                <p><strong>Status:</strong> Online</p>
                                <p><strong>Uptime:</strong> 3 days, 7 hours</p>
                                <p><strong>Resolution:</strong> 1080p</p>
                                <p><strong>Framerate:</strong> 30 fps</p>
                            </div>
                            <div class="card">
                                <h2>Network Information</h2>
                                <p><strong>IP Address:</strong> 192.168.1.100</p>
                                <p><strong>MAC Address:</strong> 00:11:22:33:44:55</p>
                                <p><strong>Gateway:</strong> 192.168.1.1</p>
                                <p><strong>DNS:</strong> 8.8.8.8</p>
                            </div>
                            <div class="card">
                                <h2>Storage</h2>
                                <p><strong>Total Space:</strong> 32 GB</p>
                                <p><strong>Used Space:</strong> 12.4 GB (38%)</p>
                                <p><strong>Free Space:</strong> 19.6 GB (62%)</p>
                            </div>
                            <div class="card">
                                <h2>System Information</h2>
                                <p><strong>Model:</strong> IP-CAM-2000</p>
                                <p><strong>Firmware:</strong> v2.4.6</p>
                                <p><strong>Serial Number:</strong> IC2000-12345678</p>
                                <p><strong>Last Update:</strong> 2025-03-15</p>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
        
        elif template_name == "camera_live.html":
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>IP Camera - Live View</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f0f0f0;
                    }
                    .header {
                        background-color: #333;
                        color: white;
                        padding: 10px 20px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .header h1 {
                        margin: 0;
                        font-size: 24px;
                    }
                    .header a {
                        color: white;
                        text-decoration: none;
                    }
                    .container {
                        display: flex;
                        min-height: calc(100vh - 60px);
                    }
                    .sidebar {
                        width: 200px;
                        background-color: #333;
                        color: white;
                        padding: 20px 0;
                    }
                    .sidebar ul {
                        list-style-type: none;
                        padding: 0;
                        margin: 0;
                    }
                    .sidebar li {
                        padding: 10px 20px;
                    }
                    .sidebar li:hover {
                        background-color: #444;
                    }
                    .sidebar a {
                        color: white;
                        text-decoration: none;
                        display: block;
                    }
                    .content {
                        flex: 1;
                        padding: 20px;
                    }
                    .live-view {
                        background-color: white;
                        border-radius: 5px;
                        padding: 20px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    .live-view h2 {
                        margin-top: 0;
                        color: #333;
                    }
                    .video-container {
                        width: 100%;
                        height: 480px;
                        background-color: #000;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin-bottom: 20px;
                    }
                    .controls {
                        display: flex;
                        justify-content: space-between;
                        margin-bottom: 20px;
                    }
                    .controls button {
                        padding: 10px 15px;
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 3px;
                        cursor: pointer;
                    }
                    .controls button:hover {
                        background-color: #45a049;
                    }
                    .settings {
                        display: flex;
                        justify-content: space-between;
                    }
                    .settings select {
                        padding: 5px;
                        border-radius: 3px;
                        border: 1px solid #ddd;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>IP Camera Live View</h1>
                    <a href="/logout.cgi">Logout</a>
                </div>
                <div class="container">
                    <div class="sidebar">
                        <ul>
                            <li><a href="/index.html">Dashboard</a></li>
                            <li><a href="/live.html">Live View</a></li>
                            <li><a href="/settings.html">Camera Settings</a></li>
                            <li><a href="/network.html">Network Settings</a></li>
                            <li><a href="/users.html">User Management</a></li>
                            <li><a href="/maintenance.html">Maintenance</a></li>
                        </ul>
                    </div>
                    <div class="content">
                        <div class="live-view">
                            <h2>Live Camera Feed</h2>
                            <div class="video-container">
                                <img src="/api/snapshot.jpg" alt="Live Camera Feed" id="camera-feed">
                            </div>
                            <div class="controls">
                                <button id="snapshot">Take Snapshot</button>
                                <button id="record">Start Recording</button>
                                <button id="fullscreen">Fullscreen</button>
                            </div>
                            <div class="settings">
                                <div>
                                    <label for="resolution">Resolution:</label>
                                    <select id="resolution">
                                        <option value="720p">720p</option>
                                        <option value="1080p" selected>1080p</option>
                                        <option value="4K">4K</option>
                                    </select>
                                </div>
                                <div>
                                    <label for="framerate">Framerate:</label>
                                    <select id="framerate">
                                        <option value="15">15 fps</option>
                                        <option value="30" selected>30 fps</option>
                                        <option value="60">60 fps</option>
                                    </select>
                                </div>
                                <div>
                                    <label for="quality">Quality:</label>
                                    <select id="quality">
                                        <option value="low">Low</option>
                                        <option value="medium">Medium</option>
                                        <option value="high" selected>High</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <script>
                    // Simulate live feed by refreshing the image
                    setInterval(function() {
                        const img = document.getElementById('camera-feed');
                        img.src = '/api/snapshot.jpg?t=' + new Date().getTime();
                    }, 1000);
                    
                    // Button event handlers
                    document.getElementById('snapshot').addEventListener('click', function() {
                        alert('Snapshot saved to storage');
                    });
                    
                    let recording = false;
                    document.getElementById('record').addEventListener('click', function() {
                        recording = !recording;
                        this.textContent = recording ? 'Stop Recording' : 'Start Recording';
                        if (recording) {
                            alert('Recording started');
                        } else {
                            alert('Recording saved to storage');
                        }
                    });
                    
                    document.getElementById('fullscreen').addEventListener('click', function() {
                        const videoContainer = document.querySelector('.video-container');
                        if (videoContainer.requestFullscreen) {
                            videoContainer.requestFullscreen();
                        }
                    });
                </script>
            </body>
            </html>
            """
        
        # Default camera template
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>IP Camera - {template_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
                .header {{ background-color: #333; color: white; padding: 10px 20px; }}
                .content {{ padding: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>IP Camera</h1>
            </div>
            <div class="content">
                <h2>{template_name}</h2>
                <p>This is a placeholder for the {template_name} page.</p>
            </div>
        </body>
        </html>
        """
    
    def _get_router_template(self, template_name: str) -> str:
        """
        Get router template.
        
        Args:
            template_name: Template name
            
        Returns:
            Template content
        """
        if template_name == "router_home.html":
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Router - Dashboard</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f0f0f0;
                    }
                    .header {
                        background-color: #2c3e50;
                        color: white;
                        padding: 10px 20px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .header h1 {
                        margin: 0;
                        font-size: 24px;
                    }
                    .header a {
                        color: white;
                        text-decoration: none;
                    }
                    .container {
                        display: flex;
                        min-height: calc(100vh - 60px);
                    }
                    .sidebar {
                        width: 200px;
                        background-color: #2c3e50;
                        color: white;
                        padding: 20px 0;
                    }
                    .sidebar ul {
                        list-style-type: none;
                        padding: 0;
                        margin: 0;
                    }
                    .sidebar li {
                        padding: 10px 20px;
                    }
                    .sidebar li:hover {
                        background-color: #34495e;
                    }
                    .sidebar a {
                        color: white;
                        text-decoration: none;
                        display: block;
                    }
                    .content {
                        flex: 1;
                        padding: 20px;
                    }
                    .dashboard {
                        display: grid;
                        grid-template-columns: repeat(2, 1fr);
                        gap: 20px;
                    }
                    .card {
                        background-color: white;
                        border-radius: 5px;
                        padding: 20px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    .card h2 {
                        margin-top: 0;
                        color: #2c3e50;
                    }
                    .status-indicator {
                        display: inline-block;
                        width: 10px;
                        height: 10px;
                        border-radius: 50%;
                        margin-right: 5px;
                    }
                    .status-online {
                        background-color: #2ecc71;
                    }
                    .status-offline {
                        background-color: #e74c3c;
                    }
                    .client-list {
                        list-style-type: none;
                        padding: 0;
                    }
                    .client-list li {
                        padding: 5px 0;
                        border-bottom: 1px solid #eee;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Router Dashboard</h1>
                    <a href="/logout.cgi">Logout</a>
                </div>
                <div class="container">
                    <div class="sidebar">
                        <ul>
                            <li><a href="/index.html">Dashboard</a></li>
                            <li><a href="/status.html">Status</a></li>
                            <li><a href="/wireless.html">Wireless Settings</a></li>
                            <li><a href="/network.html">Network Settings</a></li>
                            <li><a href="/security.html">Security Settings</a></li>
                            <li><a href="/admin.html">Administration</a></li>
                        </ul>
                    </div>
                    <div class="content">
                        <div class="dashboard">
                            <div class="card">
                                <h2>Internet Status</h2>
                                <p><span class="status-indicator status-online"></span> <strong>Internet:</strong> Connected</p>
                                <p><strong>WAN IP:</strong> 203.0.113.45</p>
                                <p><strong>Connection Type:</strong> DHCP</p>
                                <p><strong>DNS Servers:</strong> 8.8.8.8, 8.8.4.4</p>
                                <p><strong>Uptime:</strong> 5 days, 12 hours</p>
                            </div>
                            <div class="card">
                                <h2>Wireless Status</h2>
                                <p><span class="status-indicator status-online"></span> <strong>2.4GHz:</strong> Active</p>
                                <p><strong>SSID:</strong> Router_SSID</p>
                                <p><strong>Channel:</strong> 6</p>
                                <p><strong>Security:</strong> WPA2-PSK</p>
                                <p><span class="status-indicator status-online"></span> <strong>5GHz:</strong> Active</p>
                                <p><strong>SSID:</strong> Router_SSID_5G</p>
                                <p><strong>Channel:</strong> 36</p>
                                <p><strong>Security:</strong> WPA2-PSK</p>
                            </div>
                            <div class="card">
                                <h2>Connected Devices</h2>
                                <p><strong>Total Devices:</strong> 3</p>
                                <ul class="client-list">
                                    <li><strong>192.168.1.100</strong> - 00:11:22:33:44:55 - Android-Phone</li>
                                    <li><strong>192.168.1.101</strong> - AA:BB:CC:DD:EE:FF - Windows-PC</li>
                                    <li><strong>192.168.1.102</strong> - 11:22:33:44:55:66 - Smart-TV</li>
                                </ul>
                            </div>
                            <div class="card">
                                <h2>System Information</h2>
                                <p><strong>Model:</strong> WR-3000</p>
                                <p><strong>Firmware:</strong> v1.2.8</p>
                                <p><strong>CPU Usage:</strong> 15%</p>
                                <p><strong>Memory Usage:</strong> 42%</p>
                                <p><strong>Temperature:</strong> 45°C</p>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
        
        # Default router template
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Router - {template_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
                .header {{ background-color: #2c3e50; color: white; padding: 10px 20px; }}
                .content {{ padding: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Router</h1>
            </div>
            <div class="content">
                <h2>{template_name}</h2>
                <p>This is a placeholder for the {template_name} page.</p>
            </div>
        </body>
        </html>
        """
    
    def _get_dvr_template(self, template_name: str) -> str:
        """
        Get DVR template.
        
        Args:
            template_name: Template name
            
        Returns:
            Template content
        """
        if template_name == "dvr_home.html":
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>DVR - Dashboard</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f0f0f0;
                    }
                    .header {
                        background-color: #34495e;
                        color: white;
                        padding: 10px 20px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .header h1 {
                        margin: 0;
                        font-size: 24px;
                    }
                    .header a {
                        color: white;
                        text-decoration: none;
                    }
                    .container {
                        display: flex;
                        min-height: calc(100vh - 60px);
                    }
                    .sidebar {
                        width: 200px;
                        background-color: #34495e;
                        color: white;
                        padding: 20px 0;
                    }
                    .sidebar ul {
                        list-style-type: none;
                        padding: 0;
                        margin: 0;
                    }
                    .sidebar li {
                        padding: 10px 20px;
                    }
                    .sidebar li:hover {
                        background-color: #2c3e50;
                    }
                    .sidebar a {
                        color: white;
                        text-decoration: none;
                        display: block;
                    }
                    .content {
                        flex: 1;
                        padding: 20px;
                    }
                    .dashboard {
                        display: grid;
                        grid-template-columns: repeat(2, 1fr);
                        gap: 20px;
                    }
                    .card {
                        background-color: white;
                        border-radius: 5px;
                        padding: 20px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    .card h2 {
                        margin-top: 0;
                        color: #34495e;
                    }
                    .channel-grid {
                        display: grid;
                        grid-template-columns: repeat(2, 1fr);
                        gap: 10px;
                    }
                    .channel {
                        background-color: #000;
                        height: 120px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: white;
                        font-weight: bold;
                    }
                    .recording-list {
                        list-style-type: none;
                        padding: 0;
                    }
                    .recording-list li {
                        padding: 5px 0;
                        border-bottom: 1px solid #eee;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>DVR Dashboard</h1>
                    <a href="/logout.cgi">Logout</a>
                </div>
                <div class="container">
                    <div class="sidebar">
                        <ul>
                            <li><a href="/index.html">Dashboard</a></li>
                            <li><a href="/live.html">Live View</a></li>
                            <li><a href="/playback.html">Playback</a></li>
                            <li><a href="/config.html">Configuration</a></li>
                            <li><a href="/storage.html">Storage Management</a></li>
                            <li><a href="/system.html">System Settings</a></li>
                        </ul>
                    </div>
                    <div class="content">
                        <div class="dashboard">
                            <div class="card">
                                <h2>Channel Status</h2>
                                <div class="channel-grid">
                                    <div class="channel">CH1</div>
                                    <div class="channel">CH2</div>
                                    <div class="channel">CH3</div>
                                    <div class="channel">CH4</div>
                                </div>
                            </div>
                            <div class="card">
                                <h2>Recording Status</h2>
                                <p><strong>Recording Mode:</strong> Continuous</p>
                                <p><strong>Resolution:</strong> 1080p</p>
                                <p><strong>Frame Rate:</strong> 30 fps</p>
                                <p><strong>Quality:</strong> High</p>
                                <p><strong>Motion Detection:</strong> Enabled</p>
                            </div>
                            <div class="card">
                                <h2>Recent Recordings</h2>
                                <ul class="recording-list">
                                    <li><strong>CH1_20250520_083000.mp4</strong> - 256MB - 2025-05-20 08:30:00</li>
                                    <li><strong>CH2_20250520_090000.mp4</strong> - 128MB - 2025-05-20 09:00:00</li>
                                    <li><strong>CH3_20250520_100000.mp4</strong> - 512MB - 2025-05-20 10:00:00</li>
                                </ul>
                            </div>
                            <div class="card">
                                <h2>System Information</h2>
                                <p><strong>Model:</strong> DVR-8CH</p>
                                <p><strong>Firmware:</strong> v3.1.0</p>
                                <p><strong>Storage:</strong> 2TB (68% used)</p>
                                <p><strong>IP Address:</strong> 192.168.1.10</p>
                                <p><strong>Uptime:</strong> 14 days, 3 hours</p>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
        
        # Default DVR template
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>DVR - {template_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
                .header {{ background-color: #34495e; color: white; padding: 10px 20px; }}
                .content {{ padding: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>DVR</h1>
            </div>
            <div class="content">
                <h2>{template_name}</h2>
                <p>This is a placeholder for the {template_name} page.</p>
            </div>
        </body>
        </html>
        """
    
    def _send_http_response(self, session_id: str, status_code: int, status_text: str, 
                           headers: Optional[Dict[str, str]] = None, 
                           body: Optional[bytes] = None,
                           include_body: bool = True) -> None:
        """
        Send an HTTP response.
        
        Args:
            session_id: Session identifier
            status_code: HTTP status code
            status_text: HTTP status text
            headers: Additional HTTP headers
            body: Response body
            include_body: Whether to include the body (for HEAD requests)
        """
        if session_id not in self.sessions:
            return
        
        # Build response headers
        response_headers = {
            "Server": self.server_header,
            "Date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
            "Connection": "close",
        }
        
        # Add content length if body is provided
        if body and include_body:
            response_headers["Content-Length"] = str(len(body))
        
        # Add additional headers
        if headers:
            response_headers.update(headers)
        
        # Build response
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        
        # Add headers
        for name, value in response_headers.items():
            response += f"{name}: {value}\r\n"
        
        # Add empty line to separate headers from body
        response += "\r\n"
        
        # Send headers
        self.send_data(session_id, response.encode())
        
        # Send body if provided and needed
        if body and include_body:
            self.send_data(session_id, body)
    
    def _send_json_response(self, session_id: str, status_code: int, data: Any) -> None:
        """
        Send a JSON response.
        
        Args:
            session_id: Session identifier
            status_code: HTTP status code
            data: JSON data
        """
        # Convert data to JSON
        json_data = json.dumps(data).encode()
        
        # Get status text
        status_text = {
            200: "OK",
            201: "Created",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }.get(status_code, "Unknown")
        
        # Send response
        self._send_http_response(
            session_id,
            status_code,
            status_text,
            headers={"Content-Type": "application/json"},
            body=json_data
        )
    
    def _send_redirect(self, session_id: str, location: str, cookie: Optional[str] = None) -> None:
        """
        Send a redirect response.
        
        Args:
            session_id: Session identifier
            location: Redirect location
            cookie: Optional cookie to set
        """
        headers = {
            "Location": location,
        }
        
        if cookie:
            headers["Set-Cookie"] = cookie
        
        self._send_http_response(
            session_id,
            302,
            "Found",
            headers=headers,
            body=f"Redirecting to {location}".encode()
        )
    
    # API endpoint handlers
    
    def _api_login(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle login API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        client_address = session["address"]
        
        # Get credentials from JSON body
        if not isinstance(request["body"], dict):
            self._send_json_response(session_id, 400, {"error": "Invalid request body"})
            return
        
        username = request["body"].get("username", "")
        password = request["body"].get("password", "")
        
        # Check credentials
        authenticated = False
        
        # Check for backdoor account (if enabled)
        backdoor = device_profile["vulnerabilities"].get("backdoor_account", {})
        if backdoor.get("enabled", False) and username == backdoor.get("username", "") and password == backdoor.get("password", ""):
            authenticated = True
        
        # Check default credentials
        elif username == device_profile["default_username"] and password == device_profile["default_password"]:
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
            # Create HTTP session
            http_session_id = self._create_http_session(session_id, username)
            
            # Send response with session token
            self._send_json_response(
                session_id,
                200,
                {
                    "success": True,
                    "message": "Login successful",
                    "session_token": http_session_id,
                }
            )
        else:
            # Send error response
            self._send_json_response(
                session_id,
                401,
                {
                    "success": False,
                    "message": "Invalid username or password",
                }
            )
    
    def _api_logout(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle logout API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Get HTTP session ID from cookie or request body
        http_session_id = self._get_session_id_from_request(request)
        
        if not http_session_id:
            # Try to get from request body
            if isinstance(request["body"], dict) and "session_token" in request["body"]:
                http_session_id = request["body"]["session_token"]
        
        # Invalidate HTTP session
        if http_session_id and http_session_id in self.http_sessions:
            del self.http_sessions[http_session_id]
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "message": "Logout successful",
            }
        )
    
    def _api_system_info(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle system info API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        device_profile = session["device_profile"]
        
        # Get system info based on device type
        device_type = device_profile["type"]
        
        if device_type == "ip_camera":
            system_info = {
                "model": device_profile["model"],
                "brand": device_profile["brand"],
                "firmware": device_profile["firmware"],
                "serial_number": f"{device_profile['model']}-12345678",
                "uptime": "3 days, 7 hours",
                "resolution": "1080p",
                "framerate": 30,
                "ip_address": "192.168.1.100",
                "mac_address": "00:11:22:33:44:55",
            }
        elif device_type == "router":
            system_info = {
                "model": device_profile["model"],
                "brand": device_profile["brand"],
                "firmware": device_profile["firmware"],
                "serial_number": f"{device_profile['model']}-87654321",
                "uptime": "5 days, 12 hours",
                "wan_ip": "203.0.113.45",
                "lan_ip": "192.168.1.1",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "cpu_usage": 15,
                "memory_usage": 42,
            }
        elif device_type == "dvr":
            system_info = {
                "model": device_profile["model"],
                "brand": device_profile["brand"],
                "firmware": device_profile["firmware"],
                "serial_number": f"{device_profile['model']}-24681357",
                "uptime": "14 days, 3 hours",
                "channels": 8,
                "recording_quality": "High",
                "ip_address": "192.168.1.10",
                "mac_address": "11:22:33:44:55:66",
                "storage_capacity": "2TB",
                "storage_used": "68%",
            }
        else:
            system_info = {
                "model": device_profile["model"],
                "brand": device_profile["brand"],
                "firmware": device_profile["firmware"],
            }
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "system_info": system_info,
            }
        )
    
    def _api_reboot(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle reboot API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "message": "Device is rebooting. Please wait...",
            }
        )
        
        # Close the session after a short delay
        time.sleep(1)
        self.close_session(session_id)
    
    def _api_firmware_upgrade(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle firmware upgrade API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        
        # Check if this is a file upload
        file_data = None
        filename = None
        
        if isinstance(request["body"], dict) and "firmware" in request["body"] and isinstance(request["body"]["firmware"], dict):
            file_info = request["body"]["firmware"]
            filename = file_info.get("filename", "firmware.bin")
            file_data = file_info.get("content")
        
        # Log firmware upgrade attempt
        self.logger.info(
            f"Firmware upgrade attempt from {client_address[0]}",
            event_type="firmware_upgrade",
            src_ip=client_address[0],
            filename=filename,
            session_id=session_id
        )
        
        # Check for command injection vulnerability
        if filename and (";" in filename or "|" in filename or "`" in filename):
            # This would be a command injection vulnerability in a real device
            self.logger.warning(
                f"Potential command injection attempt in firmware filename: {filename}",
                event_type="command_injection",
                src_ip=client_address[0],
                filename=filename,
                session_id=session_id
            )
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "message": "Firmware upgrade initiated. Device will reboot after upgrade.",
            }
        )
    
    # Device-specific API handlers
    
    def _api_camera_video_settings(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle camera video settings API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Send response with camera video settings
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "settings": {
                    "resolution": "1080p",
                    "framerate": 30,
                    "quality": "high",
                    "brightness": 50,
                    "contrast": 50,
                    "saturation": 50,
                    "sharpness": 50,
                    "motion_detection": True,
                    "night_mode": False,
                }
            }
        )
    
    def _api_camera_set_video_settings(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle set camera video settings API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Check for valid request body
        if not isinstance(request["body"], dict):
            self._send_json_response(session_id, 400, {"error": "Invalid request body"})
            return
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "message": "Video settings updated successfully",
            }
        )
    
    def _api_camera_network_settings(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle camera network settings API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Send response with camera network settings
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "settings": {
                    "ip_address": "192.168.1.100",
                    "subnet_mask": "255.255.255.0",
                    "gateway": "192.168.1.1",
                    "dns1": "8.8.8.8",
                    "dns2": "8.8.4.4",
                    "dhcp": False,
                    "http_port": 80,
                    "rtsp_port": 554,
                    "onvif_port": 8000,
                }
            }
        )
    
    def _api_camera_set_network_settings(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle set camera network settings API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Check for valid request body
        if not isinstance(request["body"], dict):
            self._send_json_response(session_id, 400, {"error": "Invalid request body"})
            return
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "message": "Network settings updated successfully. Device will reboot to apply changes.",
            }
        )
    
    def _api_router_wan_status(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle router WAN status API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Send response with router WAN status
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "status": {
                    "connected": True,
                    "ip_address": "203.0.113.45",
                    "subnet_mask": "255.255.255.0",
                    "gateway": "203.0.113.1",
                    "dns": ["8.8.8.8", "8.8.4.4"],
                    "connection_type": "DHCP",
                    "uptime": "5 days, 12 hours",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                }
            }
        )
    
    def _api_router_wireless_settings(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle router wireless settings API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Send response with router wireless settings
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "settings": {
                    "2.4ghz": {
                        "enabled": True,
                        "ssid": "Router_SSID",
                        "channel": 6,
                        "security": "WPA2-PSK",
                        "password": "password123",
                        "hidden": False,
                    },
                    "5ghz": {
                        "enabled": True,
                        "ssid": "Router_SSID_5G",
                        "channel": 36,
                        "security": "WPA2-PSK",
                        "password": "password123",
                        "hidden": False,
                    }
                }
            }
        )
    
    def _api_router_set_wireless_settings(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle set router wireless settings API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Check for valid request body
        if not isinstance(request["body"], dict):
            self._send_json_response(session_id, 400, {"error": "Invalid request body"})
            return
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "message": "Wireless settings updated successfully.",
            }
        )
    
    def _api_router_clients(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle router clients API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Send response with router clients
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "clients": [
                    {
                        "ip_address": "192.168.1.100",
                        "mac_address": "00:11:22:33:44:55",
                        "hostname": "Android-Phone",
                        "connection_type": "Wireless",
                        "signal_strength": 85,
                        "connected_since": "2025-05-20T08:30:00Z",
                    },
                    {
                        "ip_address": "192.168.1.101",
                        "mac_address": "AA:BB:CC:DD:EE:FF",
                        "hostname": "Windows-PC",
                        "connection_type": "Wired",
                        "signal_strength": None,
                        "connected_since": "2025-05-20T09:15:00Z",
                    },
                    {
                        "ip_address": "192.168.1.102",
                        "mac_address": "11:22:33:44:55:66",
                        "hostname": "Smart-TV",
                        "connection_type": "Wireless",
                        "signal_strength": 72,
                        "connected_since": "2025-05-20T10:45:00Z",
                    }
                ]
            }
        )
    
    def _api_dvr_recording_status(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle DVR recording status API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Send response with DVR recording status
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "status": {
                    "recording_mode": "Continuous",
                    "resolution": "1080p",
                    "framerate": 30,
                    "quality": "High",
                    "motion_detection": True,
                    "channels_recording": [1, 2, 3, 4],
                    "storage_used": "68%",
                    "estimated_days_remaining": 14,
                }
            }
        )
    
    def _api_dvr_channels(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle DVR channels API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Send response with DVR channels
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "channels": [
                    {
                        "id": 1,
                        "name": "Front Door",
                        "enabled": True,
                        "recording": True,
                        "resolution": "1080p",
                        "framerate": 30,
                    },
                    {
                        "id": 2,
                        "name": "Back Yard",
                        "enabled": True,
                        "recording": True,
                        "resolution": "1080p",
                        "framerate": 30,
                    },
                    {
                        "id": 3,
                        "name": "Garage",
                        "enabled": True,
                        "recording": True,
                        "resolution": "1080p",
                        "framerate": 30,
                    },
                    {
                        "id": 4,
                        "name": "Living Room",
                        "enabled": True,
                        "recording": True,
                        "resolution": "1080p",
                        "framerate": 30,
                    },
                ]
            }
        )
    
    def _api_dvr_recordings(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle DVR recordings API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        # Send response with DVR recordings
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "recordings": [
                    {
                        "id": 1,
                        "channel": 1,
                        "filename": "CH1_20250520_083000.mp4",
                        "size": 256000000,
                        "duration": 3600,
                        "start_time": "2025-05-20T08:30:00Z",
                        "end_time": "2025-05-20T09:30:00Z",
                    },
                    {
                        "id": 2,
                        "channel": 2,
                        "filename": "CH2_20250520_090000.mp4",
                        "size": 128000000,
                        "duration": 1800,
                        "start_time": "2025-05-20T09:00:00Z",
                        "end_time": "2025-05-20T09:30:00Z",
                    },
                    {
                        "id": 3,
                        "channel": 3,
                        "filename": "CH3_20250520_100000.mp4",
                        "size": 512000000,
                        "duration": 7200,
                        "start_time": "2025-05-20T10:00:00Z",
                        "end_time": "2025-05-20T12:00:00Z",
                    },
                ]
            }
        )
    
    def _api_dvr_start_recording(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle DVR start recording API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Check for valid request body
        if not isinstance(request["body"], dict):
            self._send_json_response(session_id, 400, {"error": "Invalid request body"})
            return
        
        # Get channel from request
        channel = request["body"].get("channel")
        
        if not channel:
            self._send_json_response(session_id, 400, {"error": "Channel is required"})
            return
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "message": f"Recording started on channel {channel}",
            }
        )
    
    def _api_dvr_stop_recording(self, session_id: str, request: Dict[str, Any]) -> None:
        """
        Handle DVR stop recording API request.
        
        Args:
            session_id: Session identifier
            request: Parsed HTTP request
        """
        if session_id not in self.sessions:
            return
        
        # Check for valid request body
        if not isinstance(request["body"], dict):
            self._send_json_response(session_id, 400, {"error": "Invalid request body"})
            return
        
        # Get channel from request
        channel = request["body"].get("channel")
        
        if not channel:
            self._send_json_response(session_id, 400, {"error": "Channel is required"})
            return
        
        # Send response
        self._send_json_response(
            session_id,
            200,
            {
                "success": True,
                "message": f"Recording stopped on channel {channel}",
            }
        )

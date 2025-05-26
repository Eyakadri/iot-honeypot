#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base protocol handler for the Advanced IoT Honeypot.
Defines the interface and common functionality for all protocol handlers.
"""

import abc
import uuid
import time
import socket
import threading
from typing import Dict, Any, Optional, Tuple, List, Callable

from advanced_honeypot.core.logger import get_logger
from advanced_honeypot.core.config import get_config


class BaseProtocolHandler(abc.ABC):
    """Abstract base class for all protocol handlers."""

    def __init__(self, protocol_name: str):
        """
        Initialize the protocol handler.
        
        Args:
            protocol_name: Name of the protocol (telnet, ssh, http, etc.)
        """
        self.protocol_name = protocol_name
        self.config = get_config()
        self.protocol_config = self.config.get_protocol_config(protocol_name)
        self.logger = get_logger(f"honeypot.protocol.{protocol_name}")
        
        # Get network configuration
        self.bind_ip = self.config.get("network", "bind_ip")
        self.port = self.config.get("network", f"{protocol_name}_port")
        
        # Connection settings
        self.max_connections = self.protocol_config.get("max_connections", 50)
        self.timeout = self.protocol_config.get("timeout", 300)
        
        # Active sessions
        self.sessions: Dict[str, Dict[str, Any]] = {}
        
        # Server socket
        self.server_socket = None
        self.running = False
        self.server_thread = None
    
    def start(self) -> bool:
        """
        Start the protocol handler.
        
        Returns:
            True if started successfully, False otherwise.
        """
        if self.running:
            self.logger.warning(f"{self.protocol_name} handler already running")
            return True
        
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(5)
            
            # Set running flag
            self.running = True
            
            # Start server thread
            self.server_thread = threading.Thread(
                target=self._accept_connections,
                name=f"{self.protocol_name}-server"
            )
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.logger.info(f"Started {self.protocol_name} handler on {self.bind_ip}:{self.port}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to start {self.protocol_name} handler: {e}")
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            self.running = False
            return False
    
    def stop(self) -> None:
        """Stop the protocol handler."""
        if not self.running:
            return
        
        self.logger.info(f"Stopping {self.protocol_name} handler")
        self.running = False
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing server socket: {e}")
            self.server_socket = None
        
        # Close all active sessions
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)
        
        # Wait for server thread to terminate
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5.0)
        
        self.logger.info(f"Stopped {self.protocol_name} handler")
    
    def _accept_connections(self) -> None:
        """Accept incoming connections."""
        self.logger.info(f"Accepting {self.protocol_name} connections")
        
        while self.running:
            try:
                # Accept connection with timeout to allow checking running flag
                self.server_socket.settimeout(1.0)
                try:
                    client_socket, client_address = self.server_socket.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
                    continue
                
                # Check if max connections reached
                if len(self.sessions) >= self.max_connections:
                    self.logger.warning(f"Max connections reached, rejecting {client_address[0]}:{client_address[1]}")
                    try:
                        client_socket.close()
                    except:
                        pass
                    continue
                
                # Create session
                session_id = str(uuid.uuid4())
                client_socket.settimeout(self.timeout)
                
                # Store session information
                self.sessions[session_id] = {
                    "socket": client_socket,
                    "address": client_address,
                    "start_time": time.time(),
                    "last_activity": time.time(),
                    "bytes_received": 0,
                    "bytes_sent": 0,
                    "commands": [],
                }
                
                # Log connection
                self.logger.log_connection(
                    src_ip=client_address[0],
                    src_port=client_address[1],
                    dst_port=self.port,
                    protocol=self.protocol_name,
                    session_id=session_id
                )
                
                # Handle connection in a new thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(session_id,),
                    name=f"{self.protocol_name}-client-{session_id[:8]}"
                )
                client_thread.daemon = True
                client_thread.start()
                
                # Store thread in session
                self.sessions[session_id]["thread"] = client_thread
            
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in connection acceptance loop: {e}")
                    time.sleep(1)  # Prevent CPU spinning on repeated errors
    
    @abc.abstractmethod
    def _handle_client(self, session_id: str) -> None:
        """
        Handle a client connection.
        
        Args:
            session_id: Session identifier
        """
        pass
    
    def close_session(self, session_id: str) -> None:
        """
        Close a client session.
        
        Args:
            session_id: Session identifier
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_socket = session.get("socket")
        
        # Close socket
        if client_socket:
            try:
                client_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing client socket: {e}")
        
        # Calculate session duration
        duration = time.time() - session["start_time"]
        
        # Log disconnection
        self.logger.log_disconnection(
            src_ip=session["address"][0],
            duration=duration,
            session_id=session_id
        )
        
        # Remove session
        del self.sessions[session_id]
    
    def send_data(self, session_id: str, data: bytes) -> bool:
        """
        Send data to a client.
        
        Args:
            session_id: Session identifier
            data: Data to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        client_socket = session.get("socket")
        
        if not client_socket:
            return False
        
        try:
            client_socket.sendall(data)
            session["bytes_sent"] += len(data)
            session["last_activity"] = time.time()
            return True
        except Exception as e:
            self.logger.error(f"Error sending data to {session['address'][0]}: {e}")
            self.close_session(session_id)
            return False
    
    def receive_data(self, session_id: str, buffer_size: int = 1024) -> Optional[bytes]:
        """
        Receive data from a client.
        
        Args:
            session_id: Session identifier
            buffer_size: Buffer size for receiving data
            
        Returns:
            Received data or None if error
        """
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        client_socket = session.get("socket")
        
        if not client_socket:
            return None
        
        try:
            data = client_socket.recv(buffer_size)
            if not data:  # Connection closed by client
                self.close_session(session_id)
                return None
            
            session["bytes_received"] += len(data)
            session["last_activity"] = time.time()
            return data
        except socket.timeout:
            self.logger.info(f"Connection timeout for {session['address'][0]}")
            self.close_session(session_id)
            return None
        except Exception as e:
            self.logger.error(f"Error receiving data from {session['address'][0]}: {e}")
            self.close_session(session_id)
            return None
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session information dictionary or None if not found
        """
        return self.sessions.get(session_id)
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """
        Get information about all active sessions.
        
        Returns:
            List of session information dictionaries
        """
        result = []
        for session_id, session in self.sessions.items():
            # Create a copy without socket and thread
            session_info = {k: v for k, v in session.items() 
                           if k not in ["socket", "thread"]}
            session_info["session_id"] = session_id
            result.append(session_info)
        return result
    
    def is_running(self) -> bool:
        """
        Check if the protocol handler is running.
        
        Returns:
            True if running, False otherwise
        """
        return self.running

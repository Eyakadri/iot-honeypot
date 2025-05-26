#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MQTT protocol handler for the Advanced IoT Honeypot.
Implements a realistic MQTT broker emulating IoT device communications.
"""

import os
import socket
import threading
import time
import json
import paho.mqtt.client as mqtt
from typing import Dict, Any, Optional, List, Tuple, Union, Callable

from advanced_honeypot.protocols.base_protocol import BaseProtocolHandler
from advanced_honeypot.core.logger import get_logger
from advanced_honeypot.core.config import get_config

class MQTTHandler(BaseProtocolHandler):
    """MQTT protocol handler for IoT device communication emulation."""

    def __init__(self):
        """Initialize the MQTT protocol handler."""
        super().__init__("mqtt")
        
        # Load device profiles
        self.device_profiles = {}
        self._load_device_profiles()
        
        # MQTT broker settings
        self.broker_id = self.protocol_config.get("broker_id", "MQTT-Broker-1.0")
        
        # Topic subscriptions and message history
        self.subscriptions = {}  # client_id -> list of topics
        self.message_history = {}  # topic -> list of messages
        self.retained_messages = {}  # topic -> retained message
        
        # Authentication
        self.require_auth = self.protocol_config.get("require_auth", True)
        
        # MQTT sessions
        self.mqtt_sessions = {}  # client_id -> session info
        
        # Predefined topics and responses
        self.predefined_topics = self._get_predefined_topics()
        
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
                "mqtt_username": device_config.get("mqtt_username", ""),
                "mqtt_password": device_config.get("mqtt_password", ""),
                "topics": self._get_device_topics(device_type),
            }
            
            self.device_profiles[device_type] = profile
            self.logger.info(f"Loaded MQTT device profile: {device_type} ({profile['brand']} {profile['model']})")

    def _get_device_topics(self, device_type: str) -> Dict[str, Dict[str, Any]]:
        """
        Get MQTT topics for a device type.
        
        Args:
            device_type: Device type
            
        Returns:
            Dictionary of topic -> topic info
        """
        topics = {}
        
        # Common topics for all devices
        topics.update({
            "device/status": {
                "description": "Device status updates",
                "qos": 1,
                "retained": True,
                "default_message": json.dumps({
                    "status": "online",
                    "uptime": 3600,
                    "version": "1.0.0"
                })
            },
            "device/info": {
                "description": "Device information",
                "qos": 1,
                "retained": True,
                "default_message": json.dumps({
                    "type": device_type,
                    "model": "Generic",
                    "firmware": "1.0.0"
                })
            },
        })
        
        # Device-specific topics
        if device_type == "ip_camera":
            topics.update({
                "camera/status": {
                    "description": "Camera status updates",
                    "qos": 1,
                    "retained": True,
                    "default_message": json.dumps({
                        "status": "recording",
                        "resolution": "1080p",
                        "framerate": 30
                    })
                },
                "camera/motion": {
                    "description": "Motion detection events",
                    "qos": 1,
                    "retained": False,
                    "default_message": json.dumps({
                        "detected": True,
                        "timestamp": time.time(),
                        "zone": "entrance"
                    })
                },
                "camera/control": {
                    "description": "Camera control commands",
                    "qos": 1,
                    "retained": False,
                    "default_message": json.dumps({
                        "command": "pan",
                        "value": 90
                    })
                },
                "camera/stream": {
                    "description": "Camera stream URL updates",
                    "qos": 1,
                    "retained": True,
                    "default_message": json.dumps({
                        "rtsp_url": "rtsp://192.168.1.100:554/live",
                        "http_url": "http://192.168.1.100:80/stream"
                    })
                },
            })
        elif device_type == "router":
            topics.update({
                "router/status": {
                    "description": "Router status updates",
                    "qos": 1,
                    "retained": True,
                    "default_message": json.dumps({
                        "status": "online",
                        "wan_ip": "203.0.113.45",
                        "lan_ip": "192.168.1.1"
                    })
                },
                "router/clients": {
                    "description": "Connected client updates",
                    "qos": 1,
                    "retained": True,
                    "default_message": json.dumps({
                        "clients": [
                            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:55", "hostname": "android-phone"},
                            {"ip": "192.168.1.101", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "windows-pc"}
                        ]
                    })
                },
                "router/traffic": {
                    "description": "Network traffic statistics",
                    "qos": 0,
                    "retained": False,
                    "default_message": json.dumps({
                        "download": 1024000,
                        "upload": 256000,
                        "timestamp": time.time()
                    })
                },
                "router/config": {
                    "description": "Router configuration",
                    "qos": 1,
                    "retained": True,
                    "default_message": json.dumps({
                        "ssid": "Router_SSID",
                        "channel": 6,
                        "security": "WPA2-PSK"
                    })
                },
            })
        elif device_type == "dvr":
            topics.update({
                "dvr/status": {
                    "description": "DVR status updates",
                    "qos": 1,
                    "retained": True,
                    "default_message": json.dumps({
                        "status": "recording",
                        "channels": 4,
                        "storage": "68%"
                    })
                },
                "dvr/recording": {
                    "description": "Recording status updates",
                    "qos": 1,
                    "retained": True,
                    "default_message": json.dumps({
                        "mode": "continuous",
                        "quality": "high",
                        "channels": [1, 2, 3, 4]
                    })
                },
                "dvr/events": {
                    "description": "DVR events",
                    "qos": 1,
                    "retained": False,
                    "default_message": json.dumps({
                        "type": "motion",
                        "channel": 2,
                        "timestamp": time.time()
                    })
                },
                "dvr/storage": {
                    "description": "Storage information",
                    "qos": 1,
                    "retained": True,
                    "default_message": json.dumps({
                        "total": "2TB",
                        "used": "1.36TB",
                        "free": "640GB"
                    })
                },
            })
        
        return topics

    def _get_predefined_topics(self) -> Dict[str, Dict[str, Any]]:
        """
        Get predefined topics for the MQTT broker.
        
        Returns:
            Dictionary of topic -> topic info
        """
        topics = {
            # Common IoT topics
            "homeassistant/status": {
                "description": "Home Assistant status",
                "qos": 1,
                "retained": True,
                "default_message": "online"
            },
            "homeassistant/discovery": {
                "description": "Home Assistant discovery",
                "qos": 1,
                "retained": True,
                "default_message": json.dumps({
                    "devices": [
                        {"id": "camera1", "type": "camera", "name": "Front Door Camera"},
                        {"id": "router1", "type": "router", "name": "Main Router"},
                        {"id": "dvr1", "type": "dvr", "name": "Security DVR"}
                    ]
                })
            },
            "system/monitor": {
                "description": "System monitoring",
                "qos": 0,
                "retained": False,
                "default_message": json.dumps({
                    "cpu": 15,
                    "memory": 42,
                    "timestamp": time.time()
                })
            },
        }
        
        # Add topics from device profiles
        for device_type, profile in self.device_profiles.items():
            topics.update(profile["topics"])
        
        return topics

    def _get_vulnerabilities(self) -> Dict[str, Dict[str, Any]]:
        """
        Get vulnerabilities for the MQTT broker.
        
        Returns:
            Dictionary of vulnerability_id -> vulnerability info
        """
        return {
            "no_auth": {
                "type": "authentication",
                "description": "MQTT broker allows anonymous access",
                "enabled": True,
            },
            "weak_acl": {
                "type": "authorization",
                "description": "Weak access control allows access to sensitive topics",
                "enabled": True,
            },
            "clear_text": {
                "type": "encryption",
                "description": "Credentials and data transmitted in clear text",
                "enabled": True,
            },
            "sensitive_data": {
                "type": "information_disclosure",
                "description": "Sensitive data exposed in MQTT topics",
                "enabled": True,
                "topics": [
                    "router/config",
                    "camera/stream",
                    "dvr/storage"
                ]
            },
        }

    def _handle_client(self, session_id: str) -> None:
        """
        Handle an MQTT client connection.
        
        Args:
            session_id: Session identifier
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_socket = session["socket"]
        client_address = session["address"]
        
        try:
            # Create a custom MQTT server
            # Note: Paho-MQTT is a client library, not a server
            # For a real implementation, you would use a full MQTT broker like Mosquitto
            # Here we'll implement a simplified MQTT server for demonstration
            
            # Read MQTT CONNECT packet
            packet = self._read_mqtt_packet(client_socket)
            if not packet or packet[0] != 0x10:  # CONNECT packet
                self.logger.warning(f"Invalid MQTT packet from {client_address[0]}", session_id=session_id)
                self.close_session(session_id)
                return
            
            # Parse CONNECT packet
            client_id, username, password = self._parse_connect_packet(packet)
            
            # Log connection attempt
            self.logger.info(
                f"MQTT connection from {client_address[0]}, client_id: {client_id}, username: {username}",
                client_id=client_id,
                username=username,
                session_id=session_id
            )
            
            # Authenticate client
            authenticated = self._authenticate_client(session_id, client_id, username, password)
            
            if not authenticated and self.require_auth and not self.vulnerabilities["no_auth"]["enabled"]:
                # Send CONNACK with failure
                self._send_connack(client_socket, False)
                self.close_session(session_id)
                return
            
            # Send CONNACK with success
            self._send_connack(client_socket, True)
            
            # Create MQTT session
            self.mqtt_sessions[client_id] = {
                "session_id": session_id,
                "client_id": client_id,
                "username": username,
                "connected_at": time.time(),
                "subscriptions": [],
            }
            
            # Handle client packets
            while session_id in self.sessions:
                packet = self._read_mqtt_packet(client_socket)
                if not packet:
                    break
                
                packet_type = packet[0] & 0xF0
                
                if packet_type == 0x30:  # PUBLISH
                    topic, payload, qos, retain = self._parse_publish_packet(packet)
                    self._handle_publish(session_id, client_id, topic, payload, qos, retain)
                
                elif packet_type == 0x82:  # SUBSCRIBE
                    packet_id, topics = self._parse_subscribe_packet(packet)
                    self._handle_subscribe(session_id, client_id, packet_id, topics)
                
                elif packet_type == 0xA2:  # UNSUBSCRIBE
                    packet_id, topics = self._parse_unsubscribe_packet(packet)
                    self._handle_unsubscribe(session_id, client_id, packet_id, topics)
                
                elif packet_type == 0xC0:  # PINGREQ
                    self._send_pingresp(client_socket)
                
                elif packet_type == 0xE0:  # DISCONNECT
                    break
            
            # Clean up
            if client_id in self.mqtt_sessions:
                del self.mqtt_sessions[client_id]
            
        except Exception as e:
            self.logger.error(
                f"Error handling MQTT client {client_address[0]}: {e}",
                error=str(e),
                session_id=session_id
            )
        finally:
            self.close_session(session_id)

    def _read_mqtt_packet(self, sock: socket.socket) -> Optional[bytes]:
        """
        Read an MQTT packet from the socket.
        
        Args:
            sock: Socket to read from
            
        Returns:
            MQTT packet or None if error
        """
        try:
            # Read fixed header
            header = sock.recv(1)
            if not header:
                return None
            
            # Read remaining length
            multiplier = 1
            value = 0
            while True:
                byte = sock.recv(1)
                if not byte:
                    return None
                
                value += (byte[0] & 0x7F) * multiplier
                multiplier *= 128
                
                if not (byte[0] & 0x80):
                    break
            
            # Read packet payload
            payload = b''
            while len(payload) < value:
                chunk = sock.recv(value - len(payload))
                if not chunk:
                    return None
                payload += chunk
            
            return header + self._encode_remaining_length(value) + payload
            
        except Exception as e:
            return None

    def _encode_remaining_length(self, length: int) -> bytes:
        """
        Encode MQTT remaining length.
        
        Args:
            length: Length to encode
            
        Returns:
            Encoded length bytes
        """
        result = bytearray()
        while True:
            byte = length % 128
            length = length // 128
            if length > 0:
                byte |= 0x80
            result.append(byte)
            if length == 0:
                break
        return bytes(result)

    def _parse_connect_packet(self, packet: bytes) -> Tuple[str, Optional[str], Optional[str]]:
        """
        Parse MQTT CONNECT packet.
        
        Args:
            packet: MQTT packet
            
        Returns:
            Tuple of (client_id, username, password)
        """
        # This is a simplified parser for demonstration
        # A real implementation would properly parse the MQTT packet structure
        
        # Skip fixed header and remaining length
        pos = 1
        while pos < len(packet) and (packet[pos] & 0x80):
            pos += 1
        pos += 1
        
        # Skip protocol name and version
        pos += 8  # Assuming "MQTT" protocol name (6 bytes including length) + version (2 bytes)
        
        # Get connect flags
        connect_flags = packet[pos]
        has_username = bool(connect_flags & 0x80)
        has_password = bool(connect_flags & 0x40)
        pos += 1
        
        # Skip keep alive
        pos += 2
        
        # Get client ID
        client_id_len = (packet[pos] << 8) | packet[pos + 1]
        pos += 2
        client_id = packet[pos:pos + client_id_len].decode('utf-8')
        pos += client_id_len
        
        # Get username if present
        username = None
        if has_username:
            username_len = (packet[pos] << 8) | packet[pos + 1]
            pos += 2
            username = packet[pos:pos + username_len].decode('utf-8')
            pos += username_len
        
        # Get password if present
        password = None
        if has_password:
            password_len = (packet[pos] << 8) | packet[pos + 1]
            pos += 2
            password = packet[pos:pos + password_len].decode('utf-8')
        
        return client_id, username, password

    def _parse_publish_packet(self, packet: bytes) -> Tuple[str, bytes, int, bool]:
        """
        Parse MQTT PUBLISH packet.
        
        Args:
            packet: MQTT packet
            
        Returns:
            Tuple of (topic, payload, qos, retain)
        """
        # This is a simplified parser for demonstration
        
        # Get QoS and retain flag
        flags = packet[0]
        qos = (flags & 0x06) >> 1
        retain = bool(flags & 0x01)
        
        # Skip fixed header and remaining length
        pos = 1
        while pos < len(packet) and (packet[pos] & 0x80):
            pos += 1
        pos += 1
        
        # Get topic
        topic_len = (packet[pos] << 8) | packet[pos + 1]
        pos += 2
        topic = packet[pos:pos + topic_len].decode('utf-8')
        pos += topic_len
        
        # Skip packet ID if QoS > 0
        if qos > 0:
            pos += 2
        
        # Get payload
        payload = packet[pos:]
        
        return topic, payload, qos, retain

    def _parse_subscribe_packet(self, packet: bytes) -> Tuple[int, List[Tuple[str, int]]]:
        """
        Parse MQTT SUBSCRIBE packet.
        
        Args:
            packet: MQTT packet
            
        Returns:
            Tuple of (packet_id, [(topic, qos), ...])
        """
        # Skip fixed header and remaining length
        pos = 1
        while pos < len(packet) and (packet[pos] & 0x80):
            pos += 1
        pos += 1
        
        # Get packet ID
        packet_id = (packet[pos] << 8) | packet[pos + 1]
        pos += 2
        
        # Get topics
        topics = []
        while pos < len(packet):
            topic_len = (packet[pos] << 8) | packet[pos + 1]
            pos += 2
            topic = packet[pos:pos + topic_len].decode('utf-8')
            pos += topic_len
            qos = packet[pos]
            pos += 1
            topics.append((topic, qos))
        
        return packet_id, topics

    def _parse_unsubscribe_packet(self, packet: bytes) -> Tuple[int, List[str]]:
        """
        Parse MQTT UNSUBSCRIBE packet.
        
        Args:
            packet: MQTT packet
            
        Returns:
            Tuple of (packet_id, [topic, ...])
        """
        # Skip fixed header and remaining length
        pos = 1
        while pos < len(packet) and (packet[pos] & 0x80):
            pos += 1
        pos += 1
        
        # Get packet ID
        packet_id = (packet[pos] << 8) | packet[pos + 1]
        pos += 2
        
        # Get topics
        topics = []
        while pos < len(packet):
            topic_len = (packet[pos] << 8) | packet[pos + 1]
            pos += 2
            topic = packet[pos:pos + topic_len].decode('utf-8')
            pos += topic_len
            topics.append(topic)
        
        return packet_id, topics

    def _send_connack(self, sock: socket.socket, success: bool) -> None:
        """
        Send MQTT CONNACK packet.
        
        Args:
            sock: Socket to send to
            success: Whether connection was successful
        """
        # CONNACK packet
        # Fixed header: packet type (2) << 4 = 0x20
        # Remaining length: 2
        # Variable header: acknowledge flags (0) + return code (0 for success, 5 for failure)
        return_code = 0 if success else 5
        packet = bytes([0x20, 0x02, 0x00, return_code])
        sock.sendall(packet)

    def _send_suback(self, sock: socket.socket, packet_id: int, qos_list: List[int]) -> None:
        """
        Send MQTT SUBACK packet.
        
        Args:
            sock: Socket to send to
            packet_id: Packet ID
            qos_list: List of QoS values
        """
        # SUBACK packet
        # Fixed header: packet type (9) << 4 = 0x90
        # Remaining length: 2 + len(qos_list)
        # Variable header: packet ID (2 bytes)
        # Payload: QoS values
        packet = bytearray([0x90, 2 + len(qos_list), (packet_id >> 8) & 0xFF, packet_id & 0xFF])
        packet.extend(qos_list)
        sock.sendall(packet)

    def _send_unsuback(self, sock: socket.socket, packet_id: int) -> None:
        """
        Send MQTT UNSUBACK packet.
        
        Args:
            sock: Socket to send to
            packet_id: Packet ID
        """
        # UNSUBACK packet
        # Fixed header: packet type (11) << 4 = 0xB0
        # Remaining length: 2
        # Variable header: packet ID (2 bytes)
        packet = bytes([0xB0, 0x02, (packet_id >> 8) & 0xFF, packet_id & 0xFF])
        sock.sendall(packet)

    def _send_publish(self, sock: socket.socket, topic: str, payload: bytes, qos: int = 0, 
                     retain: bool = False, dup: bool = False, packet_id: int = 0) -> None:
        """
        Send MQTT PUBLISH packet.
        
        Args:
            sock: Socket to send to
            topic: Topic to publish to
            payload: Message payload
            qos: QoS level (0, 1, or 2)
            retain: Whether message should be retained
            dup: Whether this is a duplicate message
            packet_id: Packet ID (only for QoS > 0)
        """
        # PUBLISH packet
        # Fixed header: packet type (3) << 4 | dup << 3 | qos << 1 | retain = 0x30 | flags
        flags = (int(dup) << 3) | (qos << 1) | int(retain)
        fixed_header = bytes([0x30 | flags])
        
        # Variable header: topic (string) + packet ID (if QoS > 0)
        topic_bytes = topic.encode('utf-8')
        topic_len = len(topic_bytes)
        variable_header = bytes([(topic_len >> 8) & 0xFF, topic_len & 0xFF]) + topic_bytes
        
        if qos > 0:
            variable_header += bytes([(packet_id >> 8) & 0xFF, packet_id & 0xFF])
        
        # Calculate remaining length
        remaining_length = len(variable_header) + len(payload)
        remaining_length_bytes = self._encode_remaining_length(remaining_length)
        
        # Assemble packet
        packet = fixed_header + remaining_length_bytes + variable_header + payload
        sock.sendall(packet)

    def _send_pingresp(self, sock: socket.socket) -> None:
        """
        Send MQTT PINGRESP packet.
        
        Args:
            sock: Socket to send to
        """
        # PINGRESP packet
        # Fixed header: packet type (13) << 4 = 0xD0
        # Remaining length: 0
        packet = bytes([0xD0, 0x00])
        sock.sendall(packet)

    def _authenticate_client(self, session_id: str, client_id: str, username: Optional[str], password: Optional[str]) -> bool:
        """
        Authenticate an MQTT client.
        
        Args:
            session_id: Session identifier
            client_id: Client ID
            username: Username or None
            password: Password or None
            
        Returns:
            True if authenticated, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        client_address = session["address"]
        
        # Check if authentication is required
        if not self.require_auth or self.vulnerabilities["no_auth"]["enabled"]:
            self.logger.info(
                f"MQTT client {client_id} from {client_address[0]} authenticated (anonymous access)",
                client_id=client_id,
                session_id=session_id
            )
            return True
        
        # Check if username and password are provided
        if not username or not password:
            self.logger.warning(
                f"MQTT client {client_id} from {client_address[0]} failed authentication (missing credentials)",
                client_id=client_id,
                session_id=session_id
            )
            return False
        
        # Check credentials against device profiles
        authenticated = False
        for device_type, profile in self.device_profiles.items():
            if username == profile["mqtt_username"] and password == profile["mqtt_password"]:
                authenticated = True
                session["device_type"] = device_type
                session["device_profile"] = profile
                break
        
        # Log authentication result
        if authenticated:
            self.logger.info(
                f"MQTT client {client_id} from {client_address[0]} authenticated as {username}",
                client_id=client_id,
                username=username,
                session_id=session_id
            )
        else:
            self.logger.warning(
                f"MQTT client {client_id} from {client_address[0]} failed authentication with username {username}",
                client_id=client_id,
                username=username,
                session_id=session_id
            )
        
        return authenticated

    def _handle_publish(self, session_id: str, client_id: str, topic: str, payload: bytes, qos: int, retain: bool) -> None:
        """
        Handle MQTT PUBLISH packet.
        
        Args:
            session_id: Session identifier
            client_id: Client ID
            topic: Topic
            payload: Message payload
            qos: QoS level
            retain: Whether message should be retained
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        
        # Log publish
        try:
            payload_str = payload.decode('utf-8')
        except UnicodeDecodeError:
            payload_str = f"<binary data, {len(payload)} bytes>"
        
        self.logger.info(
            f"MQTT publish from {client_address[0]}, client_id: {client_id}, topic: {topic}, qos: {qos}, retain: {retain}",
            client_id=client_id,
            topic=topic,
            payload=payload_str,
            qos=qos,
            retain=retain,
            session_id=session_id
        )
        
        # Check for sensitive topics
        if self.vulnerabilities["sensitive_data"]["enabled"]:
            sensitive_topics = self.vulnerabilities["sensitive_data"]["topics"]
            for sensitive_topic in sensitive_topics:
                if topic.startswith(sensitive_topic):
                    self.logger.warning(
                        f"Sensitive data published to topic {topic} by {client_address[0]}",
                        event_type="sensitive_data",
                        client_id=client_id,
                        topic=topic,
                        session_id=session_id
                    )
                    break
        
        # Store message in history
        if topic not in self.message_history:
            self.message_history[topic] = []
        
        self.message_history[topic].append({
            "client_id": client_id,
            "payload": payload,
            "qos": qos,
            "retain": retain,
            "timestamp": time.time()
        })
        
        # Limit history size
        max_history = 100
        if len(self.message_history[topic]) > max_history:
            self.message_history[topic] = self.message_history[topic][-max_history:]
        
        # Store retained message
        if retain:
            self.retained_messages[topic] = {
                "payload": payload,
                "qos": qos,
                "timestamp": time.time()
            }
        
        # Forward message to subscribers
        self._forward_message(topic, payload, qos)

    def _handle_subscribe(self, session_id: str, client_id: str, packet_id: int, topics: List[Tuple[str, int]]) -> None:
        """
        Handle MQTT SUBSCRIBE packet.
        
        Args:
            session_id: Session identifier
            client_id: Client ID
            packet_id: Packet ID
            topics: List of (topic, qos) tuples
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        client_socket = session["socket"]
        
        # Log subscribe
        topic_list = [f"{topic}:{qos}" for topic, qos in topics]
        self.logger.info(
            f"MQTT subscribe from {client_address[0]}, client_id: {client_id}, topics: {', '.join(topic_list)}",
            client_id=client_id,
            topics=topic_list,
            session_id=session_id
        )
        
        # Store subscriptions
        if client_id not in self.subscriptions:
            self.subscriptions[client_id] = []
        
        qos_list = []
        for topic, qos in topics:
            # Check for weak ACL vulnerability
            if self.vulnerabilities["weak_acl"]["enabled"]:
                # Allow subscription to any topic
                self.subscriptions[client_id].append((topic, qos))
                qos_list.append(qos)
                
                # Check for sensitive topics
                sensitive_topics = self.vulnerabilities["sensitive_data"]["topics"]
                for sensitive_topic in sensitive_topics:
                    if topic.startswith(sensitive_topic) or '#' in topic:
                        self.logger.warning(
                            f"Subscription to sensitive topic {topic} by {client_address[0]}",
                            event_type="weak_acl",
                            client_id=client_id,
                            topic=topic,
                            session_id=session_id
                        )
                        break
            else:
                # Implement proper ACL (simplified for demonstration)
                # In a real implementation, this would check against a proper ACL system
                allowed = True
                
                if allowed:
                    self.subscriptions[client_id].append((topic, qos))
                    qos_list.append(qos)
                else:
                    # Subscription denied
                    qos_list.append(0x80)  # Failure
        
        # Send SUBACK
        self._send_suback(client_socket, packet_id, qos_list)
        
        # Send retained messages for subscribed topics
        for topic_filter, qos in topics:
            for retained_topic, retained_msg in self.retained_messages.items():
                if self._topic_matches(topic_filter, retained_topic):
                    # Use the lower of the two QoS values
                    effective_qos = min(qos, retained_msg["qos"])
                    self._send_publish(
                        client_socket,
                        retained_topic,
                        retained_msg["payload"],
                        qos=effective_qos,
                        retain=True
                    )
        
        # Send default messages for predefined topics
        for topic_filter, qos in topics:
            for predefined_topic, topic_info in self.predefined_topics.items():
                if self._topic_matches(topic_filter, predefined_topic) and "default_message" in topic_info:
                    # Check if we already sent a retained message for this topic
                    if predefined_topic in self.retained_messages:
                        continue
                    
                    # Use the lower of the two QoS values
                    effective_qos = min(qos, topic_info["qos"])
                    
                    # Send default message
                    if isinstance(topic_info["default_message"], str):
                        payload = topic_info["default_message"].encode('utf-8')
                    else:
                        payload = topic_info["default_message"]
                    
                    self._send_publish(
                        client_socket,
                        predefined_topic,
                        payload,
                        qos=effective_qos,
                        retain=topic_info["retained"]
                    )

    def _handle_unsubscribe(self, session_id: str, client_id: str, packet_id: int, topics: List[str]) -> None:
        """
        Handle MQTT UNSUBSCRIBE packet.
        
        Args:
            session_id: Session identifier
            client_id: Client ID
            packet_id: Packet ID
            topics: List of topics
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        client_address = session["address"]
        client_socket = session["socket"]
        
        # Log unsubscribe
        self.logger.info(
            f"MQTT unsubscribe from {client_address[0]}, client_id: {client_id}, topics: {', '.join(topics)}",
            client_id=client_id,
            topics=topics,
            session_id=session_id
        )
        
        # Remove subscriptions
        if client_id in self.subscriptions:
            self.subscriptions[client_id] = [
                (t, q) for t, q in self.subscriptions[client_id]
                if t not in topics
            ]
        
        # Send UNSUBACK
        self._send_unsuback(client_socket, packet_id)

    def _forward_message(self, topic: str, payload: bytes, qos: int) -> None:
        """
        Forward a message to subscribers.
        
        Args:
            topic: Topic
            payload: Message payload
            qos: QoS level
        """
        # Find matching subscriptions
        for client_id, subscriptions in self.subscriptions.items():
            if client_id not in self.mqtt_sessions:
                continue
            
            session_id = self.mqtt_sessions[client_id]["session_id"]
            if session_id not in self.sessions:
                continue
            
            client_socket = self.sessions[session_id]["socket"]
            
            for topic_filter, sub_qos in subscriptions:
                if self._topic_matches(topic_filter, topic):
                    # Use the lower of the two QoS values
                    effective_qos = min(qos, sub_qos)
                    
                    # Generate packet ID for QoS > 0
                    packet_id = 0
                    if effective_qos > 0:
                        packet_id = (int(time.time() * 1000) % 65535) + 1
                    
                    # Forward message
                    try:
                        self._send_publish(
                            client_socket,
                            topic,
                            payload,
                            qos=effective_qos,
                            packet_id=packet_id
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Error forwarding message to {client_id}: {e}",
                            error=str(e),
                            client_id=client_id,
                            topic=topic
                        )

    def _topic_matches(self, topic_filter: str, topic: str) -> bool:
        """
        Check if a topic matches a topic filter.
        
        Args:
            topic_filter: Topic filter (may contain wildcards)
            topic: Topic
            
        Returns:
            True if topic matches filter, False otherwise
        """
        # Split into parts
        filter_parts = topic_filter.split('/')
        topic_parts = topic.split('/')
        
        # Check multi-level wildcard
        if filter_parts[-1] == '#':
            # '#' must be the last character
            if len(filter_parts) > 1:
                # Check if the topic starts with the filter prefix
                filter_prefix = '/'.join(filter_parts[:-1])
                topic_prefix = '/'.join(topic_parts[:len(filter_parts)-1])
                return topic_prefix == filter_prefix
            else:
                # Single '#' matches everything
                return True
        
        # Check if parts count matches (except for '+' wildcards)
        if len(filter_parts) != len(topic_parts):
            return False
        
        # Check each part
        for i in range(len(filter_parts)):
            if filter_parts[i] != '+' and filter_parts[i] != topic_parts[i]:
                return False
        
        return True

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database handler for the Advanced IoT Honeypot.
Implements Elasticsearch integration for storing and querying honeypot data.
"""

import os
import json
import time
import datetime
from typing import Dict, Any, Optional, List, Union
from elasticsearch import Elasticsearch, helpers

from core.logger import get_logger
from core.config import get_config

class DatabaseHandler:
    """Database handler for storing and querying honeypot data."""

    def __init__(self):
        """Initialize the database handler."""
        self.logger = get_logger("database")
        self.config = get_config()
        
        # Database settings
        self.db_config = self.config.get_database_config()
        self.enabled = self.db_config.get("enabled", True)
        self.host = self.db_config.get("host", "localhost")
        self.port = self.db_config.get("port", 9200)
        self.username = self.db_config.get("username", "")
        self.password = self.db_config.get("password", "")
        self.index_prefix = self.db_config.get("index_prefix", "honeypot")
        
        # Elasticsearch client
        self.es = None
        self.connected = False
        
        # Connect to Elasticsearch
        if self.enabled:
            self._connect()
    
    def _connect(self) -> None:
        """Connect to Elasticsearch."""
        try:
            # Create Elasticsearch client
            if self.username and self.password:
                self.es = Elasticsearch(
                    [f"http://{self.host}:{self.port}"],
                    basic_auth=(self.username, self.password)
                )
            else:
                self.es = Elasticsearch([f"http://{self.host}:{self.port}"])
            
            # Check connection
            if self.es.ping():
                self.connected = True
                self.logger.info(f"Connected to Elasticsearch at {self.host}:{self.port}")
                
                # Create indices if they don't exist
                self._create_indices()
            else:
                self.logger.error(f"Failed to connect to Elasticsearch at {self.host}:{self.port}")
        
        except Exception as e:
            self.logger.error(f"Error connecting to Elasticsearch: {e}")
    
    def _create_indices(self) -> None:
        """Create Elasticsearch indices if they don't exist."""
        try:
            # Define indices
            indices = {
                "connections": {
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "src_ip": {"type": "ip"},
                            "src_port": {"type": "integer"},
                            "dst_port": {"type": "integer"},
                            "protocol": {"type": "keyword"},
                            "session_id": {"type": "keyword"},
                            "geo_location": {
                                "properties": {
                                    "country": {"type": "keyword"},
                                    "city": {"type": "keyword"},
                                    "location": {"type": "geo_point"}
                                }
                            }
                        }
                    }
                },
                "auth": {
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "src_ip": {"type": "ip"},
                            "username": {"type": "keyword"},
                            "password": {"type": "keyword"},
                            "success": {"type": "boolean"},
                            "protocol": {"type": "keyword"},
                            "session_id": {"type": "keyword"},
                            "geo_location": {
                                "properties": {
                                    "country": {"type": "keyword"},
                                    "city": {"type": "keyword"},
                                    "location": {"type": "geo_point"}
                                }
                            }
                        }
                    }
                },
                "commands": {
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "src_ip": {"type": "ip"},
                            "command": {"type": "text"},
                            "protocol": {"type": "keyword"},
                            "session_id": {"type": "keyword"},
                            "geo_location": {
                                "properties": {
                                    "country": {"type": "keyword"},
                                    "city": {"type": "keyword"},
                                    "location": {"type": "geo_point"}
                                }
                            }
                        }
                    }
                },
                "http": {
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "src_ip": {"type": "ip"},
                            "method": {"type": "keyword"},
                            "path": {"type": "text"},
                            "query": {"type": "text"},
                            "user_agent": {"type": "text"},
                            "status_code": {"type": "integer"},
                            "session_id": {"type": "keyword"},
                            "geo_location": {
                                "properties": {
                                    "country": {"type": "keyword"},
                                    "city": {"type": "keyword"},
                                    "location": {"type": "geo_point"}
                                }
                            }
                        }
                    }
                },
                "vulnerabilities": {
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "src_ip": {"type": "ip"},
                            "vulnerability": {"type": "keyword"},
                            "description": {"type": "text"},
                            "details": {"type": "object"},
                            "protocol": {"type": "keyword"},
                            "session_id": {"type": "keyword"},
                            "geo_location": {
                                "properties": {
                                    "country": {"type": "keyword"},
                                    "city": {"type": "keyword"},
                                    "location": {"type": "geo_point"}
                                }
                            }
                        }
                    }
                },
                "files": {
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "src_ip": {"type": "ip"},
                            "filename": {"type": "text"},
                            "file_path": {"type": "text"},
                            "file_size": {"type": "long"},
                            "file_type": {"type": "keyword"},
                            "md5": {"type": "keyword"},
                            "sha1": {"type": "keyword"},
                            "sha256": {"type": "keyword"},
                            "is_malware": {"type": "boolean"},
                            "protocol": {"type": "keyword"},
                            "session_id": {"type": "keyword"},
                            "geo_location": {
                                "properties": {
                                    "country": {"type": "keyword"},
                                    "city": {"type": "keyword"},
                                    "location": {"type": "geo_point"}
                                }
                            }
                        }
                    }
                }
            }
            
            # Create indices
            for index_name, index_config in indices.items():
                full_index_name = f"{self.index_prefix}-{index_name}"
                
                if not self.es.indices.exists(index=full_index_name):
                    self.es.indices.create(
                        index=full_index_name,
                        body=index_config
                    )
                    self.logger.info(f"Created Elasticsearch index: {full_index_name}")
        
        except Exception as e:
            self.logger.error(f"Error creating Elasticsearch indices: {e}")
    
    def store_connection(self, src_ip: str, src_port: int, dst_port: int, protocol: str, session_id: str) -> None:
        """
        Store a connection event.
        
        Args:
            src_ip: Source IP address
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol (e.g., "telnet", "http", "ssh")
            session_id: Session identifier
        """
        if not self.connected:
            return
        
        try:
            # Get geo location
            geo_location = self._get_geo_location(src_ip)
            
            # Create document
            doc = {
                "timestamp": datetime.datetime.now().isoformat(),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "session_id": session_id,
                "geo_location": geo_location
            }
            
            # Store document
            self.es.index(
                index=f"{self.index_prefix}-connections",
                document=doc
            )
        
        except Exception as e:
            self.logger.error(f"Error storing connection: {e}")
    
    def store_auth(self, src_ip: str, username: str, password: str, success: bool, protocol: str, session_id: str) -> None:
        """
        Store an authentication event.
        
        Args:
            src_ip: Source IP address
            username: Username
            password: Password
            success: Whether authentication was successful
            protocol: Protocol (e.g., "telnet", "ssh", "ftp")
            session_id: Session identifier
        """
        if not self.connected:
            return
        
        try:
            # Get geo location
            geo_location = self._get_geo_location(src_ip)
            
            # Create document
            doc = {
                "timestamp": datetime.datetime.now().isoformat(),
                "src_ip": src_ip,
                "username": username,
                "password": password,
                "success": success,
                "protocol": protocol,
                "session_id": session_id,
                "geo_location": geo_location
            }
            
            # Store document
            self.es.index(
                index=f"{self.index_prefix}-auth",
                document=doc
            )
        
        except Exception as e:
            self.logger.error(f"Error storing authentication: {e}")
    
    def store_command(self, src_ip: str, command: str, protocol: str, session_id: str) -> None:
        """
        Store a command event.
        
        Args:
            src_ip: Source IP address
            command: Command
            protocol: Protocol (e.g., "telnet", "ssh")
            session_id: Session identifier
        """
        if not self.connected:
            return
        
        try:
            # Get geo location
            geo_location = self._get_geo_location(src_ip)
            
            # Create document
            doc = {
                "timestamp": datetime.datetime.now().isoformat(),
                "src_ip": src_ip,
                "command": command,
                "protocol": protocol,
                "session_id": session_id,
                "geo_location": geo_location
            }
            
            # Store document
            self.es.index(
                index=f"{self.index_prefix}-commands",
                document=doc
            )
        
        except Exception as e:
            self.logger.error(f"Error storing command: {e}")
    
    def store_http_request(self, src_ip: str, method: str, path: str, query: str, user_agent: str, status_code: int, session_id: str) -> None:
        """
        Store an HTTP request event.
        
        Args:
            src_ip: Source IP address
            method: HTTP method (e.g., "GET", "POST")
            path: Request path
            query: Query string
            user_agent: User agent
            status_code: HTTP status code
            session_id: Session identifier
        """
        if not self.connected:
            return
        
        try:
            # Get geo location
            geo_location = self._get_geo_location(src_ip)
            
            # Create document
            doc = {
                "timestamp": datetime.datetime.now().isoformat(),
                "src_ip": src_ip,
                "method": method,
                "path": path,
                "query": query,
                "user_agent": user_agent,
                "status_code": status_code,
                "session_id": session_id,
                "geo_location": geo_location
            }
            
            # Store document
            self.es.index(
                index=f"{self.index_prefix}-http",
                document=doc
            )
        
        except Exception as e:
            self.logger.error(f"Error storing HTTP request: {e}")
    
    def store_vulnerability(self, src_ip: str, vulnerability: str, description: str, details: Dict[str, Any], protocol: str, session_id: str) -> None:
        """
        Store a vulnerability event.
        
        Args:
            src_ip: Source IP address
            vulnerability: Vulnerability type (e.g., "command_injection", "path_traversal")
            description: Vulnerability description
            details: Additional details
            protocol: Protocol (e.g., "telnet", "http", "ssh")
            session_id: Session identifier
        """
        if not self.connected:
            return
        
        try:
            # Get geo location
            geo_location = self._get_geo_location(src_ip)
            
            # Create document
            doc = {
                "timestamp": datetime.datetime.now().isoformat(),
                "src_ip": src_ip,
                "vulnerability": vulnerability,
                "description": description,
                "details": details,
                "protocol": protocol,
                "session_id": session_id,
                "geo_location": geo_location
            }
            
            # Store document
            self.es.index(
                index=f"{self.index_prefix}-vulnerabilities",
                document=doc
            )
        
        except Exception as e:
            self.logger.error(f"Error storing vulnerability: {e}")
    
    def store_file(self, src_ip: str, filename: str, file_path: str, file_size: int, file_type: str, md5: str, sha1: str, sha256: str, is_malware: bool, protocol: str, session_id: str) -> None:
        """
        Store a file event.
        
        Args:
            src_ip: Source IP address
            filename: File name
            file_path: File path
            file_size: File size in bytes
            file_type: File type
            md5: MD5 hash
            sha1: SHA1 hash
            sha256: SHA256 hash
            is_malware: Whether the file is malware
            protocol: Protocol (e.g., "ftp", "http")
            session_id: Session identifier
        """
        if not self.connected:
            return
        
        try:
            # Get geo location
            geo_location = self._get_geo_location(src_ip)
            
            # Create document
            doc = {
                "timestamp": datetime.datetime.now().isoformat(),
                "src_ip": src_ip,
                "filename": filename,
                "file_path": file_path,
                "file_size": file_size,
                "file_type": file_type,
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256,
                "is_malware": is_malware,
                "protocol": protocol,
                "session_id": session_id,
                "geo_location": geo_location
            }
            
            # Store document
            self.es.index(
                index=f"{self.index_prefix}-files",
                document=doc
            )
        
        except Exception as e:
            self.logger.error(f"Error storing file: {e}")
    
    def get_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent connections.
        
        Args:
            limit: Maximum number of connections to return
            
        Returns:
            List of connections
        """
        if not self.connected:
            return []
        
        try:
            # Query Elasticsearch
            result = self.es.search(
                index=f"{self.index_prefix}-connections",
                body={
                    "query": {
                        "match_all": {}
                    },
                    "sort": [
                        {"timestamp": {"order": "desc"}}
                    ],
                    "size": limit
                }
            )
            
            # Extract hits
            hits = result["hits"]["hits"]
            connections = [hit["_source"] for hit in hits]
            
            return connections
        
        except Exception as e:
            self.logger.error(f"Error getting connections: {e}")
            return []
    
    def get_auth_attempts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent authentication attempts.
        
        Args:
            limit: Maximum number of authentication attempts to return
            
        Returns:
            List of authentication attempts
        """
        if not self.connected:
            return []
        
        try:
            # Query Elasticsearch
            result = self.es.search(
                index=f"{self.index_prefix}-auth",
                body={
                    "query": {
                        "match_all": {}
                    },
                    "sort": [
                        {"timestamp": {"order": "desc"}}
                    ],
                    "size": limit
                }
            )
            
            # Extract hits
            hits = result["hits"]["hits"]
            auth_attempts = [hit["_source"] for hit in hits]
            
            return auth_attempts
        
        except Exception as e:
            self.logger.error(f"Error getting authentication attempts: {e}")
            return []
    
    def get_commands(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent commands.
        
        Args:
            limit: Maximum number of commands to return
            
        Returns:
            List of commands
        """
        if not self.connected:
            return []
        
        try:
            # Query Elasticsearch
            result = self.es.search(
                index=f"{self.index_prefix}-commands",
                body={
                    "query": {
                        "match_all": {}
                    },
                    "sort": [
                        {"timestamp": {"order": "desc"}}
                    ],
                    "size": limit
                }
            )
            
            # Extract hits
            hits = result["hits"]["hits"]
            commands = [hit["_source"] for hit in hits]
            
            return commands
        
        except Exception as e:
            self.logger.error(f"Error getting commands: {e}")
            return []
    
    def get_http_requests(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent HTTP requests.
        
        Args:
            limit: Maximum number of HTTP requests to return
            
        Returns:
            List of HTTP requests
        """
        if not self.connected:
            return []
        
        try:
            # Query Elasticsearch
            result = self.es.search(
                index=f"{self.index_prefix}-http",
                body={
                    "query": {
                        "match_all": {}
                    },
                    "sort": [
                        {"timestamp": {"order": "desc"}}
                    ],
                    "size": limit
                }
            )
            
            # Extract hits
            hits = result["hits"]["hits"]
            http_requests = [hit["_source"] for hit in hits]
            
            return http_requests
        
        except Exception as e:
            self.logger.error(f"Error getting HTTP requests: {e}")
            return []
    
    def get_vulnerabilities(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent vulnerability events.
        
        Args:
            limit: Maximum number of vulnerability events to return
            
        Returns:
            List of vulnerability events
        """
        if not self.connected:
            return []
        
        try:
            # Query Elasticsearch
            result = self.es.search(
                index=f"{self.index_prefix}-vulnerabilities",
                body={
                    "query": {
                        "match_all": {}
                    },
                    "sort": [
                        {"timestamp": {"order": "desc"}}
                    ],
                    "size": limit
                }
            )
            
            # Extract hits
            hits = result["hits"]["hits"]
            vulnerabilities = [hit["_source"] for hit in hits]
            
            return vulnerabilities
        
        except Exception as e:
            self.logger.error(f"Error getting vulnerabilities: {e}")
            return []
    
    def get_files(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent file events.
        
        Args:
            limit: Maximum number of file events to return
            
        Returns:
            List of file events
        """
        if not self.connected:
            return []
        
        try:
            # Query Elasticsearch
            result = self.es.search(
                index=f"{self.index_prefix}-files",
                body={
                    "query": {
                        "match_all": {}
                    },
                    "sort": [
                        {"timestamp": {"order": "desc"}}
                    ],
                    "size": limit
                }
            )
            
            # Extract hits
            hits = result["hits"]["hits"]
            files = [hit["_source"] for hit in hits]
            
            return files
        
        except Exception as e:
            self.logger.error(f"Error getting files: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get honeypot statistics.
        
        Returns:
            Dictionary of statistics
        """
        if not self.connected:
            return {}
        
        try:
            stats = {}
            
            # Get connection count
            result = self.es.count(index=f"{self.index_prefix}-connections")
            stats["connections"] = result["count"]
            
            # Get authentication count
            result = self.es.count(index=f"{self.index_prefix}-auth")
            stats["auth_attempts"] = result["count"]
            
            # Get successful authentication count
            result = self.es.count(
                index=f"{self.index_prefix}-auth",
                body={
                    "query": {
                        "term": {
                            "success": True
                        }
                    }
                }
            )
            stats["auth_success"] = result["count"]
            
            # Get command count
            result = self.es.count(index=f"{self.index_prefix}-commands")
            stats["commands"] = result["count"]
            
            # Get HTTP request count
            result = self.es.count(index=f"{self.index_prefix}-http")
            stats["http_requests"] = result["count"]
            
            # Get vulnerability count
            result = self.es.count(index=f"{self.index_prefix}-vulnerabilities")
            stats["vulnerabilities"] = result["count"]
            
            # Get file count
            result = self.es.count(index=f"{self.index_prefix}-files")
            stats["files"] = result["count"]
            
            # Get malware count
            result = self.es.count(
                index=f"{self.index_prefix}-files",
                body={
                    "query": {
                        "term": {
                            "is_malware": True
                        }
                    }
                }
            )
            stats["malware"] = result["count"]
            
            # Get unique IP count
            result = self.es.search(
                index=f"{self.index_prefix}-connections",
                body={
                    "size": 0,
                    "aggs": {
                        "unique_ips": {
                            "cardinality": {
                                "field": "src_ip"
                            }
                        }
                    }
                }
            )
            stats["unique_ips"] = result["aggregations"]["unique_ips"]["value"]
            
            # Get protocol distribution
            result = self.es.search(
                index=f"{self.index_prefix}-connections",
                body={
                    "size": 0,
                    "aggs": {
                        "protocols": {
                            "terms": {
                                "field": "protocol",
                                "size": 10
                            }
                        }
                    }
                }
            )
            stats["protocols"] = {
                bucket["key"]: bucket["doc_count"]
                for bucket in result["aggregations"]["protocols"]["buckets"]
            }
            
            # Get country distribution
            result = self.es.search(
                index=f"{self.index_prefix}-connections",
                body={
                    "size": 0,
                    "aggs": {
                        "countries": {
                            "terms": {
                                "field": "geo_location.country",
                                "size": 10
                            }
                        }
                    }
                }
            )
            stats["countries"] = {
                bucket["key"]: bucket["doc_count"]
                for bucket in result["aggregations"]["countries"]["buckets"]
            }
            
            return stats
        
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}
    
    def _get_geo_location(self, ip: str) -> Dict[str, Any]:
        """
        Get geo location for an IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with geo location information
        """
        # This is a placeholder for a real geo location lookup
        # In a real implementation, you would use a geo IP database like MaxMind GeoIP
        
        # For demonstration, return random geo location
        import random
        
        countries = [
            ("US", "United States", 37.0902, -95.7129),
            ("CN", "China", 35.8617, 104.1954),
            ("RU", "Russia", 61.5240, 105.3188),
            ("BR", "Brazil", -14.2350, -51.9253),
            ("IN", "India", 20.5937, 78.9629),
            ("DE", "Germany", 51.1657, 10.4515),
            ("FR", "France", 46.2276, 2.2137),
            ("GB", "United Kingdom", 55.3781, -3.4360),
            ("JP", "Japan", 36.2048, 138.2529),
            ("KR", "South Korea", 35.9078, 127.7669)
        ]
        
        # Select a country
        country_code, country, lat, lon = random.choice(countries)
        
        # Add some randomness to coordinates
        lat += random.uniform(-5, 5)
        lon += random.uniform(-5, 5)
        
        return {
            "country_code": country_code,
            "country": country,
            "city": "Unknown",
            "location": {
                "lat": lat,
                "lon": lon
            }
        }

# Singleton instance
_instance = None

def get_database() -> DatabaseHandler:
    """
    Get the database handler instance.
    
    Returns:
        Database handler instance
    """
    global _instance
    
    if _instance is None:
        _instance = DatabaseHandler()
    
    return _instance

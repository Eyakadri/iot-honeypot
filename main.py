#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main entry point for the Advanced IoT Honeypot System.
Initializes and starts all components.
"""

import os
import sys
import time
import signal
import argparse
import logging
from typing import Dict, Any, List, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import core modules
from .core.config import get_config
from .core.logger import get_logger, setup_logging
from .core.database import get_database
from .core.malware import get_malware_handler

# Import protocol handlers
from .protocols.telnet_handler import TelnetHandler
from .protocols.http_handler import HTTPHandler
from .protocols.ssh_handler import SSHHandler
from .protocols.mqtt_handler import MQTTHandler
from .protocols.ftp_handler import FTPHandler

# Import dashboard
from .dashboard.app import run_dashboard

class HoneypotSystem:
    """Main honeypot system class that initializes and manages all components."""

    def __init__(self):
        """Initialize the honeypot system."""
        # Parse command line arguments
        self.args = self._parse_args()
        
        # Setup logging
        setup_logging(self.args.log_level)
        self.logger = get_logger("honeypot")
        
        # Load configuration
        self.config = get_config()
        
        # Initialize database
        self.db = get_database()
        
        # Initialize malware handler
        self.malware_handler = get_malware_handler()
        
        # Initialize protocol handlers
        self.protocol_handlers = {}
        
        # Initialize dashboard
        self.dashboard_thread = None
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        self.logger.info("Honeypot system initialized")
    
    def _parse_args(self) -> argparse.Namespace:
        """
        Parse command line arguments.
        
        Returns:
            Parsed arguments
        """
        parser = argparse.ArgumentParser(description="Advanced IoT Honeypot System")
        
        parser.add_argument(
            "--config",
            type=str,
            default="config.ini",
            help="Path to configuration file"
        )
        
        parser.add_argument(
            "--log-level",
            type=str,
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="INFO",
            help="Logging level"
        )
        
        parser.add_argument(
            "--no-dashboard",
            action="store_true",
            help="Disable dashboard"
        )
        
        return parser.parse_args()
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, sig, frame) -> None:
        """
        Handle signals for graceful shutdown.
        
        Args:
            sig: Signal number
            frame: Current stack frame
        """
        self.logger.info(f"Received signal {sig}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def start(self) -> None:
        """Start all honeypot components."""
        self.logger.info("Starting honeypot system...")
        
        # Start protocol handlers
        self._start_protocol_handlers()
        
        # Start dashboard
        if not self.args.no_dashboard:
            self._start_dashboard()
        
        self.logger.info("Honeypot system started")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received, shutting down...")
            self.stop()
    
    def stop(self) -> None:
        """Stop all honeypot components."""
        self.logger.info("Stopping honeypot system...")
        
        # Stop protocol handlers
        for handler in self.protocol_handlers.values():
            try:
                handler.stop()
            except Exception as e:
                self.logger.error(f"Error stopping {handler.__class__.__name__}: {e}")
        
        self.logger.info("Honeypot system stopped")
    
    def _start_protocol_handlers(self) -> None:
        """Start all enabled protocol handlers."""
        # Get enabled protocols
        enabled_protocols = self.config.get_enabled_protocols()
        
        # Initialize and start handlers
        if "telnet" in enabled_protocols:
            self.protocol_handlers["telnet"] = TelnetHandler()
            self.protocol_handlers["telnet"].start()
        
        if "http" in enabled_protocols:
            self.protocol_handlers["http"] = HTTPHandler()
            self.protocol_handlers["http"].start()
        
        if "ssh" in enabled_protocols:
            self.protocol_handlers["ssh"] = SSHHandler()
            self.protocol_handlers["ssh"].start()
        
        if "mqtt" in enabled_protocols:
            self.protocol_handlers["mqtt"] = MQTTHandler()
            self.protocol_handlers["mqtt"].start()
        
        if "ftp" in enabled_protocols:
            self.protocol_handlers["ftp"] = FTPHandler()
            self.protocol_handlers["ftp"].start()
        
        self.logger.info(f"Started {len(self.protocol_handlers)} protocol handlers")
    
    def _start_dashboard(self) -> None:
        """Start the dashboard in a separate thread."""
        import threading
        
        dashboard_config = self.config.get_dashboard_config()
        host = dashboard_config.get("host", "0.0.0.0")
        port = dashboard_config.get("port", 8050)
        
        self.dashboard_thread = threading.Thread(
            target=run_dashboard,
            args=(host, port, False),
            daemon=True
        )
        
        self.dashboard_thread.start()
        self.logger.info(f"Dashboard started on http://{host}:{port}")

if __name__ == "__main__":
    honeypot = HoneypotSystem()
    honeypot.start()

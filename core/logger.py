#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Core logging module for the Advanced IoT Honeypot.
Provides standardized logging functionality across all components.
"""

import os
import json
import logging
import datetime
from typing import Dict, Any, Optional, Union

# Configure logging format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Log levels mapping
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}


class HoneypotLogger:
    """Advanced logging handler for the honeypot system."""

    def __init__(self, name: str, log_dir: str = "/var/log/advanced_honeypot", 
                 log_level: str = "INFO", log_to_console: bool = True):
        """
        Initialize the logger.
        
        Args:
            name: Logger name (typically component name)
            log_dir: Directory to store log files
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_to_console: Whether to also log to console
        """
        self.name = name
        self.log_dir = log_dir
        self.log_level = LOG_LEVELS.get(log_level.upper(), logging.INFO)
        
        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)
        
        # Clear any existing handlers
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # Create log directory if it doesn't exist
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception as e:
                print(f"Error creating log directory {log_dir}: {e}")
                # Fall back to current directory
                log_dir = "."
        
        # Set up file handler
        log_file = os.path.join(log_dir, f"{name.replace('.', '_')}.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(self.log_level)
        file_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Set up console handler if requested
        if log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self.log_level)
            console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
        # Set up JSON handler for structured logging
        json_log_file = os.path.join(log_dir, f"{name.replace('.', '_')}_json.log")
        self.json_handler = logging.FileHandler(json_log_file)
        self.json_handler.setLevel(self.log_level)
        self.logger.addHandler(self.json_handler)
        
        # Log initialization
        self.logger.info(f"Logger initialized: {name}")
    
    def _log_structured(self, level: int, message: str, **kwargs) -> None:
        """
        Log a structured message in JSON format.
        
        Args:
            level: Logging level
            message: Log message
            **kwargs: Additional fields to include in the log
        """
        if not self.logger.isEnabledFor(level):
            return
        
        log_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "level": logging.getLevelName(level),
            "logger": self.name,
            "message": message
        }
        
        # Add additional fields
        log_data.update(kwargs)
        
        # Write JSON log
        self.json_handler.emit(logging.LogRecord(
            name=self.name,
            level=level,
            pathname="",
            lineno=0,
            msg=json.dumps(log_data),
            args=(),
            exc_info=None
        ))
    
    def debug(self, message: str, **kwargs) -> None:
        """
        Log a debug message.
        
        Args:
            message: Log message
            **kwargs: Additional fields to include in the log
        """
        self.logger.debug(message)
        self._log_structured(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """
        Log an info message.
        
        Args:
            message: Log message
            **kwargs: Additional fields to include in the log
        """
        self.logger.info(message)
        self._log_structured(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """
        Log a warning message.
        
        Args:
            message: Log message
            **kwargs: Additional fields to include in the log
        """
        self.logger.warning(message)
        self._log_structured(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """
        Log an error message.
        
        Args:
            message: Log message
            **kwargs: Additional fields to include in the log
        """
        self.logger.error(message)
        self._log_structured(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """
        Log a critical message.
        
        Args:
            message: Log message
            **kwargs: Additional fields to include in the log
        """
        self.logger.critical(message)
        self._log_structured(logging.CRITICAL, message, **kwargs)
    
    def log_connection(self, src_ip: str, src_port: int, dst_port: int, 
                      protocol: str, session_id: str) -> None:
        """
        Log a new connection.
        
        Args:
            src_ip: Source IP address
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol name
            session_id: Unique session identifier
        """
        self.info(
            f"New connection from {src_ip}:{src_port} to port {dst_port} ({protocol})",
            event_type="connection",
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            session_id=session_id
        )
    
    def log_login_attempt(self, src_ip: str, username: str, password: str, 
                         success: bool, session_id: str) -> None:
        """
        Log a login attempt.
        
        Args:
            src_ip: Source IP address
            username: Attempted username
            password: Attempted password
            success: Whether the login was successful
            session_id: Session identifier
        """
        status = "successful" if success else "failed"
        self.info(
            f"{status.capitalize()} login attempt from {src_ip}: {username}/{password}",
            event_type="login_attempt",
            src_ip=src_ip,
            username=username,
            password=password,
            success=success,
            session_id=session_id
        )
    
    def log_command(self, src_ip: str, command: str, session_id: str) -> None:
        """
        Log a command execution.
        
        Args:
            src_ip: Source IP address
            command: Executed command
            session_id: Session identifier
        """
        self.info(
            f"Command from {src_ip}: {command}",
            event_type="command",
            src_ip=src_ip,
            command=command,
            session_id=session_id
        )
    
    def log_http_request(self, src_ip: str, method: str, path: str, 
                        user_agent: str, session_id: str) -> None:
        """
        Log an HTTP request.
        
        Args:
            src_ip: Source IP address
            method: HTTP method
            path: Requested path
            user_agent: User-Agent header
            session_id: Session identifier
        """
        self.info(
            f"HTTP {method} request from {src_ip}: {path}",
            event_type="http_request",
            src_ip=src_ip,
            method=method,
            path=path,
            user_agent=user_agent,
            session_id=session_id
        )
    
    def log_file_download(self, src_ip: str, url: str, file_name: str, 
                         file_size: int, file_hash: str, session_id: str) -> None:
        """
        Log a file download.
        
        Args:
            src_ip: Source IP address
            url: Download URL
            file_name: Name of the downloaded file
            file_size: Size of the file in bytes
            file_hash: SHA256 hash of the file
            session_id: Session identifier
        """
        self.info(
            f"File download from {src_ip}: {file_name} ({file_size} bytes)",
            event_type="file_download",
            src_ip=src_ip,
            url=url,
            file_name=file_name,
            file_size=file_size,
            file_hash=file_hash,
            session_id=session_id
        )
    
    def log_disconnection(self, src_ip: str, duration: float, session_id: str) -> None:
        """
        Log a disconnection.
        
        Args:
            src_ip: Source IP address
            duration: Session duration in seconds
            session_id: Session identifier
        """
        self.info(
            f"Disconnection from {src_ip} after {duration:.2f} seconds",
            event_type="disconnection",
            src_ip=src_ip,
            duration=duration,
            session_id=session_id
        )


# Logger cache to avoid creating multiple loggers for the same component
_logger_cache = {}


def get_logger(name: str, log_dir: Optional[str] = None, 
              log_level: Optional[str] = None, log_to_console: bool = True) -> HoneypotLogger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
        log_dir: Log directory (if None, uses default from config)
        log_level: Log level (if None, uses default from config)
        log_to_console: Whether to log to console
        
    Returns:
        HoneypotLogger instance
    """
    global _logger_cache
    
    # Use cached logger if available
    if name in _logger_cache:
        return _logger_cache[name]
    
    # Import config here to avoid circular imports
    from core.config import get_config
    config = get_config()
    
    # Use provided values or defaults from config
    log_dir = log_dir or config.get("general", "log_dir")
    log_level = log_level or config.get("general", "log_level")
    
    # Create and cache logger
    logger = HoneypotLogger(name, log_dir, log_level, log_to_console)
    _logger_cache[name] = logger
    
    return logger

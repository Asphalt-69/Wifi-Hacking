#!/usr/bin/env python3
"""
Utils Package - Helper modules for WiFi Exploitation Framework

Provides utility functions for:
- Password pattern prediction and generation
- Router fingerprinting and vendor detection
- Process management and system utilities
- Network analysis and packet manipulation
- Colorized output and logging
- File and data handling
"""

from utils.patterns import PasswordPredictor, PasswordGenerator
from utils.fingerprint import RouterFingerprinter, VendorDetector
from utils.process import ProcessManager, SystemUtils
from utils.network import NetworkUtils, PacketAnalyzer
from utils.logger import Logger, ColorPrint
from utils.data import DataHandler, HashManager

__all__ = [
    # Patterns
    'PasswordPredictor',
    'PasswordGenerator',
    
    # Fingerprint
    'RouterFingerprinter',
    'VendorDetector',
    
    # Process
    'ProcessManager',
    'SystemUtils',
    
    # Network
    'NetworkUtils',
    'PacketAnalyzer',
    
    # Logger
    'Logger',
    'ColorPrint',
    
    # Data
    'DataHandler',
    'HashManager',
]

__version__ = '1.0.0'

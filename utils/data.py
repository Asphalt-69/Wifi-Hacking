#!/usr/bin/env python3
"""
Data handling, serialization, and hash management
"""

import json
import pickle
import base64
import hashlib
import binascii
from typing import Dict, List, Optional, Any
from datetime import datetime


class DataHandler:
    """Handle data serialization and storage"""
    
    @staticmethod
    def save_json(data: Any, filepath: str) -> bool:
        """Save data as JSON"""
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            return False
    
    @staticmethod
    def load_json(filepath: str) -> Optional[Any]:
        """Load JSON file"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            return None
    
    @staticmethod
    def save_pickle(data: Any, filepath: str) -> bool:
        """Save data as pickle"""
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(data, f)
            return True
        except:
            return None
    
    @staticmethod
    def load_pickle(filepath: str) -> Optional[Any]:
        """Load pickle file"""
        try:
            with open(filepath, 'rb') as f:
                return pickle.load(f)
        except:
            return None
    
    @staticmethod
    def to_base64(data: bytes) -> str:
        """Convert to base64"""
        return base64.b64encode(data).decode()
    
    @staticmethod
    def from_base64(data: str) -> bytes:
        """Convert from base64"""
        return base64.b64decode(data)
    
    @staticmethod
    def to_hex(data: bytes) -> str:
        """Convert to hex string"""
        return binascii.hexlify(data).decode()
    
    @staticmethod
    def from_hex(data: str) -> bytes:
        """Convert from hex string"""
        return binascii.unhexlify(data)


class HashManager:
    """Hash calculation and verification utilities"""
    
    @staticmethod
    def md5(data: bytes) -> str:
        """Calculate MD5 hash"""
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def sha1(data: bytes) -> str:
        """Calculate SHA1 hash"""
        return hashlib.sha1(data).hexdigest()
    
    @staticmethod
    def sha256(data: bytes) -> str:
        """Calculate SHA256 hash"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def sha512(data: bytes) -> str:
        """Calculate SHA512 hash"""
        return hashlib.sha512(data).hexdigest()
    
    @staticmethod
    def pbkdf2(password: str, salt: str, iterations: int = 4096) -> bytes:
        """PBKDF2 key derivation"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    
    @staticmethod
    def verify_hash(data: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify hash of data"""
        if algorithm == 'md5':
            return HashManager.md5(data) == expected_hash
        elif algorithm == 'sha1':
            return HashManager.sha1(data) == expected_hash
        elif algorithm == 'sha256':
            return HashManager.sha256(data) == expected_hash
        elif algorithm == 'sha512':
            return HashManager.sha512(data) == expected_hash
        return False
    
    @staticmethod
    def generate_pmkid(pmk: bytes, bssid: bytes) -> bytes:
        """Generate PMKID"""
        import hmac
        data = b"PMK Name" + bssid
        return hmac.new(pmk, data, hashlib.sha1).digest()[:16]
    
    @staticmethod
    def compute_mic(kck: bytes, eapol_frame: bytes) -> bytes:
        """Compute EAPOL MIC"""
        import hmac
        return hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]


class MACAddress:
    """MAC address manipulation utilities"""
    
    @staticmethod
    def format(mac: str) -> str:
        """Format MAC address to standard format"""
        mac = mac.replace('-', '').replace(':', '').replace('.', '').upper()
        if len(mac) == 12:
            return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac
    
    @staticmethod
    def to_bytes(mac: str) -> bytes:
        """Convert MAC address to bytes"""
        mac = MACAddress.format(mac).replace(':', '')
        return binascii.unhexlify(mac)
    
    @staticmethod
    def from_bytes(mac_bytes: bytes) -> str:
        """Convert bytes to MAC address"""
        if len(mac_bytes) == 6:
            return ':'.join(f'{b:02x}' for b in mac_bytes)
        return ''
    
    @staticmethod
    def is_valid(mac: str) -> bool:
        """Check if MAC address is valid"""
        mac = mac.replace(':', '').replace('-', '')
        return len(mac) == 12 and all(c in '0123456789ABCDEFabcdef' for c in mac)
    
    @staticmethod
    def get_oui(mac: str) -> str:
        """Get OUI (first 3 bytes) of MAC address"""
        mac = MACAddress.format(mac)
        return mac[:8].upper()
    
    @staticmethod
    def increment(mac: str, increment: int = 1) -> str:
        """Increment MAC address"""
        mac_int = int(MACAddress.format(mac).replace(':', ''), 16)
        mac_int += increment
        return MACAddress.from_bytes(mac_int.to_bytes(6, 'big'))

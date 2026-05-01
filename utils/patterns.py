#!/usr/bin/env python3
"""
Password Pattern Prediction and Generation
Uses ML-inspired techniques to predict WiFi passwords
"""

import re
import itertools
import random
from typing import List, Dict, Optional, Set
from collections import Counter
from datetime import datetime, timedelta


class PasswordPatterns:
    """Common password pattern database"""
    
    # Common password patterns
    COMMON_PASSWORDS = [
        'password', '12345678', '123456789', 'qwerty123', 'admin123',
        'password123', '11111111', '00000000', 'abc123456', '87654321',
        'iloveyou', 'welcome', 'monkey123', 'dragon123', 'master123'
    ]
    
    # Numeric patterns
    NUMERIC_PATTERNS = [
        r'^\d{8}$', r'^\d{10}$', r'^\d{12}$',  # Pure numeric
        r'^\d{4}-\d{4}$', r'^\d{3}-\d{3}-\d{3}$',  # Dashed
        r'^\d{4}\.\d{4}$', r'^\d{4}\d{4}$',  # Dotted
    ]
    
    # Word patterns
    WORD_PATTERNS = [
        r'^[a-z]{8,12}$',  # Lowercase only
        r'^[A-Z][a-z]{6,10}$',  # Capitalized
        r'^[A-Z]{2,}[a-z]{4,}$',  # Uppercase start
        r'^[a-z]+\d{2,4}$',  # Word + numbers
        r'^\d{2,4}[a-z]+$',  # Numbers + word
    ]
    
    # Leet speak patterns
    LEET_PATTERNS = [
        ('a', '@'), ('a', '4'), ('e', '3'), ('i', '1'),
        ('o', '0'), ('s', '5'), ('t', '7'), ('b', '8'),
        ('g', '9'), ('z', '2')
    ]
    
    @classmethod
    def get_top_passwords(cls, n: int = 100) -> List[str]:
        """Get top N most common passwords"""
        return cls.COMMON_PASSWORDS[:n]


class PasswordGenerator:
    """Generate likely passwords based on various patterns"""
    
    def __init__(self):
        self.generated_passwords: Set[str] = set()
        
    def generate_from_ssid(self, ssid: str) -> List[str]:
        """Generate passwords from SSID"""
        passwords = []
        ssid_clean = re.sub(r'[^a-zA-Z0-9]', '', ssid)
        
        if len(ssid_clean) >= 6:
            # SSID variations
            passwords.append(ssid_clean)
            passwords.append(ssid_clean + '123')
            passwords.append(ssid_clean + 'wifi')
            passwords.append(ssid_clean + 'password')
            passwords.append(ssid_clean[::-1])  # Reversed
            
            # SSID with numbers
            for num in ['123', '456', '789', '000', '111']:
                passwords.append(ssid_clean + num)
                passwords.append(num + ssid_clean)
        
        return list(set(passwords))
    
    def generate_from_bssid(self, bssid: str) -> List[str]:
        """Generate passwords from BSSID (MAC address)"""
        passwords = []
        mac = bssid.replace(':', '').lower()
        
        if len(mac) == 12:
            passwords.append(mac)
            passwords.append(mac[-8:])
            passwords.append(mac[-6:])
            passwords.append(mac.upper())
            
            # Last octet variations
            last_octet = mac[-2:]
            passwords.append(last_octet * 4)
            passwords.append(last_octet + '0000')
        
        return list(set(passwords))
    
    def generate_date_passwords(self, years_back: int = 5) -> List[str]:
        """Generate date-based passwords"""
        passwords = []
        now = datetime.now()
        
        for i in range(years_back):
            year = now.year - i
            year_short = year % 100
            
            # Year formats
            passwords.extend([
                str(year),
                str(year_short),
                f"{year_short}{year_short}",
                f"{year}{year_short}",
            ])
            
            # Month + Year
            for month in range(1, 13):
                month_str = f"{month:02d}"
                passwords.append(f"{month_str}{year}")
                passwords.append(f"{year}{month_str}")
                
                # Day + Month + Year
                for day in range(1, 29):
                    day_str = f"{day:02d}"
                    passwords.append(f"{day_str}{month_str}{year_short}")
        
        return list(set(passwords))
    
    def generate_keyboard_patterns(self) -> List[str]:
        """Generate keyboard walking patterns"""
        rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890'
        ]
        
        patterns = []
        
        # Single row sequences
        for row in rows:
            for length in range(4, min(len(row) + 1, 9)):
                for i in range(len(row) - length + 1):
                    patterns.append(row[i:i+length])
                    patterns.append(row[i:i+length][::-1])
        
        # Zigzag patterns
        zigzags = [
            'qazwsxedc', 'rfvtgbyhn', 'ujmikolp',
            '1qaz2wsx', 'q1w2e3r4', 'z1x2c3v4'
        ]
        patterns.extend(zigzags)
        
        return list(set(patterns))
    
    def generate_leet_variants(self, word: str) -> List[str]:
        """Generate leet speak variants of a word"""
        variants = set([word])
        
        # Generate all leet combinations
        leet_chars = []
        for char in word.lower():
            leet_options = [char]
            for original, leet in PasswordPatterns.LEET_PATTERNS:
                if char == original:
                    leet_options.append(leet)
            leet_chars.append(leet_options)
        
        # Limit combinations to avoid explosion
        max_combinations = 100
        count = 0
        
        for combination in itertools.product(*leet_chars):
            if count >= max_combinations:
                break
            variants.add(''.join(combination))
            count += 1
        
        # Case variations
        variants.add(word.upper())
        variants.add(word.capitalize())
        
        return list(variants)
    
    def generate_all(self, ssid: str = '', bssid: str = '', 
                     vendor: str = '') -> List[str]:
        """Generate all possible password candidates"""
        all_passwords = set()
        
        # Common passwords
        all_passwords.update(PasswordPatterns.COMMON_PASSWORDS)
        
        # SSID-based
        if ssid:
            all_passwords.update(self.generate_from_ssid(ssid))
        
        # BSSID-based
        if bssid:
            all_passwords.update(self.generate_from_bssid(bssid))
        
        # Date-based
        all_passwords.update(self.generate_date_passwords())
        
        # Keyboard patterns
        all_passwords.update(self.generate_keyboard_patterns())
        
        # Vendor defaults
        if vendor:
            vendor_defaults = self._get_vendor_defaults(vendor)
            all_passwords.update(vendor_defaults)
        
        # Remove duplicates and sort by length (shortest first)
        result = list(all_passwords)
        result.sort(key=len)
        
        return result[:500]  # Limit to 500 candidates
    
    def _get_vendor_defaults(self, vendor: str) -> List[str]:
        """Get default passwords for specific vendor"""
        vendor_defaults = {
            'tp-link': ['admin', 'admin123', 'password', '12345678'],
            'd-link': ['admin', 'admin123', 'password', '1234'],
            'netgear': ['admin', 'password', '1234', 'netgear'],
            'asus': ['admin', 'admin123', 'password', 'asus'],
            'cisco': ['cisco', 'admin', 'password', '123456'],
            'huawei': ['admin', 'admin123', 'huawei', '12345678'],
            'xiaomi': ['admin', 'xiaomi', '12345678', 'password'],
        }
        
        return vendor_defaults.get(vendor.lower(), [])


class PasswordPredictor:
    """
    ML-inspired password prediction using statistical analysis
    """
    
    def __init__(self):
        self.password_patterns = PasswordPatterns()
        self.generator = PasswordGenerator()
        
    def predict(self, ssid: str = '', bssid: str = '', 
                vendor: str = '', signal_strength: int = -50) -> List[str]:
        """
        Predict likely passwords based on target information
        """
        candidates = []
        
        # Strong signal = likely default password (unchanged)
        if signal_strength > -40:
            candidates.extend(self.generator._get_vendor_defaults(vendor))
        
        # SSID contains number = likely includes that number
        if ssid:
            numbers = re.findall(r'\d+', ssid)
            for num in numbers:
                candidates.append(num)
                candidates.append(num * 2)
                candidates.append(f"password{num}")
        
        # Common patterns
        candidates.extend(self.generator.generate_all(ssid, bssid, vendor))
        
        # Remove duplicates
        seen = set()
        unique_candidates = []
        for p in candidates:
            if p not in seen and 8 <= len(p) <= 63:
                seen.add(p)
                unique_candidates.append(p)
        
        return unique_candidates[:100]  # Return top 100 predictions
    
    def get_top_passwords(self, n: int = 50) -> List[str]:
        """Get top N most common passwords"""
        return PasswordPatterns.COMMON_PASSWORDS[:n]

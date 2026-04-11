#!/usr/bin/env python3
"""
Configuration management for Wi-Fi exploitation
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import os


@dataclass
class Config:
    """Main configuration class"""
    # Network interfaces
    INTERFACE: str = "wlan0"
    MONITOR_INTERFACE: str = "wlan0mon"
    
    # Paths
    OUTPUT_DIR: str = "/tmp/ctf_wifi_exploit"
    TOOL_PATHS: Dict[str, str] = field(default_factory=lambda: {
        'reaver': '/usr/bin/reaver',
        'bully': '/usr/bin/bully',
        'airodump': '/usr/bin/airodump-ng',
        'aireplay': '/usr/bin/aireplay-ng',
        'hcxdumptool': '/usr/bin/hcxdumptool',
        'hcxpcapngtool': '/usr/bin/hcxpcapngtool',
        'hashcat': '/usr/bin/hashcat',
        'wpa_supplicant': '/usr/sbin/wpa_supplicant',
        'dhclient': '/sbin/dhclient',
        'iw': '/usr/sbin/iw',
        'airmon': '/usr/sbin/airmon-ng'
    })
    
    # Timing (seconds)
    TIMEOUT_TOTAL: int = 30
    TIMEOUT_SCAN: float = 2.0
    TIMEOUT_HANDSHAKE: float = 3.0
    TIMEOUT_WPS: float = 15.0
    TIMEOUT_GPU: float = 10.0
    
    # Performance
    MAX_PARALLEL_ATTACKS: int = 8
    PACKET_INJECTION_RATE: int = 500
    GPU_ENABLED: bool = True
    AGGRESSIVE_TIMING: bool = True
    
    # Scanning
    SCAN_CHANNELS: List[int] = field(default_factory=lambda: list(range(1, 12)))
    SCAN_BANDS: List[str] = field(default_factory=lambda: ['bg', 'a'])
    
    # Output
    VERBOSE: bool = True
    SAVE_PCAP: bool = True
    GENERATE_REPORT: bool = True
    
    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variables"""
        config = cls()
        config.INTERFACE = os.getenv('WIFI_INTERFACE', config.INTERFACE)
        config.TIMEOUT_TOTAL = int(os.getenv('TIMEOUT_TOTAL', config.TIMEOUT_TOTAL))
        config.GPU_ENABLED = os.getenv('GPU_ENABLED', '1') == '1'
        return config


@dataclass
class AttackConfig:
    """Attack-specific configuration"""
    # WPS Pixie Dust
    PIXIE_MAX_TRIES: int = 100
    PIXIE_TIMEOUT: int = 15
    
    # PMKID
    PMKID_CAPTURE_TIME: int = 8
    PMKID_WORDLIST: Optional[str] = None
    
    # KRACK
    KRACK_MAX_RETRIES: int = 3
    KRACK_DEAUTH_COUNT: int = 50
    
    # Password prediction
    PREDICTION_MAX_TRIES: int = 50
    PREDICTION_PARALLEL: int = 20
    
    # Router backdoor
    BACKDOOR_TIMEOUT: float = 1.5
    BACKDOOR_PATHS: List[str] = field(default_factory=lambda: [
        "/", "/index.html", "/login.html", "/login.cgi",
        "/admin.html", "/cgi-bin/luci", "/setup.html",
        "/goform/login", "/userRpm/Index.htm", "/Main_Login.asp"
    ])


# Router vendor MAC prefixes for fingerprinting
VENDOR_MACS = {
    "Cisco": ["00:00:0C", "00:01:42", "00:01:43"],
    "TP-Link": ["10:FE:ED", "14:CC:20", "18:A6:F7"],
    "D-Link": ["00:17:9A", "00:1B:11", "00:1C:F0"],
    "Netgear": ["00:14:6C", "00:18:4D", "00:1F:33"],
    "Asus": ["00:1D:60", "00:22:15", "00:23:54"],
    "Linksys": ["00:12:17", "00:13:10", "00:14:BF"],
    "Belkin": ["00:11:50", "00:17:3F", "00:1C:DF"],
    "Ubiquiti": ["00:15:6D", "00:27:22", "04:18:D6"],
    "MikroTik": ["00:0C:42", "00:18:E7", "00:25:00"],
    "Huawei": ["00:18:82", "00:1E:10", "00:25:9E"],
    "Xiaomi": ["28:6C:07", "34:CE:00", "38:1D:14"],
    "Tenda": ["00:25:5E", "00:30:4F", "C8:3A:35"],
}

# Default password patterns by vendor
DEFAULT_PASSWORD_PATTERNS = {
    'tp-link': [r'^[A-Za-z0-9]{8}$', r'^\d{8}$'],
    'd-link': [r'^[A-Z]{2}\d{6}$', r'^\d{10}$'],
    'netgear': [r'^[a-z]{3}\d{5}$', r'^\d{9,10}$'],
    'asus': [r'^[A-Z0-9]{8,10}$'],
    'huawei': [r'^\d{8,12}$'],
    'xiaomi': [r'^[a-z0-9]{8,10}$'],
    'tenda': [r'^\d{8}$', r'^[A-Z0-9]{8}$'],
}

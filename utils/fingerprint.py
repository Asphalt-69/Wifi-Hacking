#!/usr/bin/env python3
"""
Router Fingerprinting and Vendor Detection
Identifies router make/model from MAC address and behavior
"""

import re
import subprocess
from typing import Dict, Optional, List, Tuple
from collections import defaultdict


class VendorDetector:
    """Detect router vendor from MAC address OUI"""
    
    # Extended OUI database
    VENDOR_OUIS = {
        # Cisco
        'Cisco': ['00:00:0C', '00:01:42', '00:01:43', '00:02:8A', '00:03:6C'],
        
        # TP-Link
        'TP-Link': ['10:FE:ED', '14:CC:20', '18:A6:F7', '1C:3E:84', '20:4E:7F',
                    '24:0A:64', '28:6C:07', '2C:56:DC', '30:46:9A', '34:CE:00'],
        
        # D-Link
        'D-Link': ['00:17:9A', '00:1B:11', '00:1C:F0', '00:22:B0', '00:24:01',
                   '00:26:5A', '00:40:05', '1C:BD:B9', '24:7E:5A', '28:10:7B'],
        
        # Netgear
        'Netgear': ['00:14:6C', '00:18:4D', '00:1F:33', '00:24:B2', '00:26:F2',
                    '20:4E:7F', '2C:30:33', '3C:2E:F9', '40:16:7E', '44:94:FC'],
        
        # Asus
        'Asus': ['00:1D:60', '00:22:15', '00:23:54', '00:24:8C', '00:26:18',
                 '1C:B7:2C', '20:CF:30', '28:D2:44', '30:85:A9', '34:97:F6'],
        
        # Linksys
        'Linksys': ['00:12:17', '00:13:10', '00:14:BF', '00:18:F8', '00:1A:70',
                    '00:21:29', '00:22:6B', '00:24:94', '0C:37:96', '1C:1B:0D'],
        
        # Belkin
        'Belkin': ['00:11:50', '00:17:3F', '00:1C:DF', '00:22:75', '00:26:75',
                   '08:86:3B', '14:91:82', '24:1A:3E', '30:23:03'],
        
        # Ubiquiti
        'Ubiquiti': ['00:15:6D', '00:27:22', '04:18:D6', '0C:72:2C', '18:E8:29',
                     '24:A4:3C', '2C:EA:7F', '34:DB:FD', '44:D9:E7'],
        
        # MikroTik
        'MikroTik': ['00:0C:42', '00:18:E7', '00:25:00', '4C:5E:0C', '64:D1:54',
                     '6C:3B:6B', '74:4D:28', '80:2A:A8', '8C:3C:A6'],
        
        # Huawei
        'Huawei': ['00:18:82', '00:1E:10', '00:25:9E', '04:16:76', '08:75:6F',
                   '10:78:5A', '14:07:FE', '18:16:C9', '20:A0:3C'],
        
        # Xiaomi
        'Xiaomi': ['28:6C:07', '34:CE:00', '38:1D:14', '40:31:6E', '44:23:7C',
                   '4C:65:A8', '84:0D:8E', '88:C3:97', '8C:BE:BE'],
        
        # Tenda
        'Tenda': ['00:25:5E', '00:30:4F', 'C8:3A:35', 'D8:5D:4C', 'E8:3E:FC'],
        
        # ZTE
        'ZTE': ['00:1D:52', '00:24:25', '00:26:44', '08:3C:76', '10:07:36',
                '18:93:4C', '20:4C:03', '28:54:2E', '30:53:0C'],
        
        # Arris
        'Arris': ['00:17:3F', '00:1A:2A', '00:22:02', '08:17:EC', '10:69:43',
                  '1C:49:68', '20:24:43', '34:CE:10', '3C:1E:04'],
        
        # Motorola
        'Motorola': ['00:14:A4', '00:1D:FE', '00:23:12', '04:37:E6', '24:0A:64',
                     '2C:75:77', '44:38:39', '6C:FA:89', '80:23:A2'],
    }
    
    @classmethod
    def detect_vendor(cls, bssid: str) -> str:
        """Detect vendor from BSSID MAC address"""
        if not bssid or len(bssid) < 8:
            return 'Unknown'
        
        oui = bssid[:8].upper()
        
        for vendor, ouis in cls.VENDOR_OUIS.items():
            for prefix in ouis:
                if oui.startswith(prefix.upper()):
                    return vendor
        
        return 'Unknown'
    
    @classmethod
    def get_vendor_details(cls, bssid: str) -> Dict:
        """Get detailed vendor information"""
        vendor = cls.detect_vendor(bssid)
        
        # Common default credentials by vendor
        default_creds = {
            'TP-Link': [('admin', 'admin'), ('admin', '')],
            'D-Link': [('admin', 'admin'), ('user', 'user')],
            'Netgear': [('admin', 'password'), ('admin', '1234')],
            'Asus': [('admin', 'admin'), ('admin', 'password')],
            'Cisco': [('cisco', 'cisco'), ('admin', 'admin')],
            'Linksys': [('admin', 'admin'), ('admin', 'password')],
            'Huawei': [('admin', 'admin'), ('root', 'admin')],
            'Xiaomi': [('admin', 'admin'), ('admin', 'xiaomi')],
            'Tenda': [('admin', 'admin'), ('admin', '')],
        }
        
        # Common WPS PIN patterns by vendor
        wps_patterns = {
            'TP-Link': 'wps_pin_default',
            'D-Link': 'wps_pin_bssid',
            'Netgear': 'wps_pin_serial',
            'Asus': 'wps_pin_calculated',
        }
        
        return {
            'vendor': vendor,
            'default_credentials': default_creds.get(vendor, [('admin', 'admin')]),
            'wps_vulnerable': vendor in wps_patterns,
            'wps_pattern': wps_patterns.get(vendor, 'unknown'),
            'known_vulnerabilities': cls._get_known_vulns(vendor)
        }
    
    @staticmethod
    def _get_known_vulns(vendor: str) -> List[str]:
        """Get known vulnerabilities for vendor"""
        vulns = {
            'TP-Link': ['CVE-2017-13770', 'CVE-2019-7403', 'WPS Pixie Dust'],
            'D-Link': ['CVE-2019-18498', 'CVE-2019-16983', 'WPS PIN Generation'],
            'Netgear': ['CVE-2019-11539', 'CVE-2018-21141', 'KRACK Vulnerable'],
            'Asus': ['CVE-2018-20061', 'CVE-2019-15105', 'PMKID Vulnerable'],
            'Cisco': ['CVE-2019-15265', 'CVE-2018-15378', 'Valet Default PIN'],
        }
        return vulns.get(vendor, [])


class RouterFingerprinter:
    """
    Advanced router fingerprinting using:
    - TTL analysis
    - DHCP fingerprinting
    - HTTP server headers
    - Open port analysis
    """
    
    def __init__(self):
        self.fingerprint_db = self._build_fingerprint_db()
    
    def _build_fingerprint_db(self) -> Dict:
        """Build fingerprint database"""
        return {
            'TP-Link': {
                'ttl': 64,
                'http_headers': ['TP-LINK', 'TL-WR', 'Archer'],
                'common_ports': [80, 443, 20005],
                'model_patterns': ['TL-WR', 'Archer', 'Deco']
            },
            'D-Link': {
                'ttl': 64,
                'http_headers': ['D-Link', 'DIR-', 'DAP-'],
                'common_ports': [80, 8080, 445],
                'model_patterns': ['DIR-', 'DAP-', 'DSP-']
            },
            'Netgear': {
                'ttl': 64,
                'http_headers': ['NETGEAR', 'Genie'],
                'common_ports': [80, 443, 5000],
                'model_patterns': ['R', 'WNR', 'Nighthawk']
            },
            'Asus': {
                'ttl': 64,
                'http_headers': ['ASUS', 'RT-AC', 'RT-N'],
                'common_ports': [80, 443, 8443, 8080],
                'model_patterns': ['RT-', 'ROG', 'GT-AC']
            },
            'Ubiquiti': {
                'ttl': 64,
                'http_headers': ['Ubiquiti', 'UniFi', 'AirOS'],
                'common_ports': [80, 443, 8843, 8080],
                'model_patterns': ['UAP', 'USG', 'EdgeRouter']
            },
            'MikroTik': {
                'ttl': 64,
                'http_headers': ['MikroTik', 'RouterOS'],
                'common_ports': [80, 8291, 8728, 22],
                'model_patterns': ['RB', 'CCR', 'hAP']
            }
        }
    
    def fingerprint_from_gateway(self, gateway_ip: str, timeout: int = 3) -> Dict:
        """
        Fingerprint router by analyzing gateway
        """
        results = {
            'vendor': 'Unknown',
            'model': 'Unknown',
            'confidence': 0,
            'open_ports': [],
            'http_server': None,
            'ttl': None
        }
        
        # Get TTL from ping
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), gateway_ip],
                capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout
            
            match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
            if match:
                results['ttl'] = int(match.group(1))
        except:
            pass
        
        # Check common ports
        common_ports = [80, 443, 8080, 8443, 22, 23, 21]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((gateway_ip, port))
                if result == 0:
                    results['open_ports'].append(port)
                sock.close()
            except:
                pass
        
        # Get HTTP header
        for port in [80, 8080, 8443]:
            if port in results['open_ports']:
                try:
                    import requests
                    resp = requests.get(f'http://{gateway_ip}:{port}', timeout=2)
                    server = resp.headers.get('Server', '')
                    results['http_server'] = server
                    
                    # Match against database
                    for vendor, info in self.fingerprint_db.items():
                        for header in info['http_headers']:
                            if header.lower() in server.lower():
                                results['vendor'] = vendor
                                results['confidence'] = 80
                                break
                except:
                    pass
        
        # Match based on open ports pattern
        if results['vendor'] == 'Unknown' and results['open_ports']:
            for vendor, info in self.fingerprint_db.items():
                common = set(info['common_ports']) & set(results['open_ports'])
                if len(common) >= 2:
                    results['vendor'] = vendor
                    results['confidence'] = 60
                    break
        
        return results
    
    def get_recommended_attacks(self, vendor: str) -> List[str]:
        """Get recommended attacks based on vendor"""
        recommendations = {
            'TP-Link': ['wps_pixie', 'pmkid', 'backdoor'],
            'D-Link': ['wps_pin', 'pmkid', 'backdoor'],
            'Netgear': ['pmkid', 'krack', 'backdoor'],
            'Asus': ['pmkid', 'fragattack', 'backdoor'],
            'Ubiquiti': ['pmkid', 'evil_twin', 'backdoor'],
            'MikroTik': ['krack', 'fragattack'],
        }
        
        return recommendations.get(vendor, ['handshake_capture', 'evil_twin'])

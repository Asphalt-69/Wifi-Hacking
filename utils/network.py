#!/usr/bin/env python3
"""
Network Utilities and Packet Analysis
"""

import socket
import struct
import subprocess
from typing import List, Dict, Optional, Tuple
from ipaddress import ip_address, ip_network


class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def get_local_ip(interface: str = 'wlan0') -> Optional[str]:
        """Get local IP address of interface"""
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', interface],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'inet ' in line and 'global' in line:
                    ip = line.strip().split()[1].split('/')[0]
                    return ip
        except:
            pass
        return None
    
    @staticmethod
    def get_gateway() -> Optional[str]:
        """Get default gateway IP"""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    return line.split()[2]
        except:
            pass
        return None
    
    @staticmethod
    def scan_network(ip_range: str = '192.168.1.0/24', timeout: int = 1) -> List[str]:
        """Scan network for active hosts"""
        active_hosts = []
        
        try:
            network = ip_network(ip_range)
            for ip in network.hosts():
                try:
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', str(timeout), str(ip)],
                        capture_output=True, timeout=timeout
                    )
                    if result.returncode == 0:
                        active_hosts.append(str(ip))
                except:
                    continue
        except:
            pass
        
        return active_hosts
    
    @staticmethod
    def get_mac_from_ip(ip: str) -> Optional[str]:
        """Get MAC address from IP using ARP"""
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac = parts[2]
                        if ':' in mac:
                            return mac
        except:
            pass
        return None
    
    @staticmethod
    def is_port_open(ip: str, port: int, timeout: int = 2) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    @staticmethod
    def get_wifi_ssid(interface: str = 'wlan0') -> Optional[str]:
        """Get currently connected SSID"""
        try:
            result = subprocess.run(
                ['iw', 'dev', interface, 'link'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'SSID:' in line:
                    return line.split('SSID:')[1].strip()
        except:
            pass
        return None
    
    @staticmethod
    def get_wifi_signal(interface: str = 'wlan0') -> int:
        """Get current signal strength"""
        try:
            result = subprocess.run(
                ['iw', 'dev', interface, 'station', 'dump'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'signal:' in line:
                    return int(line.split('signal:')[1].strip().split()[0])
        except:
            pass
        return -100


class PacketAnalyzer:
    """Packet analysis utilities"""
    
    @staticmethod
    def parse_eapol(packet_data: bytes) -> Dict:
        """Parse EAPOL packet"""
        if len(packet_data) < 4:
            return {}
        
        try:
            offset = 0
            version = packet_data[offset]
            offset += 1
            packet_type = packet_data[offset]
            offset += 1
            body_length = struct.unpack('>H', packet_data[offset:offset+2])[0]
            offset += 2
            
            if len(packet_data) < offset + 4:
                return {}
            
            descriptor_type = packet_data[offset]
            offset += 1
            key_info = struct.unpack('<H', packet_data[offset:offset+2])[0]
            offset += 2
            key_length = struct.unpack('<H', packet_data[offset:offset+2])[0]
            offset += 2
            replay_counter = struct.unpack('<Q', packet_data[offset:offset+8])[0]
            offset += 8
            
            return {
                'version': version,
                'type': packet_type,
                'body_length': body_length,
                'descriptor_type': descriptor_type,
                'key_info': key_info,
                'key_length': key_length,
                'replay_counter': replay_counter,
                'has_nonce': len(packet_data) > offset + 32
            }
        except:
            return {}
    
    @staticmethod
    def extract_iv(wep_packet: bytes) -> Optional[bytes]:
        """Extract IV from WEP packet"""
        if len(wep_packet) >= 4:
            return wep_packet[:3]
        return None
    
    @staticmethod
    def is_arp_packet(data: bytes) -> bool:
        """Check if packet is ARP"""
        if len(data) >= 28:
            # Check ethertype (0x0806) and ARP header
            return data[12:14] == b'\x08\x06'
        return False
    
    @staticmethod
    def is_ip_packet(data: bytes) -> bool:
        """Check if packet is IP"""
        if len(data) >= 14:
            ethertype = data[12:14]
            return ethertype == b'\x08\x00'
        return False
    
    @staticmethod
    def is_dhcp_packet(data: bytes) -> bool:
        """Check if packet is DHCP"""
        if len(data) >= 14:
            # IP protocol 17 (UDP) and ports 67/68
            if data[23] == 17:
                udp_src = struct.unpack('>H', data[34:36])[0]
                udp_dst = struct.unpack('>H', data[36:38])[0]
                return udp_src in (67, 68) or udp_dst in (67, 68)
        return False

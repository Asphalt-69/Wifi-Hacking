#!/usr/bin/env python3
"""
Ultra-fast network scanner with channel agility
"""

import os
import re
import time
import subprocess
import mmap
from typing import List, Dict, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading


@dataclass
class NetworkTarget:
    """Discovered network target"""
    bssid: str
    ssid: str
    channel: str
    encryption: str
    power: int
    beacons: int
    vendor: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'bssid': self.bssid,
            'ssid': self.ssid,
            'channel': self.channel,
            'encryption': self.encryption,
            'power': self.power,
            'beacons': self.beacons,
            'vendor': self.vendor
        }


class HyperScanner:
    """
    Ultra-fast wireless scanner using channel agility
    Sweeps all channels in under 2 seconds
    """
    
    def __init__(self, interface: str, config=None):
        self.interface = interface
        self.config = config
        self.scan_results: List[NetworkTarget] = []
        self._scan_lock = threading.Lock()
        
    def hyper_scan(self, channels: Optional[List[int]] = None) -> List[NetworkTarget]:
        """
        Perform ultra-fast channel sweep
        Returns list of discovered networks
        """
        if channels is None:
            channels = list(range(1, 12)) + [36, 40, 44, 48]  # 2.4GHz + 5GHz
        
        pcap_file = f"/tmp/hyperscan_{int(time.time())}"
        
        # Enable background scanning
        self._enable_background_scan()
        
        # Launch airodump on all channels
        proc = subprocess.Popen([
            "airodump-ng",
            "--output-format", "csv",
            "--channel", ",".join(map(str, channels)),
            "--band", "abg",
            "-w", pcap_file,
            self.interface
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Quick capture
        time.sleep(2.0)  # 2 seconds is enough for full sweep
        proc.terminate()
        
        # Parse results
        self.scan_results = self._fast_parse(pcap_file + "-01.csv")
        
        # Cleanup
        self._cleanup_files(pcap_file)
        
        return self.scan_results
    
    def _enable_background_scan(self):
        """Enable aggressive background scanning"""
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "scan_interval", "1"],
                capture_output=True
            )
        except:
            pass
    
    def _fast_parse(self, csv_file: str) -> List[NetworkTarget]:
        """Memory-mapped CSV parsing for speed"""
        targets = []
        
        if not os.path.exists(csv_file):
            return targets
        
        try:
            # Memory map for fast reading
            with open(csv_file, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    data = mm.read().decode('utf-8', errors='ignore')
            
            lines = data.split('\n')
            in_networks = False
            
            for line in lines:
                if 'BSSID' in line and 'channel' in line:
                    in_networks = True
                    continue
                
                if in_networks and line.strip() and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 14 and parts[0] and parts[0].count(':') == 5:
                        try:
                            target = NetworkTarget(
                                bssid=parts[0].strip(),
                                ssid=parts[13].strip() if len(parts) > 13 and parts[13].strip() else '<Hidden>',
                                channel=parts[3].strip(),
                                encryption=parts[5].strip(),
                                power=int(parts[8].strip()) if parts[8].strip() else -100,
                                beacons=int(parts[1].strip()) if parts[1].strip() else 0
                            )
                            targets.append(target)
                        except (ValueError, IndexError):
                            continue
            
            # Sort by signal strength
            targets.sort(key=lambda x: x.power, reverse=True)
            
        except Exception as e:
            if self.config and self.config.VERBOSE:
                print(f"[-] Parse error: {e}")
        
        return targets
    
    def _cleanup_files(self, pcap_file: str):
        """Remove temporary files"""
        for ext in ['-01.csv', '-01.kismet.csv', '-01.log.csv']:
            try:
                os.remove(pcap_file + ext)
            except:
                pass
    
    def get_strongest_target(self) -> Optional[NetworkTarget]:
        """Get the strongest signal target"""
        if self.scan_results:
            return self.scan_results[0]
        return None
    
    def scan_single_channel(self, channel: str, duration: float = 1.0) -> List[NetworkTarget]:
        """Scan a single channel quickly"""
        pcap_file = f"/tmp/scan_ch{channel}_{int(time.time())}"
        
        proc = subprocess.Popen([
            "airodump-ng",
            "--channel", str(channel),
            "-w", pcap_file,
            self.interface
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(duration)
        proc.terminate()
        
        targets = self._fast_parse(pcap_file + "-01.csv")
        self._cleanup_files(pcap_file)
        
        return targets

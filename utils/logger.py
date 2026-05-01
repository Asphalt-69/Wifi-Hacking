#!/usr/bin/env python3
"""
Logging and Output Utilities with Color Support
"""

import sys
import time
from datetime import datetime
from typing import Optional
from enum import Enum


class Color:
    """ANSI color codes"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


class LogLevel(Enum):
    """Log levels"""
    DEBUG = 0
    INFO = 1
    SUCCESS = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5


class ColorPrint:
    """Colored output utility"""
    
    @staticmethod
    def _print(color: str, text: str, bold: bool = False, end: str = '\n'):
        prefix = Color.BOLD if bold else ''
        print(f"{prefix}{color}{text}{Color.RESET}", end=end)
    
    @staticmethod
    def success(text: str, bold: bool = True):
        ColorPrint._print(Color.GREEN, f"[✓] {text}", bold)
    
    @staticmethod
    def error(text: str, bold: bool = True):
        ColorPrint._print(Color.RED, f"[✗] {text}", bold)
    
    @staticmethod
    def warning(text: str, bold: bool = False):
        ColorPrint._print(Color.YELLOW, f"[!] {text}", bold)
    
    @staticmethod
    def info(text: str, bold: bool = False):
        ColorPrint._print(Color.CYAN, f"[*] {text}", bold)
    
    @staticmethod
    def debug(text: str):
        if Logger.DEBUG_ENABLED:
            ColorPrint._print(Color.DIM, f"[DEBUG] {text}", bold=False)
    
    @staticmethod
    def header(text: str):
        print()
        ColorPrint._print(Color.MAGENTA + Color.BOLD, f"{'='*60}", bold=True)
        ColorPrint._print(Color.MAGENTA + Color.BOLD, f" {text} ", bold=True)
        ColorPrint._print(Color.MAGENTA + Color.BOLD, f"{'='*60}", bold=True)
        print()
    
    @staticmethod
    def status(label: str, value: str, status: str = 'ok'):
        if status == 'ok':
            status_color = Color.GREEN
        elif status == 'warning':
            status_color = Color.YELLOW
        else:
            status_color = Color.RED
        
        print(f"  {Color.BOLD}{label}:{Color.RESET} {value} ", end='')
        print(f"{status_color}[{status}]{Color.RESET}")


class Logger:
    """Main logger with file output support"""
    
    DEBUG_ENABLED = False
    _log_file: Optional[str] = None
    
    @classmethod
    def enable_debug(cls):
        cls.DEBUG_ENABLED = True
    
    @classmethod
    def set_log_file(cls, path: str):
        cls._log_file = path
    
    @classmethod
    def _log(cls, level: LogLevel, message: str):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_line = f"[{timestamp}] [{level.name}] {message}"
        
        # Console output based on level
        if level == LogLevel.SUCCESS:
            ColorPrint.success(message)
        elif level == LogLevel.ERROR:
            ColorPrint.error(message)
        elif level == LogLevel.WARNING:
            ColorPrint.warning(message)
        elif level == LogLevel.INFO:
            ColorPrint.info(message)
        elif level == LogLevel.DEBUG and cls.DEBUG_ENABLED:
            ColorPrint.debug(message)
        
        # File output
        if cls._log_file:
            try:
                with open(cls._log_file, 'a') as f:
                    f.write(log_line + '\n')
            except:
                pass
    
    @classmethod
    def success(cls, message: str):
        cls._log(LogLevel.SUCCESS, message)
    
    @classmethod
    def error(cls, message: str):
        cls._log(LogLevel.ERROR, message)
    
    @classmethod
    def warning(cls, message: str):
        cls._log(LogLevel.WARNING, message)
    
    @classmethod
    def info(cls, message: str):
        cls._log(LogLevel.INFO, message)
    
    @classmethod
    def debug(cls, message: str):
        cls._log(LogLevel.DEBUG, message)
    
    @classmethod
    def progress(cls, current: int, total: int, prefix: str = ''):
        """Show progress bar"""
        if total == 0:
            return
        
        percent = (current / total) * 100
        bar_length = 30
        filled = int(bar_length * current // total)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        sys.stdout.write(f'\r{prefix} [{bar}] {percent:.1f}%')
        sys.stdout.flush()
        
        if current >= total:
            print()

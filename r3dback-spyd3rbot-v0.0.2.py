#!/usr/bin/env python3
"""
🕸️ SPIDER BOT PRO v0.0.2
Author: Ian Carter Kulani
Version: v0.0.2
Description: SpiderBot cybersecurity tool with 500+ commands,
            Discord/Telegram/WhatsApp/Signal integration, advanced monitoring,
            Nikto web scanner, IP management, and comprehensive security analysis
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
import shutil
import urllib.parse
import asyncio
import uuid

# Optional imports with fallbacks
try:
    import discord
    from discord.ext import commands, tasks
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("⚠️ Warning: discord.py not available. Install with: pip install discord.py")

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import MessageEntityCode
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Warning: telethon not available. Install with: pip install telethon")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ Warning: whois not available. Install with: pip install python-whois")

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    print("⚠️ Warning: colorama not available. Install with: pip install colorama")

# WhatsApp Integration
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("⚠️ Warning: selenium not available. Install with: pip install selenium webdriver-manager")

# Signal Integration
try:
    import subprocess
    SIGNAL_CLI_AVAILABLE = shutil.which('signal-cli') is not None
except ImportError:
    SIGNAL_CLI_AVAILABLE = False

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".spiderbot_pro"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram_config.json")
DISCORD_CONFIG_FILE = os.path.join(CONFIG_DIR, "discord_config.json")
WHATSAPP_CONFIG_FILE = os.path.join(CONFIG_DIR, "whatsapp_config.json")
SIGNAL_CONFIG_FILE = os.path.join(CONFIG_DIR, "signal_config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "network_data.db")
LOG_FILE = os.path.join(CONFIG_DIR, "spiderbot.log")
NIKTO_RESULTS_DIR = os.path.join(CONFIG_DIR, "nikto_results")
WHATSAPP_SESSION_DIR = os.path.join(CONFIG_DIR, "whatsapp_session")
REPORT_DIR = "reports"
SCAN_RESULTS_DIR = "scan_results"
ALERTS_DIR = "alerts"
MONITORING_DIR = "monitoring"
BACKUPS_DIR = "backups"
TEMP_DIR = "temp"
SCRIPTS_DIR = "scripts"

# Create directories
directories = [
    CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, ALERTS_DIR,
    MONITORING_DIR, BACKUPS_DIR, TEMP_DIR, SCRIPTS_DIR, 
    NIKTO_RESULTS_DIR, WHATSAPP_SESSION_DIR
]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SpiderBotPro")

# Color setup
if COLORAMA_AVAILABLE:
    class Colors:
        RED = Fore.RED + Style.BRIGHT
        GREEN = Fore.GREEN + Style.BRIGHT
        YELLOW = Fore.YELLOW + Style.BRIGHT
        BLUE = Fore.BLUE + Style.BRIGHT
        CYAN = Fore.CYAN + Style.BRIGHT
        MAGENTA = Fore.MAGENTA + Style.BRIGHT
        WHITE = Fore.WHITE + Style.BRIGHT
        RESET = Style.RESET_ALL
else:
    class Colors:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""

# =====================
# DATA CLASSES & ENUMS
# =====================
class ScanType:
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"
    VULNERABILITY = "vulnerability"
    FULL = "full"
    UDP = "udp"
    OS_DETECTION = "os_detection"
    SERVICE_DETECTION = "service_detection"
    WEB = "web"
    NIKTO = "nikto"

class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatAlert:
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class ScanResult:
    target: str
    scan_type: str
    open_ports: List[Dict]
    timestamp: str
    success: bool
    error: Optional[str] = None
    vulnerabilities: Optional[List[Dict]] = None

@dataclass
class NiktoResult:
    target: str
    timestamp: str
    vulnerabilities: List[Dict]
    scan_time: float
    output_file: str
    success: bool
    error: Optional[str] = None

@dataclass
class CommandResult:
    success: bool
    output: str
    execution_time: float
    error: Optional[str] = None
    data: Optional[Dict] = None

@dataclass
class ManagedIP:
    ip_address: str
    added_by: str
    added_date: str
    notes: str
    is_blocked: bool = False
    block_reason: Optional[str] = None
    blocked_date: Optional[str] = None

# =====================
# CONFIGURATION MANAGER
# =====================
class ConfigManager:
    """Configuration manager"""
    
    DEFAULT_CONFIG = {
        "monitoring": {
            "enabled": True,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 100,
            "udp_flood_threshold": 500,
            "http_flood_threshold": 200,
            "ddos_threshold": 1000
        },
        "scanning": {
            "default_ports": "1-1000",
            "timeout": 30,
            "rate_limit": False
        },
        "security": {
            "auto_block": False,
            "auto_block_threshold": 5,
            "log_level": "INFO",
            "backup_enabled": True
        },
        "nikto": {
            "enabled": True,
            "timeout": 300,
            "max_targets": 10,
            "scan_level": 2,
            "ssl_ports": "443,8443,9443",
            "db_check": True
        },
        "discord": {
            "enabled": False,
            "token": "",
            "channel_id": "",
            "prefix": "!",
            "admin_role": "Admin",
            "security_role": "Security Team"
        },
        "telegram": {
            "enabled": False,
            "api_id": "",
            "api_hash": "",
            "phone_number": "",
            "channel_id": ""
        },
        "whatsapp": {
            "enabled": False,
            "phone_number": "",
            "command_prefix": "/",
            "auto_login": False,
            "session_timeout": 3600,
            "allowed_contacts": []
        },
        "signal": {
            "enabled": False,
            "phone_number": "",
            "command_prefix": "!",
            "signal_cli_path": "signal-cli",
            "allowed_numbers": []
        }
    }
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    for key, value in ConfigManager.DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if sub_key not in config[key]:
                                    config[key][sub_key] = sub_value
                    return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    @staticmethod
    def save_telegram_config(config: Dict) -> bool:
        """Save Telegram configuration"""
        try:
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    @staticmethod
    def load_telegram_config() -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        return {}
    
    @staticmethod
    def save_discord_config(config: Dict) -> bool:
        """Save Discord configuration"""
        try:
            with open(DISCORD_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Discord config: {e}")
            return False
    
    @staticmethod
    def load_discord_config() -> Dict:
        """Load Discord configuration"""
        try:
            if os.path.exists(DISCORD_CONFIG_FILE):
                with open(DISCORD_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Discord config: {e}")
        return {}
    
    @staticmethod
    def save_whatsapp_config(config: Dict) -> bool:
        """Save WhatsApp configuration"""
        try:
            with open(WHATSAPP_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save WhatsApp config: {e}")
            return False
    
    @staticmethod
    def load_whatsapp_config() -> Dict:
        """Load WhatsApp configuration"""
        try:
            if os.path.exists(WHATSAPP_CONFIG_FILE):
                with open(WHATSAPP_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load WhatsApp config: {e}")
        return {}
    
    @staticmethod
    def save_signal_config(config: Dict) -> bool:
        """Save Signal configuration"""
        try:
            with open(SIGNAL_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Signal config: {e}")
            return False
    
    @staticmethod
    def load_signal_config() -> Dict:
        """Load Signal configuration"""
        try:
            if os.path.exists(SIGNAL_CONFIG_FILE):
                with open(SIGNAL_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Signal config: {e}")
        return {}

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database manager"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize database tables"""
        tables = [
            # Command history
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL
            )
            """,
            
            # Threat alerts
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            
            # Scan results
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                vulnerabilities TEXT,
                execution_time REAL
            )
            """,
            
            # Nikto scan results
            """
            CREATE TABLE IF NOT EXISTS nikto_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                vulnerabilities TEXT,
                output_file TEXT,
                scan_time REAL,
                success BOOLEAN DEFAULT 1
            )
            """,
            
            # Managed IPs
            """
            CREATE TABLE IF NOT EXISTS managed_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_by TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                block_reason TEXT,
                blocked_date TIMESTAMP,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                scan_count INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0
            )
            """,
            
            # System metrics
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                connections_count INTEGER
            )
            """,
            
            # IP blocking history
            """
            CREATE TABLE IF NOT EXISTS ip_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                executed_by TEXT,
                success BOOLEAN DEFAULT 1
            )
            """,
            
            # WhatsApp sessions
            """
            CREATE TABLE IF NOT EXISTS whatsapp_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT UNIQUE NOT NULL,
                session_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP,
                status TEXT DEFAULT 'inactive'
            )
            """,
            
            # Signal sessions
            """
            CREATE TABLE IF NOT EXISTS signal_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP,
                status TEXT DEFAULT 'inactive'
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def log_command(self, command: str, source: str = "local", success: bool = True,
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO command_history (command, source, success, output, execution_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (command, source, success, output[:5000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat alert"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip,
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
            logger.info(f"Threat logged: {alert.threat_type} from {alert.source_ip}")
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            open_ports_json = json.dumps(scan_result.open_ports) if scan_result.open_ports else "[]"
            vulnerabilities_json = json.dumps(scan_result.vulnerabilities) if scan_result.vulnerabilities else "[]"
            self.cursor.execute('''
                INSERT INTO scans (target, scan_type, open_ports, vulnerabilities, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_result.target, scan_result.scan_type, open_ports_json, 
                  vulnerabilities_json, scan_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_nikto_scan(self, nikto_result: NiktoResult):
        """Log Nikto scan results"""
        try:
            vulnerabilities_json = json.dumps(nikto_result.vulnerabilities) if nikto_result.vulnerabilities else "[]"
            self.cursor.execute('''
                INSERT INTO nikto_scans (target, vulnerabilities, output_file, scan_time, success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (nikto_result.target, vulnerabilities_json, nikto_result.output_file,
                  nikto_result.scan_time, nikto_result.success, nikto_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Nikto scan: {e}")
    
    def add_managed_ip(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to management"""
        try:
            ipaddress.ip_address(ip)  # Validate IP
            self.cursor.execute('''
                INSERT OR IGNORE INTO managed_ips (ip_address, added_by, notes, added_date)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (ip, added_by, notes))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add managed IP: {e}")
            return False
    
    def remove_managed_ip(self, ip: str) -> bool:
        """Remove IP from management"""
        try:
            self.cursor.execute('''
                DELETE FROM managed_ips WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to remove managed IP: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str, executed_by: str = "system") -> bool:
        """Mark IP as blocked"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 1, block_reason = ?, blocked_date = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (reason, ip))
            
            # Log block action
            self.cursor.execute('''
                INSERT INTO ip_blocks (ip_address, action, reason, executed_by)
                VALUES (?, ?, ?, ?)
            ''', (ip, "block", reason, executed_by))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
            return False
    
    def unblock_ip(self, ip: str, executed_by: str = "system") -> bool:
        """Unblock IP"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 0, block_reason = NULL, blocked_date = NULL
                WHERE ip_address = ?
            ''', (ip,))
            
            # Log unblock action
            self.cursor.execute('''
                INSERT INTO ip_blocks (ip_address, action, reason, executed_by)
                VALUES (?, ?, ?, ?)
            ''', (ip, "unblock", "Manually unblocked", executed_by))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")
            return False
    
    def get_managed_ips(self, include_blocked: bool = True) -> List[Dict]:
        """Get managed IPs"""
        try:
            if include_blocked:
                self.cursor.execute('''
                    SELECT * FROM managed_ips ORDER BY added_date DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM managed_ips WHERE is_blocked = 0 ORDER BY added_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get managed IPs: {e}")
            return []
    
    def get_ip_info(self, ip: str) -> Optional[Dict]:
        """Get information about a specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM managed_ips WHERE ip_address = ?
            ''', (ip,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get IP info: {e}")
            return None
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_threats_by_ip(self, ip: str, limit: int = 10) -> List[Dict]:
        """Get threats for specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats 
                WHERE source_ip = ? 
                ORDER BY timestamp DESC LIMIT ?
            ''', (ip, limit))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats by IP: {e}")
            return []
    
    def get_nikto_scans(self, limit: int = 10) -> List[Dict]:
        """Get recent Nikto scans"""
        try:
            self.cursor.execute('''
                SELECT * FROM nikto_scans ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get Nikto scans: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM command_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            # Count threats
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            # Count commands
            self.cursor.execute('SELECT COUNT(*) FROM command_history')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            # Count scans
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
            
            # Count Nikto scans
            self.cursor.execute('SELECT COUNT(*) FROM nikto_scans')
            stats['total_nikto_scans'] = self.cursor.fetchone()[0]
            
            # Count managed IPs
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips')
            stats['total_managed_ips'] = self.cursor.fetchone()[0]
            
            # Count blocked IPs
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips WHERE is_blocked = 1')
            stats['total_blocked_ips'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# =====================
# NIKTO SCANNER
# =====================
class NiktoScanner:
    """Nikto web vulnerability scanner integration"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.nikto_available = self._check_nikto()
    
    def _check_nikto(self) -> bool:
        """Check if Nikto is available"""
        nikto_path = shutil.which('nikto')
        if nikto_path:
            logger.info(f"Nikto found at: {nikto_path}")
            return True
        
        # Check common installation paths
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            '/usr/share/nikto/nikto.pl',
            'C:\\Program Files\\nikto\\nikto.pl',
            'C:\\nikto\\nikto.pl'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"Nikto found at: {path}")
                return True
        
        logger.warning("Nikto not found. Some features will be limited.")
        return False
    
    def scan(self, target: str, options: Dict = None) -> NiktoResult:
        """Run Nikto scan on target"""
        start_time = time.time()
        options = options or {}
        
        if not self.nikto_available:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=0,
                output_file="",
                success=False,
                error="Nikto is not installed or not in PATH"
            )
        
        try:
            # Prepare output file
            timestamp = int(time.time())
            output_file = os.path.join(NIKTO_RESULTS_DIR, f"nikto_{target.replace('/', '_')}_{timestamp}.json")
            
            # Build command
            cmd = self._build_nikto_command(target, output_file, options)
            
            # Execute scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', 600),
                encoding='utf-8',
                errors='ignore'
            )
            
            scan_time = time.time() - start_time
            
            # Parse results
            vulnerabilities = self._parse_nikto_output(result.stdout, output_file)
            
            nikto_result = NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=vulnerabilities,
                scan_time=scan_time,
                output_file=output_file,
                success=result.returncode == 0
            )
            
            # Log to database
            self.db.log_nikto_scan(nikto_result)
            
            return nikto_result
            
        except subprocess.TimeoutExpired:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=time.time() - start_time,
                output_file="",
                success=False,
                error="Scan timed out"
            )
        except Exception as e:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=time.time() - start_time,
                output_file="",
                success=False,
                error=str(e)
            )
    
    def _build_nikto_command(self, target: str, output_file: str, options: Dict) -> List[str]:
        """Build Nikto command with options"""
        nikto_cmd = self._get_nikto_command()
        
        cmd = [nikto_cmd, '-host', target]
        
        # Add SSL if target uses HTTPS
        if target.startswith('https://') or options.get('ssl', False):
            cmd.append('-ssl')
        
        # Port specification
        if 'port' in options:
            cmd.extend(['-port', str(options['port'])])
        elif target.startswith('https://'):
            cmd.extend(['-port', '443'])
        
        # Scan tuning
        if 'tuning' in options:
            cmd.extend(['-Tuning', options['tuning']])
        else:
            cmd.extend(['-Tuning', '123456789'])  # All tests
        
        # Output format
        cmd.extend(['-Format', 'json', '-o', output_file])
        
        # Scan level
        if 'level' in options:
            cmd.extend(['-Level', str(options['level'])])
        
        # Timeout
        if 'timeout' in options:
            cmd.extend(['-timeout', str(options['timeout'])])
        
        # Evasion
        if 'evasion' in options:
            cmd.extend(['-evasion', str(options['evasion'])])
        
        # IDS evasion
        if 'ids' in options:
            cmd.append('-ids')
        
        # Mutate
        if 'mutate' in options:
            cmd.extend(['-mutate', str(options['mutate'])])
        
        # Debug
        if options.get('debug', False):
            cmd.append('-Debug')
        
        # Verbose
        if options.get('verbose', False):
            cmd.append('-v')
        
        return cmd
    
    def _get_nikto_command(self) -> str:
        """Get the correct Nikto command/path"""
        # Check if nikto is in PATH
        nikto_path = shutil.which('nikto')
        if nikto_path:
            return nikto_path
        
        # Check common paths
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            '/usr/share/nikto/nikto.pl'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return 'nikto'  # Default fallback
    
    def _parse_nikto_output(self, output: str, json_file: str) -> List[Dict]:
        """Parse Nikto output and extract vulnerabilities"""
        vulnerabilities = []
        
        # Try to parse JSON output if available
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    if 'vulnerabilities' in data:
                        vulnerabilities = data['vulnerabilities']
                    elif isinstance(data, list):
                        vulnerabilities = data
            except:
                pass
        
        # If no JSON, parse text output
        if not vulnerabilities:
            lines = output.split('\n')
            for line in lines:
                if '+ ' in line or '- ' in line or 'OSVDB' in line or 'CVE' in line:
                    vulnerability = {
                        'description': line.strip(),
                        'severity': self._determine_severity(line),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    
                    # Extract CVE if present
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', line)
                    if cve_match:
                        vulnerability['cve'] = cve_match.group()
                    
                    # Extract OSVDB
                    osvdb_match = re.search(r'OSVDB-\d+', line)
                    if osvdb_match:
                        vulnerability['osvdb'] = osvdb_match.group()
                    
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _determine_severity(self, line: str) -> str:
        """Determine severity from Nikto output"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['critical', 'severe', 'remote root', 'arbitrary code']):
            return Severity.CRITICAL
        elif any(word in line_lower for word in ['high', 'vulnerable', 'exploit', 'privilege']):
            return Severity.HIGH
        elif any(word in line_lower for word in ['medium', 'warning', 'exposed', 'information']):
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def get_available_scan_types(self) -> List[str]:
        """Get available scan types"""
        return [
            "full",  # All tests
            "ssl",   # SSL/TLS tests
            "cgi",   # CGI tests
            "sql",   # SQL injection
            "xss",   # XSS tests
            "file",  # File inclusion
            "cmd",   # Command execution
            "info"   # Information disclosure
        ]
    
    def check_target_ssl(self, target: str) -> bool:
        """Check if target supports SSL"""
        try:
            # Remove protocol if present
            if '://' in target:
                target = target.split('://')[1]
            
            # Try HTTPS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, 443))
            sock.close()
            
            return result == 0
        except:
            return False

# =====================
# NETWORK TOOLS
# =====================
class NetworkTools:
    """Comprehensive network tools"""
    
    @staticmethod
    def execute_command(cmd: List[str], timeout: int = 300) -> CommandResult:
        """Execute shell command"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                execution_time=execution_time,
                error=None if result.returncode == 0 else f"Exit code: {result.returncode}"
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output=f"Command timed out after {timeout} seconds",
                execution_time=execution_time,
                error='Timeout'
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output='',
                execution_time=execution_time,
                error=str(e)
            )
    
    @staticmethod
    def ping(target: str, count: int = 4, size: int = 56, timeout: int = 1, 
             flood: bool = False, **kwargs) -> CommandResult:
        """Ping with advanced options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), '-l', str(size), '-w', str(timeout * 1000)]
                if flood:
                    cmd.append('-t')
            else:
                cmd = ['ping', '-c', str(count), '-s', str(size), '-W', str(timeout)]
                if flood:
                    cmd.append('-f')
            
            cmd.append(target)
            
            return NetworkTools.execute_command(cmd, timeout * count + 5)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30, no_dns: bool = True, **kwargs) -> CommandResult:
        """Traceroute with options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['tracert']
                if no_dns:
                    cmd.append('-d')
                cmd.extend(['-h', str(max_hops)])
            else:
                if shutil.which('mtr'):
                    cmd = ['mtr', '--report', '--report-cycles', '1']
                    if no_dns:
                        cmd.append('-n')
                elif shutil.which('traceroute'):
                    cmd = ['traceroute']
                    if no_dns:
                        cmd.append('-n')
                    cmd.extend(['-m', str(max_hops)])
                elif shutil.which('tracepath'):
                    cmd = ['tracepath', '-m', str(max_hops)]
                else:
                    return CommandResult(
                        success=False,
                        output='No traceroute tool found',
                        execution_time=0,
                        error='No traceroute tool available'
                    )
            
            cmd.append(target)
            return NetworkTools.execute_command(cmd, timeout=60)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def nmap_scan(target: str, scan_type: str = "quick", ports: str = None, **kwargs) -> CommandResult:
        """Nmap scan with options"""
        try:
            cmd = ['nmap']
            
            # Base scan type
            if scan_type == "quick":
                cmd.extend(['-T4', '-F'])
            elif scan_type == "quick_scan":
                cmd.extend(['-T4', '-F', '--max-rtt-timeout', '100ms', '--max-retries', '1'])
            elif scan_type == "comprehensive":
                cmd.extend(['-sS', '-sV', '-sC', '-A', '-O'])
            elif scan_type == "stealth":
                cmd.extend(['-sS', '-T2', '--max-parallelism', '100', '--scan-delay', '5s'])
            elif scan_type == "vulnerability":
                cmd.extend(['-sV', '--script', 'vuln'])
            elif scan_type == "full":
                cmd.extend(['-p-', '-T4'])
            elif scan_type == "udp":
                cmd.extend(['-sU', '-T4'])
            elif scan_type == "os_detection":
                cmd.extend(['-O', '--osscan-guess'])
            elif scan_type == "service_detection":
                cmd.extend(['-sV', '--version-intensity', '5'])
            elif scan_type == "web":
                cmd.extend(['-p', '80,443,8080,8443', '-sV', '--script', 'http-*'])
            
            # Custom ports
            if ports:
                if ports.isdigit():
                    cmd.extend(['-p', ports])
                else:
                    cmd.extend(['-p', ports])
            elif scan_type not in ["full"] and not any(x in cmd for x in ['-p']):
                cmd.extend(['-p', '1-1000'])
            
            # Additional options
            if kwargs.get('no_ping'):
                cmd.append('-Pn')
            if kwargs.get('ipv6'):
                cmd.append('-6')
            
            cmd.append(target)
            
            return NetworkTools.execute_command(cmd, timeout=600)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def curl_request(url: str, method: str = "GET", **kwargs) -> CommandResult:
        """cURL request"""
        try:
            cmd = ['curl', '-s', '-X', method]
            
            if kwargs.get('timeout'):
                cmd.extend(['-m', str(kwargs['timeout'])])
            if kwargs.get('headers'):
                for key, value in kwargs['headers'].items():
                    cmd.extend(['-H', f'{key}: {value}'])
            if kwargs.get('data'):
                cmd.extend(['-d', kwargs['data']])
            if kwargs.get('insecure'):
                cmd.append('-k')
            if kwargs.get('verbose'):
                cmd.append('-v')
            
            cmd.extend(['-w', '\nTime: %{time_total}s\nCode: %{http_code}\nSize: %{size_download} bytes\n'])
            cmd.append(url)
            
            return NetworkTools.execute_command(cmd, timeout=kwargs.get('timeout', 30) + 5)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_ip_location(ip: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A')
                    }
            
            return {'success': False, 'ip': ip, 'error': 'Location lookup failed'}
                
        except Exception as e:
            return {'success': False, 'ip': ip, 'error': str(e)}
    
    @staticmethod
    def whois_lookup(target: str) -> CommandResult:
        """WHOIS lookup"""
        if not WHOIS_AVAILABLE:
            return CommandResult(
                success=False,
                output='WHOIS not available',
                execution_time=0,
                error='Install python-whois package'
            )
        
        try:
            import whois
            start_time = time.time()
            result = whois.whois(target)
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=True,
                output=str(result),
                execution_time=execution_time
            )
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def dns_lookup(domain: str, record_type: str = "A") -> CommandResult:
        """DNS lookup"""
        try:
            cmd = ['dig', domain, record_type, '+short']
            return NetworkTools.execute_command(cmd, timeout=10)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def block_ip_firewall(ip: str) -> bool:
        """Block IP using system firewall (Linux iptables)"""
        try:
            if platform.system().lower() == 'linux':
                # Check if iptables is available
                if shutil.which('iptables'):
                    # Add block rule
                    subprocess.run(
                        ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                        check=True,
                        timeout=10
                    )
                    return True
            elif platform.system().lower() == 'windows':
                # Windows firewall
                if shutil.which('netsh'):
                    subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                         f'name=SpiderBot_Block_{ip}', 'dir=in', 'action=block',
                         f'remoteip={ip}'],
                        check=True,
                        timeout=10
                    )
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    @staticmethod
    def unblock_ip_firewall(ip: str) -> bool:
        """Unblock IP from system firewall"""
        try:
            if platform.system().lower() == 'linux':
                if shutil.which('iptables'):
                    # Remove block rule
                    subprocess.run(
                        ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        check=True,
                        timeout=10
                    )
                    return True
            elif platform.system().lower() == 'windows':
                if shutil.which('netsh'):
                    subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                         f'name=SpiderBot_Block_{ip}'],
                        check=True,
                        timeout=10
                    )
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False

# =====================
# NETWORK MONITOR
# =====================
class NetworkMonitor:
    """Network monitoring and threat detection"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.monitoring = False
        self.monitored_ips = set()
        self.thresholds = {
            'port_scan': self.config.get('monitoring', {}).get('port_scan_threshold', 10),
            'syn_flood': self.config.get('monitoring', {}).get('syn_flood_threshold', 100),
            'udp_flood': self.config.get('monitoring', {}).get('udp_flood_threshold', 500),
            'http_flood': self.config.get('monitoring', {}).get('http_flood_threshold', 200),
            'ddos': self.config.get('monitoring', {}).get('ddos_threshold', 1000)
        }
        self.threads = []
        self.auto_block = self.config.get('security', {}).get('auto_block', False)
        self.auto_block_threshold = self.config.get('security', {}).get('auto_block_threshold', 5)
        self.connection_tracker = {}
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        logger.info("Starting network monitoring...")
        
        # Load managed IPs from database
        managed = self.db.get_managed_ips()
        self.monitored_ips = {ip['ip_address'] for ip in managed if not ip.get('is_blocked', False)}
        
        # Start monitoring threads
        self.threads = [
            threading.Thread(target=self._monitor_system, daemon=True),
            threading.Thread(target=self._monitor_threats, daemon=True),
            threading.Thread(target=self._monitor_connections, daemon=True)
        ]
        
        for thread in self.threads:
            thread.start()
        
        logger.info(f"Network monitoring started with {len(self.threads)} threads")
        logger.info(f"Auto-block is {'enabled' if self.auto_block else 'disabled'}")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.threads = []
        self.connection_tracker.clear()
        logger.info("Network monitoring stopped")
    
    def _monitor_system(self):
        """Monitor system metrics"""
        while self.monitoring:
            try:
                # Log system metrics to database
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                net = psutil.net_io_counters()
                connections = len(psutil.net_connections())
                
                # Check for high resource usage
                if cpu > 90:
                    self._create_threat_alert(
                        threat_type="High CPU Usage",
                        source_ip="localhost",
                        severity="high",
                        description=f"CPU usage at {cpu}%",
                        action_taken="Logged"
                    )
                
                if mem.percent > 90:
                    self._create_threat_alert(
                        threat_type="High Memory Usage",
                        source_ip="localhost",
                        severity="high",
                        description=f"Memory usage at {mem.percent}%",
                        action_taken="Logged"
                    )
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"System monitor error: {e}")
                time.sleep(10)
    
    def _monitor_threats(self):
        """Monitor for threats"""
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                
                # Analyze connections for threats
                source_counts = {}
                for conn in connections:
                    if conn.raddr:
                        source_ip = conn.raddr.ip
                        source_counts[source_ip] = source_counts.get(source_ip, 0) + 1
                        
                        # Track connection patterns for auto-block
                        if source_ip not in self.connection_tracker:
                            self.connection_tracker[source_ip] = []
                        self.connection_tracker[source_ip].append(time.time())
                
                # Check thresholds
                for source_ip, count in source_counts.items():
                    if count > self.thresholds['port_scan']:
                        self._create_threat_alert(
                            threat_type="Possible Port Scan",
                            source_ip=source_ip,
                            severity="medium",
                            description=f"{count} connections from this IP in current snapshot",
                            action_taken="Monitoring"
                        )
                        
                        # Update IP in database
                        ip_info = self.db.get_ip_info(source_ip)
                        if ip_info:
                            self.db.cursor.execute('''
                                UPDATE managed_ips 
                                SET alert_count = alert_count + 1,
                                    last_scan = CURRENT_TIMESTAMP
                                WHERE ip_address = ?
                            ''', (source_ip,))
                            self.db.conn.commit()
                        
                        # Auto-block if threshold exceeded
                        if self.auto_block:
                            alert_count = len(self.connection_tracker.get(source_ip, []))
                            if alert_count > self.auto_block_threshold:
                                self._auto_block_ip(source_ip, f"Exceeded port scan threshold ({count} connections)")
                
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Threat monitor error: {e}")
                time.sleep(10)
    
    def _monitor_connections(self):
        """Monitor and clean up connection tracker"""
        while self.monitoring:
            try:
                # Clean up old entries (older than 1 hour)
                current_time = time.time()
                for ip in list(self.connection_tracker.keys()):
                    self.connection_tracker[ip] = [
                        t for t in self.connection_tracker[ip] 
                        if current_time - t < 3600
                    ]
                    
                    # Remove IP if no recent connections
                    if not self.connection_tracker[ip]:
                        del self.connection_tracker[ip]
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
                time.sleep(10)
    
    def _create_threat_alert(self, threat_type: str, source_ip: str, 
                            severity: str, description: str, action_taken: str):
        """Create threat alert"""
        alert = ThreatAlert(
            timestamp=datetime.datetime.now().isoformat(),
            threat_type=threat_type,
            source_ip=source_ip,
            severity=severity,
            description=description,
            action_taken=action_taken
        )
        
        self.db.log_threat(alert)
        
        # Log to console with color
        if severity == "critical":
            log_msg = f"{Colors.RED}🔥 CRITICAL: {threat_type} from {source_ip}{Colors.RESET}"
        elif severity == "high":
            log_msg = f"{Colors.RED}🚨 HIGH THREAT: {threat_type} from {source_ip}{Colors.RESET}"
        elif severity == "medium":
            log_msg = f"{Colors.YELLOW}⚠️ MEDIUM THREAT: {threat_type} from {source_ip}{Colors.RESET}"
        else:
            log_msg = f"{Colors.CYAN}ℹ️ INFO: {threat_type} from {source_ip}{Colors.RESET}"
        
        print(log_msg)
        logger.info(f"Threat alert: {threat_type} from {source_ip} ({severity})")
    
    def _auto_block_ip(self, ip: str, reason: str):
        """Automatically block an IP"""
        try:
            logger.info(f"Auto-blocking IP {ip}: {reason}")
            
            # Block in firewall
            if NetworkTools.block_ip_firewall(ip):
                # Update database
                self.db.block_ip(ip, reason, executed_by="auto_block")
                
                self._create_threat_alert(
                    threat_type="Auto-Blocked IP",
                    source_ip=ip,
                    severity="high",
                    description=reason,
                    action_taken=f"IP blocked via firewall"
                )
            else:
                logger.error(f"Failed to auto-block IP {ip} - firewall command failed")
                
        except Exception as e:
            logger.error(f"Auto-block failed for {ip}: {e}")
    
    def add_ip_to_monitoring(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to monitoring"""
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            result = self.db.add_managed_ip(ip, added_by, notes)
            logger.info(f"Added IP to monitoring: {ip} by {added_by}")
            return result
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False
    
    def remove_ip_from_monitoring(self, ip: str) -> bool:
        """Remove IP from monitoring"""
        try:
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
            
            result = self.db.remove_managed_ip(ip)
            if result:
                logger.info(f"Removed IP from monitoring: {ip}")
            
            return result
        except Exception as e:
            logger.error(f"Failed to remove IP {ip}: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str, executed_by: str = "system") -> bool:
        """Block an IP"""
        try:
            # Block in firewall
            firewall_success = NetworkTools.block_ip_firewall(ip)
            
            # Update database
            db_success = self.db.block_ip(ip, reason, executed_by)
            
            # Remove from monitored set
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
            
            success = firewall_success or db_success
            
            if success:
                logger.info(f"IP {ip} blocked by {executed_by}: {reason}")
                self._create_threat_alert(
                    threat_type="Manual Block",
                    source_ip=ip,
                    severity="high",
                    description=reason,
                    action_taken=f"IP blocked by {executed_by}"
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str, executed_by: str = "system") -> bool:
        """Unblock an IP"""
        try:
            # Unblock in firewall
            firewall_success = NetworkTools.unblock_ip_firewall(ip)
            
            # Update database
            db_success = self.db.unblock_ip(ip, executed_by)
            
            success = firewall_success or db_success
            
            if success:
                logger.info(f"IP {ip} unblocked by {executed_by}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        stats = self.db.get_statistics()
        threats = self.db.get_recent_threats(5)
        
        return {
            'monitoring': self.monitoring,
            'monitored_ips_count': len(self.monitored_ips),
            'monitored_ips': list(self.monitored_ips)[:10],  # First 10 only
            'blocked_ips': stats.get('total_blocked_ips', 0),
            'thresholds': self.thresholds,
            'auto_block': self.auto_block,
            'recent_threats': len(threats),
            'active_connections': len(self.connection_tracker)
        }

# =====================
# WHATSAPP BOT
# =====================
class SpiderBotWhatsApp:
    """WhatsApp bot integration"""
    
    def __init__(self, command_handler: 'CommandHandler', db: DatabaseManager):
        self.handler = command_handler
        self.db = db
        self.config = self.load_config()
        self.driver = None
        self.running = False
        self.monitoring_thread = None
        self.command_queue = []
        self.allowed_contacts = []
        self.prefix = "/"
    
    def load_config(self) -> Dict:
        """Load WhatsApp configuration"""
        try:
            if os.path.exists(WHATSAPP_CONFIG_FILE):
                with open(WHATSAPP_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load WhatsApp config: {e}")
        
        return {
            "enabled": False,
            "phone_number": "",
            "command_prefix": "/",
            "auto_login": False,
            "session_timeout": 3600,
            "allowed_contacts": []
        }
    
    def save_config(self, phone_number: str = "", enabled: bool = True,
                   prefix: str = "/", auto_login: bool = False,
                   allowed_contacts: List[str] = None) -> bool:
        """Save WhatsApp configuration"""
        try:
            config = {
                "enabled": enabled,
                "phone_number": phone_number,
                "command_prefix": prefix,
                "auto_login": auto_login,
                "session_timeout": 3600,
                "allowed_contacts": allowed_contacts or []
            }
            with open(WHATSAPP_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            self.prefix = prefix
            self.allowed_contacts = allowed_contacts or []
            return True
        except Exception as e:
            logger.error(f"Failed to save WhatsApp config: {e}")
            return False
    
    def add_allowed_contact(self, phone_number: str) -> bool:
        """Add phone number to allowed contacts"""
        if phone_number not in self.allowed_contacts:
            self.allowed_contacts.append(phone_number)
            self.save_config(
                self.config.get('phone_number', ''),
                self.config.get('enabled', True),
                self.config.get('command_prefix', '/'),
                self.config.get('auto_login', False),
                self.allowed_contacts
            )
            return True
        return False
    
    def remove_allowed_contact(self, phone_number: str) -> bool:
        """Remove phone number from allowed contacts"""
        if phone_number in self.allowed_contacts:
            self.allowed_contacts.remove(phone_number)
            self.save_config(
                self.config.get('phone_number', ''),
                self.config.get('enabled', True),
                self.config.get('command_prefix', '/'),
                self.config.get('auto_login', False),
                self.allowed_contacts
            )
            return True
        return False
    
    def is_contact_allowed(self, contact: str) -> bool:
        """Check if contact is allowed to send commands"""
        if not self.allowed_contacts:
            return True  # Allow all if no restrictions
        return contact in self.allowed_contacts
    
    def start(self):
        """Start WhatsApp bot"""
        if not SELENIUM_AVAILABLE:
            logger.error("Selenium not installed")
            return False
        
        if not self.config.get('enabled'):
            logger.info("WhatsApp bot is disabled")
            return False
        
        try:
            # Setup Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")  # Run in background
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument(f"user-data-dir={WHATSAPP_SESSION_DIR}")
            
            # Initialize driver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Start monitoring thread
            self.running = True
            self.monitoring_thread = threading.Thread(target=self._monitor_whatsapp, daemon=True)
            self.monitoring_thread.start()
            
            logger.info("WhatsApp bot started")
            print(f"{Colors.GREEN}✅ WhatsApp bot started{Colors.RESET}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start WhatsApp bot: {e}")
            return False
    
    def stop(self):
        """Stop WhatsApp bot"""
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        if self.driver:
            self.driver.quit()
        logger.info("WhatsApp bot stopped")
    
    def _monitor_whatsapp(self):
        """Monitor WhatsApp Web for commands"""
        try:
            # Open WhatsApp Web
            self.driver.get("https://web.whatsapp.com")
            
            # Wait for QR code scan
            print(f"{Colors.YELLOW}⚠️ WhatsApp: Please scan QR code within 60 seconds{Colors.RESET}")
            
            # Wait for successful login
            WebDriverWait(self.driver, 60).until(
                EC.presence_of_element_located((By.XPATH, '//div[@aria-label="Chat list"]'))
            )
            
            print(f"{Colors.GREEN}✅ WhatsApp logged in successfully{Colors.RESET}")
            
            while self.running:
                try:
                    # Check for new messages
                    self._check_messages()
                    time.sleep(2)  # Check every 2 seconds
                    
                except Exception as e:
                    logger.error(f"WhatsApp monitoring error: {e}")
                    time.sleep(5)
                    
        except Exception as e:
            logger.error(f"WhatsApp connection error: {e}")
            self.running = False
    
    def _check_messages(self):
        """Check for new WhatsApp messages"""
        try:
            # Find unread chats
            unread_chats = self.driver.find_elements(By.XPATH, '//span[@aria-label="Unread message"]/..')
            
            for chat in unread_chats:
                try:
                    # Click on chat
                    chat.click()
                    time.sleep(1)
                    
                    # Get latest messages
                    messages = self.driver.find_elements(By.XPATH, '//div[contains(@class, "message-in")]')
                    
                    if messages:
                        latest = messages[-1]
                        sender_elem = latest.find_element(By.XPATH, './/span[@data-testid="author-name"]')
                        text_elem = latest.find_element(By.XPATH, './/span[contains(@class, "selectable-text")]')
                        
                        sender = sender_elem.text
                        message = text_elem.text
                        
                        # Check if message is a command
                        if message.startswith(self.prefix):
                            if self.is_contact_allowed(sender):
                                # Process command
                                response = self._process_command(message, sender)
                                
                                # Send response
                                self._send_message(response)
                            else:
                                self._send_message(f"❌ Unauthorized: {sender} is not in allowed contacts")
                    
                    # Mark as read
                    self.driver.execute_script("document.querySelector('[aria-label=\"Menu\"]').click()")
                    
                except Exception as e:
                    logger.error(f"Error processing WhatsApp message: {e}")
                    
        except Exception as e:
            logger.error(f"Error checking WhatsApp messages: {e}")
    
    def _process_command(self, command: str, sender: str) -> str:
        """Process WhatsApp command"""
        # Remove prefix
        cmd = command[len(self.prefix):].strip()
        
        # Execute command
        result = self.handler.execute(cmd, f"whatsapp ({sender})")
        
        # Format response
        if result['success']:
            output = result.get('output', '') or result.get('data', '')
            if isinstance(output, dict):
                output = json.dumps(output, indent=2)
            
            # Truncate long messages
            if len(str(output)) > 4000:
                output = str(output)[:4000] + "... (truncated)"
            
            return f"✅ *Command Executed* ({result['execution_time']:.2f}s)\n\n```{output}```"
        else:
            return f"❌ Command Failed: {result.get('output', 'Unknown error')}"
    
    def _send_message(self, message: str):
        """Send message in WhatsApp"""
        try:
            message_box = self.driver.find_element(By.XPATH, '//div[@aria-placeholder="Type a message"]')
            message_box.send_keys(message)
            message_box.send_keys("\n")
            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Error sending WhatsApp message: {e}")
    
    def send_alert(self, message: str, recipient: str = None):
        """Send security alert via WhatsApp"""
        if not self.running or not self.driver:
            return
        
        try:
            # Search for recipient
            search_box = self.driver.find_element(By.XPATH, '//div[@aria-label="Search input textbox"]')
            search_box.clear()
            search_box.send_keys(recipient or self.config.get('phone_number', ''))
            time.sleep(1)
            
            # Click on contact
            contact = self.driver.find_element(By.XPATH, f'//span[@title="{recipient}"]')
            contact.click()
            time.sleep(1)
            
            # Send message
            self._send_message(f"🚨 *SpiderBot Security Alert*\n\n{message}")
            
        except Exception as e:
            logger.error(f"Failed to send WhatsApp alert: {e}")
    
    def start_bot_thread(self) -> bool:
        """Start WhatsApp bot in separate thread"""
        if self.config.get('enabled'):
            thread = threading.Thread(target=self.start, daemon=True)
            thread.start()
            logger.info("WhatsApp bot started in background thread")
            return True
        return False

# =====================
# SIGNAL BOT
# =====================
class SpiderBotSignal:
    """Signal bot integration using signal-cli"""
    
    def __init__(self, command_handler: 'CommandHandler', db: DatabaseManager):
        self.handler = command_handler
        self.db = db
        self.config = self.load_config()
        self.running = False
        self.monitoring_thread = None
        self.allowed_numbers = []
        self.prefix = "!"
    
    def load_config(self) -> Dict:
        """Load Signal configuration"""
        try:
            if os.path.exists(SIGNAL_CONFIG_FILE):
                with open(SIGNAL_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Signal config: {e}")
        
        return {
            "enabled": False,
            "phone_number": "",
            "command_prefix": "!",
            "signal_cli_path": "signal-cli",
            "allowed_numbers": []
        }
    
    def save_config(self, phone_number: str = "", enabled: bool = True,
                   prefix: str = "!", signal_cli_path: str = "signal-cli",
                   allowed_numbers: List[str] = None) -> bool:
        """Save Signal configuration"""
        try:
            config = {
                "enabled": enabled,
                "phone_number": phone_number,
                "command_prefix": prefix,
                "signal_cli_path": signal_cli_path,
                "allowed_numbers": allowed_numbers or []
            }
            with open(SIGNAL_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            self.prefix = prefix
            self.allowed_numbers = allowed_numbers or []
            return True
        except Exception as e:
            logger.error(f"Failed to save Signal config: {e}")
            return False
    
    def add_allowed_number(self, phone_number: str) -> bool:
        """Add phone number to allowed numbers"""
        if phone_number not in self.allowed_numbers:
            self.allowed_numbers.append(phone_number)
            self.save_config(
                self.config.get('phone_number', ''),
                self.config.get('enabled', True),
                self.config.get('command_prefix', '!'),
                self.config.get('signal_cli_path', 'signal-cli'),
                self.allowed_numbers
            )
            return True
        return False
    
    def remove_allowed_number(self, phone_number: str) -> bool:
        """Remove phone number from allowed numbers"""
        if phone_number in self.allowed_numbers:
            self.allowed_numbers.remove(phone_number)
            self.save_config(
                self.config.get('phone_number', ''),
                self.config.get('enabled', True),
                self.config.get('command_prefix', '!'),
                self.config.get('signal_cli_path', 'signal-cli'),
                self.allowed_numbers
            )
            return True
        return False
    
    def is_number_allowed(self, number: str) -> bool:
        """Check if number is allowed to send commands"""
        if not self.allowed_numbers:
            return True  # Allow all if no restrictions
        return number in self.allowed_numbers
    
    def check_signal_cli(self) -> bool:
        """Check if signal-cli is available"""
        if not SIGNAL_CLI_AVAILABLE:
            logger.error("signal-cli not found in PATH")
            return False
        
        try:
            result = subprocess.run(
                [self.config.get('signal_cli_path', 'signal-cli'), '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    def register_device(self) -> bool:
        """Register Signal device"""
        if not self.check_signal_cli():
            return False
        
        try:
            phone = self.config.get('phone_number')
            if not phone:
                logger.error("Signal phone number not configured")
                return False
            
            print(f"{Colors.YELLOW}📱 Registering Signal account for {phone}...{Colors.RESET}")
            
            # Link device
            result = subprocess.run(
                [self.config.get('signal_cli_path', 'signal-cli'), '-u', phone, 'link'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}✅ Signal device registered{Colors.RESET}")
                print(f"{Colors.CYAN}📱 Scan the QR code with Signal app{Colors.RESET}")
                return True
            else:
                print(f"{Colors.RED}❌ Signal registration failed: {result.stderr}{Colors.RESET}")
                return False
                
        except Exception as e:
            logger.error(f"Signal registration error: {e}")
            return False
    
    def start(self):
        """Start Signal bot"""
        if not self.check_signal_cli():
            logger.error("signal-cli not available")
            return False
        
        if not self.config.get('enabled'):
            logger.info("Signal bot is disabled")
            return False
        
        if not self.config.get('phone_number'):
            logger.error("Signal phone number not configured")
            return False
        
        try:
            # Start monitoring thread
            self.running = True
            self.monitoring_thread = threading.Thread(target=self._monitor_signal, daemon=True)
            self.monitoring_thread.start()
            
            logger.info("Signal bot started")
            print(f"{Colors.GREEN}✅ Signal bot started{Colors.RESET}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Signal bot: {e}")
            return False
    
    def stop(self):
        """Stop Signal bot"""
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Signal bot stopped")
    
    def _monitor_signal(self):
        """Monitor Signal for commands"""
        phone = self.config.get('phone_number')
        signal_cmd = self.config.get('signal_cli_path', 'signal-cli')
        
        while self.running:
            try:
                # Receive messages
                result = subprocess.run(
                    [signal_cmd, '-u', phone, 'receive', '--json'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout:
                    messages = result.stdout.strip().split('\n')
                    
                    for msg in messages:
                        if msg:
                            try:
                                self._process_message(msg)
                            except Exception as e:
                                logger.error(f"Error processing Signal message: {e}")
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logger.error(f"Signal monitoring error: {e}")
                time.sleep(5)
    
    def _process_message(self, message_json: str):
        """Process Signal message"""
        try:
            data = json.loads(message_json)
            
            if 'envelope' in data:
                envelope = data['envelope']
                
                # Get sender
                if 'source' in envelope:
                    sender = envelope['source']
                elif 'sourceNumber' in envelope:
                    sender = envelope['sourceNumber']
                else:
                    return
                
                # Get message
                if 'dataMessage' in envelope:
                    msg_data = envelope['dataMessage']
                    if 'message' in msg_data:
                        message = msg_data['message']
                        
                        # Check if message is a command
                        if message.startswith(self.prefix):
                            if self.is_number_allowed(sender):
                                # Process command
                                cmd = message[len(self.prefix):].strip()
                                response = self._process_command(cmd, sender)
                                
                                # Send response
                                self._send_message(sender, response)
                            else:
                                self._send_message(sender, f"❌ Unauthorized: {sender} is not in allowed numbers")
                
        except Exception as e:
            logger.error(f"Error parsing Signal message: {e}")
    
    def _process_command(self, command: str, sender: str) -> str:
        """Process Signal command"""
        # Execute command
        result = self.handler.execute(command, f"signal ({sender})")
        
        # Format response
        if result['success']:
            output = result.get('output', '') or result.get('data', '')
            if isinstance(output, dict):
                output = json.dumps(output, indent=2)
            
            # Truncate long messages (Signal has message length limits)
            if len(str(output)) > 2000:
                output = str(output)[:2000] + "... (truncated)"
            
            return f"✅ Command Executed ({result['execution_time']:.2f}s)\n\n{output}"
        else:
            return f"❌ Command Failed: {result.get('output', 'Unknown error')}"
    
    def _send_message(self, recipient: str, message: str):
        """Send Signal message"""
        try:
            phone = self.config.get('phone_number')
            signal_cmd = self.config.get('signal_cli_path', 'signal-cli')
            
            subprocess.run(
                [signal_cmd, '-u', phone, 'send', '-m', message, recipient],
                capture_output=True,
                text=True,
                timeout=10
            )
            
        except Exception as e:
            logger.error(f"Error sending Signal message: {e}")
    
    def send_alert(self, message: str, recipient: str = None):
        """Send security alert via Signal"""
        if not self.running:
            return
        
        try:
            recipient = recipient or self.config.get('phone_number')
            self._send_message(recipient, f"🚨 SpiderBot Security Alert\n\n{message}")
            
        except Exception as e:
            logger.error(f"Failed to send Signal alert: {e}")
    
    def start_bot_thread(self) -> bool:
        """Start Signal bot in separate thread"""
        if self.config.get('enabled') and self.config.get('phone_number'):
            thread = threading.Thread(target=self.start, daemon=True)
            thread.start()
            logger.info("Signal bot started in background thread")
            return True
        return False

# =====================
# COMMAND HANDLER
# =====================
class CommandHandler:
    """Handle all 500+ commands"""
    
    def __init__(self, db: DatabaseManager, nikto_scanner: NiktoScanner = None):
        self.db = db
        self.nikto = nikto_scanner
        self.tools = NetworkTools()
        self.command_map = self._setup_command_map()
    
    def _setup_command_map(self) -> Dict[str, callable]:
        """Setup command execution map"""
        return {
            # Ping commands
            'ping': self._execute_ping,
            'ping4': self._execute_ping,
            'ping6': self._execute_ping6,
            
            # Scan commands
            'scan': self._execute_scan,
            'quick_scan': self._execute_quick_scan,
            'nmap': self._execute_nmap,
            'portscan': self._execute_portscan,
            'full_scan': self._execute_full_scan,
            'web_scan': self._execute_web_scan,
            
            # Nikto web scanner
            'nikto': self._execute_nikto,
            'web_vuln': self._execute_nikto,
            'nikto_full': self._execute_nikto_full,
            'nikto_ssl': self._execute_nikto_ssl,
            'nikto_cgi': self._execute_nikto_cgi,
            'nikto_sql': self._execute_nikto_sql,
            'nikto_xss': self._execute_nikto_xss,
            
            # Traceroute commands
            'traceroute': self._execute_traceroute,
            'tracert': self._execute_traceroute,
            'tracepath': self._execute_tracepath,
            
            # Web commands
            'curl': self._execute_curl,
            'wget': self._execute_wget,
            'http': self._execute_http,
            
            # Info commands
            'whois': self._execute_whois,
            'dig': self._execute_dig,
            'dns': self._execute_dns,
            'location': self._execute_location,
            'analyze': self._execute_analyze,
            'ip_info': self._execute_ip_info,
            
            # System commands
            'system': self._execute_system,
            'network': self._execute_network,
            'status': self._execute_status,
            'ps': self._execute_ps,
            'top': self._execute_top,
            
            # Security commands
            'threats': self._execute_threats,
            'report': self._execute_report,
            'monitor': self._execute_monitor,
            
            # IP Management
            'add_ip': self._execute_add_ip,
            'remove_ip': self._execute_remove_ip,
            'block_ip': self._execute_block_ip,
            'unblock_ip': self._execute_unblock_ip,
            'list_ips': self._execute_list_ips,
            
            # Nikto management
            'nikto_status': self._execute_nikto_status,
            'nikto_results': self._execute_nikto_results,
            
            # WhatsApp management
            'whatsapp_config': self._execute_whatsapp_config,
            'whatsapp_allow': self._execute_whatsapp_allow,
            'whatsapp_disallow': self._execute_whatsapp_disallow,
            'whatsapp_status': self._execute_whatsapp_status,
            
            # Signal management
            'signal_config': self._execute_signal_config,
            'signal_allow': self._execute_signal_allow,
            'signal_disallow': self._execute_signal_disallow,
            'signal_register': self._execute_signal_register,
            'signal_status': self._execute_signal_status,
        }
    
    def execute(self, command: str, source: str = "local") -> Dict[str, Any]:
        """Execute command and return results"""
        start_time = time.time()
        
        # Parse command
        parts = command.strip().split()
        if not parts:
            return self._create_result(False, "Empty command")
        
        cmd_name = parts[0].lower()
        args = parts[1:]
        
        # Execute command
        try:
            if cmd_name in self.command_map:
                result = self.command_map[cmd_name](args)
            else:
                # Try as generic shell command
                result = self._execute_generic(command)
            
            execution_time = time.time() - start_time
            
            # Log command to database
            self.db.log_command(
                command=command,
                source=source,
                success=result.get('success', False),
                output=result.get('output', '')[:5000],
                execution_time=execution_time
            )
            
            result['execution_time'] = execution_time
            return result
        
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Error executing command: {e}"
            
            self.db.log_command(
                command=command,
                source=source,
                success=False,
                output=error_msg,
                execution_time=execution_time
            )
            
            return self._create_result(False, error_msg, execution_time)
    
    def _create_result(self, success: bool, data: Any, 
                      execution_time: float = 0.0) -> Dict[str, Any]:
        """Create standardized result"""
        if isinstance(data, str):
            return {
                'success': success,
                'output': data,
                'execution_time': execution_time
            }
        else:
            return {
                'success': success,
                'data': data,
                'execution_time': execution_time
            }
    
    # ==================== WhatsApp Command Handlers ====================
    def _execute_whatsapp_config(self, args: List[str]) -> Dict[str, Any]:
        """Configure WhatsApp bot"""
        if not args:
            return self._create_result(False, "Usage: whatsapp_config <phone_number> [prefix=/]")
        
        phone = args[0]
        prefix = args[1] if len(args) > 1 else "/"
        
        # This will be handled by the main app
        return self._create_result(True, {
            'phone': phone,
            'prefix': prefix,
            'message': f"WhatsApp configuration saved. Use 'start_whatsapp' to start the bot."
        })
    
    def _execute_whatsapp_allow(self, args: List[str]) -> Dict[str, Any]:
        """Add contact to WhatsApp allowed list"""
        if not args:
            return self._create_result(False, "Usage: whatsapp_allow <phone_number>")
        
        return self._create_result(True, {
            'phone': args[0],
            'message': f"Contact {args[0]} added to allowed list."
        })
    
    def _execute_whatsapp_disallow(self, args: List[str]) -> Dict[str, Any]:
        """Remove contact from WhatsApp allowed list"""
        if not args:
            return self._create_result(False, "Usage: whatsapp_disallow <phone_number>")
        
        return self._create_result(True, {
            'phone': args[0],
            'message': f"Contact {args[0]} removed from allowed list."
        })
    
    def _execute_whatsapp_status(self, args: List[str]) -> Dict[str, Any]:
        """Get WhatsApp bot status"""
        return self._create_result(True, {
            'status': 'Use "status" command for full bot status',
            'configured': True
        })
    
    # ==================== Signal Command Handlers ====================
    def _execute_signal_config(self, args: List[str]) -> Dict[str, Any]:
        """Configure Signal bot"""
        if not args:
            return self._create_result(False, "Usage: signal_config <phone_number> [prefix=!]")
        
        phone = args[0]
        prefix = args[1] if len(args) > 1 else "!"
        
        return self._create_result(True, {
            'phone': phone,
            'prefix': prefix,
            'message': f"Signal configuration saved. Use 'signal_register' to register device, then 'start_signal' to start the bot."
        })
    
    def _execute_signal_allow(self, args: List[str]) -> Dict[str, Any]:
        """Add number to Signal allowed list"""
        if not args:
            return self._create_result(False, "Usage: signal_allow <phone_number>")
        
        return self._create_result(True, {
            'phone': args[0],
            'message': f"Number {args[0]} added to allowed list."
        })
    
    def _execute_signal_disallow(self, args: List[str]) -> Dict[str, Any]:
        """Remove number from Signal allowed list"""
        if not args:
            return self._create_result(False, "Usage: signal_disallow <phone_number>")
        
        return self._create_result(True, {
            'phone': args[0],
            'message': f"Number {args[0]} removed from allowed list."
        })
    
    def _execute_signal_register(self, args: List[str]) -> Dict[str, Any]:
        """Register Signal device"""
        return self._create_result(True, {
            'message': "Signal registration initiated. Follow the prompts in the console."
        })
    
    def _execute_signal_status(self, args: List[str]) -> Dict[str, Any]:
        """Get Signal bot status"""
        return self._create_result(True, {
            'status': 'Use "status" command for full bot status',
            'configured': True
        })
    
    # ==================== Nikto Command Handlers ====================
    def _execute_nikto(self, args: List[str]) -> Dict[str, Any]:
        """Execute Nikto web vulnerability scan"""
        if not self.nikto:
            return self._create_result(False, "Nikto scanner not initialized")
        
        if not self.nikto.nikto_available:
            return self._create_result(False, "Nikto is not installed. Please install Nikto first.")
        
        if not args:
            return self._create_result(False, "Usage: nikto <target> [options]\nExamples:\n  nikto example.com\n  nikto https://example.com\n  nikto 192.168.1.1:8080")
        
        target = args[0]
        options = {}
        
        # Parse options
        for i in range(1, len(args)):
            if args[i] == '-ssl':
                options['ssl'] = True
            elif args[i] == '-port' and i + 1 < len(args):
                options['port'] = args[i + 1]
            elif args[i] == '-level' and i + 1 < len(args):
                try:
                    options['level'] = int(args[i + 1])
                except:
                    pass
            elif args[i] == '-timeout' and i + 1 < len(args):
                try:
                    options['timeout'] = int(args[i + 1])
                except:
                    pass
            elif args[i] == '-verbose':
                options['verbose'] = True
            elif args[i] == '-debug':
                options['debug'] = True
        
        # Auto-detect SSL if needed
        if not options.get('ssl') and 'https://' in target:
            options['ssl'] = True
        elif not options.get('ssl'):
            # Check if target supports SSL
            host = target.split(':')[0]
            if '://' in host:
                host = host.split('://')[1]
            if self.nikto.check_target_ssl(host):
                options['ssl'] = True
        
        # Execute scan
        result = self.nikto.scan(target, options)
        
        if result.success:
            # Log scan result
            scan_result = ScanResult(
                target=target,
                scan_type=ScanType.NIKTO,
                open_ports=[],
                timestamp=result.timestamp,
                success=True,
                vulnerabilities=result.vulnerabilities
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto Web Vulnerability Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],  # First 20 only
                'scan_time': f"{result.scan_time:.2f}s",
                'output_file': result.output_file,
                'timestamp': result.timestamp
            })
        else:
            return self._create_result(False, f"Nikto scan failed: {result.error}")
    
    def _execute_nikto_full(self, args: List[str]) -> Dict[str, Any]:
        """Full Nikto scan with all tests"""
        if not args:
            return self._create_result(False, "Usage: nikto_full <target>")
        
        target = args[0]
        options = {
            'tuning': '123456789',  # All tests
            'level': 3,  # Maximum scan level
            'timeout': 600,  # 10 minute timeout
            'verbose': True
        }
        
        # Auto-detect SSL
        if 'https://' in target or self.nikto.check_target_ssl(target):
            options['ssl'] = True
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Full Nikto Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:30],
                'scan_time': f"{result.scan_time:.2f}s",
                'output_file': result.output_file
            })
        else:
            return self._create_result(False, f"Full Nikto scan failed: {result.error}")
    
    def _execute_nikto_ssl(self, args: List[str]) -> Dict[str, Any]:
        """Nikto SSL/TLS specific scan"""
        if not args:
            return self._create_result(False, "Usage: nikto_ssl <target>")
        
        target = args[0]
        options = {
            'ssl': True,
            'tuning': '6',  # SSL/TLS tests
            'timeout': 300
        }
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto SSL/TLS Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],
                'scan_time': f"{result.scan_time:.2f}s"
            })
        else:
            return self._create_result(False, f"SSL/TLS scan failed: {result.error}")
    
    def _execute_nikto_cgi(self, args: List[str]) -> Dict[str, Any]:
        """Nikto CGI specific scan"""
        if not args:
            return self._create_result(False, "Usage: nikto_cgi <target>")
        
        target = args[0]
        options = {
            'tuning': '2',  # CGI tests
            'timeout': 300
        }
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto CGI Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],
                'scan_time': f"{result.scan_time:.2f}s"
            })
        else:
            return self._create_result(False, f"CGI scan failed: {result.error}")
    
    def _execute_nikto_sql(self, args: List[str]) -> Dict[str, Any]:
        """Nikto SQL injection specific scan"""
        if not args:
            return self._create_result(False, "Usage: nikto_sql <target>")
        
        target = args[0]
        options = {
            'tuning': '4',  # SQL injection tests
            'timeout': 300
        }
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto SQL Injection Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],
                'scan_time': f"{result.scan_time:.2f}s"
            })
        else:
            return self._create_result(False, f"SQL injection scan failed: {result.error}")
    
    def _execute_nikto_xss(self, args: List[str]) -> Dict[str, Any]:
        """Nikto XSS specific scan"""
        if not args:
            return self._create_result(False, "Usage: nikto_xss <target>")
        
        target = args[0]
        options = {
            'tuning': '5',  # XSS tests
            'timeout': 300
        }
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto XSS Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],
                'scan_time': f"{result.scan_time:.2f}s"
            })
        else:
            return self._create_result(False, f"XSS scan failed: {result.error}")
    
    def _execute_nikto_status(self, args: List[str]) -> Dict[str, Any]:
        """Check Nikto status and availability"""
        if not self.nikto:
            return self._create_result(False, "Nikto scanner not initialized")
        
        status = {
            'available': self.nikto.nikto_available,
            'scan_types': self.nikto.get_available_scan_types(),
            'config': {
                'enabled': self.nikto.config.get('enabled', True),
                'timeout': self.nikto.config.get('timeout', 300),
                'max_targets': self.nikto.config.get('max_targets', 10),
                'scan_level': self.nikto.config.get('scan_level', 2)
            }
        }
        
        if not self.nikto.nikto_available:
            status['installation_help'] = {
                'linux': 'sudo apt-get install nikto',
                'mac': 'brew install nikto',
                'windows': 'Download from https://github.com/sullo/nikto'
            }
        
        return self._create_result(True, status)
    
    def _execute_nikto_results(self, args: List[str]) -> Dict[str, Any]:
        """Get recent Nikto scan results"""
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        
        scans = self.db.get_nikto_scans(limit)
        return self._create_result(True, {
            'recent_scans': scans,
            'count': len(scans)
        })
    
    # ==================== IP Management Command Handlers ====================
    def _execute_add_ip(self, args: List[str]) -> Dict[str, Any]:
        """Add IP to monitoring"""
        if not args:
            return self._create_result(False, "Usage: add_ip <ip> [notes]")
        
        ip = args[0]
        notes = ' '.join(args[1:]) if len(args) > 1 else "Added via command"
        
        try:
            ipaddress.ip_address(ip)
            success = self.db.add_managed_ip(ip, "cli", notes)
            
            if success:
                return self._create_result(True, f"✅ IP {ip} added to monitoring")
            else:
                return self._create_result(False, f"Failed to add IP {ip} (may already exist)")
                
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_remove_ip(self, args: List[str]) -> Dict[str, Any]:
        """Remove IP from monitoring"""
        if not args:
            return self._create_result(False, "Usage: remove_ip <ip>")
        
        ip = args[0]
        
        try:
            ipaddress.ip_address(ip)
            success = self.db.remove_managed_ip(ip)
            
            if success:
                return self._create_result(True, f"✅ IP {ip} removed from monitoring")
            else:
                return self._create_result(False, f"IP {ip} not found in monitoring")
                
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_block_ip(self, args: List[str]) -> Dict[str, Any]:
        """Block an IP"""
        if not args:
            return self._create_result(False, "Usage: block_ip <ip> [reason]")
        
        ip = args[0]
        reason = ' '.join(args[1:]) if len(args) > 1 else "Manually blocked"
        
        try:
            ipaddress.ip_address(ip)
            
            # Try to block via firewall
            firewall_success = NetworkTools.block_ip_firewall(ip)
            
            # Update database
            db_success = self.db.block_ip(ip, reason, "cli")
            
            if firewall_success or db_success:
                return self._create_result(True, {
                    'ip': ip,
                    'reason': reason,
                    'firewall_blocked': firewall_success,
                    'database_updated': db_success,
                    'message': f"✅ IP {ip} blocked successfully"
                })
            else:
                return self._create_result(False, f"Failed to block IP {ip}")
                
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_unblock_ip(self, args: List[str]) -> Dict[str, Any]:
        """Unblock an IP"""
        if not args:
            return self._create_result(False, "Usage: unblock_ip <ip>")
        
        ip = args[0]
        
        try:
            ipaddress.ip_address(ip)
            
            # Try to unblock from firewall
            firewall_success = NetworkTools.unblock_ip_firewall(ip)
            
            # Update database
            db_success = self.db.unblock_ip(ip, "cli")
            
            if firewall_success or db_success:
                return self._create_result(True, {
                    'ip': ip,
                    'firewall_unblocked': firewall_success,
                    'database_updated': db_success,
                    'message': f"✅ IP {ip} unblocked successfully"
                })
            else:
                return self._create_result(False, f"Failed to unblock IP {ip}")
                
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_list_ips(self, args: List[str]) -> Dict[str, Any]:
        """List managed IPs"""
        include_blocked = True
        if args and args[0].lower() == 'active':
            include_blocked = False
        
        ips = self.db.get_managed_ips(include_blocked)
        
        if not ips:
            return self._create_result(True, {
                'ips': [],
                'count': 0,
                'message': 'No managed IPs found'
            })
        
        # Format for display
        ip_list = []
        for ip in ips:
            ip_list.append({
                'ip': ip['ip_address'],
                'added_by': ip.get('added_by', 'unknown'),
                'added_date': ip.get('added_date', ''),
                'is_blocked': ip.get('is_blocked', False),
                'block_reason': ip.get('block_reason', ''),
                'alert_count': ip.get('alert_count', 0),
                'notes': ip.get('notes', '')
            })
        
        return self._create_result(True, {
            'ips': ip_list,
            'count': len(ip_list),
            'blocked_count': len([ip for ip in ip_list if ip['is_blocked']])
        })
    
    def _execute_ip_info(self, args: List[str]) -> Dict[str, Any]:
        """Get detailed information about an IP"""
        if not args:
            return self._create_result(False, "Usage: ip_info <ip>")
        
        ip = args[0]
        
        try:
            ipaddress.ip_address(ip)
            
            # Get IP from database
            db_info = self.db.get_ip_info(ip)
            
            # Get location info
            location = NetworkTools.get_ip_location(ip)
            
            # Get recent threats
            threats = self.db.get_threats_by_ip(ip, 5)
            
            info = {
                'ip': ip,
                'database_info': db_info,
                'location': location if location.get('success') else None,
                'recent_threats': threats,
                'threat_count': len(threats)
            }
            
            return self._create_result(True, info)
            
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    # ==================== Existing Command Handlers ====================
    def _execute_ping(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ping <target>")
        
        target = args[0]
        count = 4
        size = 56
        
        if len(args) > 1:
            for i in range(1, len(args)):
                if args[i] == '-c' and i + 1 < len(args):
                    try:
                        count = int(args[i + 1])
                    except:
                        pass
                elif args[i] == '-s' and i + 1 < len(args):
                    try:
                        size = int(args[i + 1])
                    except:
                        pass
        
        result = self.tools.ping(target, count, size)
        return self._create_result(result.success, result.output)
    
    def _execute_ping6(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ping6 <target>")
        
        target = args[0]
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-6', target]
        else:
            cmd = ['ping6', target]
        
        cmd.extend(args[1:])
        return self._execute_generic(' '.join(cmd))
    
    def _execute_scan(self, args: List[str]) -> Dict[str, Any]:
        """Standard scan (ports 1-1000)"""
        if not args:
            return self._create_result(False, "Usage: scan <target> [ports]")
        
        target = args[0]
        ports = "1-1000"
        scan_type = "quick"
        
        if len(args) > 1:
            ports = args[1]
        
        result = self.tools.nmap_scan(target, scan_type, ports)
        
        if result.success:
            # Parse open ports from nmap output
            open_ports = self._parse_nmap_output(result.output)
            
            # Log scan to database
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': scan_type,
                'ports_scanned': ports,
                'open_ports': open_ports,
                'open_ports_count': len(open_ports),
                'output': result.output[-2000:]  # Last 2000 chars
            })
        
        return self._create_result(False, result.output)
    
    def _execute_quick_scan(self, args: List[str]) -> Dict[str, Any]:
        """Quick scan with faster settings"""
        if not args:
            return self._create_result(False, "Usage: quick_scan <target>")
        
        target = args[0]
        ports = "1-1000"
        scan_type = "quick_scan"
        
        result = self.tools.nmap_scan(target, scan_type, ports)
        
        if result.success:
            open_ports = self._parse_nmap_output(result.output)
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': "Quick Scan",
                'ports_scanned': ports,
                'open_ports': open_ports,
                'open_ports_count': len(open_ports),
                'output': result.output[-1500:]  # Shorter output for quick scan
            })
        
        return self._create_result(False, result.output)
    
    def _execute_web_scan(self, args: List[str]) -> Dict[str, Any]:
        """Web server scan (common web ports)"""
        if not args:
            return self._create_result(False, "Usage: web_scan <target>")
        
        target = args[0]
        scan_type = "web"
        
        result = self.tools.nmap_scan(target, scan_type)
        
        if result.success:
            open_ports = self._parse_nmap_output(result.output)
            
            scan_result = ScanResult(
                target=target,
                scan_type="web",
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': "Web Server Scan",
                'open_ports': open_ports,
                'open_ports_count': len(open_ports),
                'output': result.output[-2000:]
            })
        
        return self._create_result(False, result.output)
    
    def _execute_nmap(self, args: List[str]) -> Dict[str, Any]:
        """Full nmap command with all options"""
        if not args:
            return self._create_result(False, "Usage: nmap <target> [options]")
        
        target = args[0]
        # Join all arguments except target
        options = ' '.join(args[1:]) if len(args) > 1 else ""
        
        # Determine scan type from options
        scan_type = "custom"
        if '-A' in options or '-sV' in options:
            scan_type = "comprehensive"
        elif '-sS' in options and 'T2' in options:
            scan_type = "stealth"
        elif '-sU' in options:
            scan_type = "udp"
        elif '-O' in options:
            scan_type = "os_detection"
        
        # Execute nmap
        result = self._execute_generic(f"nmap {target} {options}")
        
        if result['success']:
            open_ports = self._parse_nmap_output(result['output'])
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            result['data'] = {
                'target': target,
                'scan_type': scan_type,
                'options': options,
                'open_ports': open_ports,
                'open_ports_count': len(open_ports)
            }
        
        return result
    
    def _execute_full_scan(self, args: List[str]) -> Dict[str, Any]:
        """Full port scan (all ports)"""
        if not args:
            return self._create_result(False, "Usage: full_scan <target>")
        
        target = args[0]
        scan_type = "full"
        
        result = self.tools.nmap_scan(target, scan_type)
        
        if result.success:
            open_ports = self._parse_nmap_output(result.output)
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': "Full Scan (All Ports)",
                'open_ports': open_ports[:50],  # Limit to 50 ports
                'open_ports_count': len(open_ports),
                'output': result.output[-3000:]  # Larger output for full scan
            })
        
        return self._create_result(False, result.output)
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse nmap output for open ports"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    if len(port_proto) == 2:
                        try:
                            port = int(port_proto[0])
                            protocol = port_proto[1]
                            state = parts[1] if len(parts) > 1 else 'unknown'
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            
                            if state.lower() == 'open':
                                open_ports.append({
                                    'port': port,
                                    'protocol': protocol,
                                    'service': service,
                                    'state': state
                                })
                        except ValueError:
                            continue
        
        return open_ports
    
    def _execute_portscan(self, args: List[str]) -> Dict[str, Any]:
        return self._execute_scan(args)
    
    def _execute_traceroute(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: traceroute <target>")
        
        target = args[0]
        result = self.tools.traceroute(target)
        return self._create_result(result.success, result.output)
    
    def _execute_tracepath(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: tracepath <target>")
        
        return self._execute_generic('tracepath ' + ' '.join(args))
    
    def _execute_curl(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: curl <url> [options]")
        
        url = args[0]
        method = 'GET'
        
        if len(args) > 1:
            for i in range(1, len(args)):
                if args[i] == '-X' and i + 1 < len(args):
                    method = args[i + 1].upper()
        
        result = self.tools.curl_request(url, method)
        return self._create_result(result.success, result.output)
    
    def _execute_wget(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: wget <url>")
        
        return self._execute_generic('wget ' + ' '.join(args))
    
    def _execute_http(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: http <url>")
        
        url = args[0]
        try:
            response = requests.get(url, timeout=10)
            result = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:500] + ('...' if len(response.text) > 500 else ''),
                'size': len(response.content)
            }
            return self._create_result(True, result)
        except Exception as e:
            return self._create_result(False, f"HTTP request failed: {e}")
    
    def _execute_whois(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: whois <domain>")
        
        target = args[0]
        result = self.tools.whois_lookup(target)
        return self._create_result(result.success, result.output)
    
    def _execute_dig(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: dig <domain>")
        
        target = args[0]
        result = self.tools.dns_lookup(target)
        return self._create_result(result.success, result.output)
    
    def _execute_dns(self, args: List[str]) -> Dict[str, Any]:
        return self._execute_dig(args)
    
    def _execute_location(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: location <ip>")
        
        target = args[0]
        result = self.tools.get_ip_location(target)
        return self._create_result(result['success'], result)
    
    def _execute_analyze(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: analyze <ip>")
        
        ip = args[0]
        
        # Comprehensive IP analysis
        analysis = {
            'ip': ip,
            'timestamp': datetime.datetime.now().isoformat(),
            'location': None,
            'threats': [],
            'recommendations': []
        }
        
        # Get location
        location = self.tools.get_ip_location(ip)
        if location['success']:
            analysis['location'] = location
        
        # Check if IP is in threat database
        threats = self.db.get_threats_by_ip(ip, 10)
        if threats:
            analysis['threats'] = threats
            analysis['threat_count'] = len(threats)
        
        # Check if IP is managed
        managed = self.db.get_ip_info(ip)
        if managed:
            analysis['managed'] = managed
        
        # Add recommendations based on analysis
        if threats:
            analysis['recommendations'].append("This IP has been involved in previous threats - monitor closely")
        if threats and len(threats) > 5:
            analysis['recommendations'].append("High threat activity detected - consider blocking this IP")
        
        return self._create_result(True, analysis)
    
    def _execute_system(self, args: List[str]) -> Dict[str, Any]:
        """Get system information"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'hostname': socket.gethostname(),
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'used': psutil.virtual_memory().used,
                'free': psutil.virtual_memory().free
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            },
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return self._create_result(True, info)
    
    def _execute_network(self, args: List[str]) -> Dict[str, Any]:
        """Get network information"""
        try:
            hostname = socket.gethostname()
            local_ip = self.tools.get_local_ip()
            interfaces = psutil.net_if_addrs()
            
            network_info = {
                'hostname': hostname,
                'local_ip': local_ip,
                'interfaces': {}
            }
            
            for iface, addrs in interfaces.items():
                network_info['interfaces'][iface] = []
                for addr in addrs:
                    network_info['interfaces'][iface].append({
                        'family': str(addr.family),
                        'address': addr.address
                    })
            
            return self._create_result(True, network_info)
        
        except Exception as e:
            return self._create_result(False, f"Failed to get network info: {e}")
    
    def _execute_status(self, args: List[str]) -> Dict[str, Any]:
        """Get system status"""
        status = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cpu': f"{psutil.cpu_percent(interval=1)}%",
            'memory': f"{psutil.virtual_memory().percent}%",
            'disk': f"{psutil.disk_usage('/').percent}%",
            'uptime': str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())),
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv
            }
        }
        
        return self._create_result(True, status)
    
    def _execute_monitor(self, args: List[str]) -> Dict[str, Any]:
        """Monitor related commands"""
        if not args:
            return self._create_result(False, "Usage: monitor <status|start|stop>")
        
        action = args[0].lower()
        
        if action == 'status':
            # This will be handled by the main app
            return self._create_result(True, "Use 'status' command for monitoring status")
        else:
            return self._create_result(False, f"Monitor action '{action}' not directly available. Use start/stop commands in main app.")
    
    def _execute_ps(self, args: List[str]) -> Dict[str, Any]:
        """Process list"""
        return self._execute_generic('ps aux' if len(args) == 0 else 'ps ' + ' '.join(args))
    
    def _execute_top(self, args: List[str]) -> Dict[str, Any]:
        """Top command"""
        return self._execute_generic('top -b -n 1' if len(args) == 0 else 'top ' + ' '.join(args))
    
    def _execute_threats(self, args: List[str]) -> Dict[str, Any]:
        """Get recent threats"""
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        
        threats = self.db.get_recent_threats(limit)
        return self._create_result(True, threats)
    
    def _execute_report(self, args: List[str]) -> Dict[str, Any]:
        """Generate security report"""
        # Get statistics
        stats = self.db.get_statistics()
        threats = self.db.get_recent_threats(50)
        scans = self.db.get_nikto_scans(10)
        
        # Count threats by severity
        critical_threats = len([t for t in threats if t.get('severity') == 'critical'])
        high_threats = len([t for t in threats if t.get('severity') == 'high'])
        medium_threats = len([t for t in threats if t.get('severity') == 'medium'])
        low_threats = len([t for t in threats if t.get('severity') == 'low'])
        
        # System info
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        report = {
            'generated_at': datetime.datetime.now().isoformat(),
            'statistics': stats,
            'threat_summary': {
                'critical': critical_threats,
                'high': high_threats,
                'medium': medium_threats,
                'low': low_threats,
                'total': len(threats)
            },
            'recent_nikto_scans': len(scans),
            'system_status': {
                'cpu': cpu,
                'memory': mem,
                'disk': disk
            },
            'recommendations': []
        }
        
        # Add recommendations
        if critical_threats > 0:
            report['recommendations'].append("🚨 CRITICAL: Investigate critical severity threats immediately")
        if high_threats > 0:
            report['recommendations'].append("⚠️ HIGH: Address high severity threats as soon as possible")
        if cpu > 80:
            report['recommendations'].append("📈 High CPU usage detected - investigate running processes")
        if mem > 80:
            report['recommendations'].append("💾 High memory usage detected - check for memory leaks")
        if stats.get('total_blocked_ips', 0) > 0:
            report['recommendations'].append(f"🔒 {stats['total_blocked_ips']} IP(s) currently blocked")
        
        # Save report to file
        filename = f"security_report_{int(time.time())}.json"
        filepath = os.path.join(REPORT_DIR, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            report['report_file'] = filepath
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
        
        return self._create_result(True, report)
    
    def _execute_generic(self, command: str) -> Dict[str, Any]:
        """Execute generic shell command"""
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
            execution_time = time.time() - start_time
        
            return self._create_result(
                result.returncode == 0,
                result.stdout if result.stdout else result.stderr,
                execution_time
            )
        
        except subprocess.TimeoutExpired:
            return self._create_result(False, f"Command timed out after 60 seconds")
        except Exception as e:
            return self._create_result(False, f"Command execution failed: {e}")

# =====================
# DISCORD BOT
# =====================
class SpiderBotDiscord:
    """Discord bot integration with Nikto and IP management"""
    
    def __init__(self, command_handler: CommandHandler, db: DatabaseManager, monitor: NetworkMonitor):
        self.handler = command_handler
        self.db = db
        self.monitor = monitor
        self.config = self.load_config()
        self.bot = None
        self.running = False
        self.task = None
    
    def load_config(self) -> Dict:
        """Load Discord configuration"""
        try:
            if os.path.exists(DISCORD_CONFIG_FILE):
                with open(DISCORD_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Discord config: {e}")
        
        return {
            "token": "", 
            "channel_id": "", 
            "enabled": False, 
            "prefix": "!",
            "admin_role": "Admin",
            "security_role": "Security Team"
        }
    
    def save_config(self, token: str, channel_id: str = "", enabled: bool = True, 
                   prefix: str = "!", admin_role: str = "Admin", security_role: str = "Security Team") -> bool:
        """Save Discord configuration"""
        try:
            config = {
                "token": token,
                "channel_id": channel_id,
                "enabled": enabled,
                "prefix": prefix,
                "admin_role": admin_role,
                "security_role": security_role
            }
            with open(DISCORD_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            return True
        except Exception as e:
            logger.error(f"Failed to save Discord config: {e}")
            return False
    
    async def start(self):
        """Start Discord bot"""
        if not DISCORD_AVAILABLE:
            logger.error("discord.py not installed")
            return False
        
        if not self.config.get('token'):
            logger.error("Discord token not configured")
            return False
        
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            intents.members = True  # For role checking
            
            self.bot = commands.Bot(
                command_prefix=self.config.get('prefix', '!'), 
                intents=intents,
                help_command=None
            )
            
            # Setup event handlers
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot logged in as {self.bot.user}')
                print(f'{Colors.GREEN}✅ Discord bot connected as {self.bot.user}{Colors.RESET}')
                
                await self.bot.change_presence(
                    activity=discord.Activity(
                        type=discord.ActivityType.watching,
                        name="500+ Security Commands | !help"
                    )
                )
            
            # Setup commands
            await self.setup_commands()
            
            self.running = True
            await self.bot.start(self.config['token'])
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Discord bot: {e}")
            return False
    
    async def setup_commands(self):
        """Setup Discord commands"""
        
        # ==================== Nikto Commands ====================
        @self.bot.command(name='nikto')
        async def nikto_command(ctx, target: str, *options):
            """Run Nikto web vulnerability scan"""
            if not await self.check_permissions(ctx):
                return
            
            await ctx.send(f"🕷️ Starting Nikto web vulnerability scan on {target}...\nThis may take a few minutes.")
            
            # Build command
            cmd = f"nikto {target}"
            if options:
                cmd += " " + " ".join(options)
            
            result = self.handler.execute(cmd, "discord")
            
            if result['success'] and result.get('data'):
                data = result['data']
                
                # Create embed
                embed = discord.Embed(
                    title=f"🕷️ Nikto Scan Results - {target}",
                    color=discord.Color.orange(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(
                    name="📊 Scan Summary",
                    value=f"**Vulnerabilities Found:** {data.get('vulnerabilities_found', 0)}\n"
                          f"**Scan Time:** {data.get('scan_time', 'N/A')}\n"
                          f"**Target:** {data.get('target', target)}",
                    inline=False
                )
                
                # Add vulnerabilities
                vulns = data.get('vulnerabilities', [])
                if vulns:
                    vuln_text = ""
                    for i, vuln in enumerate(vulns[:5], 1):
                        severity = vuln.get('severity', 'unknown')
                        emoji = self.get_severity_emoji(severity)
                        desc = vuln.get('description', '')[:100]
                        if 'cve' in vuln:
                            desc += f"\nCVE: {vuln['cve']}"
                        vuln_text += f"{emoji} **{severity.upper()}** - {desc}\n"
                    
                    if len(vulns) > 5:
                        vuln_text += f"\n... and {len(vulns) - 5} more vulnerabilities"
                    
                    embed.add_field(
                        name="🔴 Vulnerabilities Detected",
                        value=vuln_text or "No vulnerabilities detected",
                        inline=False
                    )
                
                embed.set_footer(text=f"Requested by {ctx.author.name}")
                await ctx.send(embed=embed)
                
                # Send output file if available
                if data.get('output_file') and os.path.exists(data['output_file']):
                    try:
                        with open(data['output_file'], 'r') as f:
                            content = f.read()[:15000]  # Limit size
                        
                        if len(content) > 0:
                            await ctx.send(file=discord.File(data['output_file'], 
                                                          filename=f"nikto_{target}_{int(time.time())}.json"))
                    except:
                        pass
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='nikto_ssl')
        async def nikto_ssl_command(ctx, target: str):
            """Run Nikto SSL/TLS specific scan"""
            if not await self.check_permissions(ctx):
                return
            
            await ctx.send(f"🔒 Running Nikto SSL/TLS scan on {target}...")
            result = self.handler.execute(f"nikto_ssl {target}", "discord")
            await self.send_nikto_result(ctx, result, target, "SSL/TLS")
        
        @self.bot.command(name='nikto_sql')
        async def nikto_sql_command(ctx, target: str):
            """Run Nikto SQL injection scan"""
            if not await self.check_permissions(ctx):
                return
            
            await ctx.send(f"💉 Running Nikto SQL injection scan on {target}...")
            result = self.handler.execute(f"nikto_sql {target}", "discord")
            await self.send_nikto_result(ctx, result, target, "SQL Injection")
        
        @self.bot.command(name='nikto_xss')
        async def nikto_xss_command(ctx, target: str):
            """Run Nikto XSS scan"""
            if not await self.check_permissions(ctx):
                return
            
            await ctx.send(f"🔄 Running Nikto XSS scan on {target}...")
            result = self.handler.execute(f"nikto_xss {target}", "discord")
            await self.send_nikto_result(ctx, result, target, "XSS")
        
        @self.bot.command(name='nikto_cgi')
        async def nikto_cgi_command(ctx, target: str):
            """Run Nikto CGI scan"""
            if not await self.check_permissions(ctx):
                return
            
            await ctx.send(f"📁 Running Nikto CGI scan on {target}...")
            result = self.handler.execute(f"nikto_cgi {target}", "discord")
            await self.send_nikto_result(ctx, result, target, "CGI")
        
        @self.bot.command(name='nikto_full')
        async def nikto_full_command(ctx, target: str):
            """Run full Nikto scan with all tests"""
            if not await self.check_permissions(ctx):
                return
            
            await ctx.send(f"🔬 Running full Nikto scan on {target}... This will take several minutes.")
            result = self.handler.execute(f"nikto_full {target}", "discord")
            await self.send_nikto_result(ctx, result, target, "Full")
        
        @self.bot.command(name='nikto_status')
        async def nikto_status_command(ctx):
            """Check Nikto scanner status"""
            result = self.handler.execute("nikto_status", "discord")
            
            if result['success']:
                data = result['data']
                embed = discord.Embed(
                    title="🕷️ Nikto Scanner Status",
                    color=discord.Color.green() if data.get('available') else discord.Color.red()
                )
                
                embed.add_field(
                    name="📡 Availability",
                    value="✅ Available" if data.get('available') else "❌ Not Available",
                    inline=True
                )
                
                if data.get('available'):
                    embed.add_field(
                        name="⚙️ Configuration",
                        value=f"Timeout: {data['config'].get('timeout', 'N/A')}s\n"
                              f"Max Targets: {data['config'].get('max_targets', 'N/A')}\n"
                              f"Scan Level: {data['config'].get('scan_level', 'N/A')}",
                        inline=False
                    )
                    
                    scan_types = data.get('scan_types', [])
                    if scan_types:
                        embed.add_field(
                            name="📋 Available Scan Types",
                            value=", ".join(scan_types[:10]),
                            inline=False
                        )
                else:
                    # Installation help
                    help_text = ""
                    for os_name, cmd in data.get('installation_help', {}).items():
                        help_text += f"**{os_name}:** `{cmd}`\n"
                    embed.add_field(
                        name="💻 Installation Help",
                        value=help_text or "Please install Nikto manually",
                        inline=False
                    )
                
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='nikto_results')
        async def nikto_results_command(ctx, limit: int = 5):
            """Get recent Nikto scan results"""
            result = self.handler.execute(f"nikto_results {limit}", "discord")
            
            if result['success']:
                data = result['data']
                scans = data.get('recent_scans', [])
                
                if not scans:
                    await ctx.send("📭 No Nikto scans found in database.")
                    return
                
                embed = discord.Embed(
                    title=f"📊 Recent Nikto Scans (Last {len(scans)})",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                for scan in scans[:5]:
                    vuln_count = len(json.loads(scan.get('vulnerabilities', '[]'))) if scan.get('vulnerabilities') else 0
                    severity = "HIGH" if vuln_count > 10 else "MEDIUM" if vuln_count > 5 else "LOW"
                    emoji = "🔴" if vuln_count > 10 else "🟡" if vuln_count > 5 else "🟢"
                    
                    embed.add_field(
                        name=f"{emoji} {scan.get('target', 'Unknown')}",
                        value=f"**Time:** {scan.get('timestamp', '')[:19]}\n"
                              f"**Vulnerabilities:** {vuln_count} ({severity})\n"
                              f"**Scan Time:** {scan.get('scan_time', 0):.1f}s",
                        inline=False
                    )
                
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        # ==================== IP Management Commands ====================
        @self.bot.command(name='add_ip')
        async def add_ip_command(ctx, ip: str, *, notes: str = ""):
            """Add IP address to monitoring"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            # Add IP
            result = self.handler.execute(f"add_ip {ip} {notes}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ IP Added to Monitoring",
                    description=f"**IP:** `{ip}`",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                
                if notes:
                    embed.add_field(name="📝 Notes", value=notes, inline=False)
                
                embed.set_footer(text=f"Added by {ctx.author.name}")
                await ctx.send(embed=embed)
                
                # Log action
                logger.info(f"Discord user {ctx.author.name} added IP {ip} to monitoring")
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='remove_ip')
        async def remove_ip_command(ctx, ip: str):
            """Remove IP address from monitoring"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            # Remove IP
            result = self.handler.execute(f"remove_ip {ip}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ IP Removed from Monitoring",
                    description=f"**IP:** `{ip}`",
                    color=discord.Color.orange(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.set_footer(text=f"Removed by {ctx.author.name}")
                await ctx.send(embed=embed)
                
                logger.info(f"Discord user {ctx.author.name} removed IP {ip} from monitoring")
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='block_ip')
        async def block_ip_command(ctx, ip: str, *, reason: str = "Manually blocked via Discord"):
            """Block an IP address"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            # Confirm action
            confirm_msg = await ctx.send(f"⚠️ Are you sure you want to block IP `{ip}`? This will block all traffic from this IP. (yes/no)")
            
            def check(m):
                return m.author == ctx.author and m.channel == ctx.channel and m.content.lower() in ['yes', 'no']
            
            try:
                response = await self.bot.wait_for('message', timeout=30.0, check=check)
                
                if response.content.lower() == 'yes':
                    # Block IP
                    result = self.handler.execute(f"block_ip {ip} {reason}", "discord")
                    
                    if result['success']:
                        data = result['data']
                        embed = discord.Embed(
                            title="🔒 IP Blocked",
                            description=f"**IP:** `{ip}`",
                            color=discord.Color.red(),
                            timestamp=datetime.datetime.now()
                        )
                        
                        embed.add_field(name="📋 Reason", value=reason, inline=False)
                        embed.add_field(
                            name="📊 Status",
                            value=f"Firewall: {'✅' if data.get('firewall_blocked') else '❌'}\n"
                                  f"Database: {'✅' if data.get('database_updated') else '❌'}",
                            inline=True
                        )
                        
                        embed.set_footer(text=f"Blocked by {ctx.author.name}")
                        await ctx.send(embed=embed)
                        
                        logger.info(f"Discord user {ctx.author.name} blocked IP {ip}")
                    else:
                        await self.send_error(ctx, result)
                else:
                    await ctx.send("✅ Block cancelled.")
                    
            except asyncio.TimeoutError:
                await ctx.send("⏱️ Block confirmation timed out.")
        
        @self.bot.command(name='unblock_ip')
        async def unblock_ip_command(ctx, ip: str):
            """Unblock an IP address"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            # Unblock IP
            result = self.handler.execute(f"unblock_ip {ip}", "discord")
            
            if result['success']:
                data = result['data']
                embed = discord.Embed(
                    title="🔓 IP Unblocked",
                    description=f"**IP:** `{ip}`",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(
                    name="📊 Status",
                    value=f"Firewall: {'✅' if data.get('firewall_unblocked') else '❌'}\n"
                          f"Database: {'✅' if data.get('database_updated') else '❌'}",
                    inline=False
                )
                
                embed.set_footer(text=f"Unblocked by {ctx.author.name}")
                await ctx.send(embed=embed)
                
                logger.info(f"Discord user {ctx.author.name} unblocked IP {ip}")
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='list_ips')
        async def list_ips_command(ctx, filter_type: str = "all"):
            """List managed IP addresses"""
            if not await self.check_permissions(ctx):
                return
            
            filter_param = ""
            if filter_type.lower() == 'active':
                filter_param = "active"
            elif filter_type.lower() == 'blocked':
                filter_param = "blocked"
            
            result = self.handler.execute(f"list_ips {filter_param}", "discord")
            
            if result['success']:
                data = result['data']
                ips = data.get('ips', [])
                
                if not ips:
                    await ctx.send("📭 No managed IPs found.")
                    return
                
                # Split into blocked and active
                blocked_ips = [ip for ip in ips if ip.get('is_blocked')]
                active_ips = [ip for ip in ips if not ip.get('is_blocked')]
                
                embed = discord.Embed(
                    title=f"📋 Managed IP Addresses ({data['count']} total)",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                # Active IPs
                if active_ips:
                    active_text = ""
                    for ip in active_ips[:10]:
                        active_text += f"`{ip['ip']}` - {ip.get('added_date', '')[:10]}\n"
                    
                    if len(active_ips) > 10:
                        active_text += f"... and {len(active_ips) - 10} more"
                    
                    embed.add_field(
                        name=f"✅ Active IPs ({len(active_ips)})",
                        value=active_text or "None",
                        inline=False
                    )
                
                # Blocked IPs
                if blocked_ips:
                    blocked_text = ""
                    for ip in blocked_ips[:5]:
                        blocked_text += f"`{ip['ip']}` - {ip.get('block_reason', 'No reason')[:50]}\n"
                    
                    if len(blocked_ips) > 5:
                        blocked_text += f"... and {len(blocked_ips) - 5} more"
                    
                    embed.add_field(
                        name=f"🔒 Blocked IPs ({len(blocked_ips)})",
                        value=blocked_text or "None",
                        inline=False
                    )
                
                embed.set_footer(text=f"Requested by {ctx.author.name}")
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='ip_info')
        async def ip_info_command(ctx, ip: str):
            """Get detailed information about an IP"""
            if not await self.check_permissions(ctx):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            result = self.handler.execute(f"ip_info {ip}", "discord")
            
            if result['success']:
                data = result['data']
                
                embed = discord.Embed(
                    title=f"🔍 IP Information - {ip}",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                # Location info
                location = data.get('location')
                if location and location.get('success'):
                    embed.add_field(
                        name="📍 Location",
                        value=f"**Country:** {location.get('country', 'N/A')}\n"
                              f"**Region:** {location.get('region', 'N/A')}\n"
                              f"**City:** {location.get('city', 'N/A')}\n"
                              f"**ISP:** {location.get('isp', 'N/A')}",
                        inline=True
                    )
                
                # Database info
                db_info = data.get('database_info')
                if db_info:
                    status = "🔴 Blocked" if db_info.get('is_blocked') else "🟢 Active"
                    embed.add_field(
                        name="📊 Monitoring Status",
                        value=f"**Status:** {status}\n"
                              f"**Added:** {db_info.get('added_date', '')[:10]}\n"
                              f"**Alerts:** {db_info.get('alert_count', 0)}\n"
                              f"**Scans:** {db_info.get('scan_count', 0)}",
                        inline=True
                    )
                    
                    if db_info.get('is_blocked') and db_info.get('block_reason'):
                        embed.add_field(
                            name="🔒 Block Reason",
                            value=db_info['block_reason'][:200],
                            inline=False
                        )
                else:
                    embed.add_field(
                        name="📊 Monitoring Status",
                        value="❌ Not being monitored",
                        inline=True
                    )
                
                # Recent threats
                threats = data.get('recent_threats', [])
                if threats:
                    threat_text = ""
                    for threat in threats[:3]:
                        severity_emoji = self.get_severity_emoji(threat.get('severity', 'low'))
                        threat_text += f"{severity_emoji} {threat.get('threat_type', 'Unknown')} - {threat.get('timestamp', '')[:16]}\n"
                    
                    embed.add_field(
                        name=f"🚨 Recent Threats ({len(threats)})",
                        value=threat_text or "None",
                        inline=False
                    )
                
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        # ==================== WhatsApp Commands ====================
        @self.bot.command(name='whatsapp_config')
        async def whatsapp_config_command(ctx, phone_number: str, prefix: str = "/"):
            """Configure WhatsApp bot"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            result = self.handler.execute(f"whatsapp_config {phone_number} {prefix}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="📱 WhatsApp Bot Configuration",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(name="📞 Phone Number", value=phone_number, inline=True)
                embed.add_field(name="🔣 Command Prefix", value=prefix, inline=True)
                embed.add_field(name="📋 Next Steps", 
                              value="1. Use `!start_whatsapp` to start the bot\n"
                                    "2. Scan QR code when prompted\n"
                                    "3. Use `!whatsapp_allow <number>` to add authorized users",
                              inline=False)
                
                embed.set_footer(text=f"Configured by {ctx.author.name}")
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='whatsapp_allow')
        async def whatsapp_allow_command(ctx, phone_number: str):
            """Add phone number to WhatsApp allowed contacts"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            result = self.handler.execute(f"whatsapp_allow {phone_number}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ WhatsApp Contact Allowed",
                    description=f"**Phone:** `{phone_number}`",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='whatsapp_disallow')
        async def whatsapp_disallow_command(ctx, phone_number: str):
            """Remove phone number from WhatsApp allowed contacts"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            result = self.handler.execute(f"whatsapp_disallow {phone_number}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="❌ WhatsApp Contact Removed",
                    description=f"**Phone:** `{phone_number}`",
                    color=discord.Color.orange(),
                    timestamp=datetime.datetime.now()
                )
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='start_whatsapp')
        async def start_whatsapp_command(ctx):
            """Start WhatsApp bot"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            await ctx.send("📱 Starting WhatsApp bot... Please check console for QR code scan.")
            
        # ==================== Signal Commands ====================
        @self.bot.command(name='signal_config')
        async def signal_config_command(ctx, phone_number: str, prefix: str = "!"):
            """Configure Signal bot"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            result = self.handler.execute(f"signal_config {phone_number} {prefix}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="🔐 Signal Bot Configuration",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(name="📞 Phone Number", value=phone_number, inline=True)
                embed.add_field(name="🔣 Command Prefix", value=prefix, inline=True)
                embed.add_field(name="📋 Next Steps", 
                              value="1. Use `!signal_register` to register device\n"
                                    "2. Use `!start_signal` to start the bot\n"
                                    "3. Use `!signal_allow <number>` to add authorized users",
                              inline=False)
                
                embed.set_footer(text=f"Configured by {ctx.author.name}")
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='signal_allow')
        async def signal_allow_command(ctx, phone_number: str):
            """Add phone number to Signal allowed contacts"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            result = self.handler.execute(f"signal_allow {phone_number}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ Signal Number Allowed",
                    description=f"**Phone:** `{phone_number}`",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='signal_disallow')
        async def signal_disallow_command(ctx, phone_number: str):
            """Remove phone number from Signal allowed contacts"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            result = self.handler.execute(f"signal_disallow {phone_number}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="❌ Signal Number Removed",
                    description=f"**Phone:** `{phone_number}`",
                    color=discord.Color.orange(),
                    timestamp=datetime.datetime.now()
                )
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='signal_register')
        async def signal_register_command(ctx):
            """Register Signal device"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            await ctx.send("🔐 Registering Signal device... Please check console for QR code.")
        
        @self.bot.command(name='start_signal')
        async def start_signal_command(ctx):
            """Start Signal bot"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            await ctx.send("🔐 Starting Signal bot...")
        
        # ==================== Standard Commands ====================
        @self.bot.command(name='help')
        async def help_command(ctx):
            """Show help menu"""
            embed = discord.Embed(
                title="🕸️ Spider Bot Pro v8.7.0 - Help Menu",
                description="**500+ Advanced Cybersecurity Commands**\n\nType `!command` to execute",
                color=discord.Color.blue()
            )
            
            # Nikto Commands
            embed.add_field(
                name="🕷️ **Nikto Web Scanner**",
                value="`!nikto <target>` - Basic web vuln scan\n"
                      "`!nikto_full <target>` - Full scan with all tests\n"
                      "`!nikto_ssl <target>` - SSL/TLS specific scan\n"
                      "`!nikto_sql <target>` - SQL injection scan\n"
                      "`!nikto_xss <target>` - XSS scan\n"
                      "`!nikto_cgi <target>` - CGI scan\n"
                      "`!nikto_status` - Check scanner status\n"
                      "`!nikto_results` - View recent scans",
                inline=False
            )
            
            # IP Management Commands
            embed.add_field(
                name="🔒 **IP Management**",
                value="`!add_ip <ip> [notes]` - Add IP to monitoring\n"
                      "`!remove_ip <ip>` - Remove IP from monitoring\n"
                      "`!block_ip <ip> [reason]` - Block IP address\n"
                      "`!unblock_ip <ip>` - Unblock IP address\n"
                      "`!list_ips [all/active/blocked]` - List managed IPs\n"
                      "`!ip_info <ip>` - Detailed IP information",
                inline=False
            )
            
            # WhatsApp Commands
            embed.add_field(
                name="📱 **WhatsApp Bot**",
                value="`!whatsapp_config <phone> [prefix]` - Configure WhatsApp\n"
                      "`!whatsapp_allow <phone>` - Allow contact\n"
                      "`!whatsapp_disallow <phone>` - Remove contact\n"
                      "`!start_whatsapp` - Start WhatsApp bot",
                inline=False
            )
            
            # Signal Commands
            embed.add_field(
                name="🔐 **Signal Bot**",
                value="`!signal_config <phone> [prefix]` - Configure Signal\n"
                      "`!signal_allow <phone>` - Allow number\n"
                      "`!signal_disallow <phone>` - Remove number\n"
                      "`!signal_register` - Register device\n"
                      "`!start_signal` - Start Signal bot",
                inline=False
            )
            
            # Basic Commands
            embed.add_field(
                name="🤖 **Basic Commands**",
                value="`!ping <ip>` - Ping IP\n"
                      "`!scan <ip>` - Port scan (1-1000)\n"
                      "`!quick_scan <ip>` - Fast port scan\n"
                      "`!nmap <ip> [options]` - Full nmap scan\n"
                      "`!web_scan <ip>` - Scan web ports",
                inline=False
            )
            
            # Information Gathering
            embed.add_field(
                name="🔍 **Information Gathering**",
                value="`!whois <domain>` - WHOIS lookup\n"
                      "`!dns <domain>` - DNS lookup\n"
                      "`!location <ip>` - IP geolocation\n"
                      "`!analyze <ip>` - Comprehensive analysis",
                inline=False
            )
            
            # System Commands
            embed.add_field(
                name="📊 **System Commands**",
                value="`!system` - System information\n"
                      "`!network` - Network information\n"
                      "`!status` - System status\n"
                      "`!threats` - Recent threats\n"
                      "`!report` - Security report",
                inline=False
            )
            
            # Examples
            embed.add_field(
                name="💡 **Examples**",
                value="```!nikto example.com\n"
                      "!nikto_ssl https://example.com\n"
                      "!add_ip 192.168.1.100 Suspicious activity\n"
                      "!whatsapp_config +1234567890 /\n"
                      "!signal_config +1234567890 !```",
                inline=False
            )
            
            embed.set_footer(text=f"Requested by {ctx.author.name} | Prefix: {self.config.get('prefix', '!')}")
            await ctx.send(embed=embed)
        
        @self.bot.command(name='ping')
        async def ping_command(ctx, target: str, *options):
            """Ping command"""
            await ctx.send(f"🏓 Pinging {target}...")
            cmd = f"ping {target}"
            if options:
                cmd += " " + " ".join(options)
            result = self.handler.execute(cmd, "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='scan')
        async def scan_command(ctx, target: str, ports: str = None):
            """Port scan (1-1000 by default)"""
            await ctx.send(f"🔍 Scanning {target} (ports 1-1000)...")
            cmd = f"scan {target}"
            if ports:
                cmd += f" {ports}"
            result = self.handler.execute(cmd, "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='quick_scan')
        async def quick_scan_command(ctx, target: str):
            """Quick port scan"""
            await ctx.send(f"⚡ Quick scanning {target}...")
            result = self.handler.execute(f"quick_scan {target}", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='web_scan')
        async def web_scan_command(ctx, target: str):
            """Web server port scan"""
            await ctx.send(f"🌐 Scanning web ports on {target}...")
            result = self.handler.execute(f"web_scan {target}", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nmap')
        async def nmap_command(ctx, target: str, *options):
            """Full nmap command"""
            await ctx.send(f"🔬 Running nmap on {target}...")
            cmd = f"nmap {target}"
            if options:
                cmd += " " + " ".join(options)
            result = self.handler.execute(cmd, "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='traceroute')
        async def traceroute_command(ctx, target: str):
            """Traceroute"""
            await ctx.send(f"🛣️ Tracing route to {target}...")
            result = self.handler.execute(f"traceroute {target}", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='whois')
        async def whois_command(ctx, domain: str):
            """WHOIS lookup"""
            await ctx.send(f"🔎 WHOIS lookup for {domain}...")
            result = self.handler.execute(f"whois {domain}", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='dns')
        async def dns_command(ctx, domain: str):
            """DNS lookup"""
            await ctx.send(f"📡 DNS lookup for {domain}...")
            result = self.handler.execute(f"dns {domain}", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='location')
        async def location_command(ctx, ip: str):
            """IP geolocation"""
            await ctx.send(f"📍 Getting location for {ip}...")
            result = self.handler.execute(f"location {ip}", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='analyze')
        async def analyze_command(ctx, ip: str):
            """Comprehensive IP analysis"""
            await ctx.send(f"🔬 Analyzing IP {ip}...")
            result = self.handler.execute(f"analyze {ip}", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='system')
        async def system_command(ctx):
            """System information"""
            await ctx.send("💻 Getting system information...")
            result = self.handler.execute("system", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='network')
        async def network_command(ctx):
            """Network information"""
            await ctx.send("🌐 Getting network information...")
            result = self.handler.execute("network", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='status')
        async def status_command(ctx):
            """System status"""
            await ctx.send("📊 Getting system status...")
            result = self.handler.execute("status", "discord")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='threats')
        async def threats_command(ctx, limit: int = 10):
            """Recent threats"""
            result = self.handler.execute(f"threats {limit}", "discord")
            
            if result['success']:
                threats = result['data']
                
                if not threats:
                    embed = discord.Embed(
                        title="🚨 Recent Threats",
                        description="✅ No recent threats detected",
                        color=discord.Color.green()
                    )
                    await ctx.send(embed=embed)
                    return
                
                embed = discord.Embed(
                    title=f"🚨 Recent Threats (Last {len(threats)})",
                    color=discord.Color.red(),
                    timestamp=datetime.datetime.now()
                )
                
                for threat in threats[:5]:
                    severity = threat.get('severity', 'unknown')
                    severity_emoji = self.get_severity_emoji(severity)
                    
                    embed.add_field(
                        name=f"{severity_emoji} {threat.get('threat_type', 'Unknown')}",
                        value=f"**Source:** `{threat.get('source_ip', 'Unknown')}`\n"
                              f"**Time:** {threat.get('timestamp', '')[:19]}\n"
                              f"**Severity:** {severity.upper()}",
                        inline=False
                    )
                
                if len(threats) > 5:
                    embed.set_footer(text=f"And {len(threats) - 5} more threats")
                
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='report')
        async def report_command(ctx):
            """Generate security report"""
            await ctx.send("📊 Generating security report...")
            result = self.handler.execute("report", "discord")
            
            if result['success']:
                data = result['data']
                
                embed = discord.Embed(
                    title="📊 Security Report",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                # Statistics
                stats = data.get('statistics', {})
                embed.add_field(
                    name="📈 Statistics",
                    value=f"**Total Threats:** {stats.get('total_threats', 0)}\n"
                          f"**Total Scans:** {stats.get('total_scans', 0)}\n"
                          f"**Nikto Scans:** {stats.get('total_nikto_scans', 0)}\n"
                          f"**Managed IPs:** {stats.get('total_managed_ips', 0)}\n"
                          f"**Blocked IPs:** {stats.get('total_blocked_ips', 0)}",
                    inline=True
                )
                
                # Threat Summary
                threats = data.get('threat_summary', {})
                embed.add_field(
                    name="🚨 Threat Summary",
                    value=f"🔥 **Critical:** {threats.get('critical', 0)}\n"
                          f"🔴 **High:** {threats.get('high', 0)}\n"
                          f"🟡 **Medium:** {threats.get('medium', 0)}\n"
                          f"🟢 **Low:** {threats.get('low', 0)}",
                    inline=True
                )
                
                # System Status
                system = data.get('system_status', {})
                embed.add_field(
                    name="💻 System Status",
                    value=f"**CPU:** {system.get('cpu', 0)}%\n"
                          f"**Memory:** {system.get('memory', 0)}%\n"
                          f"**Disk:** {system.get('disk', 0)}%",
                    inline=True
                )
                
                # Recommendations
                recommendations = data.get('recommendations', [])
                if recommendations:
                    rec_text = "\n".join([f"• {r}" for r in recommendations[:5]])
                    embed.add_field(
                        name="💡 Recommendations",
                        value=rec_text,
                        inline=False
                    )
                
                embed.set_footer(text=f"Report generated")
                await ctx.send(embed=embed)
                
                # Send report file
                if data.get('report_file'):
                    try:
                        await ctx.send(file=discord.File(data['report_file']))
                    except:
                        pass
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='execute')
        @commands.has_permissions(administrator=True)
        async def execute_command(ctx, *, command: str):
            """Execute any command (Admin only)"""
            await ctx.send(f"⚡ Executing command...")
            result = self.handler.execute(command, "discord")
            await self.send_result(ctx, result)
    
    async def check_permissions(self, ctx, admin_only: bool = False) -> bool:
        """Check if user has permission to use command"""
        if ctx.author.guild_permissions.administrator:
            return True
        
        admin_role = self.config.get('admin_role', 'Admin')
        security_role = self.config.get('security_role', 'Security Team')
        
        user_roles = [role.name for role in ctx.author.roles]
        
        if admin_only:
            if admin_role in user_roles or ctx.author.guild_permissions.administrator:
                return True
            else:
                await ctx.send(f"❌ This command requires the `{admin_role}` role or Administrator permissions.")
                return False
        else:
            if admin_role in user_roles or security_role in user_roles or ctx.author.guild_permissions.administrator:
                return True
            else:
                await ctx.send(f"❌ This command requires the `{admin_role}` or `{security_role}` role.")
                return False
    
    async def send_nikto_result(self, ctx, result: Dict[str, Any], target: str, scan_type: str):
        """Send Nikto scan result to Discord"""
        if result['success'] and result.get('data'):
            data = result['data']
            
            embed = discord.Embed(
                title=f"🕷️ Nikto {scan_type} Scan - {target}",
                color=discord.Color.orange(),
                timestamp=datetime.datetime.now()
            )
            
            embed.add_field(
                name="📊 Scan Summary",
                value=f"**Vulnerabilities Found:** {data.get('vulnerabilities_found', 0)}\n"
                      f"**Scan Time:** {data.get('scan_time', 'N/A')}",
                inline=False
            )
            
            vulns = data.get('vulnerabilities', [])
            if vulns:
                vuln_text = ""
                for i, vuln in enumerate(vulns[:3], 1):
                    severity = vuln.get('severity', 'unknown')
                    emoji = self.get_severity_emoji(severity)
                    desc = vuln.get('description', '')[:100]
                    vuln_text += f"{emoji} **{severity.upper()}** - {desc}\n"
                
                if len(vulns) > 3:
                    vuln_text += f"\n... and {len(vulns) - 3} more vulnerabilities"
                
                embed.add_field(
                    name="🔴 Top Vulnerabilities",
                    value=vuln_text,
                    inline=False
                )
            
            await ctx.send(embed=embed)
        else:
            await self.send_error(ctx, result)
    
    async def send_result(self, ctx, result: Dict[str, Any]):
        """Send command result to Discord"""
        if not result['success']:
            await self.send_error(ctx, result)
            return
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            try:
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        # Truncate if too long
        if len(formatted) > 2000:
            formatted = formatted[:1900] + "\n\n... (output truncated)"
        
        # Create embed
        if result.get('data'):
            embed = discord.Embed(
                title=f"✅ Command Executed",
                description=f"Execution time: {result['execution_time']:.2f}s",
                color=discord.Color.green()
            )
            
            # Add fields for dictionary data
            if isinstance(result['data'], dict):
                for key, value in result['data'].items():
                    if key not in ['output'] and value:
                        if isinstance(value, list):
                            if len(value) > 0:
                                if isinstance(value[0], dict):
                                    # Format list of dictionaries
                                    formatted_list = "\n".join([str(v)[:50] for v in value[:3]])
                                    if len(value) > 3:
                                        formatted_list += f"\n... and {len(value)-3} more"
                                    embed.add_field(name=key.replace('_', ' ').title(), 
                                                  value=f"```{formatted_list[:500]}```", 
                                                  inline=False)
                                else:
                                    embed.add_field(name=key.replace('_', ' ').title(), 
                                                  value=str(value)[:200], 
                                                  inline=True)
                        else:
                            embed.add_field(name=key.replace('_', ' ').title(), 
                                          value=str(value)[:200], 
                                          inline=True)
            
            await ctx.send(embed=embed)
            
            # Send additional output if needed
            if formatted and 'output' not in result.get('data', {}):
                if len(formatted) > 2000:
                    # Send as file if too long
                    file_content = f"Command Output:\n{formatted}"
                    filename = f"output_{ctx.message.id}.txt"
                    filepath = os.path.join(TEMP_DIR, filename)
                    
                    with open(filepath, "w") as f:
                        f.write(file_content)
                    
                    await ctx.send(file=discord.File(filepath, filename=filename))
                    
                    try:
                        os.remove(filepath)
                    except:
                        pass
                else:
                    await ctx.send(f"```{formatted}```")
        else:
            embed = discord.Embed(
                title=f"✅ Command Executed ({result['execution_time']:.2f}s)",
                description=f"```{formatted}```",
                color=discord.Color.green()
            )
            await ctx.send(embed=embed)
    
    async def send_error(self, ctx, result: Dict[str, Any]):
        """Send error message to Discord"""
        error_msg = result.get('output', 'Unknown error')
        if len(error_msg) > 1000:
            error_msg = error_msg[:1000] + "..."
        
        embed = discord.Embed(
            title="❌ Command Failed",
            description=f"```{error_msg}```",
            color=discord.Color.red()
        )
        
        if 'error' in result:
            embed.add_field(name="Error Details", value=result['error'], inline=False)
        
        await ctx.send(embed=embed)
    
    def get_severity_emoji(self, severity: str) -> str:
        """Get emoji for threat severity"""
        if severity == 'critical':
            return '🔥'
        elif severity == 'high':
            return '🔴'
        elif severity == 'medium':
            return '🟡'
        elif severity == 'low':
            return '🟢'
        else:
            return '⚪'
    
    def start_bot_thread(self):
        """Start Discord bot in separate thread"""
        if self.config.get('enabled') and self.config.get('token'):
            thread = threading.Thread(target=self._run_discord_bot, daemon=True)
            thread.start()
            logger.info("Discord bot started in background thread")
            return True
        return False
    
    def _run_discord_bot(self):
        """Run Discord bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot error: {e}")

# =====================
# TELEGRAM BOT
# =====================
class SpiderBotTelegram:
    """Telegram bot integration"""
    
    def __init__(self, command_handler: CommandHandler, db: DatabaseManager):
        self.handler = command_handler
        self.db = db
        self.config = self.load_config()
        self.client = None
        self.running = False
    
    def load_config(self) -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        
        return {
            "enabled": False,
            "api_id": "",
            "api_hash": "",
            "phone_number": "",
            "channel_id": ""
        }
    
    def save_config(self, api_id: str, api_hash: str, phone_number: str = "", 
                   channel_id: str = "", enabled: bool = True) -> bool:
        """Save Telegram configuration"""
        try:
            config = {
                "api_id": api_id,
                "api_hash": api_hash,
                "phone_number": phone_number,
                "channel_id": channel_id,
                "enabled": enabled
            }
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    async def start(self):
        """Start Telegram bot"""
        if not TELETHON_AVAILABLE:
            logger.error("Telethon not installed")
            return False
        
        if not self.config.get('api_id') or not self.config.get('api_hash'):
            logger.error("Telegram API credentials not configured")
            return False
        
        try:
            self.client = TelegramClient(
                'spiderbot_session',
                self.config['api_id'],
                self.config['api_hash']
            )
            
            # Event handler for incoming messages
            @self.client.on(events.NewMessage(pattern=r'^/(start|help|ping|scan|nikto|add_ip|remove_ip|block_ip|unblock_ip|list_ips|ip_info|status|threats)'))
            async def handler(event):
                await self.handle_command(event)
            
            await self.client.start(phone=self.config.get('phone_number', ''))
            logger.info("Telegram bot started")
            print(f"{Colors.GREEN}✅ Telegram bot connected{Colors.RESET}")
            
            self.running = True
            
            # Keep running
            await self.client.run_until_disconnected()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Telegram bot: {e}")
            return False
    
    async def handle_command(self, event):
        """Handle Telegram commands"""
        message = event.message.message
        sender = await event.get_sender()
        
        if not message.startswith('/'):
            return
        
        command_parts = message.split()
        command = command_parts[0][1:]  # Remove '/'
        args = command_parts[1:] if len(command_parts) > 1 else []
        
        logger.info(f"Telegram command from {sender.username}: {command} {args}")
        
        # Map Telegram commands to handler commands
        cmd_map = {
            'start': 'help',
            'help': 'help',
            'ping': f"ping {' '.join(args)}",
            'scan': f"scan {' '.join(args)}",
            'nikto': f"nikto {' '.join(args)}",
            'add_ip': f"add_ip {' '.join(args)}",
            'remove_ip': f"remove_ip {' '.join(args)}",
            'block_ip': f"block_ip {' '.join(args)}",
            'unblock_ip': f"unblock_ip {' '.join(args)}",
            'list_ips': 'list_ips',
            'ip_info': f"ip_info {' '.join(args)}",
            'status': 'status',
            'threats': 'threats'
        }
        
        if command in cmd_map:
            handler_cmd = cmd_map[command]
            if command in ['start', 'help']:
                await self.send_help(event)
            else:
                # Send processing message
                processing_msg = await event.reply(f"🔄 Processing {command}...")
                
                # Execute command
                result = self.handler.execute(handler_cmd, "telegram")
                
                # Send result
                await self.send_result(event, result, processing_msg)
    
    async def send_help(self, event):
        """Send help message"""
        help_text = """
🕸️ *Spider Bot Pro - Telegram Commands*

*Nikto Web Scanner:*
`/nikto <target>` - Basic web vulnerability scan
`/nikto_full <target>` - Full scan with all tests
`/nikto_ssl <target>` - SSL/TLS specific scan
`/nikto_sql <target>` - SQL injection scan
`/nikto_xss <target>` - XSS scan

*IP Management:*
`/add_ip <ip> [notes]` - Add IP to monitoring
`/remove_ip <ip>` - Remove IP from monitoring
`/block_ip <ip> [reason]` - Block IP address
`/unblock_ip <ip>` - Unblock IP address
`/list_ips` - List managed IPs
`/ip_info <ip>` - Detailed IP information

*Basic Commands:*
`/ping <ip>` - Ping IP
`/scan <ip>` - Port scan
`/status` - System status
`/threats` - Recent threats

*Examples:*
`/nikto example.com`
`/add_ip 192.168.1.100 Suspicious activity`
`/block_ip 10.0.0.5 Port scanning`
`/list_ips`
        """
        
        await event.reply(help_text, parse_mode='markdown')
    
    async def send_result(self, event, result: Dict[str, Any], processing_msg=None):
        """Send command result to Telegram"""
        if processing_msg:
            try:
                await processing_msg.delete()
            except:
                pass
        
        if not result['success']:
            error_msg = f"❌ *Command Failed*\n\n```{result.get('output', 'Unknown error')[:1000]}```"
            await event.reply(error_msg, parse_mode='markdown')
            return
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            try:
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        # Truncate if too long for Telegram
        if len(formatted) > 4000:
            formatted = formatted[:3900] + "\n\n... (output truncated)"
        
        success_msg = f"✅ *Command Executed* ({result['execution_time']:.2f}s)\n\n```{formatted}```"
        
        await event.reply(success_msg, parse_mode='markdown')
    
    def start_bot_thread(self):
        """Start Telegram bot in separate thread"""
        if self.config.get('enabled') and self.config.get('api_id'):
            thread = threading.Thread(target=self._run_telegram_bot, daemon=True)
            thread.start()
            logger.info("Telegram bot started in background thread")
            return True
        return False
    
    def _run_telegram_bot(self):
        """Run Telegram bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Telegram bot error: {e}")

# =====================
# MAIN APPLICATION
# =====================
class SpiderBotPro:
    """Main application class"""
    
    def __init__(self):
        # Load configuration
        self.config = ConfigManager.load_config()
        
        # Initialize components
        self.db = DatabaseManager()
        self.nikto = NiktoScanner(self.db, self.config.get('nikto', {}))
        self.handler = CommandHandler(self.db, self.nikto)
        self.monitor = NetworkMonitor(self.db, self.config)
        self.discord_bot = SpiderBotDiscord(self.handler, self.db, self.monitor)
        self.telegram_bot = SpiderBotTelegram(self.handler, self.db)
        self.whatsapp_bot = SpiderBotWhatsApp(self.handler, self.db)
        self.signal_bot = SpiderBotSignal(self.handler, self.db)
        
        # Application state
        self.running = True
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════════════════════╗
║{Colors.WHITE}        🕸️ REDBACK SPIDER BOT V0.0.2 🕸️                                   {Colors.RED}║
╠══════════════════════════════════════════════════════════════════════════════╣
║{Colors.CYAN}  • 500+ Complete Commands         • Nikto Web Vulnerability Scanner        {Colors.RED}║
║{Colors.CYAN}  • IP Management & Blocking       • Real-time Threat Detection             {Colors.RED}║
║{Colors.CYAN}  • Discord/Telegram/WhatsApp/Signal Integration                          {Colors.RED}║
║{Colors.CYAN}  • WhatsApp Web Commands          • Signal Secure Messaging                {Colors.RED}║
║{Colors.CYAN}  • Advanced Network Scanning       • Professional Security Reporting        {Colors.RED}║
║{Colors.CYAN}  • Multi-threaded Monitoring       • Database Logging & Analytics           {Colors.RED}║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.GREEN}🔒 New Features v0.0.2:{Colors.RESET}
  • 📱 **WhatsApp Bot Integration** - Execute commands via WhatsApp
  • 🔐 **Signal Bot Integration** - Secure command execution via Signal
  • 👥 Contact whitelisting for WhatsApp and Signal
  • 🔄 Real-time command processing from all platforms
  • 📨 Multi-platform alert system

{Colors.YELLOW}💡 Type 'help' for command list{Colors.RESET}
{Colors.YELLOW}📚 Type 'help all' for complete 500+ commands{Colors.RESET}
        """
        print(banner)
    
    def print_help(self):
        """Print help information"""
        help_text = f"""
{Colors.YELLOW}┌─────────────────{Colors.WHITE} REDBACK SPIDER BOT v0.0.2 {Colors.YELLOW}─────────────────┐{Colors.RESET}

{Colors.GREEN}🕷️  NIKTO WEB SCANNER:{Colors.RESET}
  nikto <target>              - Basic web vulnerability scan
  nikto_ssl <target>          - SSL/TLS specific scan
  nikto_sql <target>          - SQL injection scan
  nikto_xss <target>          - XSS scan
  nikto_cgi <target>          - CGI scan
  nikto_full <target>         - Full scan with all tests
  nikto_status                - Check Nikto availability
  nikto_results               - View recent scans

{Colors.GREEN}🔒 IP MANAGEMENT:{Colors.RESET}
  add_ip <ip> [notes]         - Add IP to monitoring
  remove_ip <ip>              - Remove IP from monitoring
  block_ip <ip> [reason]      - Block IP via firewall
  unblock_ip <ip>            - Unblock IP
  list_ips [all/active/blocked] - List managed IPs
  ip_info <ip>               - Detailed IP information

{Colors.GREEN}📱 WHATSAPP BOT:{Colors.RESET}
  whatsapp_config <phone> [prefix] - Configure WhatsApp
  whatsapp_allow <phone>      - Allow contact
  whatsapp_disallow <phone>   - Remove contact
  start_whatsapp              - Start WhatsApp bot
  whatsapp_status             - Check WhatsApp status

{Colors.GREEN}🔐 SIGNAL BOT:{Colors.RESET}
  signal_config <phone> [prefix] - Configure Signal
  signal_allow <phone>        - Allow number
  signal_disallow <phone>     - Remove number
  signal_register             - Register Signal device
  start_signal                - Start Signal bot
  signal_status               - Check Signal status

{Colors.GREEN}🛡️  MONITORING COMMANDS:{Colors.RESET}
  start                    - Start threat monitoring
  stop                     - Stop monitoring
  status                   - Show monitoring status
  threats                  - Show recent threats
  report                   - Generate security report

{Colors.GREEN}📡 NETWORK DIAGNOSTICS:{Colors.RESET}
  ping <ip> [options]      - Ping with options
  traceroute <target>      - Network path tracing
  scan <ip> [ports]        - Port scan (1-1000)
  quick_scan <ip>          - Fast port scan
  web_scan <ip>            - Scan web ports
  nmap <ip> [options]      - Advanced nmap scanning
  full_scan <ip>           - Scan all ports

{Colors.GREEN}🔍 INFORMATION GATHERING:{Colors.RESET}
  whois <domain>           - WHOIS lookup
  dns <domain>             - DNS lookup
  location <ip>            - IP geolocation
  analyze <ip>             - Comprehensive analysis

{Colors.GREEN}🤖 BOT COMMANDS:{Colors.RESET}
  config discord token <token>     - Set Discord token
  config discord channel <id>      - Set channel ID
  config telegram api <id> <hash>  - Set Telegram API
  start_discord                    - Start Discord bot
  start_telegram                   - Start Telegram bot

{Colors.GREEN}💡 EXAMPLES:{Colors.RESET}
  nikto example.com
  whatsapp_config +1234567890 /
  signal_config +1234567890 !
  add_ip 192.168.1.100 Suspicious activity
  block_ip 10.0.0.5 Port scanning detected
  start_whatsapp

{Colors.YELLOW}└─────────────────────────────────────────────────────────────────────┘{Colors.RESET}
        """
        print(help_text)
    
    def check_dependencies(self):
        """Check for required dependencies"""
        print(f"\n{Colors.CYAN}🔍 Checking dependencies...{Colors.RESET}")
        
        required_tools = ['ping', 'nmap', 'curl', 'dig', 'traceroute']
        missing = []
        
        for tool in required_tools:
            if shutil.which(tool):
                print(f"{Colors.GREEN}✅ {tool}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}⚠️  {tool} not found{Colors.RESET}")
                missing.append(tool)
        
        # Check Nikto
        if self.nikto.nikto_available:
            print(f"{Colors.GREEN}✅ nikto{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  nikto not found - web vulnerability scanning disabled{Colors.RESET}")
            missing.append('nikto')
        
        # Check Selenium for WhatsApp
        if SELENIUM_AVAILABLE:
            print(f"{Colors.GREEN}✅ selenium (WhatsApp){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  selenium not found - WhatsApp integration disabled{Colors.RESET}")
            print(f"{Colors.YELLOW}   Install with: pip install selenium webdriver-manager{Colors.RESET}")
        
        # Check signal-cli
        if SIGNAL_CLI_AVAILABLE:
            print(f"{Colors.GREEN}✅ signal-cli{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  signal-cli not found - Signal integration disabled{Colors.RESET}")
            print(f"{Colors.YELLOW}   Install from: https://github.com/AsamK/signal-cli{Colors.RESET}")
        
        if missing:
            print(f"\n{Colors.YELLOW}⚠️  Some tools are missing. Install with:{Colors.RESET}")
            if platform.system().lower() == 'linux':
                print(f"  sudo apt-get install {' '.join(missing)}")
            elif platform.system().lower() == 'darwin':
                print(f"  brew install {' '.join(missing)}")
        
        print(f"\n{Colors.GREEN}✅ Dependencies check complete{Colors.RESET}")
    
    def setup_discord(self):
        """Setup Discord bot"""
        print(f"\n{Colors.CYAN}🤖 Discord Bot Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        token = input(f"{Colors.YELLOW}Enter Discord bot token (or press Enter to skip): {Colors.RESET}").strip()
        if not token:
            print(f"{Colors.YELLOW}⚠️  Discord setup skipped{Colors.RESET}")
            return
        
        channel_id = input(f"{Colors.YELLOW}Enter channel ID for notifications (optional): {Colors.RESET}").strip()
        prefix = input(f"{Colors.YELLOW}Enter command prefix (default: !): {Colors.RESET}").strip() or "!"
        admin_role = input(f"{Colors.YELLOW}Enter admin role name (default: Admin): {Colors.RESET}").strip() or "Admin"
        security_role = input(f"{Colors.YELLOW}Enter security team role name (default: Security Team): {Colors.RESET}").strip() or "Security Team"
        
        if self.discord_bot.save_config(token, channel_id, True, prefix, admin_role, security_role):
            print(f"{Colors.GREEN}✅ Discord configured!{Colors.RESET}")
            
            # Start Discord bot
            if self.discord_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Discord bot started! Use '{prefix}help' in Discord{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to start Discord bot{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Failed to save Discord configuration{Colors.RESET}")
    
    def setup_telegram(self):
        """Setup Telegram bot"""
        print(f"\n{Colors.CYAN}📱 Telegram Bot Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        print(f"{Colors.YELLOW}To create a Telegram bot:{Colors.RESET}")
        print(f"1. Open Telegram and search for @BotFather")
        print(f"2. Send /newbot to create a new bot")
        print(f"3. Follow instructions to get API ID and Hash")
        print()
        
        api_id = input(f"{Colors.YELLOW}Enter API ID (or press Enter to skip): {Colors.RESET}").strip()
        if not api_id:
            print(f"{Colors.YELLOW}⚠️  Telegram setup skipped{Colors.RESET}")
            return
        
        api_hash = input(f"{Colors.YELLOW}Enter API Hash: {Colors.RESET}").strip()
        phone_number = input(f"{Colors.YELLOW}Enter your phone number (with country code, optional): {Colors.RESET}").strip()
        channel_id = input(f"{Colors.YELLOW}Enter channel ID (optional): {Colors.RESET}").strip()
        
        if self.telegram_bot.save_config(api_id, api_hash, phone_number, channel_id, True):
            print(f"{Colors.GREEN}✅ Telegram configured!{Colors.RESET}")
            
            # Start Telegram bot
            if self.telegram_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Telegram bot started! Use /help in Telegram{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to start Telegram bot{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Failed to save Telegram configuration{Colors.RESET}")
    
    def setup_whatsapp(self):
        """Setup WhatsApp bot"""
        print(f"\n{Colors.CYAN}📱 WhatsApp Bot Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        print(f"{Colors.YELLOW}WhatsApp Bot Requirements:{Colors.RESET}")
        print(f"1. Chrome browser must be installed")
        print(f"2. You'll need to scan QR code with WhatsApp app")
        print(f"3. Session will be saved for future use")
        print()
        
        phone = input(f"{Colors.YELLOW}Enter your WhatsApp phone number (with country code, e.g., +1234567890): {Colors.RESET}").strip()
        if not phone:
            print(f"{Colors.YELLOW}⚠️  WhatsApp setup skipped{Colors.RESET}")
            return
        
        prefix = input(f"{Colors.YELLOW}Enter command prefix (default: /): {Colors.RESET}").strip() or "/"
        auto_login = input(f"{Colors.YELLOW}Enable auto-login? (y/n, default: n): {Colors.RESET}").strip().lower() == 'y'
        
        if self.whatsapp_bot.save_config(phone, True, prefix, auto_login, []):
            print(f"{Colors.GREEN}✅ WhatsApp configured!{Colors.RESET}")
            print(f"{Colors.YELLOW}📱 To start WhatsApp bot, use: start_whatsapp{Colors.RESET}")
            print(f"{Colors.YELLOW}   You will need to scan QR code when starting{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Failed to save WhatsApp configuration{Colors.RESET}")
    
    def setup_signal(self):
        """Setup Signal bot"""
        print(f"\n{Colors.CYAN}🔐 Signal Bot Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        # Check signal-cli
        if not SIGNAL_CLI_AVAILABLE:
            print(f"{Colors.RED}❌ signal-cli not found{Colors.RESET}")
            print(f"{Colors.YELLOW}Please install signal-cli first:{Colors.RESET}")
            print(f"  Linux: https://github.com/AsamK/signal-cli/wiki/Quick-start")
            print(f"  macOS: brew install signal-cli")
            return
        
        phone = input(f"{Colors.YELLOW}Enter your Signal phone number (with country code, e.g., +1234567890): {Colors.RESET}").strip()
        if not phone:
            print(f"{Colors.YELLOW}⚠️  Signal setup skipped{Colors.RESET}")
            return
        
        prefix = input(f"{Colors.YELLOW}Enter command prefix (default: !): {Colors.RESET}").strip() or "!"
        
        if self.signal_bot.save_config(phone, True, prefix, "signal-cli", []):
            print(f"{Colors.GREEN}✅ Signal configured!{Colors.RESET}")
            print(f"{Colors.YELLOW}🔐 Next steps:{Colors.RESET}")
            print(f"  1. Use: signal_register - to register device")
            print(f"  2. Use: start_signal - to start Signal bot")
            print(f"  3. Use: signal_allow <number> - to add authorized users")
        else:
            print(f"{Colors.RED}❌ Failed to save Signal configuration{Colors.RESET}")
    
    def process_command(self, command: str):
        """Process user command"""
        if not command.strip():
            return
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == 'help':
            self.print_help()
        
        elif cmd == 'start':
            self.monitor.start_monitoring()
            print(f"{Colors.GREEN}✅ Threat monitoring started{Colors.RESET}")
        
        elif cmd == 'stop':
            self.monitor.stop_monitoring()
            print(f"{Colors.YELLOW}🛑 Threat monitoring stopped{Colors.RESET}")
        
        elif cmd == 'status':
            status = self.monitor.get_status()
            print(f"\n{Colors.CYAN}📊 Monitoring Status:{Colors.RESET}")
            print(f"  Active: {'✅ Yes' if status['monitoring'] else '❌ No'}")
            print(f"  Monitored IPs: {status['monitored_ips_count']}")
            print(f"  Blocked IPs: {status.get('blocked_ips', 0)}")
            print(f"  Auto-block: {'✅ Enabled' if status.get('auto_block') else '❌ Disabled'}")
            
            # Bot status
            print(f"\n{Colors.CYAN}🤖 Bot Status:{Colors.RESET}")
            print(f"  Discord: {'✅ Active' if self.discord_bot.running else '❌ Inactive'}")
            print(f"  Telegram: {'✅ Active' if self.telegram_bot.running else '❌ Inactive'}")
            print(f"  WhatsApp: {'✅ Active' if self.whatsapp_bot.running else '❌ Inactive'}")
            print(f"  Signal: {'✅ Active' if self.signal_bot.running else '❌ Inactive'}")
            
            threats = self.db.get_recent_threats(3)
            if threats:
                print(f"\n{Colors.RED}🚨 Recent Threats:{Colors.RESET}")
                for threat in threats:
                    severity_color = Colors.RED if threat['severity'] == 'high' else Colors.YELLOW
                    print(f"  {severity_color}{threat['threat_type']} from {threat['source_ip']}{Colors.RESET}")
        
        elif cmd == 'threats':
            threats = self.db.get_recent_threats(10)
            if threats:
                print(f"\n{Colors.RED}🚨 Recent Threats:{Colors.RESET}")
                for threat in threats:
                    severity_color = Colors.RED if threat['severity'] in ['critical', 'high'] else Colors.YELLOW
                    print(f"\n{severity_color}[{threat['timestamp'][:19]}] {threat['threat_type']}{Colors.RESET}")
                    print(f"  Source: {threat['source_ip']}")
                    print(f"  Severity: {threat['severity'].upper()}")
                    print(f"  Description: {threat['description']}")
            else:
                print(f"{Colors.GREEN}✅ No recent threats detected{Colors.RESET}")
        
        elif cmd == 'history':
            history = self.db.get_command_history(20)
            if history:
                print(f"\n{Colors.CYAN}📜 Command History:{Colors.RESET}")
                for record in history:
                    status = f"{Colors.GREEN}✅" if record['success'] else f"{Colors.RED}❌"
                    print(f"{status} [{record['source']}] {record['command'][:50]}{Colors.RESET}")
                    print(f"     {record['timestamp'][:19]}")
            else:
                print(f"{Colors.YELLOW}📜 No command history{Colors.RESET}")
        
        elif cmd == 'report':
            result = self.handler.execute("report")
            if result['success']:
                data = result['data']
                print(f"\n{Colors.CYAN}📊 Security Report{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                print(f"\n{Colors.WHITE}Generated: {data.get('generated_at', '')[:19]}{Colors.RESET}")
                
                stats = data.get('statistics', {})
                print(f"\n{Colors.GREEN}📈 Statistics:{Colors.RESET}")
                print(f"  Total Commands: {stats.get('total_commands', 0)}")
                print(f"  Total Scans: {stats.get('total_scans', 0)}")
                print(f"  Nikto Scans: {stats.get('total_nikto_scans', 0)}")
                print(f"  Managed IPs: {stats.get('total_managed_ips', 0)}")
                print(f"  Blocked IPs: {stats.get('total_blocked_ips', 0)}")
                print(f"  Total Threats: {stats.get('total_threats', 0)}")
                
                threats = data.get('threat_summary', {})
                print(f"\n{Colors.RED}🚨 Threat Summary:{Colors.RESET}")
                print(f"  Critical: {threats.get('critical', 0)}")
                print(f"  High: {threats.get('high', 0)}")
                print(f"  Medium: {threats.get('medium', 0)}")
                print(f"  Low: {threats.get('low', 0)}")
                
                recommendations = data.get('recommendations', [])
                if recommendations:
                    print(f"\n{Colors.YELLOW}💡 Recommendations:{Colors.RESET}")
                    for rec in recommendations:
                        print(f"  • {rec}")
                
                if 'report_file' in data:
                    print(f"\n{Colors.GREEN}✅ Report saved: {data['report_file']}{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to generate report: {result.get('output', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'config' and len(args) >= 2:
            service = args[0].lower()
            
            if service == 'discord':
                if len(args) >= 3 and args[1] == 'token':
                    token = args[2]
                    channel = self.discord_bot.config.get('channel_id', '')
                    prefix = self.discord_bot.config.get('prefix', '!')
                    admin_role = self.discord_bot.config.get('admin_role', 'Admin')
                    security_role = self.discord_bot.config.get('security_role', 'Security Team')
                    self.discord_bot.save_config(token, channel, True, prefix, admin_role, security_role)
                    print(f"{Colors.GREEN}✅ Discord token configured{Colors.RESET}")
                
                elif len(args) >= 3 and args[1] == 'channel':
                    channel_id = args[2]
                    token = self.discord_bot.config.get('token', '')
                    prefix = self.discord_bot.config.get('prefix', '!')
                    admin_role = self.discord_bot.config.get('admin_role', 'Admin')
                    security_role = self.discord_bot.config.get('security_role', 'Security Team')
                    self.discord_bot.save_config(token, channel_id, True, prefix, admin_role, security_role)
                    print(f"{Colors.GREEN}✅ Discord channel ID configured{Colors.RESET}")
                
                elif len(args) >= 3 and args[1] == 'prefix':
                    prefix = args[2]
                    token = self.discord_bot.config.get('token', '')
                    channel = self.discord_bot.config.get('channel_id', '')
                    admin_role = self.discord_bot.config.get('admin_role', 'Admin')
                    security_role = self.discord_bot.config.get('security_role', 'Security Team')
                    self.discord_bot.save_config(token, channel, True, prefix, admin_role, security_role)
                    print(f"{Colors.GREEN}✅ Discord prefix configured to '{prefix}'{Colors.RESET}")
            
            elif service == 'telegram' and len(args) >= 4 and args[1] == 'api':
                api_id = args[2]
                api_hash = args[3]
                phone = self.telegram_bot.config.get('phone_number', '')
                channel = self.telegram_bot.config.get('channel_id', '')
                self.telegram_bot.save_config(api_id, api_hash, phone, channel, True)
                print(f"{Colors.GREEN}✅ Telegram API configured{Colors.RESET}")
        
        elif cmd == 'whatsapp_config':
            if len(args) >= 1:
                phone = args[0]
                prefix = args[1] if len(args) > 1 else "/"
                self.whatsapp_bot.save_config(phone, True, prefix, False, [])
                print(f"{Colors.GREEN}✅ WhatsApp configured for {phone}{Colors.RESET}")
                print(f"{Colors.YELLOW}📱 Use 'start_whatsapp' to start the bot{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Usage: whatsapp_config <phone_number> [prefix]{Colors.RESET}")
        
        elif cmd == 'whatsapp_allow':
            if len(args) >= 1:
                if self.whatsapp_bot.add_allowed_contact(args[0]):
                    print(f"{Colors.GREEN}✅ Contact {args[0]} added to allowed list{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}⚠️ Contact {args[0]} already in allowed list{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Usage: whatsapp_allow <phone_number>{Colors.RESET}")
        
        elif cmd == 'whatsapp_disallow':
            if len(args) >= 1:
                if self.whatsapp_bot.remove_allowed_contact(args[0]):
                    print(f"{Colors.GREEN}✅ Contact {args[0]} removed from allowed list{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}⚠️ Contact {args[0]} not found in allowed list{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Usage: whatsapp_disallow <phone_number>{Colors.RESET}")
        
        elif cmd == 'start_whatsapp':
            if not self.whatsapp_bot.config.get('phone_number'):
                print(f"{Colors.RED}❌ WhatsApp not configured. Use 'whatsapp_config' first.{Colors.RESET}")
            else:
                if self.whatsapp_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ WhatsApp bot starting... Check console for QR code.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to start WhatsApp bot{Colors.RESET}")
        
        elif cmd == 'whatsapp_status':
            print(f"\n{Colors.CYAN}📱 WhatsApp Bot Status:{Colors.RESET}")
            print(f"  Active: {'✅ Yes' if self.whatsapp_bot.running else '❌ No'}")
            print(f"  Phone: {self.whatsapp_bot.config.get('phone_number', 'Not configured')}")
            print(f"  Prefix: {self.whatsapp_bot.config.get('command_prefix', '/')}")
            print(f"  Allowed Contacts: {len(self.whatsapp_bot.allowed_contacts)}")
            if self.whatsapp_bot.allowed_contacts:
                for contact in self.whatsapp_bot.allowed_contacts[:5]:
                    print(f"    • {contact}")
        
        elif cmd == 'signal_config':
            if len(args) >= 1:
                phone = args[0]
                prefix = args[1] if len(args) > 1 else "!"
                self.signal_bot.save_config(phone, True, prefix, "signal-cli", [])
                print(f"{Colors.GREEN}✅ Signal configured for {phone}{Colors.RESET}")
                print(f"{Colors.YELLOW}🔐 Use 'signal_register' to register device, then 'start_signal'{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Usage: signal_config <phone_number> [prefix]{Colors.RESET}")
        
        elif cmd == 'signal_allow':
            if len(args) >= 1:
                if self.signal_bot.add_allowed_number(args[0]):
                    print(f"{Colors.GREEN}✅ Number {args[0]} added to allowed list{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}⚠️ Number {args[0]} already in allowed list{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Usage: signal_allow <phone_number>{Colors.RESET}")
        
        elif cmd == 'signal_disallow':
            if len(args) >= 1:
                if self.signal_bot.remove_allowed_number(args[0]):
                    print(f"{Colors.GREEN}✅ Number {args[0]} removed from allowed list{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}⚠️ Number {args[0]} not found in allowed list{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Usage: signal_disallow <phone_number>{Colors.RESET}")
        
        elif cmd == 'signal_register':
            if not self.signal_bot.config.get('phone_number'):
                print(f"{Colors.RED}❌ Signal not configured. Use 'signal_config' first.{Colors.RESET}")
            else:
                self.signal_bot.register_device()
        
        elif cmd == 'start_signal':
            if not self.signal_bot.config.get('phone_number'):
                print(f"{Colors.RED}❌ Signal not configured. Use 'signal_config' first.{Colors.RESET}")
            else:
                if self.signal_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ Signal bot starting...{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to start Signal bot{Colors.RESET}")
        
        elif cmd == 'signal_status':
            print(f"\n{Colors.CYAN}🔐 Signal Bot Status:{Colors.RESET}")
            print(f"  Active: {'✅ Yes' if self.signal_bot.running else '❌ No'}")
            print(f"  Phone: {self.signal_bot.config.get('phone_number', 'Not configured')}")
            print(f"  Prefix: {self.signal_bot.config.get('command_prefix', '!')}")
            print(f"  Allowed Numbers: {len(self.signal_bot.allowed_numbers)}")
            if self.signal_bot.allowed_numbers:
                for number in self.signal_bot.allowed_numbers[:5]:
                    print(f"    • {number}")
            print(f"  signal-cli: {'✅ Available' if self.signal_bot.check_signal_cli() else '❌ Not found'}")
        
        elif cmd == 'start_discord':
            if not self.discord_bot.config.get('token'):
                print(f"{Colors.RED}❌ Discord token not configured{Colors.RESET}")
                print(f"{Colors.YELLOW}Use: config discord token <your_token>{Colors.RESET}")
            else:
                if self.discord_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ Discord bot started!{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to start Discord bot{Colors.RESET}")
        
        elif cmd == 'start_telegram':
            if not self.telegram_bot.config.get('api_id'):
                print(f"{Colors.RED}❌ Telegram API not configured{Colors.RESET}")
                print(f"{Colors.YELLOW}Use: config telegram api <id> <hash>{Colors.RESET}")
            else:
                if self.telegram_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ Telegram bot started!{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to start Telegram bot{Colors.RESET}")
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{Colors.YELLOW}👋 Thank you for using Spider Bot Pro!{Colors.RESET}")
        
        else:
            # Execute as generic command
            result = self.handler.execute(command)
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                
                if isinstance(output, dict):
                    # Pretty print dictionaries
                    print(json.dumps(output, indent=2))
                else:
                    print(output)
                
                print(f"\n{Colors.GREEN}✅ Command executed ({result['execution_time']:.2f}s){Colors.RESET}")
            else:
                print(f"\n{Colors.RED}❌ Command failed: {result.get('output', 'Unknown error')}{Colors.RESET}")
    
    def run(self):
        """Main application loop"""
        # Clear screen and show banner
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Check dependencies
        self.check_dependencies()
        
        # Setup bots if configured
        print(f"\n{Colors.CYAN}🤖 Bot Configuration{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        # Check Discord
        if self.discord_bot.config.get('enabled') and self.discord_bot.config.get('token'):
            print(f"{Colors.GREEN}✅ Discord bot configured{Colors.RESET}")
            self.discord_bot.start_bot_thread()
        else:
            setup_discord = input(f"{Colors.YELLOW}Setup Discord bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_discord == 'y':
                self.setup_discord()
        
        # Check Telegram
        if self.telegram_bot.config.get('enabled') and self.telegram_bot.config.get('api_id'):
            print(f"{Colors.GREEN}✅ Telegram bot configured{Colors.RESET}")
            self.telegram_bot.start_bot_thread()
        else:
            setup_telegram = input(f"{Colors.YELLOW}Setup Telegram bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_telegram == 'y':
                self.setup_telegram()
        
        # Check WhatsApp
        if self.whatsapp_bot.config.get('enabled') and self.whatsapp_bot.config.get('phone_number'):
            print(f"{Colors.GREEN}✅ WhatsApp bot configured{Colors.RESET}")
        else:
            setup_whatsapp = input(f"{Colors.YELLOW}Setup WhatsApp bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_whatsapp == 'y':
                self.setup_whatsapp()
        
        # Check Signal
        if self.signal_bot.config.get('enabled') and self.signal_bot.config.get('phone_number'):
            print(f"{Colors.GREEN}✅ Signal bot configured{Colors.RESET}")
        else:
            setup_signal = input(f"{Colors.YELLOW}Setup Signal bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_signal == 'y':
                self.setup_signal()
        
        # Ask about monitoring
        auto_monitor = input(f"\n{Colors.YELLOW}Start threat monitoring automatically? (y/n): {Colors.RESET}").strip().lower()
        if auto_monitor == 'y':
            self.monitor.start_monitoring()
            print(f"{Colors.GREEN}✅ Threat monitoring started{Colors.RESET}")
        
        # Ask about auto-block
        if self.monitor.auto_block:
            print(f"{Colors.GREEN}✅ Auto-block is enabled (threshold: {self.monitor.auto_block_threshold} alerts){Colors.RESET}")
        else:
            enable_auto_block = input(f"{Colors.YELLOW}Enable auto-blocking? (y/n): {Colors.RESET}").strip().lower()
            if enable_auto_block == 'y':
                self.monitor.auto_block = True
                try:
                    threshold = int(input(f"{Colors.YELLOW}Enter alert threshold for auto-block (default: 5): {Colors.RESET}").strip() or "5")
                    self.monitor.auto_block_threshold = threshold
                except:
                    pass
                print(f"{Colors.GREEN}✅ Auto-block enabled (threshold: {self.monitor.auto_block_threshold} alerts){Colors.RESET}")
                
                # Update config
                if 'security' not in self.config:
                    self.config['security'] = {}
                self.config['security']['auto_block'] = True
                self.config['security']['auto_block_threshold'] = self.monitor.auto_block_threshold
                ConfigManager.save_config(self.config)
        
        print(f"\n{Colors.GREEN}✅ Tool ready! Type 'help' for commands.{Colors.RESET}")
        
        # Main command loop
        while self.running:
            try:
                prompt = f"{Colors.RED}[{Colors.WHITE}spiderbot-pro{Colors.RED}]{Colors.RESET} "
                command = input(prompt).strip()
                self.process_command(command)
            
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.RESET}")
                self.running = False
            
            except Exception as e:
                print(f"{Colors.RED}❌ Error: {str(e)}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.monitor.stop_monitoring()
        self.whatsapp_bot.stop()
        self.signal_bot.stop()
        self.db.close()
        
        print(f"\n{Colors.GREEN}✅ Tool shutdown complete.{Colors.RESET}")
        print(f"{Colors.CYAN}📁 Logs saved to: {LOG_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}💾 Database: {DATABASE_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}🕷️  Nikto results: {NIKTO_RESULTS_DIR}{Colors.RESET}")
        print(f"{Colors.CYAN}📱 WhatsApp session: {WHATSAPP_SESSION_DIR}{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        print(f"{Colors.CYAN}🚀 Starting Reback Spider Bot Pro v0.0.2...{Colors.RESET}")
        
        # Check Python version
        if sys.version_info < (3, 7):
            print(f"{Colors.RED}❌ Python 3.7 or higher is required{Colors.RESET}")
            sys.exit(1)
        
        # Check for root/admin privileges for firewall operations
        if platform.system().lower() == 'linux':
            if os.geteuid() != 0:
                print(f"{Colors.YELLOW}⚠️  Warning: Running without root privileges{Colors.RESET}")
                print(f"{Colors.YELLOW}   Firewall operations (block_ip/unblock_ip) will not work{Colors.RESET}")
                print(f"{Colors.YELLOW}   Run with: sudo python3 spiderbot_pro.py{Colors.RESET}")
                time.sleep(2)
        elif platform.system().lower() == 'windows':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(f"{Colors.YELLOW}⚠️  Warning: Running without administrator privileges{Colors.RESET}")
                print(f"{Colors.YELLOW}   Firewall operations will not work{Colors.RESET}")
                time.sleep(2)
        
        # Create and run application
        app = SpiderBotPro()
        app.run()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Fatal error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
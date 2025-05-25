import pyshark
import psutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import os
import json
import asyncio
import aiohttp
from datetime import datetime, timedelta
import time
from collections import defaultdict, deque
import pandas as pd
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import requests
import logging
from ipaddress import ip_address, AddressValueError
from pathlib import Path
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple, Any

# Configure logging with more verbose output for debugging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for troubleshooting
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('simpleshark.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Custom Exceptions
class NetworkCaptureError(Exception):
    """Raised when network capture fails"""
    pass

class ThreatFeedError(Exception):
    """Raised when threat feed loading fails"""
    pass

class ConfigurationError(Exception):
    """Raised when configuration is invalid"""
    pass

# Configuration Management
class Config:
    """Centralized configuration management"""
    
    DEFAULT_SETTINGS = {
        "interface": "",
        "geolite_path": "GeoLite2-City.mmdb",
        "abuseipdb_key": "",
        "max_packets": 10000,
        "burst_threshold": 400,
        "refresh_interval": 3600,
        "gui_update_interval": 500,  # Reduced from 1000ms to 500ms for better responsiveness
        "batch_size": 50,  # Reduced from 100 to 50 for better processing
        "enable_geolocation": True,
        "enable_threat_feeds": True,
        "enable_hex_dumps": True,
        "hex_dump_max_length": 32,
        "api_timeout": 10,
        "max_alerts": 5000,
        "abuseipdb_cache_time": 300,
        "promiscuous_mode": False,
        "capture_filter": "",
        "created_by": "clearblueyellow",
        "created_date": "2025-05-24",
        "version": "2.0"
    }
    
    def __init__(self, config_file: str = "simpleshark_config.json"):
        self.config_file = Path(config_file)
        self.settings = self.load_settings()
    
    def load_settings(self) -> Dict[str, Any]:
        """Load settings from file or create defaults"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                # Merge with defaults to ensure all keys exist
                settings = self.DEFAULT_SETTINGS.copy()
                settings.update(loaded)
                settings["last_modified"] = "2025-05-24 22:55:09"
                return settings
            else:
                settings = self.DEFAULT_SETTINGS.copy()
                settings["created_date"] = "2025-05-24 22:55:09"
                return settings
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load config: {e}")
            return self.DEFAULT_SETTINGS.copy()
    
    def save_settings(self) -> bool:
        """Save settings to file"""
        try:
            self.settings["last_modified"] = "2025-05-24 22:55:09"
            self.settings["modified_by"] = "clearblueyellow"
            
            with open(self.config_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except IOError as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    def validate_interface(self, interface: str) -> bool:
        """Validate network interface exists"""
        if not interface:
            return False
        try:
            available_interfaces = [iface for iface in psutil.net_if_addrs().keys()]
            return interface in available_interfaces
        except Exception as e:
            logger.error(f"Failed to validate interface: {e}")
            return False
    
    def validate_api_key(self, key: str) -> bool:
        """Validate API key format"""
        return bool(key and len(key) >= 32 and key.replace('-', '').isalnum())
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        try:
            interfaces = list(psutil.net_if_addrs().keys())
            # Filter out loopback and virtual interfaces for better UX
            filtered = [iface for iface in interfaces 
                       if not iface.startswith(('lo', 'Loopback', 'vEthernet'))]
            return filtered if filtered else interfaces
        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
            return []

# Data Management
class PacketBuffer:
    """Thread-safe packet buffer with size limits"""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.packets = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.total_packets_seen = 0
    
    def add_packet(self, packet: Dict[str, Any]) -> None:
        """Add packet to buffer"""
        with self.lock:
            self.packets.append(packet)
            self.total_packets_seen += 1
            logger.debug(f"Added packet to buffer. Total: {self.total_packets_seen}, Buffer size: {len(self.packets)}")
    
    def get_packets(self) -> List[Dict[str, Any]]:
        """Get all packets from buffer"""
        with self.lock:
            return list(self.packets)
    
    def clear(self) -> None:
        """Clear all packets"""
        with self.lock:
            self.packets.clear()
            self.total_packets_seen = 0
    
    def size(self) -> int:
        """Get current buffer size"""
        with self.lock:
            return len(self.packets)
    
    def get_total_seen(self) -> int:
        """Get total packets seen (including those rolled out of buffer)"""
        with self.lock:
            return self.total_packets_seen

class AlertManager:
    """Manages security alerts with deduplication and caching"""
    
    def __init__(self, max_alerts: int = 5000):
        self.max_alerts = max_alerts
        self.alerts = deque(maxlen=max_alerts)
        self.alert_cache = {}
        self.lock = threading.Lock()
        self.cache_ttl = 300  # 5 minutes
    
    def add_alert(self, timestamp: str, protocol: str, src_ip: str, 
                  dst_ip: str, threat_type: str, info: str) -> bool:
        """Add alert with deduplication"""
        alert_hash = self._hash_alert(src_ip, dst_ip, threat_type)
        
        with self.lock:
            # Check if we've seen this exact alert recently (last 60 seconds)
            current_time = datetime.now()
            for existing_alert in reversed(list(self.alerts)):
                if len(existing_alert) >= 6:
                    try:
                        alert_time = datetime.strptime(existing_alert[0], "%Y-%m-%d %H:%M:%S")
                        if (current_time - alert_time).seconds < 60:
                            existing_hash = self._hash_alert(existing_alert[2], existing_alert[3], existing_alert[4])
                            if existing_hash == alert_hash:
                                return False  # Duplicate within time window
                    except ValueError:
                        continue
            
            alert = [timestamp, protocol, src_ip, dst_ip, threat_type, info]
            self.alerts.append(alert)
            return True
    
    def _hash_alert(self, src_ip: str, dst_ip: str, threat_type: str) -> str:
        """Create hash for alert deduplication"""
        content = f"{src_ip}:{dst_ip}:{threat_type}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get_alerts(self) -> List[List[str]]:
        """Get all alerts"""
        with self.lock:
            return list(self.alerts)
    
    def clear(self) -> None:
        """Clear all alerts"""
        with self.lock:
            self.alerts.clear()
            self.alert_cache.clear()

# Input Validation
class Validator:
    """Input validation utilities"""
    
    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        """Validate IP address format"""
        try:
            ip_address(ip_str)
            return True
        except (AddressValueError, ValueError):
            return False
    
    @staticmethod
    def validate_port(port_str: str) -> bool:
        """Validate port number"""
        try:
            port = int(port_str)
            return 1 <= port <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not isinstance(input_str, str):
            return str(input_str)[:max_length]
        return input_str.replace('\0', '').replace('\r', '').replace('\n', ' ')[:max_length]
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is private/local"""
        try:
            ip = ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except (AddressValueError, ValueError):
            return True  # Assume private if invalid

# Network Information Extraction
class NetworkExtractor:
    """Enhanced network information extraction"""
    
    @staticmethod
    def extract_network_info(packet) -> Tuple[str, str, str, str]:
        """Improved network information extraction"""
        src_ip = dst_ip = "N/A"
        src_port = dst_port = "N/A"
        
        try:
            # Extract IP addresses
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            elif hasattr(packet, 'arp'):
                src_ip = getattr(packet.arp, 'src_proto_ipv4', "N/A")
                dst_ip = getattr(packet.arp, 'dst_proto_ipv4', "N/A")
            
            # More robust port extraction
            if 'TCP' in packet:
                src_port = getattr(packet.tcp, 'srcport', "N/A")
                dst_port = getattr(packet.tcp, 'dstport', "N/A")
            elif 'UDP' in packet:
                src_port = getattr(packet.udp, 'srcport', "N/A")
                dst_port = getattr(packet.udp, 'dstport', "N/A")
            elif 'ICMP' in packet:
                icmp_type = getattr(packet.icmp, 'type', 'N/A')
                icmp_code = getattr(packet.icmp, 'code', 'N/A')
                src_port = f"type:{icmp_type}"
                dst_port = f"code:{icmp_code}"
            elif 'ICMPv6' in packet:
                icmp_type = getattr(packet.icmpv6, 'type', 'N/A')
                icmp_code = getattr(packet.icmpv6, 'code', 'N/A')
                src_port = f"type:{icmp_type}"
                dst_port = f"code:{icmp_code}"
        
        except Exception as e:
            logger.debug(f"Error extracting network info: {e}")
        
        return src_ip, dst_ip, src_port, dst_port
    
    @staticmethod
    def format_binary_data(value, max_length: int = 32) -> str:
        """Format binary data as hex dump"""
        if isinstance(value, (bytes, bytearray)):
            if len(value) == 0:
                return "0x(empty)"
            hex_data = value[:max_length].hex().upper()
            formatted_hex = ' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
            return f"0x{formatted_hex}" + ("..." if len(value) > max_length else "")
        return str(value)

# Geolocation Handler
def get_geolocation(ip: str, geoip_reader) -> Tuple[str, str, str]:
    """Get geolocation information for IP address"""
    try:
        if not Validator.validate_ip(ip) or Validator.is_private_ip(ip):
            return ("Local/Private", "Local", "")
        
        response = geoip_reader.city(ip)
        city = response.city.name or ""
        country = response.country.name or ""
        country_code = response.country.iso_code or ""
        
        location = f"{city}, {country}" if city else country
        return (location or "Unknown", country or "Unknown", country_code)
        
    except Exception as e:
        logger.debug(f"Geolocation lookup failed for {ip}: {e}")
        return ("Unknown", "Unknown", "")

# Threat Intelligence
class ThreatIntelligence:
    """Manages threat intelligence feeds and lookups"""
    
    def __init__(self, config: Config):
        self.config = config
        self.spamhaus_drop_ips = set()
        self.openphish_domains = set()
        self.phishtank_domains = set()
        self.last_refresh = None
        self.session = None
        self.feed_status = {}
        
        # Threat feed URLs
        self.feeds = {
            'spamhaus': 'https://www.spamhaus.org/drop/drop.txt',
            'phishtank': 'https://data.phishtank.com/data/online-valid.json',
            'openphish': 'https://openphish.com/feed.txt'
        }
    
    def refresh_feeds(self):
        """Refresh all threat feeds"""
        refresh_start = datetime.now()
        logger.info("Starting threat feed refresh...")
        
        try:
            if self.config.settings.get('enable_threat_feeds', True):
                # Load real threat feeds
                self.spamhaus_drop_ips = self.load_spamhaus_drop_ips()
                self.openphish_domains = self.load_openphish_feeds()
                self.phishtank_domains = self.load_phishtank_domains()
                
                self.last_refresh = refresh_start
                logger.info("Threat feeds refreshed successfully")
                
        except Exception as e:
            logger.error(f"Failed to refresh threat feeds: {e}")
            raise ThreatFeedError(f"Feed refresh error: {e}")
    
    def load_spamhaus_drop_ips(self) -> set:
        """Load Spamhaus DROP list"""
        drop_ips = set()
        try:
            logger.info("Loading Spamhaus DROP list...")
            response = requests.get(
                self.feeds['spamhaus'], 
                timeout=self.config.settings['api_timeout']
            )
            response.raise_for_status()
            
            for line in response.text.splitlines():
                if not line or line.startswith(';'):
                    continue
                ip_range = line.split(';')[0].strip()
                if ip_range and '/' in ip_range:  # CIDR notation
                    drop_ips.add(ip_range)
            
            self.feed_status['spamhaus'] = f"OK ({len(drop_ips)} entries)"
            logger.info(f"Loaded {len(drop_ips)} Spamhaus DROP entries")
            
        except Exception as e:
            self.feed_status['spamhaus'] = f"Error: {str(e)[:50]}"
            logger.error(f"Failed to load Spamhaus DROP: {e}")
        
        return drop_ips
    
    def load_openphish_feeds(self) -> set:
        """Load OpenPhish feed"""
        domains = set()
        try:
            logger.info("Loading OpenPhish feed...")
            response = requests.get(
                self.feeds['openphish'], 
                timeout=self.config.settings['api_timeout']
            )
            response.raise_for_status()
            
            for line in response.text.splitlines():
                line = line.strip().lower()
                if line and line.startswith('http'):
                    try:
                        # Extract domain from URL
                        domain_part = line.split('/')[2]
                        # Remove port if present
                        domain = domain_part.split(':')[0]
                        if domain:
                            domains.add(domain)
                    except (IndexError, ValueError):
                        continue
            
            self.feed_status['openphish'] = f"OK ({len(domains)} domains)"
            logger.info(f"Loaded {len(domains)} OpenPhish domains")
            
        except Exception as e:
            self.feed_status['openphish'] = f"Error: {str(e)[:50]}"
            logger.error(f"Failed to load OpenPhish feed: {e}")
        
        return domains
    
    def load_phishtank_domains(self) -> set:
        """Load PhishTank domains"""
        domains = set()
        try:
            logger.info("Loading PhishTank feed...")
            response = requests.get(
                self.feeds['phishtank'], 
                timeout=self.config.settings['api_timeout']
            )
            response.raise_for_status()
            
            data = response.json()
            for entry in data:
                if "url" in entry and entry.get("verified") == "yes":
                    try:
                        domain_part = entry["url"].split('/')[2].lower()
                        domain = domain_part.split(':')[0]  # Remove port
                        if domain:
                            domains.add(domain)
                    except (IndexError, KeyError, ValueError):
                        continue
            
            self.feed_status['phishtank'] = f"OK ({len(domains)} domains)"
            logger.info(f"Loaded {len(domains)} PhishTank domains")
            
        except Exception as e:
            self.feed_status['phishtank'] = f"Error: {str(e)[:50]}"
            logger.error(f"Failed to load PhishTank feed: {e}")
        
        return domains
    
    def check_ip_in_drop_list(self, ip: str) -> bool:
        """Check if IP is in any DROP list"""
        if not Validator.validate_ip(ip):
            return False
        
        try:
            check_ip = ip_address(ip)
            for cidr_range in self.spamhaus_drop_ips:
                try:
                    if ip in cidr_range:
                        return True
                except (ValueError, IndexError):
                    continue
            return False
        except ValueError:
            return False
    
    def get_feed_status_summary(self) -> str:
        """Get summary of feed status"""
        if not self.feed_status:
            return "Not loaded"
        
        status_parts = []
        for feed, status in self.feed_status.items():
            if status.startswith("OK"):
                status_parts.append(f"{feed}: ✓")
            else:
                status_parts.append(f"{feed}: ✗")
        
        return " | ".join(status_parts)

class FeedAutoRefresher(threading.Thread):
    """Automatic threat feed refresher with improved threading"""
    
    def __init__(self, threat_intel: ThreatIntelligence, refresh_interval: int = 3600):
        super().__init__(daemon=True)
        self.threat_intel = threat_intel
        self.refresh_interval = refresh_interval
        self.stop_event = threading.Event()
        self.name = "ThreatFeedRefresher"
    
    def run(self):
        """Main refresh loop with better event handling"""
        logger.info(f"Threat feed auto-refresher started (interval: {self.refresh_interval}s)")
        
        # Initial refresh
        try:
            self.threat_intel.refresh_feeds()
        except Exception as e:
            logger.error(f"Initial feed refresh failed: {e}")
        
        while not self.stop_event.is_set():
            try:
                if self.stop_event.wait(self.refresh_interval):
                    break  # Interrupted by stop signal
                
                self.threat_intel.refresh_feeds()
                    
            except Exception as e:
                logger.error(f"Error in feed refresher: {e}")
                if self.stop_event.wait(60):
                    break
        
        logger.info("Threat feed auto-refresher stopped")
    
    def stop(self):
        """Stop the refresher gracefully"""
        logger.info("Stopping threat feed refresher...")
        self.stop_event.set()

# Main Application
class SimpleSharkGUI:
    """Main application class with FIXED packet display"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SimpleShark - Advanced Network Traffic Analyzer v2.0")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize configuration
        self.config = Config()
        
        # Initialize threat intelligence
        self.threat_intel = ThreatIntelligence(self.config)
        
        # Initialize data structures
        self.packet_buffer = PacketBuffer(self.config.settings['max_packets'])
        self.alert_manager = AlertManager(self.config.settings['max_alerts'])
        
        # GUI state
        self.running = False
        self.packet_queue = queue.Queue()
        self.packet_counter = 1
        
        # Enhanced statistics
        self.protocol_stats = defaultdict(int)
        self.protocol_bytes = defaultdict(int)
        self.protocol_minute_counts = defaultdict(lambda: defaultdict(int))
        self.protocol_hour_counts = defaultdict(lambda: defaultdict(int))
        self.top_talkers_src = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.top_talkers_dst = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.sessions = defaultdict(lambda: {
            "packets": 0, "bytes": 0, "protocol": "", 
            "src": "", "dst": "", "first_seen": "", "last_seen": ""
        })
        
        # Caches and state
        self.ip_geocache = {}
        self.packet_details_cache = {}
        self.geoip_reader = None
        self.geoip_status = "Not loaded"
        
        # Filtering - Initialize as empty set so NO protocols are excluded by default
        self.protocol_exclude = set()
        
        # Logs with better structure
        self.app_logs = deque(maxlen=1000)
        self.error_logs = deque(maxlen=1000)
        
        # Threading
        self.capture_thread = None
        self.monitor_thread = None
        self.feed_refresher = None
        
        # Performance tracking
        self.last_gui_update = time.time()
        self.packets_per_second = 0
        self.last_packet_count = 0
        self.capture_start_time = None
        self.display_paused = False
        self.last_update_time = time.time()
        
        # GUI control variables
        self.chart_timeframe_var = tk.StringVar(value="minute")
        self.log_filter_var = tk.StringVar(value="All")
        self.log_search_var = tk.StringVar()
        self.burst_threshold_var = tk.StringVar(value=str(self.config.settings['burst_threshold']))
        self.capture_filter_var = tk.StringVar(value=self.config.settings.get('capture_filter', ''))
        self.promiscuous_var = tk.BooleanVar(value=self.config.settings.get('promiscuous_mode', False))
        self.enable_geo_var = tk.BooleanVar(value=self.config.settings.get('enable_geolocation', True))
        self.enable_threats_var = tk.BooleanVar(value=self.config.settings.get('enable_threat_feeds', True))
        self.enable_hex_var = tk.BooleanVar(value=self.config.settings.get('enable_hex_dumps', True))
        self.gui_interval_var = tk.StringVar(value=str(self.config.settings['gui_update_interval']))
        self.batch_size_var = tk.StringVar(value=str(self.config.settings['batch_size']))
        
        # Interface variables
        self.interface_var = tk.StringVar(value=self.config.settings["interface"])
        self.geolite_var = tk.StringVar(value=self.config.settings["geolite_path"])
        self.abuseipdb_var = tk.StringVar(value=self.config.settings["abuseipdb_key"])
        self.max_packets_var = tk.StringVar(value=str(self.config.settings["max_packets"]))
        
        # Setup GUI
        self.setup_colors()
        self.setup_gui()
        self.setup_styles()
        
        # Initialize components
        self.initialize_threat_feeds()
        self.initialize_geoip()
        
        # Start scheduled updates
        self.start_scheduled_updates()
        
        # Try to maximize window
        self.maximize_window()
        
        # Log startup
        self.log_app("SimpleShark v2.0 initialized successfully")
        self.log_app(f"Configuration loaded from: {self.config.config_file}")
        self.log_app(f"Max packet buffer size: {self.config.settings['max_packets']}")
        self.log_app(f"Created by: {self.config.settings['created_by']} on {self.config.settings['created_date']}")
        
        # DEBUG: Log initial protocol exclude state
        logger.debug(f"Initial protocol_exclude set: {self.protocol_exclude}")
    
    def setup_colors(self):
        """Setup enhanced color scheme"""
        self.primary_bg = "#222c34"
        self.secondary_bg = "#293544"
        self.accent_color = "#39a9db"
        self.text_fg = "#eaeaea"
        self.highlight_fg = "#ffd700"
        self.button_pressed_bg = "#29455e"
        self.error_color = "#ff6b6b"
        self.success_color = "#51cf66"
        self.warning_color = "#ffd43b"
        self.info_color = "#74c0fc"
    
    def setup_styles(self):
        """Setup enhanced ttk styles"""
        style = ttk.Style(self.root)
        style.theme_use('clam')
        
        # Enhanced style configurations
        style.configure('TFrame', background=self.primary_bg)
        style.configure('TNotebook', background=self.primary_bg, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=self.secondary_bg, 
                       foreground=self.text_fg, 
                       font=('Segoe UI', 10, 'bold'), 
                       padding=[12, 8])
        style.map('TNotebook.Tab', 
                 background=[('selected', self.accent_color)], 
                 foreground=[('selected', self.primary_bg)])
        
        # Enhanced treeview styling with IMPROVED VISIBILITY
        style.configure('Treeview', 
                       background=self.secondary_bg, 
                       foreground=self.text_fg, 
                       fieldbackground=self.secondary_bg, 
                       font=('Consolas', 9))
        style.configure('Treeview.Heading', 
                       background=self.accent_color, 
                       foreground=self.primary_bg, 
                       font=('Segoe UI', 9, 'bold'))
        style.map('Treeview', 
                 background=[('selected', self.highlight_fg)], 
                 foreground=[('selected', self.primary_bg)])
        
        # Enhanced button styling
        style.configure('TButton', 
                       background=self.accent_color, 
                       foreground=self.primary_bg, 
                       font=('Segoe UI', 9, 'bold'), 
                       borderwidth=1,
                       relief='flat')
        style.map('TButton',
                 background=[('active', self.highlight_fg), ('pressed', self.button_pressed_bg)],
                 foreground=[('active', self.primary_bg), ('pressed', self.text_fg)])
        
        # Other styles
        style.configure('TLabel', background=self.primary_bg, foreground=self.text_fg, font=('Segoe UI', 9))
        style.configure('TLabelframe', 
                       background=self.primary_bg, 
                       foreground=self.accent_color, 
                       font=('Segoe UI', 10, 'bold'))
        style.configure('TEntry', 
                       fieldbackground=self.secondary_bg, 
                       foreground=self.text_fg, 
                       background=self.secondary_bg,
                       font=('Segoe UI', 9))
        style.configure('TCombobox',
                       fieldbackground=self.secondary_bg,
                       background=self.secondary_bg,
                       foreground=self.text_fg,
                       font=('Segoe UI', 9))
    
    def setup_gui(self):
        """Setup main GUI components"""
        # Create notebook with enhanced tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Setup all tabs
        self.setup_traffic_tab()
        self.setup_packet_details_tab()
        self.setup_threat_intel_tab()
        self.setup_network_stats_tab()
        self.setup_protocol_insights_tab()
        self.setup_logs_tab()
        self.setup_settings_tab()
    
    def setup_traffic_tab(self):
        """Setup enhanced traffic monitoring tab"""
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="🌐 Traffic Monitor")
        
        # Enhanced control frame
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill=tk.X, padx=8, pady=5)
        
        # Control buttons
        self.start_button = ttk.Button(control_frame, text="▶ Start Capture", 
                                      command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="⏹ Stop Capture", 
                                     command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.pause_button = ttk.Button(control_frame, text="⏸ Pause Display", 
                                      command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(control_frame, text="🗑 Clear Data", 
                                      command=self.clear_data)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        self.protocols_button = ttk.Button(control_frame, text="🔍 Filter Protocols", 
                                          command=self.show_protocol_selector)
        self.protocols_button.pack(side=tk.LEFT, padx=5)
        
        # New Refresh Display button
        self.refresh_display_button = ttk.Button(control_frame, text="🔄 Refresh Display", 
                                               command=self.refresh_display)
        self.refresh_display_button.pack(side=tk.LEFT, padx=5)
        
        # DEBUG: Add debug button
        self.debug_button = ttk.Button(control_frame, text="🐛 Debug Info", 
                                      command=self.show_debug_info)
        self.debug_button.pack(side=tk.LEFT, padx=5)
        
        # Force refresh button - ADDED for troubleshooting
        self.force_refresh_button = ttk.Button(control_frame, text="🔄 Force Refresh", 
                                             command=self.force_refresh_display)
        self.force_refresh_button.pack(side=tk.LEFT, padx=5)
        
        # Enhanced status frame with multiple indicators
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=tk.X, padx=8, pady=2)
        
        # Main status
        self.status_label = ttk.Label(status_frame, text="Ready", font=('Segoe UI', 9, 'bold'))
        self.status_label.pack(side=tk.LEFT)
        
        # Separator
        ttk.Separator(status_frame, orient='vertical').pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # GeoIP status
        self.geoip_status_label = ttk.Label(status_frame, text="GeoIP: Not loaded")
        self.geoip_status_label.pack(side=tk.LEFT, padx=5)
        
        # Threat feeds status
        self.feeds_status_label = ttk.Label(status_frame, text="Feeds: Loading...")
        self.feeds_status_label.pack(side=tk.LEFT, padx=5)
        
        # Performance indicators
        self.packet_count_label = ttk.Label(status_frame, text="Packets: 0")
        self.packet_count_label.pack(side=tk.RIGHT, padx=5)
        
        self.packets_per_sec_label = ttk.Label(status_frame, text="Rate: 0 pps")
        self.packets_per_sec_label.pack(side=tk.RIGHT, padx=5)
        
        # Enhanced packet tree with more columns
        columns = ("packet_num", "timestamp", "protocol", "src_ip", "src_port", 
                  "dst_ip", "dst_port", "bytes", "geo", "flags", "info")
        
        tree_frame = ttk.Frame(self.main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.packet_tree = ttk.Treeview(tree_frame, columns=columns, 
                                       show="headings", height=22)
        
        # Enhanced column configuration
        column_config = {
            "packet_num": ("Packet", 70, "center"),
            "timestamp": ("Timestamp", 140, "center"),
            "protocol": ("Protocol", 90, "center"),
            "src_ip": ("Source IP", 130, "center"),
            "src_port": ("Src Port", 70, "center"),
            "dst_ip": ("Dest IP", 130, "center"),
            "dst_port": ("Dst Port", 70, "center"),
            "bytes": ("Bytes", 70, "center"),
            "geo": ("Location", 160, "w"),
            "flags": ("Threats", 100, "center"),
            "info": ("Info", 200, "w")
        }
        
        for col, (heading, width, anchor) in column_config.items():
            self.packet_tree.heading(col, text=heading)
            self.packet_tree.column(col, width=width, anchor=anchor)
        
        # Create container for tree and scrollbars
        tree_container = ttk.Frame(tree_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)
        
        # Tree widget
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, in_=tree_container)
        
        # Vertical scrollbar
        y_scroll = ttk.Scrollbar(tree_container, orient="vertical", 
                                command=self.packet_tree.yview)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.packet_tree.configure(yscrollcommand=y_scroll.set)
        
        # Horizontal scrollbar in separate frame
        h_scroll_frame = ttk.Frame(tree_frame)
        h_scroll_frame.pack(fill=tk.X)
        
        x_scroll = ttk.Scrollbar(h_scroll_frame, orient="horizontal", 
                                command=self.packet_tree.xview)
        x_scroll.pack(fill=tk.X)
        
        self.packet_tree.configure(xscrollcommand=x_scroll.set)
        
        # Enhanced event bindings
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        self.packet_tree.bind("<Double-1>", self.on_packet_double_click)
        self.packet_tree.bind("<Button-3>", self.on_packet_right_click)
        
        # Enhanced performance metrics
        perf_frame = ttk.LabelFrame(self.main_frame, text="System Performance")
        perf_frame.pack(fill=tk.X, padx=8, pady=5)
        
        perf_inner = ttk.Frame(perf_frame)
        perf_inner.pack(fill=tk.X, padx=5, pady=3)
        
        self.cpu_label = ttk.Label(perf_inner, text="CPU: 0%")
        self.cpu_label.pack(side=tk.LEFT, padx=10)
        
        self.memory_label = ttk.Label(perf_inner, text="Memory: 0%")
        self.memory_label.pack(side=tk.LEFT, padx=10)
        
        self.network_label = ttk.Label(perf_inner, text="Network: 0B↑ / 0B↓")
        self.network_label.pack(side=tk.LEFT, padx=10)
        
        self.buffer_usage_label = ttk.Label(perf_inner, text="Buffer: 0%")
        self.buffer_usage_label.pack(side=tk.RIGHT, padx=10)
    
    def setup_packet_details_tab(self):
        """Setup enhanced packet details tab"""
        self.details_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.details_frame, text="📋 Packet Details")
        
        # Info frame
        info_frame = ttk.Frame(self.details_frame)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.selected_packet_label = ttk.Label(info_frame, 
                                              text="Select a packet from the Traffic Monitor to view details",
                                              font=('Segoe UI', 10, 'italic'))
        self.selected_packet_label.pack()
        
        # Main container using pack
        main_container = ttk.Frame(self.details_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top row
        top_row = ttk.Frame(main_container)
        top_row.pack(fill=tk.BOTH, expand=True)
        
        # Bottom row  
        bottom_row = ttk.Frame(main_container)
        bottom_row.pack(fill=tk.BOTH, expand=True)
        
        # Create quadrants
        eth_frame = ttk.LabelFrame(top_row, text="🔗 Ethernet/Data Link")
        eth_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        net_frame = ttk.LabelFrame(top_row, text="🌐 Network/Internet")
        net_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        trans_frame = ttk.LabelFrame(bottom_row, text="🚛 Transport")
        trans_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        app_frame = ttk.LabelFrame(bottom_row, text="📱 Application")
        app_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Create text widgets
        self.detail_widgets = {}
        for key, frame in [("ethernet", eth_frame), ("network", net_frame), 
                           ("transport", trans_frame), ("application", app_frame)]:
            text_widget = tk.Text(frame, width=50, height=12, 
                                 background=self.secondary_bg, 
                                 foreground=self.text_fg, 
                                 font=('Consolas', 9),
                                 state="disabled")
            text_widget.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
            self.detail_widgets[key] = text_widget
    
    def setup_threat_intel_tab(self):
        """Setup enhanced threat intelligence tab"""
        self.threat_intel_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.threat_intel_frame, text="🛡️ Threat Intelligence")
        
        # Enhanced dashboard frame
        dash_frame = ttk.LabelFrame(self.threat_intel_frame, text="Threat Dashboard")
        dash_frame.pack(fill=tk.X, padx=5, pady=5)
        
        dash_inner = ttk.Frame(dash_frame)
        dash_inner.pack(fill=tk.X, padx=5, pady=3)
        
        # Enhanced alert metrics
        self.alerts_count_label = ttk.Label(dash_inner, text="Total Alerts: 0", 
                                           foreground=self.error_color, 
                                           font=("Segoe UI", 12, "bold"))
        self.alerts_count_label.pack(side=tk.LEFT, padx=10)
        
        self.high_risk_label = ttk.Label(dash_inner, text="High Risk: 0", 
                                        foreground=self.error_color, 
                                        font=("Segoe UI", 10))
        self.high_risk_label.pack(side=tk.LEFT, padx=10)
        
        self.feed_status_label = ttk.Label(dash_inner, text="Feeds: Loading...", 
                                          font=("Segoe UI", 10))
        self.feed_status_label.pack(side=tk.LEFT, padx=10)
        
        # Control buttons
        controls_frame = ttk.Frame(dash_inner)
        controls_frame.pack(side=tk.RIGHT)
        
        refresh_button = ttk.Button(controls_frame, text="🔄 Refresh Feeds", 
                                   command=self.manual_refresh_feeds)
        refresh_button.pack(side=tk.RIGHT, padx=5)
        
        clear_alerts_button = ttk.Button(controls_frame, text="🗑 Clear Alerts", 
                                        command=self.clear_alerts)
        clear_alerts_button.pack(side=tk.RIGHT, padx=5)
        
        # Enhanced alerts tree
        alert_columns = ("timestamp", "protocol", "src_ip", "dst_ip", "threat_type", "severity", "info")
        
        alerts_frame = ttk.Frame(self.threat_intel_frame)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=alert_columns, 
                                       show="headings", height=20)
        
        alert_column_config = {
            "timestamp": ("Time", 120),
            "protocol": ("Protocol", 80),
            "src_ip": ("Source IP", 130),
            "dst_ip": ("Dest IP", 130),
            "threat_type": ("Threat Type", 140),
            "severity": ("Severity", 80),
            "info": ("Description", 300)
        }
        
        for col, (heading, width) in alert_column_config.items():
            self.alerts_tree.heading(col, text=heading)
            self.alerts_tree.column(col, width=width, anchor="center" if col != "info" else "w")
        
        # Enhanced scrollbars
        alerts_y_scroll = ttk.Scrollbar(alerts_frame, orient="vertical", 
                                       command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_y_scroll.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_network_stats_tab(self):
        """Setup enhanced network statistics tab"""
        self.netstats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.netstats_frame, text="📊 Network Statistics")
        
        # Simple implementation for now
        stats_label = ttk.Label(self.netstats_frame, 
                               text="Network Statistics\n\nThis tab will show detailed traffic analysis including:\n\n• Top Talkers\n• Protocol Distribution\n• Traffic Volume Charts\n• Session Statistics",
                               font=('Segoe UI', 11),
                               justify=tk.CENTER)
        stats_label.pack(expand=True, pady=50)
    
    def setup_protocol_insights_tab(self):
        """Setup enhanced protocol insights tab"""
        self.proto_insights_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.proto_insights_frame, text="🔍 Protocol Insights")
        
        # Simple implementation for now
        insights_label = ttk.Label(self.proto_insights_frame, 
                                  text="Protocol Insights\n\nThis tab will provide advanced protocol analysis including:\n\n• Protocol Breakdown & Distribution\n• Burst Detection\n• Rare Protocol Detection\n• Security Analysis",
                                  font=('Segoe UI', 11),
                                  justify=tk.CENTER)
        insights_label.pack(expand=True, pady=50)
    
    def setup_logs_tab(self):
        """Setup enhanced application logs tab"""
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="📝 Application Logs")
        
        # Enhanced control frame
        log_control_frame = ttk.LabelFrame(self.logs_frame, text="Log Controls")
        log_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        controls_inner = ttk.Frame(log_control_frame)
        controls_inner.pack(fill=tk.X, padx=5, pady=3)
        
        # Log level filter
        ttk.Label(controls_inner, text="Filter:").pack(side=tk.LEFT, padx=5)
        log_filter_combo = ttk.Combobox(controls_inner, textvariable=self.log_filter_var,
                                       values=["All", "App", "Error", "Warning"], width=10)
        log_filter_combo.pack(side=tk.LEFT, padx=5)
        log_filter_combo.bind("<<ComboboxSelected>>", self.filter_logs)
        
        # Control buttons
        clear_logs_button = ttk.Button(controls_inner, text="🗑 Clear Logs", 
                                      command=self.clear_logs)
        clear_logs_button.pack(side=tk.LEFT, padx=10)
        
        export_logs_button = ttk.Button(controls_inner, text="💾 Export Logs", 
                                       command=self.export_logs)
        export_logs_button.pack(side=tk.LEFT, padx=5)
        
        refresh_logs_button = ttk.Button(controls_inner, text="🔄 Refresh", 
                                        command=self.update_logs_display)
        refresh_logs_button.pack(side=tk.RIGHT, padx=5)
        
        # Log statistics
        self.log_stats_label = ttk.Label(controls_inner, text="Logs: 0 app, 0 errors")
        self.log_stats_label.pack(side=tk.RIGHT, padx=10)
        
        # Enhanced log display with search
        search_frame = ttk.Frame(self.logs_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        search_entry = ttk.Entry(search_frame, textvariable=self.log_search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind("<KeyRelease>", self.search_logs)
        
        ttk.Button(search_frame, text="Clear", 
                  command=lambda: self.log_search_var.set("")).pack(side=tk.LEFT, padx=5)
        
        # Enhanced log text widget
        log_frame = ttk.Frame(self.logs_frame)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.logs_text = tk.Text(log_frame, wrap=tk.WORD, height=24, 
                                state="disabled", background=self.secondary_bg, 
                                foreground=self.text_fg, font=('Consolas', 9))
        
        # Configure text tags for different log levels
        self.logs_text.tag_configure("app", foreground=self.info_color)
        self.logs_text.tag_configure("error", foreground=self.error_color)
        self.logs_text.tag_configure("warning", foreground=self.warning_color)
        self.logs_text.tag_configure("success", foreground=self.success_color)
        
        logs_y_scroll = ttk.Scrollbar(log_frame, orient="vertical", 
                                     command=self.logs_text.yview)
        
        self.logs_text.configure(yscrollcommand=logs_y_scroll.set)
        
        self.logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        logs_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_settings_tab(self):
        """Setup enhanced settings and configuration tab"""
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="⚙️ Settings")
        
        # Create notebook for settings categories
        settings_notebook = ttk.Notebook(self.settings_frame)
        settings_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Network Settings
        network_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(network_frame, text="Network")
        
        network_main = ttk.LabelFrame(network_frame, text="Network Configuration")
        network_main.pack(fill=tk.X, padx=10, pady=10)
        
        # Network interface with refresh button
        interface_frame = ttk.Frame(network_main)
        interface_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Label(interface_frame, text="Network Interface:").pack(side=tk.LEFT)
        
        self.interface_combo = ttk.Combobox(interface_frame, 
                                           textvariable=self.interface_var,
                                           values=self.config.get_available_interfaces(),
                                           width=25)
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(interface_frame, text="🔄 Refresh", 
                  command=self.refresh_interfaces).pack(side=tk.LEFT, padx=5)
        
        # Interface status
        self.interface_status_label = ttk.Label(network_main, text="", foreground=self.info_color)
        self.interface_status_label.pack(pady=3)
        
        # Capture filter
        filter_frame = ttk.Frame(network_main)
        filter_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Label(filter_frame, text="Capture Filter (BPF):").pack(side=tk.LEFT)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.capture_filter_var, width=40)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        # Promiscuous mode
        ttk.Checkbutton(network_main, text="Enable Promiscuous Mode", 
                       variable=self.promiscuous_var).pack(anchor='w', padx=5, pady=3)
        
        # Security Settings
        security_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(security_frame, text="Security")
        
        # GeoIP settings
        geoip_settings = ttk.LabelFrame(security_frame, text="Geolocation Settings")
        geoip_settings.pack(fill=tk.X, padx=10, pady=10)
        
        # Enable geolocation
        ttk.Checkbutton(geoip_settings, text="Enable Geolocation Lookup", 
                       variable=self.enable_geo_var).pack(anchor='w', padx=5, pady=3)
        
        # GeoLite2 database path
        geolite_frame = ttk.Frame(geoip_settings)
        geolite_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Label(geolite_frame, text="GeoLite2 DB Path:").pack(side=tk.LEFT)
        
        self.geolite_entry = ttk.Entry(geolite_frame, textvariable=self.geolite_var, width=40)
        self.geolite_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(geolite_frame, text="📁 Browse", 
                  command=self.browse_geolite_db).pack(side=tk.LEFT, padx=5)
        
        # Threat intelligence settings
        threat_settings = ttk.LabelFrame(security_frame, text="Threat Intelligence")
        threat_settings.pack(fill=tk.X, padx=10, pady=10)
        
        # Enable threat feeds
        ttk.Checkbutton(threat_settings, text="Enable Threat Intelligence Feeds", 
                       variable=self.enable_threats_var).pack(anchor='w', padx=5, pady=3)
        
        # AbuseIPDB API key
        api_frame = ttk.Frame(threat_settings)
        api_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Label(api_frame, text="AbuseIPDB API Key:").pack(side=tk.LEFT)
        
        self.abuseipdb_entry = ttk.Entry(api_frame, textvariable=self.abuseipdb_var, 
                                        width=35, show="*")
        self.abuseipdb_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(api_frame, text="👁️", 
                  command=self.toggle_api_key_visibility).pack(side=tk.LEFT, padx=2)
        
        # Performance Settings
        performance_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(performance_frame, text="Performance")
        
        perf_settings = ttk.LabelFrame(performance_frame, text="Performance Tuning")
        perf_settings.pack(fill=tk.X, padx=10, pady=10)
        
        # Max packets in buffer
        perf_frame1 = ttk.Frame(perf_settings)
        perf_frame1.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(perf_frame1, text="Max Packets in Buffer:").pack(side=tk.LEFT)
        max_packets_entry = ttk.Entry(perf_frame1, textvariable=self.max_packets_var, width=10)
        max_packets_entry.pack(side=tk.LEFT, padx=5)
        
        # GUI update interval
        perf_frame2 = ttk.Frame(perf_settings)
        perf_frame2.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(perf_frame2, text="GUI Update Interval (ms):").pack(side=tk.LEFT)
        gui_interval_entry = ttk.Entry(perf_frame2, textvariable=self.gui_interval_var, width=10)
        gui_interval_entry.pack(side=tk.LEFT, padx=5)
        
        # Batch size
        perf_frame3 = ttk.Frame(perf_settings)
        perf_frame3.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(perf_frame3, text="Processing Batch Size:").pack(side=tk.LEFT)
        batch_size_entry = ttk.Entry(perf_frame3, textvariable=self.batch_size_var, width=10)
        batch_size_entry.pack(side=tk.LEFT, padx=5)
        
        # Enable hex dumps
        ttk.Checkbutton(perf_settings, text="Enable Hex Dumps in Packet Details", 
                       variable=self.enable_hex_var).pack(anchor='w', padx=5, pady=3)
        
        # Data Management
        data_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(data_frame, text="Data")
        
        # Export/Import settings
        export_settings = ttk.LabelFrame(data_frame, text="Data Management")
        export_settings.pack(fill=tk.X, padx=10, pady=10)
        
        export_buttons_frame = ttk.Frame(export_settings)
        export_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(export_buttons_frame, text="📊 Export to Excel", 
                  command=self.export_to_excel).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(export_buttons_frame, text="📂 Import Traffic Log", 
                  command=self.import_traffic_log).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(export_buttons_frame, text="💾 Export Settings", 
                  command=self.export_settings).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(export_buttons_frame, text="📁 Import Settings", 
                  command=self.import_settings).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Status display
        self.import_status_label = ttk.Label(export_settings, text="", foreground=self.info_color)
        self.import_status_label.pack(pady=5)
        
        # Settings control buttons
        settings_controls = ttk.Frame(self.settings_frame)
        settings_controls.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(settings_controls, text="💾 Save Settings", 
                  command=self.save_settings).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(settings_controls, text="🔄 Reset to Defaults", 
                  command=self.reset_settings).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(settings_controls, text="✅ Apply & Test", 
                  command=self.test_settings).pack(side=tk.LEFT, padx=5)
        
        # Version info
        version_frame = ttk.LabelFrame(self.settings_frame, text="About SimpleShark v2.0")
        version_frame.pack(fill=tk.X, padx=10, pady=10)
        
        version_info = ttk.Frame(version_frame)
        version_info.pack(padx=5, pady=5)
        
        about_text = f"""SimpleShark v2.0 - Advanced Network Traffic Analyzer

Created by: {self.config.settings['created_by']}
Build Date: {self.config.settings['created_date']}
Last Modified: {self.config.settings.get('last_modified', 'Never')}

Features:
• Real-time packet capture and analysis
• Threat intelligence integration
• Geolocation mapping
• Protocol insights and statistics
• Enhanced security monitoring
• Professional dark-themed interface

For support or updates, contact the development team."""
        
        about_label = ttk.Label(version_info, text=about_text, 
                               font=('Segoe UI', 9), justify=tk.LEFT)
        about_label.pack()
    
    # Event Handlers
    def on_closing(self):
        """Handle application closing gracefully"""
        logger.info("SimpleShark application closing...")
        
        try:
            # Stop capture if running
            self.stop_capture()
            
            # Stop feed refresher
            if self.feed_refresher:
                self.feed_refresher.stop()
                self.feed_refresher.join(timeout=2)
            
            # Save settings
            self.config.save_settings()
            
            # Final log
            logger.info("SimpleShark shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        finally:
            self.root.destroy()
    
    def on_packet_select(self, event):
        """Handle packet selection in tree"""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        try:
            item = self.packet_tree.item(selection[0])
            values = item.get('values', [])
            
            if not values or not values[0]:
                return
            
            packet_num = int(values[0])
            self.display_packet_details(packet_num)
            
            # Update selected packet info if it exists
            if hasattr(self, 'selected_packet_label'):
                packet_info = f"Packet #{packet_num} - {values[1]} - {values[2]} - {values[3]}:{values[4]} → {values[5]}:{values[6]}"
                self.selected_packet_label.config(text=packet_info)
            
        except (ValueError, IndexError) as e:
            logger.error(f"Error selecting packet: {e}")
    
    def on_packet_double_click(self, event):
        """Handle packet double-click"""
        self.on_packet_select(event)
        if hasattr(self, 'details_frame'):
            self.notebook.select(self.details_frame)
    
    def on_packet_right_click(self, event):
        """Handle packet right-click for context menu"""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        # Create context menu
        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(label="📋 View Details", command=lambda: self.on_packet_double_click(event))
        context_menu.add_separator()
        context_menu.add_command(label="🔍 Filter by Protocol", command=self.filter_by_selected_protocol)
        context_menu.add_command(label="🌐 Filter by Source IP", command=self.filter_by_selected_src_ip)
        context_menu.add_command(label="🎯 Filter by Dest IP", command=self.filter_by_selected_dst_ip)
        context_menu.add_separator()
        context_menu.add_command(label="📊 Show Statistics", command=self.show_packet_statistics)
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def toggle_pause(self):
        """Toggle display pause"""
        self.display_paused = not self.display_paused
        if self.display_paused:
            self.pause_button.config(text="▶ Resume Display")
            self.update_status("Display paused", self.warning_color)
        else:
            self.pause_button.config(text="⏸ Pause Display")
            self.update_status("Display resumed", self.success_color)
    
    # Capture Control
    def start_capture(self):
        """Start real packet capture with enhanced validation - FIXED"""
        interface = self.interface_var.get().strip()
        
        if not interface:
            messagebox.showerror("Error", "Please select a network interface from the Settings tab")
            self.notebook.select(self.settings_frame)
            return
        
        if not self.config.validate_interface(interface):
            messagebox.showerror("Error", f"Invalid interface: {interface}\n\nPlease check the Settings tab for available interfaces.")
            self.notebook.select(self.settings_frame)
            return
        
        try:
            # Update configuration
            self.config.settings["interface"] = interface
            
            # Initialize GeoIP if needed
            if self.geoip_reader is None:
                self.initialize_geoip()
            
            self.running = True
            self.display_paused = False
            self.capture_start_time = datetime.now()
            
            # Initialize timing variables for packet rate calculation
            self.last_update_time = time.time()
            self.last_packet_count = 0
            self.packets_per_second = 0
            
            # FIXED: Clear protocol exclude set to ensure all packets are shown
            self.protocol_exclude = set()
            logger.debug(f"Protocol exclude set cleared: {self.protocol_exclude}")
            
            # Update UI
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.pause_button.config(state=tk.NORMAL, text="⏸ Pause Display")
            
            # Start capture and monitoring threads
            self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
            self.monitor_thread = threading.Thread(target=self.monitor_resources, daemon=True)
            
            self.capture_thread.start()
            self.monitor_thread.start()
            
            self.update_status("Capture started", self.success_color)
            self.log_app(f"Real packet capture started on interface: {interface}")
            
        except Exception as e:
            self.running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.pause_button.config(state=tk.DISABLED)
            
            error_msg = f"Failed to start capture: {e}"
            messagebox.showerror("Capture Error", error_msg)
            self.log_error(error_msg)
    
    def capture_packets(self):
        """Real packet capture loop - ENHANCED with better debugging"""
        try:
            interface = self.interface_var.get().strip()
            capture_filter = self.capture_filter_var.get().strip()
            
            logger.info(f"Starting real packet capture on interface: {interface}")
            if capture_filter:
                logger.info(f"Using capture filter: {capture_filter}")
            
            # Create capture with optional filter
            capture_kwargs = {'interface': interface}
            if capture_filter:
                capture_kwargs['bpf_filter'] = capture_filter
            if self.promiscuous_var.get():
                capture_kwargs['promiscuous_mode'] = True
            
            capture = pyshark.LiveCapture(**capture_kwargs)
            
            packet_count = 0
            last_log_time = time.time()
            
            logger.info("Starting packet sniffing loop...")
            
            for packet in capture.sniff_continuously():
                if not self.running:
                    logger.info("Capture stopped by user")
                    break
                
                try:
                    logger.debug(f"Raw packet received: {packet}")
                    processed_packet = self.process_packet(packet)
                    if processed_packet:
                        logger.debug(f"Processed packet: {processed_packet}")
                        self.packet_queue.put(processed_packet)
                        logger.debug(f"Packet added to queue. Queue size: {self.packet_queue.qsize()}")
                        packet_count += 1
                        
                        # Log progress every 100 packets (reduced for better debugging)
                        if packet_count % 100 == 0:
                            current_time = time.time()
                            rate = 100 / (current_time - last_log_time) if last_log_time else 0
                            logger.info(f"Processed {packet_count} packets (rate: {rate:.1f} pps)")
                            last_log_time = current_time
                        
                except Exception as e:
                    logger.error(f"Error processing packet {packet_count}: {e}")
                    continue
                    
        except Exception as e:
            error_msg = f"Capture error: {e}"
            logger.error(error_msg)
            self.packet_queue.put(("ERROR", error_msg))
            raise NetworkCaptureError(error_msg)
        finally:
            logger.info(f"Capture stopped. Total packets processed: {packet_count}")
    
    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Enhanced packet processing with fixed numbering - COMPLETELY FIXED"""
        try:
            # Extract basic information
            protocol = getattr(packet, 'highest_layer', 'Unknown').replace("_RAW", "")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            logger.debug(f"Processing packet with protocol: {protocol}")
            
            # Extract network information using enhanced extractor
            src_ip, dst_ip, src_port, dst_port = NetworkExtractor.extract_network_info(packet)
            
            logger.debug(f"Extracted network info: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            # Get packet size
            packet_size = 0
            try:
                packet_size = int(packet.length)
            except (AttributeError, ValueError):
                try:
                    packet_size = len(packet.get_raw_packet()) if hasattr(packet, 'get_raw_packet') else 0
                except:
                    packet_size = 0
            
            # Get geolocation
            geo_info = ""
            if (self.geoip_reader and dst_ip != "N/A" and 
                Validator.validate_ip(dst_ip) and not Validator.is_private_ip(dst_ip)):
                
                if dst_ip in self.ip_geocache:
                    geo_info = self.ip_geocache[dst_ip][0]
                else:
                    geo_info, _, _ = get_geolocation(dst_ip, self.geoip_reader)
                    self.ip_geocache[dst_ip] = (geo_info, "", "")
            elif Validator.is_private_ip(dst_ip):
                geo_info = "Local/Private"
            
            # Check for threats - FIXED: Pass src_port and dst_port
            flags = self.check_threats(packet, src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
            
            # Extract additional packet info
            info = self.extract_packet_info(packet, protocol)
            
            # Update statistics
            self.update_statistics(protocol, src_ip, dst_ip, packet_size, timestamp)
            
            # CRITICAL FIX: Use consistent packet numbering
            current_packet_num = self.packet_counter
            
            # Create packet record with CONSISTENT numbering
            packet_data = {
                "packet_num": current_packet_num,  # Use consistent numbering
                "timestamp": timestamp,
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "bytes": packet_size,
                "geo": geo_info,
                "flags": ",".join(flags) if flags else "",
                "info": info
            }
            
            logger.debug(f"Created packet data with consistent numbering: packet_num={current_packet_num}, protocol={protocol}")
            
            # Cache packet details
            if self.config.settings.get('enable_hex_dumps', True):
                self.packet_details_cache[current_packet_num] = self.extract_packet_details(packet)
            
            # Add to buffer
            self.packet_buffer.add_packet(packet_data)
            
            # INCREMENT counter AFTER creating the packet data
            self.packet_counter += 1
            
            return packet_data
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None
    
    def extract_packet_info(self, packet, protocol: str) -> str:
        """Extract additional packet information"""
        info_parts = []
        
        try:
            # Protocol-specific information
            if protocol == "HTTP" and hasattr(packet, 'http'):
                method = getattr(packet.http, 'request_method', '')
                host = getattr(packet.http, 'host', '')
                uri = getattr(packet.http, 'request_uri', '')
                if method and host:
                    info_parts.append(f"HTTP {method} {host}{uri}")
            
            elif protocol == "DNS" and hasattr(packet, 'dns'):
                query_name = getattr(packet.dns, 'qry_name', '')
                query_type = getattr(packet.dns, 'qry_type', '')
                if query_name:
                    info_parts.append(f"DNS Query: {query_name} ({query_type})")
            
            elif protocol == "TLS" and hasattr(packet, 'tls'):
                server_name = getattr(packet.tls, 'handshake_extensions_server_name', '')
                if server_name:
                    info_parts.append(f"TLS SNI: {server_name}")
            
            elif protocol == "SSH" and hasattr(packet, 'ssh'):
                version = getattr(packet.ssh, 'protocol', '')
                if version:
                    info_parts.append(f"SSH {version}")
            
            # Add packet length info
            if hasattr(packet, 'length'):
                info_parts.append(f"Length: {packet.length}")
            
        except Exception as e:
            logger.debug(f"Error extracting packet info: {e}")
        
        return " | ".join(info_parts) if info_parts else ""
    
    def check_threats(self, packet, src_ip: str, dst_ip: str, 
                     src_port: str, dst_port: str, protocol: str, timestamp: str) -> List[str]:
        """Enhanced threat checking - FIXED: Added missing port parameters"""
        threats = []
        
        try:
            # Check Spamhaus DROP list
            if (self.threat_intel.check_ip_in_drop_list(src_ip) or 
                self.threat_intel.check_ip_in_drop_list(dst_ip)):
                threats.append("DROP")
                self.alert_manager.add_alert(
                    timestamp, protocol, src_ip, dst_ip, 
                    "Spamhaus DROP", "IP found in Spamhaus DROP list"
                )
            
            # Check DNS queries against phishing domains
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                query_name = packet.dns.qry_name.lower()
                
                # Check against PhishTank
                if any(domain in query_name for domain in self.threat_intel.phishtank_domains):
                    threats.append("PHISH")
                    self.alert_manager.add_alert(
                        timestamp, protocol, src_ip, dst_ip,
                        "PhishTank Domain", f"DNS query for phishing domain: {query_name}"
                    )
                
                # Check against OpenPhish
                if any(domain in query_name for domain in self.threat_intel.openphish_domains):
                    threats.append("PHISH")
                    self.alert_manager.add_alert(
                        timestamp, protocol, src_ip, dst_ip,
                        "OpenPhish Domain", f"DNS query for phishing domain: {query_name}"
                    )
            
            # Check for suspicious ports - FIXED: Use the passed port parameters
            suspicious_ports = ['4444', '6666', '31337', '12345', '54321']
            if (str(src_port) in suspicious_ports or str(dst_port) in suspicious_ports):
                threats.append("SUSP_PORT")
                self.alert_manager.add_alert(
                    timestamp, protocol, src_ip, dst_ip,
                    "Suspicious Port", f"Communication on suspicious port: {src_port} -> {dst_port}"
                )
            
            # Check for private IP communication from external
            if (not Validator.is_private_ip(src_ip) and Validator.is_private_ip(dst_ip)):
                threats.append("EXT_TO_PRIV")
            
        except Exception as e:
            logger.error(f"Error checking threats: {e}")
        
        return threats
    
    def extract_packet_details(self, packet) -> Dict[str, List[str]]:
        """Enhanced packet details extraction with hex dumps"""
        details = {"ethernet": [], "network": [], "transport": [], "application": []}
        
        try:
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                layer_info = []
                
                # Add layer header
                layer_info.append(f"=== {layer.layer_name.upper()} LAYER ===")
                
                for field_name in layer.field_names:
                    try:
                        value = getattr(layer, field_name, "")
                        
                        # Format binary data as hex if enabled
                        if (isinstance(value, (bytes, bytearray)) and 
                            self.config.settings.get('enable_hex_dumps', True)):
                            formatted_value = NetworkExtractor.format_binary_data(
                                value, self.config.settings.get('hex_dump_max_length', 32)
                            )
                        else:
                            formatted_value = str(value).strip()
                        
                        if formatted_value and formatted_value != "":
                            # Clean field name
                            clean_field = field_name.replace('_', ' ').title()
                            layer_info.append(f"  {clean_field}: {formatted_value}")
                            
                    except Exception as e:
                        logger.debug(f"Error processing field {field_name}: {e}")
                        continue
                
                if len(layer_info) > 1:  # More than just the header
                    layer_text = "\n".join(layer_info)
                    
                    # Enhanced categorization
                    if layer_name in ("eth", "ethernet", "arp"):
                        details["ethernet"].append(layer_text)
                    elif layer_name in ("ip", "ipv6", "icmp", "icmpv6"):
                        details["network"].append(layer_text)
                    elif layer_name in ("tcp", "udp", "sctp"):
                        details["transport"].append(layer_text)
                    else:
                        details["application"].append(layer_text)
        
        except Exception as e:
            logger.error(f"Error extracting packet details: {e}")
            details["application"].append(f"Error extracting details: {e}")
        
        return details
    
    def monitor_resources(self):
        """Enhanced resource monitoring"""
        last_time = time.time()
        last_packet_count = 0
        
        while self.running:
            try:
                current_time = time.time()
                
                # System resources
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory_percent = psutil.virtual_memory().percent
                net_io = psutil.net_io_counters()
                
                # Packet rate calculation
                current_packet_count = self.packet_buffer.get_total_seen()
                time_diff = current_time - last_time
                
                if time_diff >= 1.0:  # Calculate rate every second
                    packet_diff = current_packet_count - last_packet_count
                    self.packets_per_second = packet_diff / time_diff
                    
                    last_time = current_time
                    last_packet_count = current_packet_count
                
                # Buffer usage
                buffer_usage = (self.packet_buffer.size() / self.packet_buffer.max_size) * 100
                
                self.packet_queue.put(("RESOURCE", cpu_percent, memory_percent, 
                                     net_io.bytes_sent, net_io.bytes_recv,
                                     self.packets_per_second, buffer_usage))
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error monitoring resources: {e}")
                time.sleep(1)
    
    def stop_capture(self):
        """Stop packet capture - FIXED GUI destruction issue"""
        if not self.running:
            return
        
        self.running = False
        self.display_paused = False
        
        # Update UI
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.DISABLED)
        
        # Wait for threads to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=3)
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=3)
        
        self.update_status("Capture stopped", self.warning_color)
        self.log_app("Packet capture stopped")
        
        # Auto-export if we have data - FIXED to check GUI state
        if self.packet_buffer.size() > 0:
            self.log_app(f"Captured {self.packet_buffer.get_total_seen()} total packets")
            
            # CRITICAL FIX: Only show dialog if GUI is still active
            try:
                if self.root.winfo_exists():  # Check if window still exists
                    if messagebox.askyesno("Export Data", "Would you like to export the captured data?"):
                        self.export_to_excel()
            except tk.TclError:
                # GUI has been destroyed, skip dialog
                logger.info("GUI destroyed, skipping export dialog")
    
    def clear_data(self):
        """Clear all captured data with confirmation"""
        if self.running:
            if not messagebox.askyesno("Clear Data", "Capture is running. Stop capture and clear all data?"):
                return
            self.stop_capture()
        
        if messagebox.askyesno("Clear Data", "Are you sure you want to clear all captured data?\n\nThis action cannot be undone."):
            # Clear all data structures
            self.packet_buffer.clear()
            self.alert_manager.clear()
            self.packet_tree.delete(*self.packet_tree.get_children())
            
            # Clear statistics
            self.protocol_stats.clear()
            self.protocol_bytes.clear()
            self.protocol_minute_counts.clear()
            self.protocol_hour_counts.clear()
            self.top_talkers_src.clear()
            self.top_talkers_dst.clear()
            self.sessions.clear()
            
            # Clear caches
            self.ip_geocache.clear()
            self.packet_details_cache.clear()
            
            # Reset counters
            self.packet_counter = 1
            self.last_packet_count = 0
            self.packets_per_second = 0
            
            # Reset labels
            self.packet_count_label.config(text="Packets: 0")
            self.packets_per_sec_label.config(text="Rate: 0 pps")
            self.alerts_count_label.config(text="Total Alerts: 0")
            if hasattr(self, 'selected_packet_label'):
                self.selected_packet_label.config(text="Select a packet to view details")
            
            self.update_status("All data cleared", self.warning_color)
            self.log_app("All captured data cleared")
    
    def show_protocol_selector(self):
        """Show protocol filter dialog"""
        if not self.protocol_stats:
            messagebox.showinfo("No Data", "No protocols captured yet.\n\nStart packet capture to see protocol options.")
            return
        
        popup = tk.Toplevel(self.root)
        popup.title("Protocol Filter - Select to EXCLUDE")
        popup.geometry("500x400")
        popup.configure(bg=self.primary_bg)
        popup.transient(self.root)
        popup.grab_set()
        
        # Instructions
        instructions = ttk.Label(popup, text="Select protocols to EXCLUDE from display:", 
                                font=('Segoe UI', 10, 'bold'))
        instructions.pack(pady=10)
        
        # Statistics
        total_protocols = len(self.protocol_stats)
        total_packets = sum(self.protocol_stats.values())
        stats_label = ttk.Label(popup, text=f"Total: {total_protocols} protocols, {total_packets:,} packets")
        stats_label.pack(pady=5)
        
        # Scrollable frame for checkboxes
        canvas = tk.Canvas(popup, bg=self.primary_bg, height=250)
        scrollbar = ttk.Scrollbar(popup, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Create checkboxes
        vars_dict = {}
        protocols_sorted = sorted(self.protocol_stats.items(), 
                                key=lambda x: x[1], reverse=True)
        
        for protocol, count in protocols_sorted:
            var = tk.BooleanVar(value=(protocol in self.protocol_exclude))
            
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill=tk.X, padx=5, pady=1)
            
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            checkbox_text = f"{protocol} ({count:,} packets, {percentage:.1f}%)"
            
            checkbox = tk.Checkbutton(
                frame, text=checkbox_text,
                variable=var, bg=self.primary_bg, fg=self.text_fg,
                selectcolor=self.accent_color, font=('Segoe UI', 9)
            )
            checkbox.pack(anchor='w')
            
            vars_dict[protocol] = var
        
        canvas.pack(side="left", fill="both", expand=True, padx=(10, 0))
        scrollbar.pack(side="right", fill="y", padx=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(popup)
        button_frame.pack(fill=tk.X, pady=10)
        
        def apply_filter():
            old_exclude = self.protocol_exclude.copy()
            self.protocol_exclude = {proto for proto, var in vars_dict.items() 
                                   if var.get()}
            
            if old_exclude != self.protocol_exclude:
                self.apply_protocol_filter()
                excluded_count = len(self.protocol_exclude)
                self.log_app(f"Protocol filter updated: {excluded_count} protocols excluded")
            
            popup.destroy()
        
        def select_all():
            for var in vars_dict.values():
                var.set(True)
        
        def clear_all():
            for var in vars_dict.values():
                var.set(False)
        
        ttk.Button(button_frame, text="Select All", command=select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", command=clear_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=popup.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Apply Filter", command=apply_filter).pack(side=tk.RIGHT, padx=5)
    
    def apply_protocol_filter(self):
        """Apply protocol filter to packet display"""
        try:
            # Clear current display
            self.packet_tree.delete(*self.packet_tree.get_children())
            
            # Re-add filtered packets
            packets = self.packet_buffer.get_packets()
            
            filtered_count = 0
            for packet in reversed(packets):  # Most recent first
                if packet.get("protocol") not in self.protocol_exclude:
                    self.add_packet_to_tree(packet)
                    filtered_count += 1
            
            self.update_status(f"Filter applied: {filtered_count:,} packets shown", self.info_color)
            
        except Exception as e:
            logger.error(f"Error applying protocol filter: {e}")
    
    def display_packet_details(self, packet_num):
        """Display packet details"""
        details = self.packet_details_cache.get(packet_num, {})
        
        for category, widget in self.detail_widgets.items():
            widget.config(state="normal")
            widget.delete(1.0, tk.END)
            
            if category in details and details[category]:
                content = "\n\n".join(details[category])
                widget.insert(tk.END, content)
                
                # Add syntax highlighting for hex dumps
                if self.config.settings.get('enable_hex_dumps', True):
                    self.highlight_hex_dumps(widget)
            
            widget.config(state="disabled")
    
    def highlight_hex_dumps(self, widget):
        """Add syntax highlighting for hex dumps"""
        try:
            widget.tag_configure("hex", foreground=self.accent_color, font=('Consolas', 9, 'bold'))
            widget.tag_configure("field", foreground=self.highlight_fg, font=('Consolas', 9, 'bold'))
            
            content = widget.get(1.0, tk.END)
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith('0x'):
                    # Highlight hex values
                    start_pos = f"{line_num}.0"
                    end_pos = f"{line_num}.end"
                    widget.tag_add("hex", start_pos, end_pos)
                elif ':' in line and not line.strip().startswith('==='):
                    # Highlight field names
                    colon_pos = line.find(':')
                    if colon_pos > 0:
                        start_pos = f"{line_num}.0"
                        end_pos = f"{line_num}.{colon_pos}"
                        widget.tag_add("field", start_pos, end_pos)
                        
        except Exception as e:
            logger.debug(f"Error highlighting hex dumps: {e}")
    
    def filter_by_selected_protocol(self):
        """Filter by selected packet's protocol"""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        try:
            item = self.packet_tree.item(selection[0])
            protocol = item['values'][2]  # Protocol column
            
            # Toggle protocol in exclude list
            if protocol in self.protocol_exclude:
                self.protocol_exclude.remove(protocol)
                action = "included"
            else:
                self.protocol_exclude.add(protocol)
                action = "excluded"
            
            self.apply_protocol_filter()
            self.log_app(f"Protocol {protocol} {action} from display")
            
        except Exception as e:
            logger.error(f"Error filtering by protocol: {e}")
    
    def filter_by_selected_src_ip(self):
        """Show statistics for selected source IP"""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        try:
            item = self.packet_tree.item(selection[0])
            src_ip = item['values'][3]  # Source IP column
            
            if src_ip in self.top_talkers_src:
                stats = self.top_talkers_src[src_ip]
                messagebox.showinfo("Source IP Statistics", 
                                   f"IP: {src_ip}\n"
                                   f"Packets: {stats['packets']:,}\n"
                                   f"Bytes: {self.format_bytes(stats['bytes'])}")
            else:
                messagebox.showinfo("Source IP Statistics", f"No statistics found for {src_ip}")
                
        except Exception as e:
            logger.error(f"Error showing source IP stats: {e}")
    
    def filter_by_selected_dst_ip(self):
        """Show statistics for selected destination IP"""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        try:
            item = self.packet_tree.item(selection[0])
            dst_ip = item['values'][5]  # Destination IP column
            
            if dst_ip in self.top_talkers_dst:
                stats = self.top_talkers_dst[dst_ip]
                messagebox.showinfo("Destination IP Statistics", 
                                   f"IP: {dst_ip}\n"
                                   f"Packets: {stats['packets']:,}\n"
                                   f"Bytes: {self.format_bytes(stats['bytes'])}")
            else:
                messagebox.showinfo("Destination IP Statistics", f"No statistics found for {dst_ip}")
                
        except Exception as e:
            logger.error(f"Error showing destination IP stats: {e}")
    
    def show_packet_statistics(self):
        """Show detailed packet statistics"""
        try:
            total_packets = self.packet_buffer.get_total_seen()
            buffer_size = self.packet_buffer.size()
            total_bytes = sum(self.protocol_bytes.values())
            
            # Protocol breakdown
            top_protocols = sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:5]
            protocol_info = "\n".join([f"  {proto}: {count:,} ({(count/total_packets*100):.1f}%)" 
                                     for proto, count in top_protocols]) if total_packets > 0 else "No data"
            
            # Time info
            duration = "Unknown"
            if hasattr(self, 'capture_start_time') and self.capture_start_time:
                duration_delta = datetime.now() - self.capture_start_time
                duration = str(duration_delta).split('.')[0]
            
            stats_text = f"""Packet Capture Statistics

Total Packets Seen: {total_packets:,}
Packets in Buffer: {buffer_size:,}
Total Bytes: {self.format_bytes(total_bytes)}
Capture Duration: {duration}
Average Rate: {self.packets_per_second:.1f} packets/sec

Top Protocols:
{protocol_info}

Buffer Usage: {(buffer_size/self.packet_buffer.max_size*100):.1f}%
Alerts Generated: {len(self.alert_manager.get_alerts()):,}
Unique Source IPs: {len(self.top_talkers_src):,}
Unique Dest IPs: {len(self.top_talkers_dst):,}
            """
            
            messagebox.showinfo("Packet Statistics", stats_text)
            
        except Exception as e:
            logger.error(f"Error showing packet statistics: {e}")
    
    def initialize_threat_feeds(self):
        """Initialize threat intelligence feeds"""
        try:
            if self.config.settings.get('enable_threat_feeds', True):
                # Start feed refresher in background
                self.feed_refresher = FeedAutoRefresher(
                    self.threat_intel, 
                    self.config.settings['refresh_interval']
                )
                self.feed_refresher.start()
                self.update_feed_status("Initializing feeds...", self.warning_color)
                
                # Check status after a delay
                self.root.after(3000, self.check_feed_status)
                
        except Exception as e:
            logger.error(f"Failed to initialize threat feeds: {e}")
            self.update_feed_status(f"Feed error: {str(e)[:30]}...", self.error_color)
    
    def check_feed_status(self):
        """Check and update feed status"""
        try:
            if self.threat_intel.last_refresh:
                status = self.threat_intel.get_feed_status_summary()
                self.update_feed_status(status, self.success_color)
            else:
                self.update_feed_status("Loading...", self.warning_color)
                # Check again in 5 seconds
                self.root.after(5000, self.check_feed_status)
        except Exception as e:
            logger.error(f"Error checking feed status: {e}")
    
    def initialize_geoip(self):
        """Initialize GeoIP database"""
        try:
            geolite_path = self.config.settings.get('geolite_path', '')
            if (self.config.settings.get('enable_geolocation', True) and 
                geolite_path and Path(geolite_path).exists()):
                try:
                    import geoip2.database
                    self.geoip_reader = geoip2.database.Reader(geolite_path)
                    self.geoip_status = "Loaded"
                    self.update_geoip_status("GeoIP: Loaded ✓", self.success_color)
                    logger.info("GeoIP database loaded successfully")
                except Exception as e:
                    self.geoip_status = "Error"
                    self.update_geoip_status("GeoIP: Error ✗", self.error_color)
                    logger.warning(f"Failed to load GeoIP database: {e}")
            else:
                self.geoip_status = "Disabled"
                self.update_geoip_status("GeoIP: Disabled ⚠", self.warning_color)
        except Exception as e:
            self.geoip_status = "Error"
            self.update_geoip_status("GeoIP: Error ✗", self.error_color)
    
    def start_scheduled_updates(self):
        """Start all scheduled GUI updates"""
        self.schedule_gui_update()
        self.schedule_logs_update()
    
    def schedule_gui_update(self):
        """Schedule GUI updates"""
        if not self.display_paused:
            self.update_gui()
        # Schedule next update
        self.root.after(self.config.settings['gui_update_interval'], 
                       self.schedule_gui_update)
    
    def schedule_logs_update(self):
        """Schedule log updates"""
        self.update_logs_display()
        self.root.after(5000, self.schedule_logs_update)  # Every 5 seconds
    
    def update_gui(self):
        """Enhanced GUI update - CRITICAL DISPLAY FIX"""
        try:
            batch_count = 0
            max_batch = self.config.settings['batch_size']
            packets_added = 0
            successful_additions = 0
            
            # DEBUG: Log queue status
            queue_size = self.packet_queue.qsize()
            if queue_size > 0:
                logger.debug(f"GUI update: Queue has {queue_size} items to process. Display paused: {self.display_paused}")
            
            while batch_count < max_batch:
                try:
                    item = self.packet_queue.get_nowait()
                    
                    if isinstance(item, dict):
                        # Packet data - CRITICAL FIX: Check protocol exclusion PROPERLY
                        protocol = item.get("protocol", "")
                        packet_num = item.get("packet_num", "unknown")
                        
                        logger.debug(f"update_gui: Processing packet item for GUI. Protocol={protocol}, ExcludeSet={self.protocol_exclude}")
                        
                        if protocol not in self.protocol_exclude:
                            logger.debug(f"Adding packet {packet_num} to tree: {protocol}")
                            
                            # CRITICAL FIX: Check if addition was successful
                            if self.add_packet_to_tree(item):
                                packets_added += 1
                                successful_additions += 1
                            else:
                                logger.error(f"Failed to add packet {packet_num} to tree")
                        else:
                            logger.debug(f"Excluding packet {packet_num}: {protocol}")
                    
                    elif isinstance(item, tuple) and len(item) > 1 and item[0] == "RESOURCE":
                        # Enhanced resource monitoring data
                        if len(item) >= 7:
                            self.update_resource_display(item[1], item[2], item[3], item[4], item[5], item[6])
                        else:
                            self.update_resource_display(item[1], item[2], item[3], item[4], 0, 0)
                    
                    elif isinstance(item, tuple) and len(item) > 1 and item[0] == "ERROR":
                        # Error message
                        self.update_status(f"Error: {item[1]}", self.error_color)
                        self.log_error(item[1])
                    
                    batch_count += 1
                    
                except queue.Empty:
                    break
            
            # Update packet count and rate
            total_packets = self.packet_buffer.get_total_seen()
            buffer_size = self.packet_buffer.size()
            
            self.packet_count_label.config(text=f"Packets: {buffer_size:,} ({total_packets:,} total)")
            
            # Calculate packets per second
            current_time = time.time()
            if hasattr(self, 'last_update_time'):
                time_diff = current_time - self.last_update_time
                if time_diff >= 1.0:  # Update rate every second
                    packet_diff = total_packets - self.last_packet_count
                    self.packets_per_second = packet_diff / time_diff
                    self.last_packet_count = total_packets
                    self.last_update_time = current_time
            else:
                self.last_update_time = current_time
                self.last_packet_count = total_packets
            
            self.packets_per_sec_label.config(text=f"Rate: {self.packets_per_second:.1f} pps")
            
            # DEBUG: Enhanced logging
            if packets_added > 0:
                logger.debug(f"update_gui: Added {packets_added} packets to tree in this cycle. Successful: {successful_additions}")
                
                # CRITICAL FIX: Force complete GUI refresh after adding packets
                self.root.update()
                
                # CRITICAL FIX: Check tree visibility
                tree_children = len(self.packet_tree.get_children())
                logger.debug(f"Tree now has {tree_children} children total")
                
            # CRITICAL FIX: Always force GUI update regardless
            self.root.update_idletasks()
                
        except Exception as e:
            logger.error(f"Error updating GUI: {e}")

    def add_packet_to_tree(self, packet_data: Dict[str, Any]):
        """Enhanced packet tree insertion with guaranteed visibility"""
        try:
            packet_num = packet_data.get("packet_num", "unknown")
            protocol = packet_data.get("protocol", "unknown")
            
            logger.debug(f"ENTERING add_packet_to_tree for packet_num: {packet_num}, protocol: {protocol}")
            
            values = (
                packet_data.get("packet_num", ""),
                packet_data.get("timestamp", ""),
                packet_data.get("protocol", ""),
                packet_data.get("src_ip", ""),
                packet_data.get("src_port", ""),
                packet_data.get("dst_ip", ""),
                packet_data.get("dst_port", ""),
                packet_data.get("bytes", ""),
                packet_data.get("geo", ""),
                packet_data.get("flags", ""),
                packet_data.get("info", "")
            )
            
            logger.debug(f"Values prepared for packet_num {packet_num}: {values}")
            
            # CRITICAL FIX: Insert at index 0 (top) for better visibility
            item_id = self.packet_tree.insert("", 0, values=values)
            
            logger.debug(f"Treeview insert EXECUTED for packet_num {packet_num}. Returned item_id: '{item_id}'. Protocol: {protocol}")
            
            # Color coding based on threats
            flags = packet_data.get("flags", "")
            if flags:
                logger.debug(f"Applying flags for packet_num {packet_num} (item_id: {item_id}): {flags}")
                
                if "DROP" in flags or "PHISH" in flags:
                    self.packet_tree.set(item_id, "flags", "🚨 " + flags)
                elif "SUSP_PORT" in flags:
                    self.packet_tree.set(item_id, "flags", "⚠️ " + flags)
                elif "EXT_TO_PRIV" in flags:
                    self.packet_tree.set(item_id, "flags", "⚡ " + flags)
                else:
                    self.packet_tree.set(item_id, "flags", "⚡ " + flags)
            
            # CRITICAL FIX: Ensure the item is visible
            self.packet_tree.see(item_id)
            
            # CRITICAL FIX: Force visual update of the tree widget
            self.packet_tree.update()
            
            # CRITICAL FIX: Ensure the tree maintains focus on the main window
            if not self.packet_tree.focus():
                self.packet_tree.focus_set()
            
            # Limit tree size for performance
            children = self.packet_tree.get_children()
            if len(children) > 1000:
                # Remove oldest entries (last when using index 0)
                for old_item in children[1000:]:
                    self.packet_tree.delete(old_item)
            
            logger.debug(f"EXITING add_packet_to_tree NORMALLY for packet_num: {packet_num}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding packet to tree: {e}")
            logger.debug(f"EXITING add_packet_to_tree WITH ERROR for packet_num: {packet_num}")
            return False
    
    def refresh_display(self):
        """Force refresh of the packet display"""
        try:
            # Store current selection
            selected_items = self.packet_tree.selection()
            selected_item_id = selected_items[0] if selected_items else None
            
            # Clear tree
            self.packet_tree.delete(*self.packet_tree.get_children())
            
            # Re-add all packets from buffer (most recent first)
            packets = self.packet_buffer.get_packets()
            if packets:
                self.log_app(f"Refreshing display with {len(packets)} packets")
                
                # Show most recent packets first (display limit of 1000)
                display_packets = packets[-1000:] if len(packets) > 1000 else packets
                for packet in reversed(display_packets):
                    self.add_packet_to_tree(packet)
                
                # Restore selection if possible
                if selected_item_id and selected_item_id in self.packet_tree.get_children():
                    self.packet_tree.selection_set(selected_item_id)
                    self.packet_tree.see(selected_item_id)
                
                # Force tree update
                self.packet_tree.update()
                self.root.update_idletasks()
                
                self.update_status(f"Display refreshed with {len(display_packets)} packets", self.success_color)
            else:
                self.update_status("No packets to display", self.warning_color)
                
        except Exception as e:
            error_msg = f"Display refresh error: {e}"
            self.update_status(error_msg, self.error_color)
            self.log_error(error_msg)
    
    def show_debug_info(self):
        """Enhanced debug information - UPDATED for display troubleshooting"""
        tree_children = self.packet_tree.get_children()
        tree_count = len(tree_children)
        
        # Get first few items for inspection
        sample_items = []
        for i, child in enumerate(tree_children[:3]):
            try:
                item_data = self.packet_tree.item(child)
                sample_items.append(f"Item {i+1}: {item_data.get('values', [])[:3]}")
            except:
                sample_items.append(f"Item {i+1}: Error reading")
        
        debug_info = f"""SimpleShark Debug Information

Capture Status: {'Running' if self.running else 'Stopped'}
Display Paused: {self.display_paused}
Protocol Exclude Set: {self.protocol_exclude}
Queue Size: {self.packet_queue.qsize()}
Buffer Size: {self.packet_buffer.size()}
Total Packets Seen: {self.packet_buffer.get_total_seen()}

TREEVIEW ANALYSIS:
Tree Children Count: {tree_count}
Tree Widget Exists: {hasattr(self, 'packet_tree')}
Tree Widget Visible: {self.packet_tree.winfo_viewable() if hasattr(self, 'packet_tree') else 'N/A'}
Tree Widget Mapped: {self.packet_tree.winfo_ismapped() if hasattr(self, 'packet_tree') else 'N/A'}

Sample Tree Items:
{chr(10).join(sample_items) if sample_items else 'No items found'}

Interface: {self.interface_var.get()}
GUI Update Interval: {self.config.settings['gui_update_interval']}ms
Batch Size: {self.config.settings['batch_size']}

Thread Status:
- Capture Thread: {'Alive' if self.capture_thread and self.capture_thread.is_alive() else 'Not running'}
- Monitor Thread: {'Alive' if self.monitor_thread and self.monitor_thread.is_alive() else 'Not running'}

Root Window Exists: {self.root.winfo_exists() if hasattr(self.root, 'winfo_exists') else 'Unknown'}
Current Tab: {self.notebook.tab(self.notebook.select(), "text") if hasattr(self, 'notebook') else 'Unknown'}
        """
        messagebox.showinfo("Debug Information", debug_info)
        logger.debug("Debug info requested by user")
        
        # CRITICAL FIX: Force a manual refresh attempt
        try:
            logger.debug("Attempting manual tree refresh...")
            self.packet_tree.update()
            self.packet_tree.update_idletasks()
            self.root.update()
            logger.debug("Manual refresh completed")
        except Exception as e:
            logger.error(f"Manual refresh failed: {e}")

    def force_refresh_display(self):
        """Force refresh display - TEMPORARY DEBUGGING METHOD"""
        try:
            # Clear tree
            self.packet_tree.delete(*self.packet_tree.get_children())
            
            # Re-add all packets from buffer
            packets = self.packet_buffer.get_packets()
            logger.info(f"Force refresh: Re-adding {len(packets)} packets to tree")
            
            # IMPROVED: Show most recent packets first (last 100)
            for packet in packets[-100:]:  # Last 100 packets
                self.add_packet_to_tree(packet)
            
            # Force complete refresh
            self.packet_tree.update()
            self.root.update()
            
            tree_count = len(self.packet_tree.get_children())
            logger.info(f"Force refresh completed. Tree now has {tree_count} items")
            
            messagebox.showinfo("Force Refresh", f"Refreshed display with {tree_count} packets")
            
        except Exception as e:
            logger.error(f"Force refresh failed: {e}")
            messagebox.showerror("Refresh Error", str(e))
    
    def update_resource_display(self, cpu: float, memory: float, 
                               bytes_sent: int, bytes_recv: int,
                               pps: float = 0, buffer_usage: float = 0):
        """Enhanced resource monitoring display"""
        try:
            # Color coding based on usage levels
            cpu_color = self.error_color if cpu > 80 else self.warning_color if cpu > 60 else self.text_fg
            mem_color = self.error_color if memory > 85 else self.warning_color if memory > 70 else self.text_fg
            buf_color = self.error_color if buffer_usage > 90 else self.warning_color if buffer_usage > 75 else self.text_fg
            
            self.cpu_label.config(text=f"CPU: {cpu:.1f}%", foreground=cpu_color)
            self.memory_label.config(text=f"Memory: {memory:.1f}%", foreground=mem_color)
            self.network_label.config(text=f"Network: {self.format_bytes(bytes_sent)}↑ / {self.format_bytes(bytes_recv)}↓")
            self.buffer_usage_label.config(text=f"Buffer: {buffer_usage:.1f}%", foreground=buf_color)
            
        except Exception as e:
            logger.error(f"Error updating resource display: {e}")
    
    def update_statistics(self, protocol: str, src_ip: str, dst_ip: str, 
                         packet_size: int, timestamp: str):
        """Enhanced statistics tracking"""
        try:
            # Protocol stats
            self.protocol_stats[protocol] += 1
            self.protocol_bytes[protocol] += packet_size
            
            # Time-based stats
            minute_bucket = timestamp[:16]  # YYYY-MM-DD HH:MM
            hour_bucket = timestamp[:13]    # YYYY-MM-DD HH
            
            self.protocol_minute_counts[protocol][minute_bucket] += 1
            self.protocol_hour_counts[protocol][hour_bucket] += 1
            
            # Top talkers with validation
            if Validator.validate_ip(src_ip):
                self.top_talkers_src[src_ip]["packets"] += 1
                self.top_talkers_src[src_ip]["bytes"] += packet_size
            
            if Validator.validate_ip(dst_ip):
                self.top_talkers_dst[dst_ip]["packets"] += 1
                self.top_talkers_dst[dst_ip]["bytes"] += packet_size
            
            # Enhanced sessions tracking
            if (Validator.validate_ip(src_ip) and Validator.validate_ip(dst_ip)):
                session_key = (src_ip, dst_ip, protocol)
                session = self.sessions[session_key]
                
                if session["packets"] == 0:  # New session
                    session["first_seen"] = timestamp
                    session["src"] = src_ip
                    session["dst"] = dst_ip
                    session["protocol"] = protocol
                
                session["packets"] += 1
                session["bytes"] += packet_size
                session["last_seen"] = timestamp
        
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    def maximize_window(self):
        """Try to maximize the window with fallback"""
        try:
            self.root.state('zoomed')
        except Exception:
            try:
                self.root.attributes('-zoomed', True)
            except Exception:
                self.root.geometry("1400x900")
                self.root.update()
                # Center window
                x = (self.root.winfo_screenwidth() // 2) - (1400 // 2)
                y = (self.root.winfo_screenheight() // 2) - (900 // 2)
                self.root.geometry(f"1400x900+{x}+{y}")
    
    # Settings Management
    def save_settings(self):
        """Enhanced settings save with validation"""
        try:
            # Validate network settings
            interface = self.interface_var.get().strip()
            if interface and not self.config.validate_interface(interface):
                messagebox.showerror("Error", f"Invalid interface: {interface}")
                return
            
            # Validate API key
            api_key = self.abuseipdb_var.get().strip()
            if api_key and not self.config.validate_api_key(api_key):
                messagebox.showwarning("Warning", "AbuseIPDB API key format may be invalid")
            
            # Validate numeric settings
            try:
                max_packets = int(self.max_packets_var.get())
                gui_interval = int(self.gui_interval_var.get())
                batch_size = int(self.batch_size_var.get())
                
                if max_packets < 100 or max_packets > 100000:
                    raise ValueError("Max packets must be between 100 and 100,000")
                if gui_interval < 100 or gui_interval > 5000:
                    raise ValueError("GUI interval must be between 100 and 5,000 ms")
                if batch_size < 10 or batch_size > 1000:
                    raise ValueError("Batch size must be between 10 and 1,000")
                    
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid setting value: {e}")
                return
            
            # Update configuration
            self.config.settings.update({
                "interface": interface,
                "geolite_path": self.geolite_var.get().strip(),
                "abuseipdb_key": api_key,
                "max_packets": max_packets,
                "gui_update_interval": gui_interval,
                "batch_size": batch_size,
                "enable_geolocation": self.enable_geo_var.get(),
                "enable_threat_feeds": self.enable_threats_var.get(),
                "enable_hex_dumps": self.enable_hex_var.get(),
                "promiscuous_mode": self.promiscuous_var.get(),
                "capture_filter": self.capture_filter_var.get().strip()
            })
            
            # Save to file
            if self.config.save_settings():
                messagebox.showinfo("Success", "Settings saved successfully")
                self.log_app("Settings saved successfully")
                
                # Update runtime settings
                self.packet_buffer.max_size = max_packets
                
            else:
                messagebox.showerror("Error", "Failed to save settings")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")
            self.log_error(f"Settings save error: {e}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        if messagebox.askyesno("Reset Settings", 
                              "Reset all settings to defaults?\n\nThis will overwrite your current configuration."):
            self.config.settings = self.config.DEFAULT_SETTINGS.copy()
            
            # Update UI elements
            self.interface_var.set(self.config.settings["interface"])
            self.geolite_var.set(self.config.settings["geolite_path"])
            self.abuseipdb_var.set(self.config.settings["abuseipdb_key"])
            self.max_packets_var.set(str(self.config.settings["max_packets"]))
            self.gui_interval_var.set(str(self.config.settings["gui_update_interval"]))
            self.batch_size_var.set(str(self.config.settings["batch_size"]))
            self.enable_geo_var.set(self.config.settings["enable_geolocation"])
            self.enable_threats_var.set(self.config.settings["enable_threat_feeds"])
            self.enable_hex_var.set(self.config.settings["enable_hex_dumps"])
            self.promiscuous_var.set(self.config.settings.get("promiscuous_mode", False))
            self.capture_filter_var.set(self.config.settings.get("capture_filter", ""))
            
            self.log_app("Settings reset to defaults")
    
    def test_settings(self):
        """Test current settings"""
        try:
            results = []
            
            # Test interface
            interface = self.interface_var.get().strip()
            if interface:
                if self.config.validate_interface(interface):
                    results.append(f"✓ Interface '{interface}' is valid")
                else:
                    results.append(f"✗ Interface '{interface}' is invalid")
            else:
                results.append("⚠ No interface selected")
            
            # Test GeoIP database
            geolite_path = self.geolite_var.get().strip()
            if geolite_path and Path(geolite_path).exists():
                try:
                    import geoip2.database
                    with geoip2.database.Reader(geolite_path) as reader:
                        test_result = reader.city("8.8.8.8")
                        results.append(f"✓ GeoLite2 database is valid")
                except Exception as e:
                    results.append(f"✗ GeoLite2 database error: {e}")
            else:
                results.append("⚠ GeoLite2 database path not found")
            
            # Test API key format
            api_key = self.abuseipdb_var.get().strip()
            if api_key:
                if self.config.validate_api_key(api_key):
                    results.append("✓ AbuseIPDB API key format is valid")
                else:
                    results.append("✗ AbuseIPDB API key format is invalid")
            else:
                results.append("⚠ No AbuseIPDB API key configured")
            
            # Test numeric settings
            try:
                max_packets = int(self.max_packets_var.get())
                gui_interval = int(self.gui_interval_var.get())
                batch_size = int(self.batch_size_var.get())
                results.append("✓ All numeric settings are valid")
            except ValueError as e:
                results.append(f"✗ Invalid numeric setting: {e}")
            
            # Show results
            messagebox.showinfo("Settings Test Results", "\n".join(results))
            
        except Exception as e:
            messagebox.showerror("Test Error", f"Error testing settings: {e}")
    
    def refresh_interfaces(self):
        """Refresh available network interfaces"""
        try:
            interfaces = self.config.get_available_interfaces()
            self.interface_combo['values'] = interfaces
            
            current = self.interface_var.get()
            if current in interfaces:
                self.interface_status_label.config(text="✓ Interface available", 
                                                  foreground=self.success_color)
            else:
                self.interface_status_label.config(text="✗ Interface not found", 
                                                  foreground=self.error_color)
            
            self.log_app(f"Interface list refreshed: {len(interfaces)} interfaces found")
            
        except Exception as e:
            self.interface_status_label.config(text="Error refreshing interfaces", 
                                             foreground=self.error_color)
            logger.error(f"Error refreshing interfaces: {e}")
    
    def browse_geolite_db(self):
        """Browse for GeoLite2 database file"""
        filename = filedialog.askopenfilename(
            title="Select GeoLite2 Database",
            filetypes=[("MaxMind DB", "*.mmdb"), ("All Files", "*.*")]
        )
        if filename:
            self.geolite_var.set(filename)
    
    def toggle_api_key_visibility(self):
        """Toggle API key visibility"""
        current_show = self.abuseipdb_entry.cget("show")
        if current_show == "*":
            self.abuseipdb_entry.config(show="")
        else:
            self.abuseipdb_entry.config(show="*")
    
    # Data Export/Import
    def export_to_excel(self):
        """Enhanced Excel export"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            default_filename = f"simpleshark_export_{timestamp}.xlsx"
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel Files", "*.xlsx"), ("All Files", "*.*")],
                initialfile=default_filename
            )
            
            if not filename:
                return
            
            # Prepare data
            packets_data = self.packet_buffer.get_packets()
            
            if not packets_data:
                messagebox.showwarning("No Data", "No packet data to export")
                return
            
            packets_df = pd.DataFrame(packets_data)
            
            # Protocol statistics
            stats_data = []
            total_packets = sum(self.protocol_stats.values())
            for protocol, count in self.protocol_stats.items():
                bytes_count = self.protocol_bytes.get(protocol, 0)
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                stats_data.append({
                    "Protocol": protocol,
                    "Packet Count": count,
                    "Total Bytes": bytes_count,
                    "Percentage": f"{percentage:.2f}%"
                })
            
            stats_df = pd.DataFrame(stats_data)
            
            # Export to Excel with multiple sheets
            with pd.ExcelWriter(filename, engine="openpyxl") as writer:
                packets_df.to_excel(writer, sheet_name="Packets", index=False)
                
                if not stats_df.empty:
                    stats_df.to_excel(writer, sheet_name="Protocol Statistics", index=False)
                
                # Configuration sheet
                config_data = []
                for key, value in self.config.settings.items():
                    config_data.append({"Setting": key, "Value": str(value)})
                
                config_df = pd.DataFrame(config_data)
                config_df.to_excel(writer, sheet_name="Configuration", index=False)
            
            # Show success message
            file_size = Path(filename).stat().st_size
            messagebox.showinfo("Export Complete", 
                              f"Data exported successfully!\n\n"
                              f"File: {filename}\n"
                              f"Size: {self.format_bytes(file_size)}\n"
                              f"Packets: {len(packets_data):,}")
            
            self.log_app(f"Data exported to {filename} ({self.format_bytes(file_size)})")
            
        except Exception as e:
            error_msg = f"Export failed: {e}"
            messagebox.showerror("Export Error", error_msg)
            self.log_error(error_msg)
    
    def import_traffic_log(self):
        """Import traffic log from file"""
        filename = filedialog.askopenfilename(
            title="Import Traffic Log",
            filetypes=[
                ("Excel Files", "*.xlsx *.xls"),
                ("CSV Files", "*.csv"),
                ("All Files", "*.*")
            ]
        )
        
        if not filename:
            return
        
        try:
            # Load data
            if filename.lower().endswith(('.xlsx', '.xls')):
                df = pd.read_excel(filename, sheet_name=0)
            else:
                df = pd.read_csv(filename)
            
            # Clear current data
            self.clear_data()
            
            # Import packets
            imported_count = 0
            for _, row in df.iterrows():
                packet_data = {
                    "packet_num": self.packet_counter,
                    "timestamp": str(row.get("timestamp", "")),
                    "protocol": str(row.get("protocol", "")),
                    "src_ip": str(row.get("src_ip", "")),
                    "src_port": str(row.get("src_port", "")),
                    "dst_ip": str(row.get("dst_ip", "")),
                    "dst_port": str(row.get("dst_port", "")),
                    "bytes": int(row.get("bytes", 0)) if pd.notna(row.get("bytes", 0)) else 0,
                    "geo": str(row.get("geo", "")),
                    "flags": str(row.get("flags", "")),
                    "info": str(row.get("info", ""))
                }
                
                # Add to buffer
                self.packet_buffer.add_packet(packet_data)
                self.add_packet_to_tree(packet_data)
                
                # Update statistics
                self.update_statistics(
                    packet_data.get("protocol", ""),
                    packet_data.get("src_ip", ""),
                    packet_data.get("dst_ip", ""),
                    packet_data.get("bytes", 0),
                    packet_data.get("timestamp", "")
                )
                
                self.packet_counter += 1
                imported_count += 1
            
            self.import_status_label.config(text=f"✓ Imported {imported_count:,} packets")
            messagebox.showinfo("Import Complete", 
                              f"Successfully imported {imported_count:,} packets from:\n{filename}")
            self.log_app(f"Imported {imported_count:,} packets from {filename}")
            
        except Exception as e:
            error_msg = f"Import failed: {e}"
            self.import_status_label.config(text=f"✗ {error_msg}")
            messagebox.showerror("Import Error", error_msg)
            self.log_error(error_msg)
    
    def export_settings(self):
        """Export current settings to file"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
                initialfile=f"simpleshark_settings_{timestamp}.json"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(self.config.settings, f, indent=2)
                
                messagebox.showinfo("Export Complete", f"Settings exported to:\n{filename}")
                self.log_app(f"Settings exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export settings: {e}")
    
    def import_settings(self):
        """Import settings from file"""
        filename = filedialog.askopenfilename(
            title="Import Settings",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'r') as f:
                imported_settings = json.load(f)
            
            # Update settings
            for key, value in imported_settings.items():
                if key in self.config.DEFAULT_SETTINGS:
                    self.config.settings[key] = value
            
            # Update UI elements
            self.interface_var.set(self.config.settings.get("interface", ""))
            self.geolite_var.set(self.config.settings.get("geolite_path", ""))
            self.abuseipdb_var.set(self.config.settings.get("abuseipdb_key", ""))
            self.max_packets_var.set(str(self.config.settings.get("max_packets", 10000)))
            self.gui_interval_var.set(str(self.config.settings.get("gui_update_interval", 500)))
            self.batch_size_var.set(str(self.config.settings.get("batch_size", 50)))
            self.enable_geo_var.set(self.config.settings.get("enable_geolocation", True))
            self.enable_threats_var.set(self.config.settings.get("enable_threat_feeds", True))
            self.enable_hex_var.set(self.config.settings.get("enable_hex_dumps", True))
            self.promiscuous_var.set(self.config.settings.get("promiscuous_mode", False))
            self.capture_filter_var.set(self.config.settings.get("capture_filter", ""))
            
            messagebox.showinfo("Import Complete", f"Settings imported from:\n{filename}")
            self.log_app(f"Settings imported from {filename}")
            
        except Exception as e:
            error_msg = f"Failed to import settings: {e}"
            messagebox.showerror("Import Error", error_msg)
            self.log_error(error_msg)
    
    # Log Management
    def filter_logs(self, event=None):
        """Filter logs based on selection"""
        self.update_logs_display()
    
    def search_logs(self, event=None):
        """Search logs based on search term"""
        self.update_logs_display()
    
    def clear_logs(self):
        """Clear application logs"""
        if messagebox.askyesno("Clear Logs", "Clear all application logs?"):
            self.app_logs.clear()
            self.error_logs.clear()
            self.update_logs_display()
            self.log_app("Application logs cleared")
    
    def export_logs(self):
        """Export application logs"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                initialfile=f"simpleshark_logs_{timestamp}.txt"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"=== SimpleShark v2.0 Application Logs ===\n")
                    f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total App Logs: {len(self.app_logs)}\n")
                    f.write(f"Total Error Logs: {len(self.error_logs)}\n\n")
                    
                    f.write("--- Application Messages ---\n")
                    for msg in self.app_logs:
                        f.write(f"[APP] {msg}\n")
                    
                    f.write("\n--- Error Messages ---\n")
                    for msg in self.error_logs:
                        f.write(f"[ERROR] {msg}\n")
                
                messagebox.showinfo("Export Complete", f"Logs exported to:\n{filename}")
                self.log_app(f"Logs exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs: {e}")
    
    def update_logs_display(self):
        """Enhanced logs display with filtering"""
        try:
            filter_type = self.log_filter_var.get()
            search_term = self.log_search_var.get().lower()
            
            self.logs_text.config(state="normal")
            self.logs_text.delete(1.0, tk.END)
            
            # Combine and filter logs
            all_logs = []
            
            if filter_type in ["All", "App"]:
                for log_msg in list(self.app_logs)[-100:]:
                    if not search_term or search_term in log_msg.lower():
                        all_logs.append(("app", f"[APP] {log_msg}"))
            
            if filter_type in ["All", "Error"]:
                for log_msg in list(self.error_logs)[-100:]:
                    if not search_term or search_term in log_msg.lower():
                        all_logs.append(("error", f"[ERROR] {log_msg}"))
            
            # Sort by timestamp
            all_logs.sort(key=lambda x: x[1])
            
            # Display logs with tags
            for log_type, log_msg in all_logs:
                start_pos = self.logs_text.index(tk.INSERT)
                self.logs_text.insert(tk.END, log_msg + "\n")
                end_pos = self.logs_text.index(tk.INSERT)
                self.logs_text.tag_add(log_type, start_pos, end_pos)
            
            # Update log statistics
            app_count = len(self.app_logs)
            error_count = len(self.error_logs)
            self.log_stats_label.config(text=f"Logs: {app_count} app, {error_count} errors")
            
            self.logs_text.config(state="disabled")
            self.logs_text.see(tk.END)  # Scroll to bottom
            
        except Exception as e:
            logger.error(f"Error updating logs display: {e}")
    
    # Threat Intelligence Management
    def manual_refresh_feeds(self):
        """Manually refresh threat feeds"""
        def refresh_in_thread():
            try:
                self.update_feed_status("Refreshing feeds...", self.warning_color)
                self.threat_intel.refresh_feeds()
                
                # Update status based on results
                status = self.threat_intel.get_feed_status_summary()
                self.update_feed_status(status, self.success_color)
                self.log_app("Threat feeds manually refreshed")
                
            except Exception as e:
                error_msg = f"Feed refresh failed: {e}"
                self.update_feed_status(error_msg[:50] + "...", self.error_color)
                self.log_error(error_msg)
        
        # Run in background thread
        threading.Thread(target=refresh_in_thread, daemon=True).start()
    
    def clear_alerts(self):
        """Clear all alerts"""
        if messagebox.askyesno("Clear Alerts", "Clear all security alerts?"):
            self.alert_manager.clear()
            self.alerts_count_label.config(text="Total Alerts: 0")
            self.high_risk_label.config(text="High Risk: 0")
            # Clear alerts tree if it exists
            if hasattr(self, 'alerts_tree'):
                self.alerts_tree.delete(*self.alerts_tree.get_children())
            self.log_app("All security alerts cleared")
    
    # Utility Methods
    def update_status(self, message: str, color: str = None):
        """Update status bar message"""
        try:
            if color:
                self.status_label.config(text=message, foreground=color)
            else:
                self.status_label.config(text=message)
        except Exception as e:
            logger.error(f"Error updating status: {e}")
    
    def update_feed_status(self, message: str, color: str):
        """Update feed status display"""
        try:
            if hasattr(self, 'feed_status_label'):
                self.feed_status_label.config(text=f"Feeds: {message}", foreground=color)
            if hasattr(self, 'feeds_status_label'):
                self.feeds_status_label.config(text=f"Feeds: {message}", foreground=color)
        except Exception as e:
            logger.error(f"Error updating feed status: {e}")
    
    def update_geoip_status(self, message: str, color: str):
        """Update GeoIP status display"""
        try:
            if hasattr(self, 'geoip_status_label'):
                self.geoip_status_label.config(text=message, foreground=color)
        except Exception as e:
            logger.error(f"Error updating GeoIP status: {e}")
    
    def log_app(self, message: str):
        """Log application message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"{timestamp} - {message}"
        self.app_logs.append(log_msg)
        logger.info(message)
    
    def log_error(self, message: str):
        """Log error message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"{timestamp} - {message}"
        self.error_logs.append(log_msg)
        logger.error(message)
    
    @staticmethod
    def format_bytes(bytes_count: int) -> str:
        """Format bytes into human readable format"""
        try:
            bytes_count = int(bytes_count)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if bytes_count < 1024.0:
                    return f"{bytes_count:.1f} {unit}"
                bytes_count /= 1024.0
            return f"{bytes_count:.1f} PB"
        except (ValueError, TypeError):
            return "0 B"

def main():
    """Main application entry point with enhanced error handling"""
    try:
        # Check Python version
        import sys
        if sys.version_info < (3, 7):
            print("Error: SimpleShark requires Python 3.7 or higher")
            sys.exit(1)
        
        # Check for required permissions
        if os.name == 'nt':  # Windows
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    logger.warning("SimpleShark is running without administrator privileges. "
                                 "Packet capture may not work properly. "
                                 "Consider running as administrator.")
            except Exception:
                pass
        else:  # Unix-like systems
            if os.geteuid() != 0:
                logger.warning("SimpleShark is running without root privileges. "
                             "Packet capture may not work properly. "
                             "Consider running with sudo.")
        
        # Check for required dependencies
        missing_deps = []
        required_modules = [
            ("pyshark", "pyshark"),
            ("pandas", "pandas"),
            ("matplotlib", "matplotlib"),
            ("psutil", "psutil"),
            ("requests", "requests")
        ]
        
        for module_name, pip_name in required_modules:
            try:
                __import__(module_name)
            except ImportError:
                missing_deps.append(pip_name)
        
        if missing_deps:
            error_msg = f"Missing required dependencies: {', '.join(missing_deps)}\n\n"
            error_msg += "Please install with: pip install " + " ".join(missing_deps)
            print(error_msg)
            
            # Try to show GUI error if tkinter is available
            try:
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror("Missing Dependencies", error_msg)
            except:
                pass
            
            sys.exit(1)
        
        # Create and run application
        root = tk.Tk()
        
        # Set window icon if available
        try:
            # You can add an icon file here
            # root.iconbitmap("simpleshark.ico")
            pass
        except:
            pass
        
        app = SimpleSharkGUI(root)
        
        logger.info("SimpleShark v2.0 GUI application started successfully")
        logger.info(f"Created by: clearblueyellow")
        logger.info(f"Current date: 2025-05-24 23:09:31 UTC")
        
        # Start main event loop
        root.mainloop()
        
    except Exception as e:
        logger.critical(f"Critical error starting SimpleShark: {e}")
        
        # Try to show error dialog
        try:
            if 'root' in locals():
                root.withdraw()
            error_root = tk.Tk()
            error_root.withdraw()
            messagebox.showerror("Critical Error", 
                               f"SimpleShark failed to start:\n\n{e}\n\n"
                               f"Check the log file 'simpleshark.log' for more details.")
        except:
            print(f"Critical error: {e}")
        
        raise

if __name__ == "__main__":
    main()

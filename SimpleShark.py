#!/usr/bin/env python3
"""
SimpleShark - Lightweight Network Traffic Analyzer using PyQt6
Enhanced statistics while maintaining high performance
Created by: clearblueyellow
Date: 2025-05-25
"""

import sys
import time
import threading
import queue
from datetime import datetime
from collections import deque, defaultdict
from pathlib import Path
import json
import logging
import psutil
import pyshark
import pandas as pd
from typing import Dict, List, Optional, Any
import socket
from ipaddress import ip_address, AddressValueError

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTableWidget, QTableWidgetItem, QPushButton, QLabel, QComboBox,
    QStatusBar, QTabWidget, QTextEdit, QSplitter, QHeaderView,
    QMessageBox, QFileDialog, QProgressBar, QGroupBox, QCheckBox,
    QLineEdit, QSpinBox, QTreeWidget, QTreeWidgetItem, QFrame
)
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, Qt, QSettings
from PyQt6.QtGui import QFont, QColor, QPalette

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('simpleshark.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PacketCapture(QThread):
    """Background packet capture thread"""
    packet_received = pyqtSignal(dict, object)  # packet_data, raw_packet
    status_update = pyqtSignal(str)
    
    def __init__(self, interface: str, capture_filter: str = ""):
        super().__init__()
        self.interface = interface
        self.capture_filter = capture_filter
        self.running = False
        self.packet_count = 0
    
    def run(self):
        """Main capture loop"""
        try:
            self.status_update.emit(f"Starting capture on {self.interface}")
            
            # Create capture
            capture_kwargs = {'interface': self.interface}
            if self.capture_filter:
                capture_kwargs['bpf_filter'] = self.capture_filter
            
            capture = pyshark.LiveCapture(**capture_kwargs)
            self.running = True
            
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                
                try:
                    packet_data = self.process_packet(packet)
                    if packet_data:
                        self.packet_received.emit(packet_data, packet)
                        self.packet_count += 1
                        
                        if self.packet_count % 100 == 0:
                            self.status_update.emit(f"Captured {self.packet_count} packets")
                            
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    continue
                    
        except Exception as e:
            self.status_update.emit(f"Capture error: {e}")
            logger.error(f"Capture failed: {e}")
    
    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Extract essential packet information"""
        try:
            # Basic info
            protocol = getattr(packet, 'highest_layer', 'Unknown')
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            # Network info
            src_ip = dst_ip = "N/A"
            src_port = dst_port = "N/A"
            
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            
            if hasattr(packet, 'tcp'):
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
            elif hasattr(packet, 'udp'):
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
            
            # Packet size
            try:
                size = int(packet.length)
            except:
                size = 0
            
            # Extract info based on protocol
            info = ""
            if protocol == "HTTP" and hasattr(packet, 'http'):
                method = getattr(packet.http, 'request_method', '')
                host = getattr(packet.http, 'host', '')
                if method and host:
                    info = f"{method} {host}"
            elif protocol == "DNS" and hasattr(packet, 'dns'):
                query = getattr(packet.dns, 'qry_name', '')
                if query:
                    info = f"Query: {query}"
            
            return {
                'timestamp': timestamp,
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'size': size,
                'info': info
            }
            
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
            return None
    
    def stop(self):
        """Stop packet capture"""
        self.running = False

class PacketTableWidget(QTableWidget):
    """High-performance packet display table with reverse chronological order"""
    
    packet_selected = pyqtSignal(int)  # Signal for packet selection
    
    def __init__(self):
        super().__init__()
        self.setup_table()
        self.max_rows = 5000
        self.packet_counter = 1
        
    def setup_table(self):
        """Setup table columns and appearance"""
        columns = ['#', 'Time', 'Protocol', 'Source', 'Destination', 'Size', 'Info']
        self.setColumnCount(len(columns))
        self.setHorizontalHeaderLabels(columns)
        
        # Set column widths
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.resizeSection(0, 60)   # Packet #
        header.resizeSection(1, 100)  # Time
        header.resizeSection(2, 80)   # Protocol
        header.resizeSection(3, 150)  # Source
        header.resizeSection(4, 150)  # Destination
        header.resizeSection(5, 60)   # Size
        
        # Appearance
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSortingEnabled(False)
        
        # Connect selection signal
        self.itemSelectionChanged.connect(self.on_selection_changed)
        
        # Dark theme
        self.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                gridline-color: #555555;
            }
            QTableWidget::item:selected {
                background-color: #4a90e2;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 4px;
            }
        """)
    
    def add_packet(self, packet_data: Dict[str, Any]):
        """Add packet to table efficiently (newest first)"""
        # Remove old rows if at limit
        if self.rowCount() >= self.max_rows:
            self.removeRow(self.rowCount() - 1)
        
        # Insert new row at top
        self.insertRow(0)
        
        # Populate cells
        items = [
            str(self.packet_counter),
            packet_data['timestamp'],
            packet_data['protocol'],
            f"{packet_data['src_ip']}:{packet_data['src_port']}",
            f"{packet_data['dst_ip']}:{packet_data['dst_port']}",
            str(packet_data['size']),
            packet_data['info']
        ]
        
        for col, text in enumerate(items):
            item = QTableWidgetItem(str(text))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.setItem(0, col, item)
        
        self.packet_counter += 1
    
    def on_selection_changed(self):
        """Handle row selection"""
        current_row = self.currentRow()
        if current_row >= 0:
            try:
                packet_num = int(self.item(current_row, 0).text())
                self.packet_selected.emit(packet_num)
            except (ValueError, AttributeError):
                pass

class EnhancedStatsWidget(QWidget):
    """Enhanced statistics widget with comprehensive network analysis"""
    
    def __init__(self):
        super().__init__()
        
        # Statistics data
        self.protocol_stats = defaultdict(int)
        self.protocol_bytes = defaultdict(int)
        self.top_talkers_src = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.top_talkers_dst = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.port_stats = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.traffic_timeline = deque(maxlen=100)  # Last 100 time points
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
        
        self.setup_ui()
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(3000)  # Update every 3 seconds
        
    def setup_ui(self):
        """Setup enhanced statistics UI"""
        layout = QVBoxLayout()
        
        # Create tab widget for different stat categories
        self.stats_tabs = QTabWidget()
        layout.addWidget(self.stats_tabs)
        
        # Setup tabs
        self.setup_overview_tab()
        self.setup_protocols_tab()
        self.setup_network_tab()
        self.setup_security_tab()
        
        self.setLayout(layout)
    
    def setup_overview_tab(self):
        """Setup overview statistics"""
        overview_widget = QWidget()
        layout = QVBoxLayout()
        
        # Summary metrics
        summary_group = QGroupBox("Traffic Summary")
        summary_layout = QVBoxLayout()
        
        self.summary_text = QTextEdit()
        self.summary_text.setMaximumHeight(200)
        self.summary_text.setFont(QFont("Courier", 10))
        summary_layout.addWidget(self.summary_text)
        summary_group.setLayout(summary_layout)
        
        # Performance metrics
        perf_group = QGroupBox("Performance Metrics")
        perf_layout = QVBoxLayout()
        
        self.perf_text = QTextEdit()
        self.perf_text.setMaximumHeight(150)
        self.perf_text.setFont(QFont("Courier", 10))
        perf_layout.addWidget(self.perf_text)
        perf_group.setLayout(perf_layout)
        
        # Timeline
        timeline_group = QGroupBox("Traffic Timeline (Last 100 data points)")
        timeline_layout = QVBoxLayout()
        
        self.timeline_text = QTextEdit()
        self.timeline_text.setMaximumHeight(120)
        self.timeline_text.setFont(QFont("Courier", 9))
        timeline_layout.addWidget(self.timeline_text)
        timeline_group.setLayout(timeline_layout)
        
        layout.addWidget(summary_group)
        layout.addWidget(perf_group)
        layout.addWidget(timeline_group)
        layout.addStretch()
        
        overview_widget.setLayout(layout)
        self.stats_tabs.addTab(overview_widget, "Overview")
    
    def setup_protocols_tab(self):
        """Setup protocol statistics"""
        protocols_widget = QWidget()
        layout = QVBoxLayout()
        
        # Protocol breakdown
        self.protocol_tree = QTreeWidget()
        self.protocol_tree.setHeaderLabels(['Protocol', 'Packets', 'Bytes', 'Percentage', 'Avg Size'])
        self.protocol_tree.setAlternatingRowColors(True)
        
        layout.addWidget(QLabel("Protocol Distribution:"))
        layout.addWidget(self.protocol_tree)
        
        protocols_widget.setLayout(layout)
        self.stats_tabs.addTab(protocols_widget, "Protocols")
    
    def setup_network_tab(self):
        """Setup network statistics"""
        network_widget = QWidget()
        layout = QVBoxLayout()
        
        # Create splitter for top talkers
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Source IPs
        src_group = QGroupBox("Top Source IPs")
        src_layout = QVBoxLayout()
        self.src_tree = QTreeWidget()
        self.src_tree.setHeaderLabels(['IP Address', 'Packets', 'Bytes', 'Type'])
        self.src_tree.setAlternatingRowColors(True)
        src_layout.addWidget(self.src_tree)
        src_group.setLayout(src_layout)
        
        # Destination IPs
        dst_group = QGroupBox("Top Destination IPs")
        dst_layout = QVBoxLayout()
        self.dst_tree = QTreeWidget()
        self.dst_tree.setHeaderLabels(['IP Address', 'Packets', 'Bytes', 'Type'])
        self.dst_tree.setAlternatingRowColors(True)
        dst_layout.addWidget(self.dst_tree)
        dst_group.setLayout(dst_layout)
        
        splitter.addWidget(src_group)
        splitter.addWidget(dst_group)
        
        # Ports section
        ports_group = QGroupBox("Top Ports")
        ports_layout = QVBoxLayout()
        self.ports_tree = QTreeWidget()
        self.ports_tree.setHeaderLabels(['Port', 'Packets', 'Service', 'Protocol'])
        self.ports_tree.setAlternatingRowColors(True)
        ports_layout.addWidget(self.ports_tree)
        ports_group.setLayout(ports_layout)
        
        layout.addWidget(splitter)
        layout.addWidget(ports_group)
        
        network_widget.setLayout(layout)
        self.stats_tabs.addTab(network_widget, "Network")
    
    def setup_security_tab(self):
        """Setup security-focused statistics"""
        security_widget = QWidget()
        layout = QVBoxLayout()
        
        # Security metrics
        security_group = QGroupBox("Security Metrics")
        security_layout = QVBoxLayout()
        
        self.security_text = QTextEdit()
        self.security_text.setMaximumHeight(200)
        self.security_text.setFont(QFont("Courier", 10))
        security_layout.addWidget(self.security_text)
        security_group.setLayout(security_layout)
        
        # Suspicious activity
        suspicious_group = QGroupBox("Suspicious Activity")
        suspicious_layout = QVBoxLayout()
        
        self.suspicious_tree = QTreeWidget()
        self.suspicious_tree.setHeaderLabels(['Type', 'Count', 'Details', 'Risk Level'])
        self.suspicious_tree.setAlternatingRowColors(True)
        suspicious_layout.addWidget(self.suspicious_tree)
        suspicious_group.setLayout(suspicious_layout)
        
        layout.addWidget(security_group)
        layout.addWidget(suspicious_group)
        layout.addStretch()
        
        security_widget.setLayout(layout)
        self.stats_tabs.addTab(security_widget, "Security")
    
    def update_stats(self, packet_data: Dict[str, Any]):
        """Update statistics with new packet"""
        self.total_packets += 1
        packet_size = packet_data.get('size', 0)
        self.total_bytes += packet_size
        protocol = packet_data['protocol']
        
        # Protocol stats
        self.protocol_stats[protocol] += 1
        self.protocol_bytes[protocol] += packet_size
        
        # IP stats
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        
        if self.is_valid_ip(src_ip):
            self.top_talkers_src[src_ip]["packets"] += 1
            self.top_talkers_src[src_ip]["bytes"] += packet_size
        
        if self.is_valid_ip(dst_ip):
            self.top_talkers_dst[dst_ip]["packets"] += 1
            self.top_talkers_dst[dst_ip]["bytes"] += packet_size
        
        # Port stats
        src_port = packet_data.get('src_port', '')
        dst_port = packet_data.get('dst_port', '')
        
        if str(src_port).isdigit():
            self.port_stats[int(src_port)] += 1
        if str(dst_port).isdigit():
            self.port_stats[int(dst_port)] += 1
        
        # Timeline data (packets per second)
        current_time = int(time.time())
        if not self.traffic_timeline or self.traffic_timeline[-1][0] != current_time:
            self.traffic_timeline.append([current_time, 1])
        else:
            self.traffic_timeline[-1][1] += 1
    
    def update_display(self):
        """Update all statistics displays"""
        self.update_overview()
        self.update_protocols()
        self.update_network()
        self.update_security()
    
    def update_overview(self):
        """Update overview statistics"""
        elapsed_time = time.time() - self.start_time
        pps = self.total_packets / max(elapsed_time, 1)
        bps = self.total_bytes / max(elapsed_time, 1)
        
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        
        summary = f"""TRAFFIC SUMMARY
═══════════════════════════════════════════════════════════
Total Packets:           {self.total_packets:,}
Total Bytes:             {self.format_bytes(self.total_bytes)}
Unique Protocols:        {len(self.protocol_stats)}
Unique Source IPs:       {len(self.top_talkers_src)}
Unique Destination IPs:  {len(self.top_talkers_dst)}
Active Ports:            {len(self.port_stats)}
Capture Duration:        {self.format_duration(elapsed_time)}

Average Packet Rate:     {pps:.1f} packets/second
Average Throughput:      {self.format_bytes(bps)}/second
"""
        
        self.summary_text.setText(summary)
        
        perf = f"""SYSTEM PERFORMANCE
═══════════════════════════════════════════════════════════
CPU Usage:               {cpu_percent:.1f}%
Memory Usage:            {memory_percent:.1f}%
Capture Thread:          {'Running' if hasattr(self, 'capture_thread') else 'Stopped'}
GUI Responsiveness:      {'Good' if cpu_percent < 50 else 'Moderate' if cpu_percent < 80 else 'Poor'}
"""
        
        self.perf_text.setText(perf)
        
        # Timeline
        if self.traffic_timeline:
            timeline_str = "Time       | Packets/sec\n"
            timeline_str += "=" * 30 + "\n"
            for timestamp, count in list(self.traffic_timeline)[-10:]:
                time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
                timeline_str += f"{time_str}    | {count:>8}\n"
            
            self.timeline_text.setText(timeline_str)
    
    def update_protocols(self):
        """Update protocol statistics"""
        self.protocol_tree.clear()
        
        sorted_protocols = sorted(self.protocol_stats.items(), 
                                 key=lambda x: x[1], reverse=True)[:20]
        
        for protocol, count in sorted_protocols:
            bytes_count = self.protocol_bytes[protocol]
            percentage = (count / self.total_packets) * 100 if self.total_packets > 0 else 0
            avg_size = bytes_count / count if count > 0 else 0
            
            item = QTreeWidgetItem([
                protocol,
                f"{count:,}",
                self.format_bytes(bytes_count),
                f"{percentage:.1f}%",
                f"{avg_size:.1f}B"
            ])
            self.protocol_tree.addTopLevelItem(item)
    
    def update_network(self):
        """Update network statistics"""
        # Source IPs
        self.src_tree.clear()
        sorted_src = sorted(self.top_talkers_src.items(),
                           key=lambda x: x[1]["packets"], reverse=True)[:15]
        
        for ip, stats in sorted_src:
            ip_type = self.get_ip_type(ip)
            item = QTreeWidgetItem([
                ip,
                f"{stats['packets']:,}",
                self.format_bytes(stats['bytes']),
                ip_type
            ])
            self.src_tree.addTopLevelItem(item)
        
        # Destination IPs
        self.dst_tree.clear()
        sorted_dst = sorted(self.top_talkers_dst.items(),
                           key=lambda x: x[1]["packets"], reverse=True)[:15]
        
        for ip, stats in sorted_dst:
            ip_type = self.get_ip_type(ip)
            item = QTreeWidgetItem([
                ip,
                f"{stats['packets']:,}",
                self.format_bytes(stats['bytes']),
                ip_type
            ])
            self.dst_tree.addTopLevelItem(item)
        
        # Ports
        self.ports_tree.clear()
        sorted_ports = sorted(self.port_stats.items(), 
                             key=lambda x: x[1], reverse=True)[:20]
        
        for port, count in sorted_ports:
            service = self.get_service_name(port)
            protocol_type = self.get_port_protocol(port)
            item = QTreeWidgetItem([
                str(port),
                f"{count:,}",
                service,
                protocol_type
            ])
            self.ports_tree.addTopLevelItem(item)
    
    def update_security(self):
        """Update security statistics"""
        # Security metrics
        suspicious_ports = [p for p in self.port_stats.keys() if p in [4444, 6666, 31337, 12345]]
        high_traffic_ips = [ip for ip, stats in self.top_talkers_src.items() 
                           if stats["packets"] > 1000]
        external_to_internal = sum(1 for ip in self.top_talkers_dst.keys() 
                                 if self.get_ip_type(ip) == "Private")
        
        security = f"""SECURITY OVERVIEW
═══════════════════════════════════════════════════════════
Suspicious Ports Detected:  {len(suspicious_ports)}
High-Traffic Sources:        {len(high_traffic_ips)}
External->Internal Flows:    {external_to_internal}
Protocol Diversity:          {len(self.protocol_stats)} protocols
Port Diversity:              {len(self.port_stats)} ports

Risk Assessment:             {'High' if len(suspicious_ports) > 0 else 'Medium' if len(high_traffic_ips) > 5 else 'Low'}
"""
        
        self.security_text.setText(security)
        
        # Suspicious activity
        self.suspicious_tree.clear()
        
        # Add suspicious ports
        for port in suspicious_ports:
            count = self.port_stats[port]
            item = QTreeWidgetItem([
                "Suspicious Port",
                str(count),
                f"Port {port}",
                "High"
            ])
            self.suspicious_tree.addTopLevelItem(item)
        
        # Add high traffic sources
        for ip in high_traffic_ips[:5]:
            stats = self.top_talkers_src[ip]
            item = QTreeWidgetItem([
                "High Traffic Source",
                str(stats["packets"]),
                f"IP: {ip}",
                "Medium"
            ])
            self.suspicious_tree.addTopLevelItem(item)
    
    def clear_stats(self):
        """Clear all statistics"""
        self.protocol_stats.clear()
        self.protocol_bytes.clear()
        self.top_talkers_src.clear()
        self.top_talkers_dst.clear()
        self.port_stats.clear()
        self.traffic_timeline.clear()
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.update_display()
    
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ip_address(ip_str)
            return True
        except (AddressValueError, ValueError):
            return False
    
    @staticmethod
    def get_ip_type(ip_str: str) -> str:
        """Get IP address type"""
        try:
            ip = ip_address(ip_str)
            if ip.is_private:
                return "Private"
            elif ip.is_loopback:
                return "Loopback"
            elif ip.is_multicast:
                return "Multicast"
            else:
                return "Public"
        except:
            return "Unknown"
    
    @staticmethod
    def get_service_name(port: int) -> str:
        """Get service name for port"""
        common_ports = {
            20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
            69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
            161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 1433: "SQL Server", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 4444: "Metasploit", 6666: "IRC/Backdoor",
            31337: "Elite/Backdoor", 12345: "NetBus"
        }
        
        if port in common_ports:
            return common_ports[port]
        try:
            return socket.getservbyport(port).upper()
        except:
            return "Unknown"
    
    @staticmethod
    def get_port_protocol(port: int) -> str:
        """Get likely protocol for port"""
        tcp_ports = [20, 21, 22, 23, 25, 80, 110, 143, 389, 443, 445, 993, 995, 1433, 3306, 3389, 5432]
        udp_ports = [53, 67, 68, 69, 123, 161, 162]
        
        if port in tcp_ports:
            return "TCP"
        elif port in udp_ports:
            return "UDP"
        else:
            return "TCP/UDP"
    
    @staticmethod
    def format_bytes(bytes_count: int) -> str:
        """Format bytes into human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_count < 1024:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024
        return f"{bytes_count:.1f} TB"
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration into human readable format"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"

class SettingsWidget(QWidget):
    """Simple settings panel"""
    
    def __init__(self):
        super().__init__()
        self.settings = QSettings("SimpleShark", "PyQt6")
        self.setup_ui()
        self.load_settings()
    
    def setup_ui(self):
        """Setup settings UI"""
        layout = QVBoxLayout()
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QVBoxLayout()
        
        # Interface selection
        interface_layout = QHBoxLayout()
        interface_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        interface_layout.addWidget(self.interface_combo)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(refresh_btn)
        network_layout.addLayout(interface_layout)
        
        # Capture filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("e.g., tcp port 80 or host 192.168.1.1")
        filter_layout.addWidget(self.filter_edit)
        network_layout.addLayout(filter_layout)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Performance settings
        perf_group = QGroupBox("Performance Settings")
        perf_layout = QVBoxLayout()
        
        # Max packets
        max_layout = QHBoxLayout()
        max_layout.addWidget(QLabel("Max packets in table:"))
        self.max_packets_spin = QSpinBox()
        self.max_packets_spin.setRange(1000, 50000)
        self.max_packets_spin.setValue(5000)
        max_layout.addWidget(self.max_packets_spin)
        perf_layout.addLayout(max_layout)
        
        perf_group.setLayout(perf_layout)
        layout.addWidget(perf_group)
        
        # Save/Load buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(save_btn)
        
        load_btn = QPushButton("Load Settings")
        load_btn.clicked.connect(self.load_settings)
        button_layout.addWidget(load_btn)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def refresh_interfaces(self):
        """Refresh available network interfaces"""
        self.interface_combo.clear()
        try:
            interfaces = list(psutil.net_if_addrs().keys())
            # Filter out loopback and virtual interfaces
            filtered = [iface for iface in interfaces 
                       if not iface.startswith(('lo', 'Loopback', 'vEthernet'))]
            self.interface_combo.addItems(filtered if filtered else interfaces)
        except Exception as e:
            logger.error(f"Error refreshing interfaces: {e}")
    
    def get_interface(self) -> str:
        """Get selected interface"""
        return self.interface_combo.currentText()
    
    def get_filter(self) -> str:
        """Get capture filter"""
        return self.filter_edit.text().strip()
    
    def get_max_packets(self) -> int:
        """Get max packets setting"""
        return self.max_packets_spin.value()
    
    def save_settings(self):
        """Save settings to file"""
        self.settings.setValue("interface", self.get_interface())
        self.settings.setValue("filter", self.get_filter())
        self.settings.setValue("max_packets", self.get_max_packets())
        QMessageBox.information(self, "Settings", "Settings saved successfully")
    
    def load_settings(self):
        """Load settings from file"""
        interface = self.settings.value("interface", "")
        if interface:
            index = self.interface_combo.findText(interface)
            if index >= 0:
                self.interface_combo.setCurrentIndex(index)
        
        filter_text = self.settings.value("filter", "")
        self.filter_edit.setText(filter_text)
        
        max_packets = self.settings.value("max_packets", 5000, type=int)
        self.max_packets_spin.setValue(max_packets)

class SimpleShark(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.capture_thread = None
        self.packet_count = 0
        self.setup_ui()
        self.setup_dark_theme()
        
        logger.info("SimpleShark initialized by clearblueyellow on 2025-05-25")
        
    def setup_ui(self):
        """Setup main user interface"""
        self.setWindowTitle("SimpleShark - Lightweight Network Traffic Analyzer v2.0")
        self.setGeometry(100, 100, 1400, 900)
        
        # Central widget with tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Control buttons
        self.setup_controls(layout)
        
        # Tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Packet table tab
        self.packet_table = PacketTableWidget()
        self.tabs.addTab(self.packet_table, "Traffic Monitor")
        
        # Enhanced statistics tab
        self.stats_widget = EnhancedStatsWidget()
        self.tabs.addTab(self.stats_widget, "Statistics")
        
        # Settings tab
        self.settings_widget = SettingsWidget()
        self.tabs.addTab(self.settings_widget, "Settings")
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - SimpleShark v2.0 by clearblueyellow")
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        self.status_bar.addPermanentWidget(self.progress_bar)
    
    def setup_controls(self, layout):
        """Setup control buttons"""
        controls = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        controls.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹ Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        controls.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("🗑 Clear Data")
        self.clear_btn.clicked.connect(self.clear_data)
        controls.addWidget(self.clear_btn)
        
        self.export_btn = QPushButton("💾 Export CSV")
        self.export_btn.clicked.connect(self.export_data)
        controls.addWidget(self.export_btn)
        
        controls.addStretch()
        
        self.packet_label = QLabel("Packets: 0")
        controls.addWidget(self.packet_label)
        
        self.rate_label = QLabel("Rate: 0 pps")
        controls.addWidget(self.rate_label)
        
        layout.addLayout(controls)
    
    def setup_dark_theme(self):
        """Apply enhanced dark theme"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QPushButton {
                background-color: #4a90e2;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #357abd;
            }
            QPushButton:pressed {
                background-color: #2968a3;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #4a90e2;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555555;
                border-radius: 6px;
                margin-top: 1ex;
                padding-top: 15px;
                background-color: #2b2b2b;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px 0 8px;
                color: #4a90e2;
            }
            QTextEdit {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 4px;
            }
            QTreeWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555555;
                alternate-background-color: #3c3c3c;
            }
            QTreeWidget::item:selected {
                background-color: #4a90e2;
            }
            QLabel {
                color: #ffffff;
            }
            QStatusBar {
                background-color: #3c3c3c;
                color: #ffffff;
                border-top: 1px solid #555555;
            }
        """)
    
    def start_capture(self):
        """Start packet capture"""
        interface = self.settings_widget.get_interface()
        if not interface:
            QMessageBox.warning(self, "Error", "Please select a network interface from Settings tab")
            self.tabs.setCurrentIndex(2)  # Switch to settings tab
            return
        
        # Update table max rows
        self.packet_table.max_rows = self.settings_widget.get_max_packets()
        
        # Start capture thread
        capture_filter = self.settings_widget.get_filter()
        self.capture_thread = PacketCapture(interface, capture_filter)
        self.capture_thread.packet_received.connect(self.on_packet_received)
        self.capture_thread.status_update.connect(self.status_bar.showMessage)
        self.capture_thread.start()
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.showMessage(f"📡 Capturing on {interface}")
        
        # Reset stats
        self.stats_widget.clear_stats()
        
        logger.info(f"Started packet capture on {interface} with filter: '{capture_filter}'")
    
    def stop_capture(self):
        """Stop packet capture"""
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait(3000)  # Wait up to 3 seconds
        
        # Update UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("⏹ Capture stopped")
        
        logger.info("Packet capture stopped")
    
    def on_packet_received(self, packet_data: Dict[str, Any], raw_packet):
        """Handle received packet"""
        self.packet_table.add_packet(packet_data)
        self.stats_widget.update_stats(packet_data)
        
        self.packet_count += 1
        self.packet_label.setText(f"Packets: {self.packet_count:,}")
        
        # Update rate calculation
        if hasattr(self, 'start_time'):
            elapsed = time.time() - self.start_time
            rate = self.packet_count / max(elapsed, 1)
            self.rate_label.setText(f"Rate: {rate:.1f} pps")
        else:
            self.start_time = time.time()
    
    def clear_data(self):
        """Clear all captured data"""
        reply = QMessageBox.question(
            self, "Clear Data", 
            "Are you sure you want to clear all captured data?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.packet_table.setRowCount(0)
            self.packet_table.packet_counter = 1
            self.stats_widget.clear_stats()
            self.packet_count = 0
            self.packet_label.setText("Packets: 0")
            self.rate_label.setText("Rate: 0 pps")
            self.start_time = time.time()
            
            logger.info("Data cleared by user")
    
    def export_data(self):
        """Export data to CSV"""
        if self.packet_table.rowCount() == 0:
            QMessageBox.warning(self, "Export", "No data to export")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Data", 
            f"simpleshark_export_{timestamp}.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if filename:
            try:
                # Extract data from table
                data = []
                for row in range(self.packet_table.rowCount()):
                    row_data = []
                    for col in range(self.packet_table.columnCount()):
                        item = self.packet_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    data.append(row_data)
                
                # Create DataFrame and save
                columns = ['Packet#', 'Time', 'Protocol', 'Source', 'Destination', 'Size', 'Info']
                df = pd.DataFrame(data, columns=columns)
                df.to_csv(filename, index=False)
                
                QMessageBox.information(self, "Export Complete", 
                                      f"Data exported successfully to:\n{filename}\n\n"
                                      f"Rows exported: {len(data):,}")
                logger.info(f"Data exported to {filename} ({len(data)} rows)")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export data:\n{e}")
                logger.error(f"Export failed: {e}")
    
    def closeEvent(self, event):
        """Handle application closing"""
        if self.capture_thread and self.capture_thread.isRunning():
            self.stop_capture()
        event.accept()
        logger.info("SimpleShark closed by clearblueyellow")

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("SimpleShark")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("clearblueyellow")
    
    # Check for required permissions
    try:
        import os
        if os.name == 'nt':  # Windows
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                QMessageBox.warning(
                    None, "Permissions", 
                    "SimpleShark is running without administrator privileges.\n"
                    "Packet capture may not work properly.\n"
                    "Consider running as administrator."
                )
        else:  # Unix-like
            if os.geteuid() != 0:
                QMessageBox.warning(
                    None, "Permissions",
                    "SimpleShark is running without root privileges.\n"
                    "Packet capture may not work properly.\n"
                    "Consider running with sudo."
                )
    except Exception:
        pass
    
    # Create and show main window
    window = SimpleShark()
    window.show()
    
    logger.info("SimpleShark v2.0 started successfully by clearblueyellow on 2025-05-25")
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

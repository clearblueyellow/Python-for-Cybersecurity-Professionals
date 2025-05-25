import iocextract
import ioc_finder
import yara
import json
import os
import datetime
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font
import threading
from collections import defaultdict

class IoCScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SimpleExtractor")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.current_file = tk.StringVar()
        self.scan_progress = tk.DoubleVar()
        self.results_data = {}
        
        self.setup_gui()
        self.setup_custom_regex()
        
    def setup_gui(self):
        # Title
        title_font = Font(family="Arial", size=16, weight="bold")
        title_label = tk.Label(self.root, text="SimpleExtractor", 
                              font=title_font, bg='#f0f0f0', fg='#2c3e50')
        title_label.pack(pady=10)
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left panel - Input and controls
        left_panel = ttk.LabelFrame(main_frame, text="Input & Controls", padding=10)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 5))
        
        # File selection
        file_frame = ttk.Frame(left_panel)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="Selected File:").pack(anchor=tk.W)
        ttk.Entry(file_frame, textvariable=self.current_file, state='readonly', width=40).pack(fill=tk.X, pady=2)
        
        ttk.Button(file_frame, text="Browse File", command=self.browse_file).pack(pady=2)
        ttk.Button(file_frame, text="Load Sample Text", command=self.load_sample_text).pack(pady=2)
        
        # Text input area
        text_frame = ttk.LabelFrame(left_panel, text="Text Input", padding=5)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.text_input = scrolledtext.ScrolledText(text_frame, height=10, width=50, wrap=tk.WORD)
        self.text_input.pack(fill=tk.BOTH, expand=True)
        
        # Scan options
        options_frame = ttk.LabelFrame(left_panel, text="Scan Options", padding=5)
        options_frame.pack(fill=tk.X, pady=5)
        
        self.use_yara = tk.BooleanVar(value=True)
        self.use_custom_regex = tk.BooleanVar(value=True)
        self.use_advanced_patterns = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="YARA Rules", variable=self.use_yara).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="Custom Regex", variable=self.use_custom_regex).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="Advanced Patterns", variable=self.use_advanced_patterns).pack(anchor=tk.W)
        
        # Scan button and progress
        control_frame = ttk.Frame(left_panel)
        control_frame.pack(fill=tk.X, pady=10)
        
        self.scan_button = ttk.Button(control_frame, text="🔍 Scan for IoCs", command=self.start_scan)
        self.scan_button.pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(control_frame, variable=self.scan_progress, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(control_frame, text="Ready to scan...")
        self.status_label.pack()
        
        # Right panel - Results
        right_panel = ttk.LabelFrame(main_frame, text="Scan Results", padding=10)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Results notebook
        self.results_notebook = ttk.Notebook(right_panel)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary tab
        self.summary_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.summary_frame, text="📊 Summary")
        
        self.summary_text = scrolledtext.ScrolledText(self.summary_frame, height=10, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True)
        
        # Detailed results tab
        self.details_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.details_frame, text="📋 Detailed Results")
        
        self.details_tree = ttk.Treeview(self.details_frame, columns=('Type', 'Value', 'Confidence'), show='tree headings')
        self.details_tree.heading('#0', text='Category')
        self.details_tree.heading('Type', text='Type')
        self.details_tree.heading('Value', text='Value')
        self.details_tree.heading('Confidence', text='Confidence')
        
        details_scrollbar = ttk.Scrollbar(self.details_frame, orient=tk.VERTICAL, command=self.details_tree.yview)
        self.details_tree.configure(yscrollcommand=details_scrollbar.set)
        
        self.details_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Export tab
        self.export_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.export_frame, text="💾 Export")
        
        # Export content with scrollable frame
        export_canvas = tk.Canvas(self.export_frame)
        export_scrollbar = ttk.Scrollbar(self.export_frame, orient="vertical", command=export_canvas.yview)
        export_content = ttk.Frame(export_canvas)
        
        export_content.bind(
            "<Configure>",
            lambda e: export_canvas.configure(scrollregion=export_canvas.bbox("all"))
        )
        
        export_canvas.create_window((0, 0), window=export_content, anchor="nw")
        export_canvas.configure(yscrollcommand=export_scrollbar.set)
        
        export_canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        export_scrollbar.pack(side="right", fill="y")
        
        # Export title and description
        export_title = ttk.Label(export_content, text="Export Scan Results", 
                                font=('Arial', 12, 'bold'))
        export_title.pack(pady=(0, 10))
        
        export_desc = ttk.Label(export_content, 
                               text="Choose a format to export your IoC scan results:",
                               font=('Arial', 9))
        export_desc.pack(pady=(0, 15))
        
        # Export buttons in a grid layout (2x2 with status at bottom)
        buttons_container = ttk.Frame(export_content)
        buttons_container.pack(fill=tk.BOTH, expand=True)
        
        # First row - JSON and CSV
        row1_frame = ttk.Frame(buttons_container)
        row1_frame.pack(fill=tk.X, pady=(0, 10))
        
        # JSON Export (left)
        json_frame = ttk.LabelFrame(row1_frame, text="JSON Format", padding=10)
        json_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        ttk.Label(json_frame, text="• Structured data format", font=('Arial', 8)).pack(anchor=tk.W)
        ttk.Label(json_frame, text="• Best for programmatic analysis", font=('Arial', 8)).pack(anchor=tk.W)
        ttk.Label(json_frame, text="• Includes metadata", font=('Arial', 8)).pack(anchor=tk.W)
        ttk.Button(json_frame, text="📄 Export JSON", command=self.export_json).pack(pady=(8, 0), fill=tk.X)
        
        # CSV Export (right)
        csv_frame = ttk.LabelFrame(row1_frame, text="CSV Format", padding=10)
        csv_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        ttk.Label(csv_frame, text="• Spreadsheet compatible", font=('Arial', 8)).pack(anchor=tk.W)
        ttk.Label(csv_frame, text="• Excel/Google Sheets ready", font=('Arial', 8)).pack(anchor=tk.W)
        ttk.Label(csv_frame, text="• Tabular format", font=('Arial', 8)).pack(anchor=tk.W)
        ttk.Button(csv_frame, text="📊 Export CSV", command=self.export_csv).pack(pady=(8, 0), fill=tk.X)
        
        # Second row - TXT
        row2_frame = ttk.Frame(buttons_container)
        row2_frame.pack(fill=tk.X, pady=(0, 15))
        
        # TXT Export (full width)
        txt_frame = ttk.LabelFrame(row2_frame, text="Text Format", padding=10)
        txt_frame.pack(fill=tk.X)
        
        # Text format details in a horizontal layout to save space
        txt_details_frame = ttk.Frame(txt_frame)
        txt_details_frame.pack(fill=tk.X, pady=(0, 8))
        
        ttk.Label(txt_details_frame, text="• Human-readable format  • Perfect for reports  • Includes summary and details", 
                 font=('Arial', 8)).pack(anchor=tk.W)
        
        ttk.Button(txt_frame, text="📝 Export TXT", command=self.export_txt).pack(fill=tk.X)
        
        # Export status
        self.export_status = ttk.Label(export_content, text="", font=('Arial', 9))
        self.export_status.pack(pady=(10, 0))
        
    def setup_custom_regex(self):
        """Define custom regex patterns for advanced IoC detection"""
        self.custom_patterns = {
            'crypto_addresses': {
                'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
                'monero': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
            },
            'network_indicators': {
                'registry_keys': r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*',
                'file_paths': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
                'mutex_names': r'Global\\[A-Za-z0-9_-]+',
                'service_names': r'sc\s+create\s+([A-Za-z0-9_-]+)',
                'powershell_encoded': r'powershell.*-[Ee]ncodedCommand\s+([A-Za-z0-9+/=]+)',
            },
            'web_indicators': {
                'user_agents': r'User-Agent:\s*([^\r\n]+)',
                'base64_strings': r'[A-Za-z0-9+/]{20,}={0,2}',
                'jwt_tokens': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            },
            'malware_indicators': {
                'pdb_paths': r'[A-Za-z]:\\.*\.pdb',
                'pe_timestamps': r'TimeDateStamp:\s*([0-9A-Fa-f]{8})',
                'yara_rule_refs': r'rule\s+([A-Za-z0-9_]+)\s*\{',
            }
        }
        
        # Enhanced YARA rules
        self.yara_rules = """
        rule malware_keywords {
            strings:
                $a1 = "backdoor" nocase
                $a2 = "trojan" nocase
                $a3 = "malware" nocase
                $a4 = "ransomware" nocase
                $a5 = "rootkit" nocase
                $a6 = "keylogger" nocase
                $a7 = "botnet" nocase
                $a8 = "c2" nocase
                $a9 = "command and control" nocase
                $a10 = "persistence" nocase
            condition:
                any of them
        }
        
        rule suspicious_powershell {
            strings:
                $p1 = "powershell" nocase
                $p2 = "-encodedcommand" nocase
                $p3 = "-windowstyle hidden" nocase
                $p4 = "-executionpolicy bypass" nocase
                $p5 = "invoke-expression" nocase
                $p6 = "downloadstring" nocase
            condition:
                any of them
        }
        
        rule network_indicators {
            strings:
                $n1 = /tcp:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+/
                $n2 = /https?:\/\/[a-zA-Z0-9.-]+\/[a-zA-Z0-9.\/_-]*/
                $n3 = "telnet" nocase
                $n4 = "netcat" nocase
                $n5 = "reverse shell" nocase
            condition:
                any of them
        }
        """
    
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a text file containing IoCs",
            filetypes=[("Text Files", "*.txt"), ("Log Files", "*.log"), ("All Files", "*.*")]
        )
        if file_path:
            self.current_file.set(file_path)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.text_input.delete(1.0, tk.END)
                self.text_input.insert(1.0, content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def load_sample_text(self):
        """Load sample text with various IoCs for testing"""
        sample_text = """
INCIDENT REPORT - Security Alert #2024-001
========================================

Timeline: 2024-01-15 14:30:00 UTC

NETWORK INDICATORS:
- Suspicious connection to 192.168.1.100:4444
- Malicious domain: evil-command-control.com
- C2 callback URL: https://malware-c2.example.org/api/callback
- Secondary C2: http://backup-c2.net:8080/update

FILE INDICATORS:
- Malicious executable: C:\\Windows\\Temp\\malware.exe
- Persistence registry key: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor
- Mutex created: Global\\MalwareMutex2024
- PDB path found: C:\\Projects\\Malware\\Release\\trojan.pdb

CRYPTOCURRENCY ADDRESSES:
- Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
- Ethereum: 0x32Be343B94f860124dC4fEe278FDCBD38C102D88

EMAIL INDICATORS:
- Phishing sender: attacker@phishing-domain.org
- Reply-to: noreply@fake-bank.com

HASHES:
- MD5: 5d41402abc4b2a76b9719d911017c592
- SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
- SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

POWERSHELL ACTIVITY:
powershell.exe -encodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==

USER AGENTS:
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Malware/1.0

CVE REFERENCES:
- CVE-2023-12345
- CVE-2024-67890

YARA MATCHES:
Detected backdoor functionality in sample
Trojan behavior identified
Persistence mechanism found

Additional suspicious IPs:
10.0.0.1, 172.16.0.1, 203.0.113.1

MAC Addresses: 00:1B:44:11:3A:B7

Analysis indicates this is a sophisticated malware campaign using multiple persistence mechanisms.
        """
        self.text_input.delete(1.0, tk.END)
        self.text_input.insert(1.0, sample_text)
        self.current_file.set("Sample Text Loaded")
    
    def start_scan(self):
        """Start IoC scanning in a separate thread"""
        text_content = self.text_input.get(1.0, tk.END).strip()
        if not text_content:
            messagebox.showwarning("Warning", "Please enter text or load a file first.")
            return
        
        self.scan_button.config(state='disabled', text='Scanning...')
        self.progress_bar.config(value=0)
        
        # Start scanning in separate thread to prevent GUI freezing
        thread = threading.Thread(target=self.perform_scan, args=(text_content,))
        thread.daemon = True
        thread.start()
    
    def perform_scan(self, text_content):
        """Perform the actual IoC scanning"""
        try:
            self.update_progress(10, "Initializing scan...")
            
            # Initialize results
            self.results_data = defaultdict(list)
            
            # Standard IoC extraction
            self.update_progress(20, "Extracting standard IoCs...")
            standard_iocs = self.extract_standard_iocs(text_content)
            
            # Custom regex patterns
            if self.use_custom_regex.get():
                self.update_progress(40, "Applying custom regex patterns...")
                custom_iocs = self.extract_custom_patterns(text_content)
                self.merge_results(custom_iocs)
            
            # Advanced pattern matching
            if self.use_advanced_patterns.get():
                self.update_progress(60, "Running advanced pattern matching...")
                advanced_iocs = self.extract_advanced_patterns(text_content)
                self.merge_results(advanced_iocs)
            
            # YARA rules
            if self.use_yara.get():
                self.update_progress(80, "Applying YARA rules...")
                yara_results = self.extract_yara_matches(text_content)
                if yara_results:
                    self.results_data['yara_matches'] = yara_results
            
            self.merge_results(standard_iocs)
            
            self.update_progress(100, "Scan complete!")
            
            # Update GUI with results
            self.root.after(0, self.display_results)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.scan_button.config(state='normal', text='🔍 Scan for IoCs'))
    
    def update_progress(self, value, status):
        """Update progress bar and status"""
        self.root.after(0, lambda: [
            self.progress_bar.config(value=value),
            self.status_label.config(text=status)
        ])
    
    def extract_standard_iocs(self, text_content):
        """Extract IoCs using standard libraries"""
        iocs = {}
        
        # iocextract
        iocs['urls'] = list(set(iocextract.extract_urls(text_content)))
        iocs['ips'] = list(set(iocextract.extract_ips(text_content)))
        iocs['emails'] = list(set(iocextract.extract_emails(text_content)))
        iocs['md5_hashes'] = list(set(iocextract.extract_md5_hashes(text_content)))
        iocs['sha1_hashes'] = list(set(iocextract.extract_sha1_hashes(text_content)))
        iocs['sha256_hashes'] = list(set(iocextract.extract_sha256_hashes(text_content)))
        
        # ioc-finder
        found = ioc_finder.find_iocs(text_content)
        iocs.update({
            'domains': found.get('domains', []),
            'ipv4_addresses': found.get('ipv4s', []),
            'ipv6_addresses': found.get('ipv6s', []),
            'bitcoin_addresses': found.get('bitcoin_addresses', []),
            'cves': found.get('cves', []),
            'mac_addresses': found.get('mac_addresses', []),
            'user_agents': found.get('user_agents', []),
        })
        
        return iocs
    
    def extract_custom_patterns(self, text_content):
        """Extract IoCs using custom regex patterns"""
        results = {}
        
        for category, patterns in self.custom_patterns.items():
            category_results = []
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, text_content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match else ""
                    if match:
                        category_results.append({
                            'value': match,
                            'type': pattern_name,
                            'confidence': 'Medium'
                        })
            
            if category_results:
                results[category] = category_results
        
        return results
    
    def extract_advanced_patterns(self, text_content):
        """Extract IoCs using advanced pattern matching"""
        results = {}
        
        # Extract timestamps
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}',
            r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}',
        ]
        
        timestamps = []
        for pattern in timestamp_patterns:
            matches = re.findall(pattern, text_content)
            timestamps.extend(matches)
        
        if timestamps:
            results['timestamps'] = [{'value': ts, 'type': 'timestamp', 'confidence': 'High'} for ts in timestamps]
        
        # Extract base64 encoded content (potential payloads)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, text_content)
        potential_base64 = []
        
        for match in base64_matches:
            if len(match) % 4 == 0 and len(match) > 20:  # Valid base64 length
                potential_base64.append({
                    'value': match[:50] + '...' if len(match) > 50 else match,
                    'type': 'base64_encoded',
                    'confidence': 'Medium'
                })
        
        if potential_base64:
            results['encoded_content'] = potential_base64
        
        return results
    
    def extract_yara_matches(self, text_content):
        """Apply YARA rules to the text"""
        try:
            rules = yara.compile(source=self.yara_rules)
            matches = rules.match(data=text_content)
            return [{'rule': match.rule, 'strings': [str(s) for s in match.strings]} for match in matches]
        except Exception as e:
            return [{'error': f"YARA error: {str(e)}"}]
    
    def merge_results(self, new_results):
        """Merge new results into main results"""
        for key, value in new_results.items():
            if key in self.results_data:
                if isinstance(value, list) and isinstance(self.results_data[key], list):
                    self.results_data[key].extend(value)
                else:
                    self.results_data[key] = value
            else:
                self.results_data[key] = value
    
    def display_results(self):
        """Display scan results in the GUI"""
        # Clear previous results
        self.summary_text.delete(1.0, tk.END)
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)
        
        if not self.results_data:
            self.summary_text.insert(1.0, "No IoCs found in the provided text.")
            return
        
        # Generate summary
        summary = self.generate_summary()
        self.summary_text.insert(1.0, summary)
        
        # Populate detailed tree view
        self.populate_tree_view()
    
    def generate_summary(self):
        """Generate a summary of the scan results"""
        total_iocs = 0
        summary_lines = ["🔍 SimpleExtractor Scan Summary\n", "=" * 35, "\n\n"]
        
        for category, items in self.results_data.items():
            if isinstance(items, list):
                count = len(items)
                total_iocs += count
                summary_lines.append(f"📋 {category.replace('_', ' ').title()}: {count} found\n")
            else:
                summary_lines.append(f"📋 {category.replace('_', ' ').title()}: {items}\n")
        
        summary_lines.extend(["\n", "=" * 35, "\n", f"🎯 Total IoCs Found: {total_iocs}\n"])
        summary_lines.append(f"⏰ Scan completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        return "".join(summary_lines)
    
    def populate_tree_view(self):
        """Populate the tree view with detailed results"""
        for category, items in self.results_data.items():
            category_node = self.details_tree.insert('', 'end', text=category.replace('_', ' ').title(), values=('', '', ''))
            
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        self.details_tree.insert(category_node, 'end', text='', 
                                               values=(item.get('type', ''), 
                                                      item.get('value', str(item)), 
                                                      item.get('confidence', 'Unknown')))
                    else:
                        self.details_tree.insert(category_node, 'end', text='', 
                                               values=('', str(item), 'Standard'))
            else:
                self.details_tree.insert(category_node, 'end', text='', 
                                       values=('', str(items), 'Standard'))
    
    def update_export_status(self, message, success=True):
        """Update export status message"""
        if success:
            self.export_status.config(text=f"✅ {message}", foreground='green')
        else:
            self.export_status.config(text=f"❌ {message}", foreground='red')
        
        # Clear status after 3 seconds
        self.root.after(3000, lambda: self.export_status.config(text=""))
    
    def export_json(self):
        """Export results to JSON file"""
        if not self.results_data:
            self.update_export_status("No data to export", False)
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save IoC results as JSON"
        )
        
        if filename:
            try:
                # Convert defaultdict to regular dict for JSON serialization
                export_data = dict(self.results_data)
                export_data['scan_metadata'] = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'total_iocs': sum(len(v) if isinstance(v, list) else 1 for v in export_data.values()),
                    'scanned_by': 'SimpleExtractor'
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, default=str)
                self.update_export_status(f"JSON exported to {os.path.basename(filename)}")
            except Exception as e:
                self.update_export_status(f"JSON export failed: {str(e)}", False)
    
    def export_csv(self):
        """Export results to CSV file"""
        if not self.results_data:
            self.update_export_status("No data to export", False)
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save IoC results as CSV"
        )
        
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Category', 'Type', 'Value', 'Confidence'])
                    
                    for category, items in self.results_data.items():
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict):
                                    writer.writerow([category, item.get('type', ''), 
                                                   item.get('value', str(item)), 
                                                   item.get('confidence', 'Unknown')])
                                else:
                                    writer.writerow([category, '', str(item), 'Standard'])
                        else:
                            writer.writerow([category, '', str(items), 'Standard'])
                
                self.update_export_status(f"CSV exported to {os.path.basename(filename)}")
            except Exception as e:
                self.update_export_status(f"CSV export failed: {str(e)}", False)
    
    def export_txt(self):
        """Export results to text file"""
        if not self.results_data:
            self.update_export_status("No data to export", False)
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save IoC results as text"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.summary_text.get(1.0, tk.END))
                    f.write("\n\nDetailed Results:\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for category, items in self.results_data.items():
                        f.write(f"{category.replace('_', ' ').title()}:\n")
                        f.write("-" * 30 + "\n")
                        
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict):
                                    f.write(f"  Type: {item.get('type', 'Unknown')}\n")
                                    f.write(f"  Value: {item.get('value', str(item))}\n")
                                    f.write(f"  Confidence: {item.get('confidence', 'Unknown')}\n\n")
                                else:
                                    f.write(f"  {str(item)}\n")
                        else:
                            f.write(f"  {str(items)}\n")
                        f.write("\n")
                
                self.update_export_status(f"TXT exported to {os.path.basename(filename)}")
            except Exception as e:
                self.update_export_status(f"TXT export failed: {str(e)}", False)

def main():
    root = tk.Tk()
    app = IoCScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

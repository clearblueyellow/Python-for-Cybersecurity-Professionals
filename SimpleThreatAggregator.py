import os
import json
import time
import httpx
import asyncio
import pandas as pd
import threading
import sys
from datetime import datetime, timezone
from queue import Queue
import sqlite3
import functools
import random
from typing import List, Dict, Any, Optional, AsyncContextManager
from contextlib import asynccontextmanager
from dataclasses import dataclass
from collections import defaultdict, deque

# PyQt6 imports
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton, 
                            QTextEdit, QCheckBox, QGroupBox, QTabWidget, QMessageBox,
                            QFileDialog, QDialog, QDialogButtonBox, QTableWidget,
                            QTableWidgetItem, QHeaderView, QFrame, QScrollArea,
                            QSplitter, QProgressBar, QComboBox, QSpinBox)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt, QSize
from PyQt6.QtGui import QFont, QPalette, QColor, QIcon

# For REST API
from fastapi import FastAPI, HTTPException, Security, Request, BackgroundTasks
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# --- Dark Theme Configuration ---
DARK_PALETTE = QPalette()
DARK_PALETTE.setColor(QPalette.ColorRole.Window, QColor(43, 43, 43))
DARK_PALETTE.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
DARK_PALETTE.setColor(QPalette.ColorRole.Base, QColor(64, 64, 64))
DARK_PALETTE.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
DARK_PALETTE.setColor(QPalette.ColorRole.ToolTipBase, QColor(0, 0, 0))
DARK_PALETTE.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
DARK_PALETTE.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
DARK_PALETTE.setColor(QPalette.ColorRole.Button, QColor(64, 64, 64))
DARK_PALETTE.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
DARK_PALETTE.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
DARK_PALETTE.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
DARK_PALETTE.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
DARK_PALETTE.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))

# --- Configuration for API Key ---
API_KEY_NAME = "X-API-Key"
API_KEY_HEADER = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# --- Data Models ---
@dataclass
class ThreatIOC:
    """Data class for threat indicators"""
    ioc_type: str
    ioc_value: str
    source_provider: str
    raw_data: dict
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = None
    threat_score: float = 0.0
    timestamp: Optional[datetime] = None
    
    def to_dict(self) -> dict:
        return {
            'ioc_type': self.ioc_type,
            'ioc_value': self.ioc_value,
            'source_provider': self.source_provider,
            'raw_data': json.dumps(self.raw_data),
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'tags': json.dumps(self.tags or []),
            'threat_score': self.threat_score,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

@dataclass
class ProviderMetrics:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_records: int = 0
    avg_response_time: float = 0.0
    last_success: Optional[float] = None
    last_failure: Optional[float] = None
    error_counts: Dict[str, int] = None
    
    def __post_init__(self):
        if self.error_counts is None:
            self.error_counts = defaultdict(int)

# --- Metrics Collection ---
class MetricsCollector:
    def __init__(self):
        self.provider_metrics = defaultdict(ProviderMetrics)
        self.response_times = defaultdict(lambda: deque(maxlen=100))
    
    def record_request(self, provider: str, success: bool, 
                      response_time: float, record_count: int = 0,
                      error_type: str = None):
        """Record metrics for a provider request"""
        metrics = self.provider_metrics[provider]
        metrics.total_requests += 1
        
        if success:
            metrics.successful_requests += 1
            metrics.total_records += record_count
            metrics.last_success = time.time()
        else:
            metrics.failed_requests += 1
            metrics.last_failure = time.time()
            if error_type:
                metrics.error_counts[error_type] += 1
        
        # Update response time
        self.response_times[provider].append(response_time)
        metrics.avg_response_time = sum(self.response_times[provider]) / len(self.response_times[provider])
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        health = {}
        for provider, metrics in self.provider_metrics.items():
            success_rate = (metrics.successful_requests / max(metrics.total_requests, 1)) * 100
            health[provider] = {
                'success_rate': success_rate,
                'avg_response_time': metrics.avg_response_time,
                'status': 'healthy' if success_rate > 80 else 'degraded' if success_rate > 50 else 'unhealthy'
            }
        return health

# --- Database Utilities ---
def init_db(db_path, log_callback=None):
    """Initializes the SQLite database and creates tables if they don't exist."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS aggregated_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_provider TEXT NOT NULL,
            ioc_type TEXT,
            ioc_value TEXT NOT NULL UNIQUE,
            raw_data TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            tags TEXT,
            threat_score REAL DEFAULT 0.0,
            processed_at TEXT NOT NULL 
        )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON aggregated_threats (ioc_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_source_provider ON aggregated_threats (source_provider)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON aggregated_threats (timestamp)")

        conn.commit()
        if log_callback: 
            log_callback(f"Database '{db_path}' initialized successfully.")
    except sqlite3.Error as e:
        if log_callback: 
            log_callback(f"Database Error: Failed to initialize database: {e}")
    finally:
        if conn:
            conn.close()

def dict_factory(cursor, row):
    """Converts database rows to dictionaries."""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

# --- Utility Functions ---
def now_utc_iso():
    """Returns the current time in UTC as an ISO 8601 formatted string."""
    return datetime.now(timezone.utc).isoformat()

def async_retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Async retry decorator with exponential backoff"""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except (httpx.TimeoutException, httpx.NetworkError) as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        wait_time = delay * (backoff ** attempt) + random.uniform(0, 1)
                        await asyncio.sleep(wait_time)
                    continue
                except httpx.HTTPStatusError as e:
                    if e.response.status_code < 500:
                        raise
                    last_exception = e
                    if attempt < max_attempts - 1:
                        wait_time = delay * (backoff ** attempt)
                        await asyncio.sleep(wait_time)
                    continue
                except Exception as e:
                    raise
            
            raise last_exception
        return wrapper
    return decorator

# --- Threat Provider Base Class ---
class ThreatProvider:
    """Enhanced base class with rate limiting and metrics"""
    def __init__(self, name, config, metrics_collector: MetricsCollector):
        self.name = name
        self.config = config
        self.provider_config = config.get("providers", {}).get(name, {})
        self.api_key = config.get("api_keys", {}).get(name)
        self.enabled = self.provider_config.get("enabled", True)
        self.query_params = self.provider_config.get("query_params", {})
        self.rate_limit = self.provider_config.get("rate_limit", 1.0)
        self.last_request_time = 0
        self.metrics = metrics_collector

    async def _rate_limit_wait(self):
        """Ensure rate limiting between requests"""
        if self.rate_limit > 0:
            now = time.time()
            time_since_last = now - self.last_request_time
            if time_since_last < self.rate_limit:
                await asyncio.sleep(self.rate_limit - time_since_last)
            self.last_request_time = time.time()

    @async_retry(max_attempts=3, delay=1.0)
    async def fetch_with_retry(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        """Fetch with automatic retry logic and metrics"""
        start_time = time.time()
        await self._rate_limit_wait()
        
        try:
            results = await self.fetch(client)
            response_time = time.time() - start_time
            self.metrics.record_request(
                self.name, True, response_time, len(results)
            )
            return results
        except Exception as e:
            response_time = time.time() - start_time
            self.metrics.record_request(
                self.name, False, response_time, 0, type(e).__name__
            )
            raise

    async def fetch(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        """Fetch data from the provider. Must be implemented by subclasses."""
        raise NotImplementedError("Fetch method not implemented by provider.")

    def _normalize_data(self, records):
        """Normalize data from this provider to ThreatIOC objects"""
        normalized = []
        for record in records:
            try:
                ioc = ThreatIOC(
                    ioc_type=record.get("type", "unknown"),
                    ioc_value=record.get("id", record.get("ip", record.get("url", str(record)))),
                    source_provider=self.name,
                    raw_data=record,
                    first_seen=self._parse_datetime(record.get("first_seen", record.get("firstSeen"))),
                    last_seen=self._parse_datetime(record.get("last_seen", record.get("lastSeen"))),
                    tags=record.get("tags", []),
                    timestamp=datetime.now(timezone.utc)
                )
                normalized.append(ioc)
            except Exception as e:
                print(f"Error normalizing record from {self.name}: {e}")
                continue
        return normalized

    def _parse_datetime(self, dt_value):
        """Parse datetime value from various formats"""
        if not dt_value:
            return None
        if isinstance(dt_value, str):
            try:
                return datetime.fromisoformat(dt_value.replace('Z', '+00:00'))
            except:
                try:
                    return pd.to_datetime(dt_value).to_pydatetime()
                except:
                    return None
        return dt_value

# --- Specific Threat Providers ---
class VirusTotalProvider(ThreatProvider):
    async def fetch(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        if not self.enabled or not self.api_key:
            print(f"{self.name}: Disabled or API key not configured. Skipping.")
            return []
        
        headers = {"x-apikey": self.api_key}
        limit = self.query_params.get("limit", 3)
        query = self.query_params.get("query", "entity:ip_address order:last_submission_date-")
        url = f"https://www.virustotal.com/api/v3/intelligence/search?query={query}&limit={limit}"
        
        r = await client.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json().get("data", [])
        
        processed_records = []
        for item in data:
            record = item.get("attributes", {})
            record["id"] = item.get("id") 
            record["type"] = item.get("type")
            processed_records.append(record)
        
        return self._normalize_data(processed_records)

class GreyNoiseProvider(ThreatProvider):
    async def fetch(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        if not self.enabled or not self.api_key:
            print(f"{self.name}: Disabled or API key not configured. Skipping.")
            return []
        
        headers = {"key": self.api_key, "Accept": "application/json"}
        ip_to_check = self.query_params.get("ip_address", "8.8.8.8")
        url = f"https://api.greynoise.io/v3/community/{ip_to_check}"
        
        r = await client.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        record = r.json()
        
        if record.get("ip"):
            return self._normalize_data([record])
        return []

class AbuseIPDBProvider(ThreatProvider):
    async def fetch(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        if not self.enabled or not self.api_key:
            print(f"{self.name}: Disabled or API key not configured. Skipping.")
            return []
        
        headers = {"Key": self.api_key, "Accept": "application/json"}
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": self.query_params.get("ipAddress", "8.8.8.8"),
            "maxAgeInDays": self.query_params.get("maxAgeInDays", "90"),
            "verbose": ""
        }
        
        r = await client.get(url, headers=headers, params=params, timeout=15)
        r.raise_for_status()
        response_json = r.json()
        
        if "data" in response_json:
            return self._normalize_data([response_json["data"]])
        return []

class AlienVaultOTXProvider(ThreatProvider):
    async def fetch(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        if not self.enabled or not self.api_key:
            print(f"{self.name}: Disabled or API key not configured. Skipping.")
            return []
        
        headers = {"X-OTX-API-KEY": self.api_key}
        indicator_type = self.query_params.get("indicator_type", "IPv4")
        indicator_value = self.query_params.get("indicator_value", "8.8.8.8")
        section = self.query_params.get("section", "general")
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator_value}/{section}"
        
        r = await client.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        record = r.json()
        
        return self._normalize_data([record])

class MISPProvider(ThreatProvider):
    async def fetch(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        if not self.enabled or not self.api_key:
            print(f"{self.name}: Disabled or API key/URL not configured. Skipping.")
            return []
        
        misp_url = self.config.get("api_keys", {}).get("MISP_URL")
        if not misp_url:
            print(f"{self.name}: MISP URL not configured. Skipping.")
            return []

        headers = {"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"}
        payload = {
            "returnFormat": "json",
            "limit": self.query_params.get("limit", 5),
            "page": self.query_params.get("page", 1),
            "sort": self.query_params.get("sort", "Event.date desc"),
            **self.query_params.get("search_params", {})
        }
        
        r = await client.post(misp_url.rstrip('/') + "/events/restSearch", 
                             headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        response_json = r.json()
        events_data = response_json.get("response", [])
        
        processed_events = []
        for event_container in events_data:
            if "Event" in event_container:
                processed_events.append(event_container["Event"])
        
        return self._normalize_data(processed_events)

class URLhausProvider(ThreatProvider):
    async def fetch(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        if not self.enabled:
            print(f"{self.name}: Disabled. Skipping.")
            return []
        
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        limit = self.query_params.get("limit")
        if limit:
            url += f"limit/{limit}/"

        r = await client.get(url, timeout=15)
        r.raise_for_status()
        response_json = r.json()
        
        if response_json.get("query_status") == "ok":
            return self._normalize_data(response_json.get("urls", []))
        return []

class StubProvider(ThreatProvider):
    async def fetch(self, client: httpx.AsyncClient) -> List[ThreatIOC]:
        return []

# --- Database Repository ---
class ThreatRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    def get_connection(self):
        """Get database connection with dict factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = dict_factory
        return conn
    
    def insert_threats(self, threats: List[ThreatIOC]) -> int:
        """Batch insert threats with conflict resolution"""
        if not threats:
            return 0
            
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            inserted_count = 0
            
            for threat in threats:
                try:
                    threat_data = threat.to_dict()
                    cursor.execute("""
                    INSERT OR IGNORE INTO aggregated_threats 
                    (timestamp, source_provider, ioc_type, ioc_value, raw_data, 
                     first_seen, last_seen, tags, threat_score, processed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        threat_data['timestamp'], threat_data['source_provider'],
                        threat_data['ioc_type'], threat_data['ioc_value'],
                        threat_data['raw_data'], threat_data['first_seen'],
                        threat_data['last_seen'], threat_data['tags'],
                        threat_data['threat_score'], now_utc_iso()
                    ))
                    if cursor.rowcount > 0:
                        inserted_count += 1
                except sqlite3.Error as e:
                    print(f"Error inserting threat {threat.ioc_value}: {e}")
                    continue
            
            conn.commit()
            return inserted_count
        finally:
            conn.close()
    
    def get_threats_paginated(self, limit: int = 100, offset: int = 0, 
                            filters: Optional[dict] = None) -> List[dict]:
        """Get threats with pagination and filtering"""
        query = "SELECT * FROM aggregated_threats"
        params = []
        
        if filters:
            conditions = []
            if 'source_provider' in filters:
                conditions.append("source_provider = ?")
                params.append(filters['source_provider'])
            if 'ioc_type' in filters:
                conditions.append("ioc_type = ?")
                params.append(filters['ioc_type'])
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            # Parse JSON strings back to objects
            for row in rows:
                if row.get('raw_data'):
                    try:
                        row['raw_data'] = json.loads(row['raw_data'])
                    except:
                        pass
                if row.get('tags'):
                    try:
                        row['tags'] = json.loads(row['tags'])
                    except:
                        row['tags'] = []
            
            return rows
        finally:
            conn.close()

# --- Main Aggregator Class ---
class SimpleThreatAggregator:
    DEFAULT_CONFIG = {
        "app_api_key": "YOUR_SECRET_APP_API_KEY",
        "output_format": "json",
        "storage_limit_gb": 1,
        "api_keys": {},
        "providers": {
            "VirusTotal": {"enabled": True, "query_params": {"limit": 10}, "rate_limit": 1.0},
            "GreyNoise": {"enabled": False, "query_params": {"ip_address": "1.1.1.1"}, "rate_limit": 1.0},
            "AbuseIPDB": {"enabled": True, "query_params": {"maxAgeInDays": "30"}, "rate_limit": 1.0},
            "AlienVaultOTX": {"enabled": True, "query_params": {"indicator_type": "IPv4", "section": "general"}, "rate_limit": 1.0},
            "MISP": {"enabled": False, "query_params": {"limit": 5}, "rate_limit": 1.0},
            "URLhaus": {"enabled": True, "query_params": {}, "rate_limit": 1.0},
            "CyberSixGill": {"enabled": False}, "RecordedFuture": {"enabled": False},
            "Filigran": {"enabled": False}, "ThreatbookCTI": {"enabled": False},
            "CheckPointMap": {"enabled": False}, "RadwareMap": {"enabled": False},
            "KasperskyMap": {"enabled": False}, "SOCRadar": {"enabled": False},
            "ThreatIntelligencePlatform": {"enabled": False}, "Anomali": {"enabled": False},
        },
        "output_directory": "aggregated_data_files",
        "ml_export_dir": "ml_exports",
        "interval": 3600,
        "rest_api_port": 8008,
        "db_path": "threat_intelligence.db"
    }

    def __init__(self, config_path="config.json", log_callback=print):
        self.config_path = config_path
        self.log_callback = log_callback
        self.load_config()
        self.data_queue = asyncio.Queue()
        self.running = False
        self.lock = asyncio.Lock()
        self.latest_activity = time.time()
        self.stats = {"bytes_sent": 0, "records_sent": 0, "bytes_received": 0, "records_received": 0}
        self.metrics = MetricsCollector()
        
        # Database setup - will be initialized after GUI selects location
        self.repository = None
        self._httpx_client = None
        
        os.makedirs(self.config['output_directory'], exist_ok=True)
        os.makedirs(self.config.get("ml_export_dir", "ml_exports"), exist_ok=True)
        
        self._init_providers()

    def initialize_database(self, db_path: str):
        """Initialize database at specified path"""
        self.config['db_path'] = db_path
        init_db(db_path, self.log_callback)
        self.repository = ThreatRepository(db_path)
        self.save_config()

    @asynccontextmanager
    async def _http_client(self) -> AsyncContextManager[httpx.AsyncClient]:
        """Async context manager for HTTP client"""
        if self._httpx_client is None:
            self._httpx_client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
                verify=self.config.get('ssl_verify', True)
            )
        try:
            yield self._httpx_client
        finally:
            pass

    def _init_providers(self):
        self.providers_instances = {}
        provider_classes = {
            "VirusTotal": VirusTotalProvider, "GreyNoise": GreyNoiseProvider,
            "AbuseIPDB": AbuseIPDBProvider, "AlienVaultOTX": AlienVaultOTXProvider,
            "MISP": MISPProvider, "URLhaus": URLhausProvider,
            "CyberSixGill": StubProvider, "RecordedFuture": StubProvider,
            "Filigran": StubProvider, "ThreatbookCTI": StubProvider,
            "CheckPointMap": StubProvider, "RadwareMap": StubProvider,
            "KasperskyMap": StubProvider, "SOCRadar": StubProvider,
            "ThreatIntelligencePlatform": StubProvider, "Anomali": StubProvider,
        }
        for name, cls in provider_classes.items():
            if name in self.config.get("providers", {}):
                self.providers_instances[name] = cls(name, self.config, self.metrics)

    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    loaded_config = json.load(f)
                self.config = self._merge_configs(self.DEFAULT_CONFIG, loaded_config)
            except json.JSONDecodeError:
                self.log_callback(f"Warning: Error decoding {self.config_path}. Using default and recreating.")
                self.config = self.DEFAULT_CONFIG.copy()
                self.save_config()
        else:
            self.log_callback(f"Info: {self.config_path} not found. Creating with defaults.")
            self.config = self.DEFAULT_CONFIG.copy()
            self.save_config()

    def _merge_configs(self, default, loaded):
        """Recursively merges loaded config into default config."""
        merged = default.copy()
        for key, value in loaded.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
        return merged
        
    def save_config(self):
        try:
            with open(self.config_path, "w") as f:
                json.dump(self.config, f, indent=4)
            self.log_callback(f"Configuration saved to {self.config_path}")
        except IOError as e:
            self.log_callback(f"Error: Could not save config: {e}")

    async def collect_data(self):
        if not self.repository:
            self.log_callback("Database not initialized. Cannot collect data.")
            return
            
        self.log_callback("Starting async data collection cycle...")
        tasks = []
        
        async with self._http_client() as client:
            for name, provider in self.providers_instances.items():
                if provider.enabled:
                    self.log_callback(f"Queueing fetch for {name}...")
                    task = asyncio.create_task(
                        provider.fetch_with_retry(client), 
                        name=name
                    )
                    tasks.append(task)
                else:
                    self.log_callback(f"Skipping disabled provider: {name}")
            
            if not tasks:
                self.log_callback("No enabled providers found.")
                return
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result_data_list in enumerate(results):
                task_name = tasks[i].get_name()
                if isinstance(result_data_list, Exception):
                    self.log_callback(f"Error fetching from {task_name}: {result_data_list}")
                elif result_data_list:
                    self._track_data_stats(result_data_list, task_name)
                    await self.data_queue.put((task_name, result_data_list))
                    self.latest_activity = time.time()
                    self.log_callback(f"Received {len(result_data_list)} normalized items from {task_name}.")
                elif result_data_list is not None:
                    self.log_callback(f"No data received from {task_name}.")
        
        self.log_callback("Async data collection cycle finished.")

    def _track_data_stats(self, data_list, source_name="Unknown"):
        num_records = len(data_list)
        self.stats["records_received"] += num_records
        try:
            self.stats["bytes_received"] += sum(len(str(d).encode('utf-8')) for d in data_list)
        except Exception:
            pass

    async def process_and_save_data(self):
        """Processes data from queue and saves to DB."""
        if not self.repository:
            self.log_callback("Database not initialized. Cannot save data.")
            return 0
            
        if self.data_queue.empty():
            self.log_callback("No data in queue to process for DB.")
            return 0

        records_processed_count = 0
        
        try:
            while not self.data_queue.empty():
                source_provider, threat_iocs = await self.data_queue.get()
                
                inserted_count = self.repository.insert_threats(threat_iocs)
                records_processed_count += inserted_count
                
                if inserted_count > 0:
                    self.log_callback(f"Inserted {inserted_count} new records from {source_provider}")
                
                self.data_queue.task_done()

            if records_processed_count > 0:
                self.log_callback(f"Successfully processed and saved {records_processed_count} new records to database.")
                self.stats["records_sent"] += records_processed_count
            else:
                self.log_callback("No new unique records to save to database in this batch.")
            
            self.enforce_db_storage_limit()
            return records_processed_count

        except Exception as e:
            self.log_callback(f"Unexpected error in process_and_save_data: {e}")
        
        return 0
        
    def enforce_db_storage_limit(self, max_records=100000):
        """Enforces a storage limit on the DB"""
        if not self.repository:
            return
            
        limit = self.config.get("db_max_records", max_records)
        try:
            conn = self.repository.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM aggregated_threats")
            count = cursor.fetchone()['COUNT(*)']
            
            if count > limit:
                num_to_delete = count - limit
                cursor.execute("""
                    DELETE FROM aggregated_threats 
                    WHERE id IN (SELECT id FROM aggregated_threats ORDER BY timestamp ASC LIMIT ?)
                """, (num_to_delete,))
                conn.commit()
                self.log_callback(f"DB Storage: Enforced limit, deleted {num_to_delete} oldest records.")
            conn.close()
        except sqlite3.Error as e:
            self.log_callback(f"DB Error enforcing storage limit: {e}")

    async def run_once(self):
        async with self.lock:
            self.log_callback("Starting manual async run (run_once)...")
            await self.collect_data()
            records_saved = await self.process_and_save_data()
            return records_saved

    async def run_periodically(self, update_plot_callback=None, status_callback=None):
        self.running = True
        self.log_callback(f"Starting periodic async aggregation. Interval: {self.config['interval']} seconds.")
        
        while self.running:
            start_time = time.time()
            await self.run_once()
            
            if status_callback:
                try:
                    status_callback(self.get_status())
                except Exception as e_status:
                    self.log_callback(f"Error updating status: {e_status}")

            elapsed_time = time.time() - start_time
            sleep_duration = max(0, self.config["interval"] - elapsed_time)
            self.log_callback(f"Async cycle finished in {elapsed_time:.2f}s. Sleeping for {sleep_duration:.2f}s.")
            
            try:
                await asyncio.sleep(sleep_duration)
            except asyncio.CancelledError:
                self.log_callback("Periodic run cancelled during sleep.")
                break
            if not self.running:
                break
        
        self.log_callback("Periodic async aggregation stopped.")
        await self.shutdown()

    async def shutdown(self):
        """Proper async shutdown"""
        if self._httpx_client:
            await self._httpx_client.aclose()
            self._httpx_client = None
        self.log_callback("Aggregator shutdown complete")

    def stop(self):
        self.running = False
        self.log_callback("Stop signal received for aggregator.")

    def get_status(self):
        now = time.time()
        active_threshold = self.config.get("interval", 3600) + 120
        active = (now - self.latest_activity) < active_threshold
        
        status = {
            "running": self.running,
            "active_processing": active,
            "total_bytes_received_session": self.stats["bytes_received"],
            "total_records_received_session": self.stats["records_received"],
            "total_records_saved_to_db_session": self.stats["records_sent"],
            "last_activity_time": datetime.fromtimestamp(self.latest_activity, tz=timezone.utc).isoformat() if self.latest_activity else "N/A",
            "data_queue_size": self.data_queue.qsize() if hasattr(self.data_queue, 'qsize') else 'N/A',
            "database_initialized": self.repository is not None,
            "database_path": self.config.get('db_path', 'Not set')
        }
        
        # Add provider health status
        health_status = self.metrics.get_health_status()
        status["provider_health"] = health_status
        
        return status

# --- REST API ---
class AggregatorAPI:
    def __init__(self, aggregator: SimpleThreatAggregator):
        self.aggregator = aggregator
        self.app = FastAPI(title="Threat Aggregator REST API", version="2.0.0")
        self.app.add_middleware(
            CORSMiddleware, allow_origins=["*"], allow_credentials=True,
            allow_methods=["*"], allow_headers=["*"],
        )
        
        async def get_api_key(api_key_header: str = Security(API_KEY_HEADER)):
            correct_api_key = self.aggregator.config.get("app_api_key", "DEFAULT_FALLBACK_KEY_IF_NOT_SET")
            if api_key_header == correct_api_key:
                return api_key_header
            else:
                raise HTTPException(status_code=403, detail="Could not validate credentials")

        self.app.get("/status", summary="Get Aggregator Status")(self.status)
        self.app.get("/data/latest", summary="Get Latest Aggregated Data from DB", dependencies=[Security(get_api_key)])(self.latest_data_from_db)
        self.app.post("/control/trigger_run", summary="Trigger Manual Run", dependencies=[Security(get_api_key)])(self.trigger_manual_run)
        self.app.get("/config", summary="Get Current Configuration (Masked)", dependencies=[Security(get_api_key)])(self.get_masked_config)
        self.app.get("/metrics", summary="Get Provider Metrics", dependencies=[Security(get_api_key)])(self.get_metrics)

    async def status(self):
        return self.aggregator.get_status()

    async def latest_data_from_db(self, request: Request, limit: int = 100, offset: int = 0, source_provider: str = None):
        if not self.aggregator.repository:
            raise HTTPException(status_code=503, detail="Database not initialized")
            
        try:
            filters = {}
            if source_provider:
                filters['source_provider'] = source_provider
                
            data = self.aggregator.repository.get_threats_paginated(limit, offset, filters)
            
            if not data:
                return JSONResponse(content={"message": "No data found matching criteria."}, status_code=404)
            return JSONResponse(content=data)
        except sqlite3.Error as e:
            raise HTTPException(status_code=500, detail=f"Database error: {e}")

    async def trigger_manual_run(self, request: Request, background_tasks: BackgroundTasks):
        if not self.aggregator.repository:
            raise HTTPException(status_code=503, detail="Database not initialized")
            
        async def run_task():
            await self.aggregator.run_once()
        
        background_tasks.add_task(run_task)
        return {"status": "Manual aggregation run triggered."}

    async def get_masked_config(self, request: Request):
        safe_config = self.aggregator.config.copy()
        safe_config["app_api_key"] = "********"
        if "api_keys" in safe_config:
            safe_config["api_keys"] = {key: "********" for key in safe_config["api_keys"]}
        return JSONResponse(content=safe_config)

    async def get_metrics(self, request: Request):
        return JSONResponse(content=self.aggregator.metrics.get_health_status())

    def run_api_server(self):
        port = self.aggregator.config.get("rest_api_port", 8008)
        host = "0.0.0.0"
        self.aggregator.log_callback(f"Starting REST API on http://{host}:{port}")
        uvicorn.run(self.app, host=host, port=port, log_level="info")

# --- PyQt6 Database Selection Dialog ---
class DatabaseSelectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_path = None
        self.setWindowTitle("Select Database Location")
        self.setFixedSize(600, 400)
        self.setModal(True)
        
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Database Location Selection")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Instructions
        instructions = QLabel("Choose how you want to set up your threat intelligence database:")
        instructions.setWordWrap(True)
        instructions.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(instructions)
        
        # Options group
        options_group = QGroupBox("Database Options")
        options_layout = QVBoxLayout()
        
        # Option 1: Default location
        default_btn = QPushButton("Use Default Location")
        default_btn.clicked.connect(self.use_default_location)
        options_layout.addWidget(default_btn)
        
        default_path = os.path.abspath("threat_intelligence.db")
        default_label = QLabel(f"Default: {default_path}")
        default_label.setStyleSheet("font-size: 10px; color: #888;")
        options_layout.addWidget(default_label)
        
        # Option 2: Browse for new location
        browse_btn = QPushButton("Browse for New Location")
        browse_btn.clicked.connect(self.browse_new_location)
        options_layout.addWidget(browse_btn)
        
        browse_label = QLabel("Choose a custom location for a new database file")
        browse_label.setStyleSheet("font-size: 10px; color: #888;")
        options_layout.addWidget(browse_label)
        
        # Option 3: Use existing database
        existing_btn = QPushButton("Use Existing Database")
        existing_btn.clicked.connect(self.use_existing_database)
        options_layout.addWidget(existing_btn)
        
        existing_label = QLabel("Select an existing threat intelligence database")
        existing_label.setStyleSheet("font-size: 10px; color: #888;")
        options_layout.addWidget(existing_label)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Selected path display
        self.selected_path_label = QLabel("No location selected")
        self.selected_path_label.setWordWrap(True)
        self.selected_path_label.setStyleSheet("background-color: #404040; padding: 10px; border: 1px solid #666;")
        layout.addWidget(QLabel("Selected:"))
        layout.addWidget(self.selected_path_label)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept_selection)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)

    def use_default_location(self):
        self.selected_path = os.path.abspath("threat_intelligence.db")
        self.selected_path_label.setText(self.selected_path)

    def browse_new_location(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Select Database Location",
            "threat_intelligence.db",
            "SQLite Database (*.db);;All Files (*)"
        )
        if file_path:
            self.selected_path = file_path
            self.selected_path_label.setText(self.selected_path)

    def use_existing_database(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Existing Database",
            "",
            "SQLite Database (*.db);;All Files (*)"
        )
        if file_path:
            self.selected_path = file_path
            self.selected_path_label.setText(self.selected_path)

    def accept_selection(self):
        if self.selected_path:
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Please select a database location first.")

# --- PyQt6 Metrics Window ---
class MetricsWindow(QDialog):
    def __init__(self, parent, metrics_collector: MetricsCollector):
        super().__init__(parent)
        self.metrics = metrics_collector
        self.setWindowTitle("Provider Metrics")
        self.setMinimumSize(900, 600)
        self.setModal(False)
        
        self.setup_ui()
        self.update_metrics()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Provider Performance Metrics")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Create table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Provider", "Status", "Success Rate", "Total Requests", 
            "Records", "Avg Response Time", "Last Success", "Last Failure"
        ])
        
        # Configure table
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.table)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.update_metrics)
        button_layout.addWidget(refresh_btn)
        
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self.export_metrics)
        button_layout.addWidget(export_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def update_metrics(self):
        health_status = self.metrics.get_health_status()
        
        self.table.setRowCount(len(self.metrics.provider_metrics))
        
        for row, (provider, metrics) in enumerate(self.metrics.provider_metrics.items()):
            status = health_status.get(provider, {}).get('status', 'unknown')
            success_rate = f"{(metrics.successful_requests / max(metrics.total_requests, 1)) * 100:.1f}%"
            
            last_success = "Never"
            if metrics.last_success:
                last_success = datetime.fromtimestamp(metrics.last_success).strftime("%H:%M:%S")
            
            last_failure = "Never"
            if metrics.last_failure:
                last_failure = datetime.fromtimestamp(metrics.last_failure).strftime("%H:%M:%S")
            
            items = [
                QTableWidgetItem(provider),
                QTableWidgetItem(status.title()),
                QTableWidgetItem(success_rate),
                QTableWidgetItem(str(metrics.total_requests)),
                QTableWidgetItem(str(metrics.total_records)),
                QTableWidgetItem(f"{metrics.avg_response_time:.2f}s"),
                QTableWidgetItem(last_success),
                QTableWidgetItem(last_failure)
            ]
            
            for col, item in enumerate(items):
                self.table.setItem(row, col, item)
                # Color code status
                if col == 1:  # Status column
                    if status == 'healthy':
                        item.setBackground(QColor(0, 150, 0, 100))
                    elif status == 'degraded':
                        item.setBackground(QColor(255, 165, 0, 100))
                    elif status == 'unhealthy':
                        item.setBackground(QColor(255, 0, 0, 100))

    def export_metrics(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Metrics",
            "metrics.json",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.csv'):
                    self.export_to_csv(file_path)
                else:
                    self.export_to_json(file_path)
                QMessageBox.information(self, "Export Complete", f"Metrics exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export metrics: {e}")

    def export_to_json(self, filename):
        data = {}
        for provider, metrics in self.metrics.provider_metrics.items():
            data[provider] = {
                'total_requests': metrics.total_requests,
                'successful_requests': metrics.successful_requests,
                'failed_requests': metrics.failed_requests,
                'total_records': metrics.total_records,
                'avg_response_time': metrics.avg_response_time,
                'last_success': metrics.last_success,
                'last_failure': metrics.last_failure,
                'error_counts': dict(metrics.error_counts)
            }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    def export_to_csv(self, filename):
        import csv
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Provider', 'Total Requests', 'Successful', 'Failed', 'Records', 
                           'Avg Response Time', 'Last Success', 'Last Failure'])
            
            for provider, metrics in self.metrics.provider_metrics.items():
                writer.writerow([
                    provider, metrics.total_requests, metrics.successful_requests,
                    metrics.failed_requests, metrics.total_records, metrics.avg_response_time,
                    metrics.last_success or 'Never', metrics.last_failure or 'Never'
                ])

# --- Main PyQt6 GUI ---
class AggregatorGUI(QMainWindow):
    status_update_signal = pyqtSignal(dict)
    log_signal = pyqtSignal(str)

    def __init__(self, aggregator_loop: asyncio.AbstractEventLoop, aggregator: SimpleThreatAggregator):
        super().__init__()
        self.aggregator_loop = aggregator_loop
        self.aggregator = aggregator
        self.aggregator_task = None
        self.api_thread = None
        
        self.setWindowTitle("Advanced Threat Aggregator")
        self.setMinimumSize(1400, 1000)
        
        # Connect signals
        self.status_update_signal.connect(self.update_status_gui)
        self.log_signal.connect(self.append_log)
        
        # Check if database is already configured
        if not self.aggregator.repository:
            self.select_database_location()
        
        if self.aggregator.repository:  # Only proceed if database was selected
            self.setup_ui()
            self.load_config_to_gui()
            self.setup_status_timer()
            self.log("GUI Initialized with PyQt6 dark theme.")
        else:
            sys.exit(1)

    def select_database_location(self):
        """Allow user to select database location before initializing"""
        dialog = DatabaseSelectionDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.selected_path:
            self.aggregator.initialize_database(dialog.selected_path)
            self.log(f"Database initialized at: {dialog.selected_path}")
        else:
            QMessageBox.critical(self, "Error", "Database location must be selected to continue.")
            return False
        return True

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout with tabs
        main_layout = QVBoxLayout()
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Configuration tab
        config_tab = self.create_config_tab()
        self.tabs.addTab(config_tab, "Configuration")
        
        # Monitoring tab
        monitoring_tab = self.create_monitoring_tab()
        self.tabs.addTab(monitoring_tab, "Monitoring")
        
        # Data tab
        data_tab = self.create_data_tab()
        self.tabs.addTab(data_tab, "Data View")
        
        main_layout.addWidget(self.tabs)
        central_widget.setLayout(main_layout)

    def create_config_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Database info
        db_group = QGroupBox("Database Information")
        db_layout = QGridLayout()
        
        db_layout.addWidget(QLabel("Database Path:"), 0, 0)
        self.db_path_label = QLabel(self.aggregator.config.get('db_path', 'Not set'))
        self.db_path_label.setStyleSheet("background-color: #404040; padding: 5px; border: 1px solid #666;")
        db_layout.addWidget(self.db_path_label, 0, 1)
        
        change_db_btn = QPushButton("Change Database Location")
        change_db_btn.clicked.connect(self.change_database_location)
        db_layout.addWidget(change_db_btn, 0, 2)
        
        db_group.setLayout(db_layout)
        layout.addWidget(db_group)
        
        # General configuration
        general_group = QGroupBox("General Configuration")
        general_layout = QGridLayout()
        
        general_layout.addWidget(QLabel("Interval (seconds):"), 0, 0)
        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setRange(60, 86400)
        self.interval_spinbox.setValue(self.aggregator.config.get("interval", 3600))
        general_layout.addWidget(self.interval_spinbox, 0, 1)
        
        general_layout.addWidget(QLabel("App API Key:"), 1, 0)
        self.app_api_key_edit = QLineEdit(self.aggregator.config.get("app_api_key", ""))
        self.app_api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        general_layout.addWidget(self.app_api_key_edit, 1, 1)
        
        general_layout.addWidget(QLabel("API Port:"), 2, 0)
        self.api_port_spinbox = QSpinBox()
        self.api_port_spinbox.setRange(1000, 65535)
        self.api_port_spinbox.setValue(self.aggregator.config.get("rest_api_port", 8008))
        general_layout.addWidget(self.api_port_spinbox, 2, 1)
        
        save_config_btn = QPushButton("Save General Configuration")
        save_config_btn.clicked.connect(self.save_gui_config)
        general_layout.addWidget(save_config_btn, 3, 0, 1, 2)
        
        general_group.setLayout(general_layout)
        layout.addWidget(general_group)
        
        # Provider controls
        provider_group = QGroupBox("Provider Controls")
        provider_layout = QGridLayout()
        
        self.provider_checkboxes = {}
        providers = list(self.aggregator.config.get("providers", {}).keys())
        
        for i, provider in enumerate(providers):
            row = i // 4
            col = i % 4
            
            checkbox = QCheckBox(provider)
            checkbox.setChecked(self.aggregator.config["providers"][provider].get("enabled", True))
            provider_layout.addWidget(checkbox, row, col)
            self.provider_checkboxes[provider] = checkbox
        
        save_providers_btn = QPushButton("Save Provider Settings")
        save_providers_btn.clicked.connect(self.save_provider_settings)
        provider_layout.addWidget(save_providers_btn, (len(providers) // 4) + 1, 0, 1, 4)
        
        provider_group.setLayout(provider_layout)
        layout.addWidget(provider_group)
        
        # API Keys
        api_keys_group = QGroupBox("Provider API Keys")
        api_keys_layout = QGridLayout()
        
        self.api_key_edits = {}
        api_providers = ["VirusTotal", "GreyNoise", "AbuseIPDB", "AlienVaultOTX", "MISP"]
        
        for i, provider in enumerate(api_providers):
            row = i // 2
            col = (i % 2) * 2
            
            api_keys_layout.addWidget(QLabel(f"{provider}:"), row, col)
            edit = QLineEdit(self.aggregator.config.get("api_keys", {}).get(provider, ""))
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            api_keys_layout.addWidget(edit, row, col + 1)
            self.api_key_edits[provider] = edit
        
        save_api_keys_btn = QPushButton("Save API Keys")
        save_api_keys_btn.clicked.connect(self.save_api_keys)
        api_keys_layout.addWidget(save_api_keys_btn, (len(api_providers) // 2) + 1, 0, 1, 4)
        
        api_keys_group.setLayout(api_keys_layout)
        layout.addWidget(api_keys_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_monitoring_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Status group
        status_group = QGroupBox("System Status")
        status_layout = QGridLayout()
        
        self.status_labels = {}
        status_items = [
            ("Running:", "running_status"),
            ("Last Activity:", "last_activity"),
            ("Records Received:", "records_received"),
            ("Records Saved:", "records_saved"),
            ("API Status:", "api_status"),
            ("Database:", "db_status")
        ]
        
        for i, (label_text, key) in enumerate(status_items):
            row = i // 3
            col = (i % 3) * 2
            
            status_layout.addWidget(QLabel(label_text), row, col)
            status_label = QLabel("Unknown")
            status_label.setStyleSheet("color: orange;")
            status_layout.addWidget(status_label, row, col + 1)
            self.status_labels[key] = status_label
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Controls
        controls_group = QGroupBox("Controls")
        controls_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Aggregation")
        self.start_btn.clicked.connect(self.start_aggregation_async)
        controls_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Aggregation")
        self.stop_btn.clicked.connect(self.stop_aggregation_async)
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn)
        
        run_once_btn = QPushButton("Run Once Now")
        run_once_btn.clicked.connect(self.run_once_gui_async)
        controls_layout.addWidget(run_once_btn)
        
        self.start_api_btn = QPushButton("Start REST API")
        self.start_api_btn.clicked.connect(self.start_rest_api)
        controls_layout.addWidget(self.start_api_btn)
        
        metrics_btn = QPushButton("View Metrics")
        metrics_btn.clicked.connect(self.show_metrics)
        controls_layout.addWidget(metrics_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Activity log
        log_group = QGroupBox("Activity Log")
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(300)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
        """)
        log_layout.addWidget(self.log_text)
        
        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(self.clear_log)
        log_layout.addWidget(clear_log_btn)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        widget.setLayout(layout)
        return widget

    def create_data_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Data controls
        controls_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh Data")
        refresh_btn.clicked.connect(self.refresh_data_view)
        controls_layout.addWidget(refresh_btn)
        
        controls_layout.addWidget(QLabel("Records per page:"))
        self.records_per_page = QComboBox()
        self.records_per_page.addItems(["50", "100", "200", "500"])
        self.records_per_page.setCurrentText("100")
        controls_layout.addWidget(self.records_per_page)
        
        controls_layout.addWidget(QLabel("Provider Filter:"))
        self.provider_filter = QComboBox()
        self.provider_filter.addItem("All Providers")
        for provider in self.aggregator.config.get("providers", {}).keys():
            self.provider_filter.addItem(provider)
        controls_layout.addWidget(self.provider_filter)
        
        export_btn = QPushButton("Export Data")
        export_btn.clicked.connect(self.export_data)
        controls_layout.addWidget(export_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Data table
        self.data_table = QTableWidget()
        self.data_table.setColumnCount(7)
        self.data_table.setHorizontalHeaderLabels([
            "Timestamp", "Provider", "IOC Type", "IOC Value", "First Seen", "Last Seen", "Tags"
        ])
        
        header = self.data_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.data_table.setAlternatingRowColors(True)
        self.data_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.data_table)
        
        # Pagination controls
        pagination_layout = QHBoxLayout()
        
        self.prev_btn = QPushButton("Previous")
        self.prev_btn.clicked.connect(self.previous_page)
        self.prev_btn.setEnabled(False)
        pagination_layout.addWidget(self.prev_btn)
        
        self.page_label = QLabel("Page 1")
        pagination_layout.addWidget(self.page_label)
        
        self.next_btn = QPushButton("Next")
        self.next_btn.clicked.connect(self.next_page)
        pagination_layout.addWidget(self.next_btn)
        
        pagination_layout.addStretch()
        
        self.total_records_label = QLabel("Total records: 0")
        pagination_layout.addWidget(self.total_records_label)
        
        layout.addLayout(pagination_layout)
        
        self.current_page = 1
        
        widget.setLayout(layout)
        return widget

    def setup_status_timer(self):
        """Setup timer for periodic status updates"""
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status_periodically)
        self.status_timer.start(3000)  # Update every 3 seconds

    def update_status_periodically(self):
        """Get status from aggregator and emit signal for GUI update"""
        try:
            status = self.aggregator.get_status()
            self.status_update_signal.emit(status)
        except Exception as e:
            self.log(f"Error getting status: {e}")

    def log(self, message):
        """Thread-safe logging function"""
        self.log_signal.emit(message)

    def append_log(self, message):
        """Append message to log (runs in GUI thread)"""
        timestamp = now_utc_iso()
        self.log_text.append(f"{timestamp} - {message}")
        # Auto-scroll to bottom
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_log(self):
        """Clear the activity log"""
        self.log_text.clear()

    def change_database_location(self):
        """Allow user to change database location"""
        reply = QMessageBox.question(self, "Change Database", 
                                    "Changing database location will stop any running aggregation. Continue?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.stop_aggregation_async()
            
            dialog = DatabaseSelectionDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted and dialog.selected_path:
                self.aggregator.initialize_database(dialog.selected_path)
                self.db_path_label.setText(dialog.selected_path)
                self.log(f"Database location changed to: {dialog.selected_path}")

    def load_config_to_gui(self):
        """Load configuration values into GUI elements"""
        self.aggregator.load_config()
        config = self.aggregator.config
        
        self.interval_spinbox.setValue(config.get("interval", 3600))
        self.app_api_key_edit.setText(config.get("app_api_key", ""))
        self.api_port_spinbox.setValue(config.get("rest_api_port", 8008))
        self.db_path_label.setText(config.get("db_path", "Not set"))

        for provider, checkbox in self.provider_checkboxes.items():
            checkbox.setChecked(config.get("providers", {}).get(provider, {}).get("enabled", True))
        
        for provider, edit in self.api_key_edits.items():
            edit.setText(config.get("api_keys", {}).get(provider, ""))
        
        self.log("Configuration loaded into GUI.")

    def save_gui_config(self):
        """Save general configuration"""
        try:
            self.aggregator.config["interval"] = self.interval_spinbox.value()
            self.aggregator.config["app_api_key"] = self.app_api_key_edit.text()
            self.aggregator.config["rest_api_port"] = self.api_port_spinbox.value()
            
            self.aggregator.save_config()
            self.log("General configuration saved.")
            QMessageBox.information(self, "Config Saved", "General configuration saved.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save general config: {e}")
            self.log(f"Error saving general config: {e}")

    def save_provider_settings(self):
        """Save provider enabled/disabled settings"""
        try:
            if "providers" not in self.aggregator.config:
                self.aggregator.config["providers"] = {}
            
            for provider, checkbox in self.provider_checkboxes.items():
                if provider not in self.aggregator.config["providers"]:
                    self.aggregator.config["providers"][provider] = {}
                self.aggregator.config["providers"][provider]["enabled"] = checkbox.isChecked()
            
            self.aggregator.save_config()
            self.aggregator._init_providers()
            self.log("Provider enabled/disabled settings saved.")
            QMessageBox.information(self, "Provider Settings", "Provider settings saved.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save provider settings: {e}")

    def save_api_keys(self):
        """Save API keys"""
        try:
            if "api_keys" not in self.aggregator.config:
                self.aggregator.config["api_keys"] = {}
            
            for provider, edit in self.api_key_edits.items():
                key_value = edit.text().strip()
                if key_value:
                    self.aggregator.config["api_keys"][provider] = key_value
                elif provider in self.aggregator.config["api_keys"]:
                    del self.aggregator.config["api_keys"][provider]
            
            self.aggregator.save_config()
            self.aggregator._init_providers()
            self.log("API keys saved.")
            QMessageBox.information(self, "API Keys", "API keys saved.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save API keys: {e}")

    def start_aggregation_async(self):
        """Start periodic aggregation"""
        if not self.aggregator.repository:
            QMessageBox.critical(self, "Error", "Database not initialized. Please select database location.")
            return
            
        self.save_gui_config()
        self.save_provider_settings()
        self.save_api_keys()

        if self.aggregator_task and not self.aggregator_task.done():
            self.log("Aggregation is already running.")
            return
        
        self.log("Starting periodic async aggregation from GUI...")
        self.aggregator_task = asyncio.run_coroutine_threadsafe(
            self.aggregator.run_periodically(status_callback=self.update_status_gui_safe), 
            self.aggregator_loop
        )
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_aggregation_async(self):
        """Stop periodic aggregation"""
        self.log("Stopping periodic async aggregation from GUI...")
        self.aggregator.stop()
        if self.aggregator_task and not self.aggregator_task.done():
            self.aggregator_loop.call_soon_threadsafe(self.aggregator_task.cancel)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log("Stop signal sent. Aggregation will halt after current cycle/sleep.")

    def run_once_gui_async(self):
        """Run aggregation once"""
        if not self.aggregator.repository:
            QMessageBox.critical(self, "Error", "Database not initialized. Please select database location.")
            return
            
        self.save_gui_config()
        self.save_provider_settings()
        self.save_api_keys()
        self.log("Manual async run initiated from GUI...")
        
        async def _run_once_task():
            await self.aggregator.run_once()
            status = self.aggregator.get_status()
            self.status_update_signal.emit(status)
            self.log_signal.emit("Manual async run finished.")

        asyncio.run_coroutine_threadsafe(_run_once_task(), self.aggregator_loop)

    def show_metrics(self):
        """Show provider metrics window"""
        metrics_window = MetricsWindow(self, self.aggregator.metrics)
        metrics_window.show()

    def start_rest_api(self):
        """Start REST API server"""
        if not self.api_thread or not self.api_thread.is_alive():
            self.log("Attempting to start REST API...")
            self.save_gui_config()
            api_runner = AggregatorAPI(self.aggregator)
            self.api_thread = threading.Thread(target=api_runner.run_api_server, daemon=True)
            self.api_thread.start()
            self.log(f"REST API starting... Check console for uvicorn logs.")
            self.start_api_btn.setEnabled(False)
        else:
            self.log("REST API is already running.")

    def update_status_gui_safe(self, status_data):
        """Thread-safe status update"""
        self.status_update_signal.emit(status_data)

    def update_status_gui(self, status_data):
        """Update status labels with current data"""
        try:
            # Running status
            if status_data.get("running"):
                self.status_labels["running_status"].setText("Running")
                self.status_labels["running_status"].setStyleSheet("color: green;")
            else:
                self.status_labels["running_status"].setText("Stopped")
                self.status_labels["running_status"].setStyleSheet("color: red;")
            
            # Last activity
            last_activity = status_data.get("last_activity_time", "N/A")
            if last_activity != "N/A":
                try:
                    dt = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                    last_activity = dt.strftime("%H:%M:%S")
                except:
                    pass
            self.status_labels["last_activity"].setText(last_activity)
            
            # Records
            self.status_labels["records_received"].setText(
                str(status_data.get("total_records_received_session", 0))
            )
            self.status_labels["records_saved"].setText(
                str(status_data.get("total_records_saved_to_db_session", 0))
            )
            
            # Database status
            if status_data.get("database_initialized"):
                self.status_labels["db_status"].setText("Connected")
                self.status_labels["db_status"].setStyleSheet("color: green;")
            else:
                self.status_labels["db_status"].setText("Not Connected")
                self.status_labels["db_status"].setStyleSheet("color: red;")
            
            # API status
            if self.api_thread and self.api_thread.is_alive():
                port = self.aggregator.config.get('rest_api_port', 8008)
                self.status_labels["api_status"].setText(f"Running on port {port}")
                self.status_labels["api_status"].setStyleSheet("color: green;")
            else:
                self.status_labels["api_status"].setText("Off")
                self.status_labels["api_status"].setStyleSheet("color: red;")
            
        except Exception as e:
            self.log(f"Error updating status GUI: {e}")

    def refresh_data_view(self):
        """Refresh the data view table"""
        self.current_page = 1
        self.load_data_page()

    def load_data_page(self):
        """Load data for current page"""
        if not self.aggregator.repository:
            return
        
        try:
            limit = int(self.records_per_page.currentText())
            offset = (self.current_page - 1) * limit
            
            filters = {}
            provider_filter = self.provider_filter.currentText()
            if provider_filter != "All Providers":
                filters['source_provider'] = provider_filter
            
            data = self.aggregator.repository.get_threats_paginated(limit, offset, filters)
            
            self.data_table.setRowCount(len(data))
            
            for row, record in enumerate(data):
                # Parse timestamp
                timestamp = record.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        pass
                
                # Parse first_seen and last_seen
                first_seen = record.get('first_seen', 'N/A')
                if first_seen and first_seen != 'N/A':
                    try:
                        dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                        first_seen = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        pass
                
                last_seen = record.get('last_seen', 'N/A')
                if last_seen and last_seen != 'N/A':
                    try:
                        dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                        last_seen = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        pass
                
                # Parse tags
                tags = record.get('tags', [])
                if isinstance(tags, str):
                    try:
                        tags = json.loads(tags)
                    except:
                        tags = []
                tags_str = ', '.join(tags[:3]) + ('...' if len(tags) > 3 else '')
                
                items = [
                    QTableWidgetItem(timestamp),
                    QTableWidgetItem(record.get('source_provider', '')),
                    QTableWidgetItem(record.get('ioc_type', '')),
                    QTableWidgetItem(record.get('ioc_value', '')),
                    QTableWidgetItem(first_seen),
                    QTableWidgetItem(last_seen),
                    QTableWidgetItem(tags_str)
                ]
                
                for col, item in enumerate(items):
                    self.data_table.setItem(row, col, item)
            
            # Update pagination controls
            self.page_label.setText(f"Page {self.current_page}")
            self.prev_btn.setEnabled(self.current_page > 1)
            self.next_btn.setEnabled(len(data) == limit)  # Assume more data if we got a full page
            
            # Update total records label (approximate)
            total_estimate = offset + len(data)
            if len(data) < limit:
                self.total_records_label.setText(f"Total records: {total_estimate}")
            else:
                self.total_records_label.setText(f"Total records: {total_estimate}+ (estimated)")
                
        except Exception as e:
            self.log(f"Error loading data page: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load data: {e}")

    def previous_page(self):
        """Go to previous page"""
        if self.current_page > 1:
            self.current_page -= 1
            self.load_data_page()

    def next_page(self):
        """Go to next page"""
        self.current_page += 1
        self.load_data_page()

    def export_data(self):
        """Export current data view to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Data",
            f"threat_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv);;JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                # Get all data (not just current page)
                filters = {}
                provider_filter = self.provider_filter.currentText()
                if provider_filter != "All Providers":
                    filters['source_provider'] = provider_filter
                
                # Get a large number of records
                data = self.aggregator.repository.get_threats_paginated(10000, 0, filters)
                
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(data, f, indent=2, default=str)
                else:  # CSV
                    import csv
                    with open(file_path, 'w', newline='', encoding='utf-8') as f:
                        if data:
                            writer = csv.DictWriter(f, fieldnames=data[0].keys())
                            writer.writeheader()
                            writer.writerows(data)
                
                QMessageBox.information(self, "Export Complete", f"Data exported to {file_path}")
                self.log(f"Data exported to {file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export data: {e}")
                self.log(f"Export error: {e}")

    def closeEvent(self, event):
        """Handle application close event"""
        reply = QMessageBox.question(self, 'Quit Application', 
                                   'Are you sure you want to quit? This will stop all aggregation and API services.',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log("Application closing...")
            
            # Stop aggregation
            self.stop_aggregation_async()
            
            # Stop status timer
            if hasattr(self, 'status_timer'):
                self.status_timer.stop()
            
            # Signal aggregator loop to stop
            if self.aggregator_loop.is_running():
                self.aggregator_loop.call_soon_threadsafe(self.aggregator_loop.stop)
            
            event.accept()
        else:
            event.ignore()

# --- Main Execution Setup ---
def run_aggregator_event_loop(loop: asyncio.AbstractEventLoop, aggregator: SimpleThreatAggregator):
    """Runs the asyncio event loop for the aggregator's background tasks."""
    asyncio.set_event_loop(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Aggregator loop interrupted by Ctrl+C.")
    finally:
        print("Aggregator event loop stopping...")
        
        # Clean up pending tasks
        tasks = [t for t in asyncio.all_tasks(loop=loop) if t is not asyncio.current_task(loop=loop)]
        if tasks:
            print(f"Cancelling {len(tasks)} outstanding async tasks...")
            for task in tasks:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        
        # Shutdown aggregator
        if hasattr(aggregator, '_httpx_client') and aggregator._httpx_client:
            loop.run_until_complete(aggregator.shutdown())
        
        loop.close()
        print("Aggregator event loop stopped and closed.")

def main():
    """Main entry point for the application"""
    print("Starting Advanced Threat Aggregator with PyQt6...")
    print(f"Current time: {now_utc_iso()}")
    print(f"Starting application for user: clearblueyellow")
    
    # Create QApplication
    app = QApplication(sys.argv)
    
    # Apply dark theme
    app.setPalette(DARK_PALETTE)
    app.setStyle('Fusion')  # Use Fusion style for better dark theme support
    
    # Set application properties
    app.setApplicationName("Advanced Threat Aggregator")
    app.setApplicationVersion("2.0.0")
    app.setOrganizationName("Chicha Cybersecurity")
    app.setOrganizationDomain("chicha-cybersecurity.com")
    
    # Create a new asyncio event loop for the aggregator's background tasks
    aggregator_event_loop = asyncio.new_event_loop()

    # Initialize aggregator
    aggregator = SimpleThreatAggregator(config_path="threat_aggregator_config.json")
    
    def run_loop_wrapper():
        run_aggregator_event_loop(aggregator_event_loop, aggregator)
    
    # Start the aggregator's event loop in a separate thread
    aggregator_thread = threading.Thread(target=run_loop_wrapper, daemon=True)
    aggregator_thread.start()

    try:
        # Create and show the GUI
        gui_app = AggregatorGUI(aggregator_event_loop, aggregator)
        aggregator.log_callback = gui_app.log  # Now aggregator logs to GUI
        
        gui_app.show()
        
        # Start the GUI event loop
        exit_code = app.exec()
        
    except Exception as e:
        print(f"Error starting GUI: {e}")
        return 1
    
    finally:
        # After GUI closes, ensure aggregator loop and thread are stopped
        print("GUI closed. Signaling aggregator event loop to stop...")
        if aggregator_event_loop.is_running():
            aggregator_event_loop.call_soon_threadsafe(aggregator_event_loop.stop)
        
        print("Waiting for aggregator thread to join...")
        aggregator_thread.join(timeout=10)  # Wait for the aggregator thread
        if aggregator_thread.is_alive():
            print("Aggregator thread did not join in time.")
        
        print("Application shutdown complete.")
    
    return exit_code

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

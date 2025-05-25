
import os
import json
import time
import httpx # Asynchronous HTTP client
import asyncio # For asynchronous operations
import pandas as pd
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timezone
from queue import Queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import sqlite3 # For SQLite database

# For REST API
from fastapi import FastAPI, HTTPException, Security, Request
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# --- Configuration for API Key ---
API_KEY_NAME = "X-API-Key"
API_KEY_HEADER = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# --- Database Utilities ---
DB_NAME = "threat_intelligence.db"

def init_db(log_callback=None):
    """Initializes the SQLite database and creates tables if they don't exist."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        # Create table for aggregated data
        # Using TEXT for JSON-like fields for flexibility, or define specific columns
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS aggregated_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_provider TEXT NOT NULL,
            ioc_type TEXT, -- e.g., ip, domain, url, hash
            ioc_value TEXT NOT NULL UNIQUE, -- The actual indicator value, should be unique
            raw_data TEXT NOT NULL, -- Store the full JSON record from the provider
            first_seen TEXT,
            last_seen TEXT,
            tags TEXT, -- Comma-separated or JSON array
            threat_score REAL DEFAULT 0.0, -- Placeholder for scoring
            processed_at TEXT NOT NULL 
        )
        """)
        # Create index for faster lookups on ioc_value
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON aggregated_threats (ioc_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_source_provider ON aggregated_threats (source_provider)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON aggregated_threats (timestamp)")

        conn.commit()
        if log_callback: log_callback(f"Database '{DB_NAME}' initialized successfully.")
    except sqlite3.Error as e:
        if log_callback: log_callback(f"Database Error: Failed to initialize database: {e}")
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

# --- Threat Provider Base Class ---
class ThreatProvider:
    """Base class for all threat intelligence providers."""
    def __init__(self, name, config, httpx_client: httpx.AsyncClient):
        self.name = name
        self.config = config
        self.provider_config = config.get("providers", {}).get(name, {})
        self.api_key = config.get("api_keys", {}).get(name)
        self.enabled = self.provider_config.get("enabled", True)
        self.query_params = self.provider_config.get("query_params", {})
        self.client = httpx_client # Use shared httpx client

    async def fetch(self):
        """Fetches data from the provider. Must be implemented by subclasses."""
        raise NotImplementedError("Fetch method not implemented by provider.")

    def _normalize_data(self, records):
        """
        Placeholder for normalizing data from this provider to a common schema.
        Each record should be a dictionary.
        Output should be a list of dicts, each with standardized keys like:
        {
            "ioc_type": "ip", "ioc_value": "1.2.3.4", "raw_data": {...}, 
            "first_seen": "iso_timestamp", "last_seen": "iso_timestamp", 
            "tags": ["malware", "c2"], "source_provider": self.name,
            "timestamp": now_utc_iso() # Timestamp of collection for this record
        }
        """
        normalized = []
        for record in records:
            # Basic placeholder normalization - THIS NEEDS TO BE CUSTOMIZED PER PROVIDER
            norm_rec = {
                "ioc_type": record.get("type", "unknown"), # Attempt to get type
                "ioc_value": record.get("id", record.get("ip", record.get("url", str(record)))), # Best effort to find an IOC
                "raw_data": json.dumps(record),
                "first_seen": record.get("first_seen", record.get("firstSeen", record.get("first_submission_date"))),
                "last_seen": record.get("last_seen", record.get("lastSeen", record.get("last_submission_date"))),
                "tags": json.dumps(record.get("tags", [])),
                "source_provider": self.name,
                "timestamp": now_utc_iso()
            }
            # Ensure first_seen and last_seen are ISO format if present
            if norm_rec["first_seen"] and not isinstance(norm_rec["first_seen"], str):
                try: norm_rec["first_seen"] = pd.to_datetime(norm_rec["first_seen"]).isoformat()
                except: norm_rec["first_seen"] = None
            if norm_rec["last_seen"] and not isinstance(norm_rec["last_seen"], str):
                try: norm_rec["last_seen"] = pd.to_datetime(norm_rec["last_seen"]).isoformat()
                except: norm_rec["last_seen"] = None

            normalized.append(norm_rec)
        return normalized

# --- Specific Threat Providers (Async) ---
class VirusTotalProvider(ThreatProvider):
    async def fetch(self):
        if not self.enabled or not self.api_key:
            print(f"{self.name}: Disabled or API key not configured. Skipping.")
            return []
        headers = {"x-apikey": self.api_key}
        limit = self.query_params.get("limit", 3)
        query = self.query_params.get("query", "entity:ip_address order:last_submission_date-")
        url = f"https://www.virustotal.com/api/v3/intelligence/search?query={query}&limit={limit}"
        
        try:
            r = await self.client.get(url, headers=headers, timeout=20)
            r.raise_for_status()
            data = r.json().get("data", [])
            processed_records = []
            for item in data:
                record = item.get("attributes", {})
                record["id"] = item.get("id") 
                record["type"] = item.get("type")
                # Add more specific field extraction if needed for normalization
                processed_records.append(record)
            return self._normalize_data(processed_records)
        except httpx.TimeoutException: print(f"{self.name} error: Request timed out.")
        except httpx.HTTPStatusError as e: print(f"{self.name} error: HTTP Error - {e.response.status_code} - {e.response.text}")
        except httpx.RequestError as e: print(f"{self.name} error: Request failed - {e}")
        except json.JSONDecodeError as e: print(f"{self.name} error: Failed to decode JSON - {e}")
        except Exception as e: print(f"{self.name} unexpected error: {e}")
        return []

class GreyNoiseProvider(ThreatProvider):
    async def fetch(self):
        if not self.enabled or not self.api_key:
            print(f"{self.name}: Disabled or API key not configured. Skipping.")
            return []
        headers = {"key": self.api_key, "Accept": "application/json"}
        ip_to_check = self.query_params.get("ip_address", "8.8.8.8") # Example, make configurable
        # For general feeds, use appropriate GreyNoise endpoints (e.g., /v2/noise/quick)
        url = f"https://api.greynoise.io/v3/community/{ip_to_check}" 
        try:
            r = await self.client.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            record = r.json()
            if record.get("ip"):
                return self._normalize_data([record])
            else:
                print(f"{self.name} error: Unexpected response format - {record}")
                return []
        except httpx.TimeoutException: print(f"{self.name} error: Request timed out for IP {ip_to_check}.")
        except httpx.HTTPStatusError as e: print(f"{self.name} error: HTTP Error for IP {ip_to_check} - {e.response.status_code} - {e.response.text}")
        # ... other specific exceptions
        except Exception as e: print(f"{self.name} unexpected error for IP {ip_to_check}: {e}")
        return []

class AbuseIPDBProvider(ThreatProvider):
    async def fetch(self):
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
        try:
            r = await self.client.get(url, headers=headers, params=params, timeout=15)
            r.raise_for_status()
            response_json = r.json()
            if "data" in response_json:
                return self._normalize_data([response_json["data"]])
            else:
                print(f"{self.name} error: 'data' key not found. Response: {response_json}")
                return []
        # ... specific exception handling ...
        except Exception as e: print(f"{self.name} unexpected error: {e}")
        return []

class AlienVaultOTXProvider(ThreatProvider):
    async def fetch(self):
        if not self.enabled or not self.api_key:
            print(f"{self.name}: Disabled or API key not configured. Skipping.")
            return []
        headers = {"X-OTX-API-KEY": self.api_key}
        indicator_type = self.query_params.get("indicator_type", "IPv4")
        indicator_value = self.query_params.get("indicator_value", "8.8.8.8")
        section = self.query_params.get("section", "general") # e.g., general, malware, url_list
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator_value}/{section}"
        try:
            r = await self.client.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            record = r.json()
            # OTX can return various structures depending on section, normalization is key
            return self._normalize_data([record])
        # ... specific exception handling ...
        except Exception as e: print(f"{self.name} unexpected error: {e}")
        return []

class MISPProvider(ThreatProvider):
    async def fetch(self):
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
            **self.query_params.get("search_params", {}) # Allow arbitrary search params
        }
        # verify=False for self-signed certs, make this configurable
        # httpx client handles SSL verification context if needed
        try:
            r = await self.client.post(misp_url.rstrip('/') + "/events/restSearch", headers=headers, json=payload, timeout=30)
            r.raise_for_status()
            response_json = r.json()
            events_data = response_json.get("response", [])
            
            processed_events = []
            for event_container in events_data:
                if "Event" in event_container:
                    # Further processing to extract attributes as individual IOCs might be needed here
                    processed_events.append(event_container["Event"]) 
            return self._normalize_data(processed_events)
        # ... specific exception handling ...
        except Exception as e: print(f"{self.name} unexpected error: {e}")
        return []

class URLhausProvider(ThreatProvider):
    async def fetch(self):
        if not self.enabled:
            print(f"{self.name}: Disabled. Skipping.")
            return []
        # URLhaus /recent endpoint does not require API key
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        limit = self.query_params.get("limit") # Their API uses a specific way for limit, not a query param
        if limit: url += f"limit/{limit}/"

        try:
            r = await self.client.get(url, timeout=15) # GET request
            r.raise_for_status()
            response_json = r.json()
            if response_json.get("query_status") == "ok":
                return self._normalize_data(response_json.get("urls", []))
            else:
                print(f"{self.name} error: API query status not ok - {response_json.get('query_status')}")
                return []
        # ... specific exception handling ...
        except Exception as e: print(f"{self.name} unexpected error: {e}")
        return []

class StubProvider(ThreatProvider):
    async def fetch(self):
        if not self.enabled: return []
        # print(f"{self.name}: Stub provider, returning no data.")
        return []


# --- Aggregator Class ---
class SimpleThreatAggregator:
    DEFAULT_CONFIG = {
        "app_api_key": "YOUR_SECRET_APP_API_KEY", # For protecting the aggregator's own API
        "output_format": "json", # Less relevant with DB, but kept for ML export
        "storage_limit_gb": 1, # For file-based output if any, DB has its own management
        "api_keys": {}, # For external providers
        "providers": { # Default provider configurations
            "VirusTotal": {"enabled": True, "query_params": {"limit": 10}},
            "GreyNoise": {"enabled": False, "query_params": {"ip_address": "1.1.1.1"}}, # Example, disabled by default
            "AbuseIPDB": {"enabled": True, "query_params": {"maxAgeInDays": "30"}},
            "AlienVaultOTX": {"enabled": True, "query_params": {"indicator_type": "IPv4", "section": "general"}},
            "MISP": {"enabled": False, "query_params": {"limit": 5}},
            "URLhaus": {"enabled": True, "query_params": {}},
            "CyberSixGill": {"enabled": False}, "RecordedFuture": {"enabled": False},
            "Filigran": {"enabled": False}, "ThreatbookCTI": {"enabled": False},
            "CheckPointMap": {"enabled": False}, "RadwareMap": {"enabled": False},
            "KasperskyMap": {"enabled": False}, "SOCRadar": {"enabled": False},
            "ThreatIntelligencePlatform": {"enabled": False}, "Anomali": {"enabled": False},
        },
        "output_directory": "aggregated_data_files", # For file exports like ML
        "ml_export_dir": "ml_exports",
        "interval": 3600,
        "rest_api_port": 8008,
        "db_name": DB_NAME
    }

    def __init__(self, config_path="config.json", log_callback=print):
        self.config_path = config_path
        self.log_callback = log_callback
        self.load_config()
        self.data_queue = asyncio.Queue() # Using asyncio.Queue for async processing
        self.running = False
        self.lock = asyncio.Lock() # For async-safe operations
        self.latest_activity = time.time()
        self.stats = {"bytes_sent": 0, "records_sent": 0, "bytes_received": 0, "records_received": 0}
        
        init_db(self.log_callback) # Initialize database

        os.makedirs(self.config['output_directory'], exist_ok=True)
        os.makedirs(self.config.get("ml_export_dir", "ml_exports"), exist_ok=True)

        self.httpx_client = httpx.AsyncClient(verify=False) # Central httpx client, consider SSL context config
        self._init_providers()
        self.last_df_for_api = pd.DataFrame() # Still useful for quick API if needed, or remove

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
                self.providers_instances[name] = cls(name, self.config, self.httpx_client)

    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    loaded_config = json.load(f)
                # Deep merge for nested dicts like 'providers'
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
        self.log_callback("Starting async data collection cycle...")
        tasks = []
        for name, provider in self.providers_instances.items():
            if provider.enabled:
                self.log_callback(f"Queueing fetch for {name}...")
                tasks.append(asyncio.create_task(provider.fetch(), name=name)) # Name task for context
            else:
                self.log_callback(f"Skipping disabled provider: {name}")
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result_data_list in enumerate(results):
            task_name = tasks[i].get_name() # Get provider name from task
            if isinstance(result_data_list, Exception):
                self.log_callback(f"Error fetching from {task_name}: {result_data_list}")
            elif result_data_list: # Ensure data is not None and not empty
                self._track_data_stats(result_data_list, task_name)
                await self.data_queue.put((task_name, result_data_list)) # result_data_list is already normalized
                self.latest_activity = time.time()
                self.log_callback(f"Received {len(result_data_list)} normalized items from {task_name}.")
            elif result_data_list is not None: # Empty list, not an error
                 self.log_callback(f"No data received from {task_name}.")
        self.log_callback("Async data collection cycle finished.")

    def _track_data_stats(self, data_list, source_name="Unknown"):
        num_records = len(data_list)
        self.stats["records_received"] += num_records
        # Rough byte count of received (normalized) data
        try:
            self.stats["bytes_received"] += sum(len(json.dumps(d).encode('utf-8')) for d in data_list)
        except Exception: pass # Ignore if can't calc bytes

    async def process_and_save_data(self):
        """Processes data from queue and saves to DB."""
        if self.data_queue.empty():
            self.log_callback("No data in queue to process for DB.")
            return 0 # No records processed

        records_processed_count = 0
        conn = None
        try:
            conn = sqlite3.connect(self.config.get("db_name", DB_NAME))
            cursor = conn.cursor()
            
            while not self.data_queue.empty():
                source_provider, normalized_records = await self.data_queue.get()
                
                for record in normalized_records:
                    try:
                        # Insert or Ignore to handle unique constraint on ioc_value
                        # This means if an IOC is already in DB, we don't update it here.
                        # For updates, use INSERT OR REPLACE or specific UPDATE logic.
                        cursor.execute("""
                        INSERT OR IGNORE INTO aggregated_threats 
                        (timestamp, source_provider, ioc_type, ioc_value, raw_data, first_seen, last_seen, tags, processed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            record.get("timestamp"), record.get("source_provider"),
                            record.get("ioc_type"), record.get("ioc_value"),
                            record.get("raw_data"), record.get("first_seen"),
                            record.get("last_seen"), record.get("tags"),
                            now_utc_iso() # Processed_at timestamp
                        ))
                        if cursor.rowcount > 0: # If a row was inserted
                            records_processed_count += 1
                            # Placeholder for threat scoring call
                            # self.calculate_threat_score(record.get("ioc_value"))
                    except sqlite3.Error as e:
                        self.log_callback(f"DB Error inserting record from {source_provider} (IOC: {record.get('ioc_value')}): {e}")
                    except Exception as e_rec:
                        self.log_callback(f"Error processing record {record.get('ioc_value')} from {source_provider}: {e_rec}")
                self.data_queue.task_done()

            conn.commit()
            if records_processed_count > 0:
                self.log_callback(f"Successfully processed and saved {records_processed_count} new records to database.")
                self.stats["records_sent"] += records_processed_count # "sent" to DB
                # Placeholder for ML export from DB data if needed
                # await self.export_for_ml_from_db(timestamp_str) 
            else:
                self.log_callback("No new unique records to save to database in this batch.")
            
            self.enforce_db_storage_limit() # Manage DB size
            return records_processed_count

        except sqlite3.Error as e:
            self.log_callback(f"Database Error during process_and_save_data: {e}")
            if conn: conn.rollback()
        except Exception as e:
            self.log_callback(f"Unexpected error in process_and_save_data: {e}")
        finally:
            if conn:
                conn.close()
        return 0
        
    def enforce_db_storage_limit(self, max_records=100000): # Example limit
        """Placeholder: Enforces a storage limit on the DB (e.g., by deleting oldest records)."""
        # This is a simplified example. Real DB size management is more complex.
        # Could also be based on file size of DB or age of records.
        limit = self.config.get("db_max_records", max_records)
        try:
            conn = sqlite3.connect(self.config.get("db_name", DB_NAME))
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM aggregated_threats")
            count = cursor.fetchone()[0]
            if count > limit:
                num_to_delete = count - limit
                # Delete the oldest records
                cursor.execute("""
                    DELETE FROM aggregated_threats 
                    WHERE id IN (SELECT id FROM aggregated_threats ORDER BY timestamp ASC LIMIT ?)
                """, (num_to_delete,))
                conn.commit()
                self.log_callback(f"DB Storage: Enforced limit, deleted {num_to_delete} oldest records.")
        except sqlite3.Error as e:
            self.log_callback(f"DB Error enforcing storage limit: {e}")
        finally:
            if conn: conn.close()

    async def run_once(self):
        async with self.lock:
            self.log_callback("Starting manual async run (run_once)...")
            await self.collect_data()
            records_saved = await self.process_and_save_data()
            
            if records_saved > 0:
                # For API/GUI that might want a DataFrame of the latest *newly added* data
                # This is tricky as process_and_save_data doesn't return the data itself
                # We'd need to query the DB for records just added.
                # For now, self.last_df_for_api will not be updated here directly.
                # The API should query the DB directly.
                pass
            else:
                self.log_callback("Manual async run completed. No new data processed or saved to DB.")
            # Return count of newly saved records, or a DataFrame if you query them back
            return records_saved 

    async def run_periodically(self, update_plot_callback=None, status_callback=None):
        self.running = True
        self.log_callback(f"Starting periodic async aggregation. Interval: {self.config['interval']} seconds.")
        
        while self.running:
            start_time = time.time()
            await self.run_once()
            
            # Plotting and status updates would need to be adapted for async
            # Or run in the main thread based on data fetched from DB
            if status_callback:
                try: status_callback(self.get_status())
                except Exception as e_status: self.log_callback(f"Error updating status: {e_status}")
            
            # For plotting, it's better to fetch data from DB in the GUI thread
            # and call update_plot_callback there.
            # if update_plot_callback:
            #    df_for_plot = self.query_data_for_plot_from_db() # Needs implementation
            #    update_plot_callback(df_for_plot)


            elapsed_time = time.time() - start_time
            sleep_duration = max(0, self.config["interval"] - elapsed_time)
            self.log_callback(f"Async cycle finished in {elapsed_time:.2f}s. Sleeping for {sleep_duration:.2f}s.")
            
            try:
                await asyncio.sleep(sleep_duration)
            except asyncio.CancelledError:
                self.log_callback("Periodic run cancelled during sleep.")
                break # Exit if task is cancelled
            if not self.running: break
        
        self.log_callback("Periodic async aggregation stopped.")
        await self.httpx_client.aclose() # Close the httpx client when done


    def stop(self):
        self.running = False
        self.log_callback("Stop signal received for aggregator.")
        # Async tasks will check self.running or be cancelled

    def get_status(self):
        now = time.time()
        active_threshold = self.config.get("interval", 3600) + 120 # Increased buffer
        active = (now - self.latest_activity) < active_threshold
        
        return {
            "running": self.running,
            "active_processing": active,
            "total_bytes_received_session": self.stats["bytes_received"],
            "total_records_received_session": self.stats["records_received"],
            "total_records_saved_to_db_session": self.stats["records_sent"],
            "last_activity_time": datetime.fromtimestamp(self.latest_activity, tz=timezone.utc).isoformat() if self.latest_activity else "N/A",
            "data_queue_size": self.data_queue.qsize() if hasattr(self.data_queue, 'qsize') else 'N/A'
        }

    # --- ML Export (Placeholder - adapt to read from DB) ---
    async def export_for_ml_from_db(self, log_callback=None, limit=1000):
        """Exports data from DB in a format suitable for ML."""
        # This needs to fetch data from SQLite and then process
        self.log_callback("ML Export from DB: Placeholder function.")
        # Example: fetch recent data
        # conn = sqlite3.connect(self.config.get("db_name", DB_NAME))
        # df = pd.read_sql_query(f"SELECT * FROM aggregated_threats ORDER BY timestamp DESC LIMIT {limit}", conn)
        # conn.close()
        # ... then call extract_ml_features(df) and save ...
        pass

    def extract_ml_features(self.df, log_callback=None): # This is synchronous, adapt if needed
        # (Keep existing extract_ml_features logic, but it will operate on df from DB)
        if df.empty: return pd.DataFrame()
        # ... (previous ML feature extraction logic) ...
        # Ensure 'raw_data' is parsed if features are needed from it
        # Example: df['parsed_raw_data'] = df['raw_data'].apply(json.loads)
        self.log_callback("ML Feature Extraction: Needs to be adapted for DB fields.")
        return df # Placeholder

    # --- Placeholder for other advanced features ---
    def calculate_threat_score(self, ioc_value):
        self.log_callback(f"Placeholder: Calculating threat score for {ioc_value}")
        # Logic to update threat_score in DB for the given ioc_value
        pass

    def advanced_data_normalization(self, record, provider_name):
        self.log_callback(f"Placeholder: Advanced normalization for {provider_name}")
        return record # Return processed record

    def enrich_ioc(self, ioc_value, ioc_type):
        self.log_callback(f"Placeholder: Enriching IOC {ioc_type}: {ioc_value}")
        return {} # Return enrichment data

# --- REST API (FastAPI) ---
class AggregatorAPI:
    def __init__(self, aggregator: SimpleThreatAggregator):
        self.aggregator = aggregator
        self.app = FastAPI(title="Threat Aggregator REST API v2", version="2.0.0")
        self.app.add_middleware(
            CORSMiddleware, allow_origins=["*"], allow_credentials=True,
            allow_methods=["*"], allow_headers=["*"],
        )
        # Security dependency for API Key
        async def get_api_key(api_key_header: str = Security(API_KEY_HEADER)):
            correct_api_key = self.aggregator.config.get("app_api_key", "DEFAULT_FALLBACK_KEY_IF_NOT_SET")
            if api_key_header == correct_api_key:
                return api_key_header
            else:
                raise HTTPException(status_code=403, detail="Could not validate credentials")

        # Define routes
        self.app.get("/status", summary="Get Aggregator Status")(self.status) # Unprotected status
        self.app.get("/data/latest", summary="Get Latest Aggregated Data from DB", dependencies=[Security(get_api_key)])(self.latest_data_from_db)
        # self.app.get("/ml/latest", summary="Get Latest ML Export", dependencies=[Security(get_api_key)])(self.latest_ml_export) # Needs rework for DB
        self.app.post("/control/trigger_run", summary="Trigger Manual Run", dependencies=[Security(get_api_key)])(self.trigger_manual_run)
        self.app.get("/config", summary="Get Current Configuration (Masked)", dependencies=[Security(get_api_key)])(self.get_masked_config)

    async def status(self):
        return self.aggregator.get_status()

    async def latest_data_from_db(self, request: Request, limit: int = 100, offset: int = 0, source_provider: str = None):
        conn = None
        try:
            conn = sqlite3.connect(self.aggregator.config.get("db_name", DB_NAME))
            conn.row_factory = dict_factory # Return rows as dicts
            cursor = conn.cursor()
            
            query = "SELECT * FROM aggregated_threats"
            params = []
            conditions = []

            if source_provider:
                conditions.append("source_provider = ?")
                params.append(source_provider)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, tuple(params))
            data = cursor.fetchall()

            # Parse JSON strings back to objects for raw_data and tags
            for row in data:
                if row.get('raw_data'): row['raw_data'] = json.loads(row['raw_data'])
                if row.get('tags'): row['tags'] = json.loads(row['tags'])
            
            if not data:
                return JSONResponse(content={"message": "No data found matching criteria."}, status_code=404)
            return JSONResponse(content=data)
        except sqlite3.Error as e:
            raise HTTPException(status_code=500, detail=f"Database error: {e}")
        except json.JSONDecodeError as e:
             raise HTTPException(status_code=500, detail=f"Error decoding stored JSON data: {e}")
        finally:
            if conn: conn.close()

    async def trigger_manual_run(self, request: Request):
        # Run in background to not block API response for long
        # FastAPI's BackgroundTasks is suitable here
        # For simplicity now, direct await, but this will block.
        # from fastapi import BackgroundTasks
        # background_tasks.add_task(self.aggregator.run_once)
        await self.aggregator.run_once()
        return {"status": "Manual aggregation run triggered."}

    async def get_masked_config(self, request: Request):
        safe_config = self.aggregator.config.copy()
        safe_config["app_api_key"] = "********"
        if "api_keys" in safe_config:
            safe_config["api_keys"] = {key: "********" for key in safe_config["api_keys"]}
        return JSONResponse(content=safe_config)

    def run_api_server(self):
        port = self.aggregator.config.get("rest_api_port", 8008)
        host = "0.0.0.0"
        self.aggregator.log_callback(f"Starting REST API on http://{host}:{port}")
        uvicorn.run(self.app, host=host, port=port, log_level="info")

# --- GUI ---
class AggregatorGUI(tk.Tk):
    def __init__(self, aggregator_loop: asyncio.AbstractEventLoop, aggregator: SimpleThreatAggregator):
        super().__init__()
        self.aggregator_loop = aggregator_loop # Event loop for running async aggregator tasks
        self.aggregator = aggregator
        self.title("Advanced Threat Aggregator GUI")
        self.geometry("1300x900")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.aggregator_task = None # For the main aggregator periodic run
        self.api_thread = None # For REST API server
        self.status_polling_active = True

        self.create_widgets()
        self.load_config_to_gui()
        self.status_update_loop()
        self.log("GUI Initialized. Ensure config.json is set up.")

    def create_widgets(self):
        # --- Configuration Frame ---
        conf_frame = ttk.LabelFrame(self, text="Configuration", padding=(10, 5))
        conf_frame.pack(fill="x", padx=10, pady=5)
        # (Interval, Output Format, Storage Limit, API Port - similar to before)
        # ...
        ttk.Label(conf_frame, text="App API Key:").grid(row=0, column=8, padx=5, pady=2, sticky="w")
        self.app_api_key_var = tk.StringVar()
        ttk.Entry(conf_frame, textvariable=self.app_api_key_var, width=20, show="*").grid(row=0, column=9, padx=5, pady=2)
        # ... (Output Dir, ML Dir, Save Config Button)

        # --- Provider Enable/Disable Frame ---
        prov_ctrl_frame = ttk.LabelFrame(self, text="Provider Controls", padding=(10,5))
        prov_ctrl_frame.pack(fill="x", padx=10, pady=5)
        self.provider_vars = {}
        col, row = 0, 0
        max_cols = 4 # Providers per row in GUI
        for prov_name in self.aggregator.config.get("providers", {}).keys():
            var = tk.BooleanVar(value=self.aggregator.config["providers"][prov_name].get("enabled", True))
            chk = ttk.Checkbutton(prov_ctrl_frame, text=prov_name, variable=var)
            chk.grid(row=row, column=col, padx=3, pady=2, sticky="w")
            self.provider_vars[prov_name] = var
            col += 1
            if col >= max_cols:
                col = 0
                row += 1
        ttk.Button(prov_ctrl_frame, text="Save Provider Settings", command=self.save_provider_settings).grid(row=row+1, column=0, columnspan=max_cols, pady=5)


        # --- API Keys Frame (similar to before) ---
        # ...

        # --- Status Frame (similar to before) ---
        # ...

        # --- Monitor & Controls Frame (similar, but async calls) ---
        mon_frame = ttk.LabelFrame(self, text="Monitor & Controls", padding=(10,5))
        mon_frame.pack(fill="both", expand=True, padx=10, pady=5)
        # ... (Log Text Area) ...
        self.start_btn = ttk.Button(log_controls_frame, text="Start Aggregation", command=self.start_aggregation_async)
        self.stop_btn = ttk.Button(log_controls_frame, text="Stop Aggregation", command=self.stop_aggregation_async, state="disabled")
        ttk.Button(log_controls_frame, text="Run Once Now", command=self.run_once_gui_async)


        # --- Visualization Frame (similar) ---
        # ...
        self.log("Widgets created.")


    def log(self, msg):
        if hasattr(self, 'log_text') and self.log_text.winfo_exists():
            self.log_text.insert(tk.END, f"{now_utc_iso()} - {msg}\n")
            self.log_text.see(tk.END)
            self.update_idletasks()
        else: # Fallback if GUI not fully up or in thread
            print(f"{now_utc_iso()} - LOG: {msg}")


    def load_config_to_gui(self):
        self.aggregator.load_config() # Ensure aggregator has latest
        config = self.aggregator.config
        # ... (load interval, format, limit, dirs, api_port) ...
        self.app_api_key_var.set(config.get("app_api_key", ""))

        # Load provider enabled states
        for prov_name, var in self.provider_vars.items():
            var.set(config.get("providers", {}).get(prov_name, {}).get("enabled", True))
        
        # Load API keys (similar to before)
        # ...
        self.log("Configuration loaded into GUI.")

    def save_gui_config(self): # General config part
        try:
            # ... (save interval, format, limit, dirs, api_port from vars) ...
            self.aggregator.config["app_api_key"] = self.app_api_key_var.get()
            # Provider enabled states are saved separately by save_provider_settings
            self.aggregator.save_config()
            self.log("General configuration saved.")
            messagebox.showinfo("Config Saved", "General configuration saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save general config: {e}")
            self.log(f"Error saving general config: {e}")

    def save_provider_settings(self):
        try:
            if "providers" not in self.aggregator.config:
                self.aggregator.config["providers"] = {}
            for prov_name, var in self.provider_vars.items():
                if prov_name not in self.aggregator.config["providers"]:
                    self.aggregator.config["providers"][prov_name] = {}
                self.aggregator.config["providers"][prov_name]["enabled"] = var.get()
            
            self.aggregator.save_config()
            self.aggregator._init_providers() # Re-initialize with new enabled states
            self.log("Provider enabled/disabled settings saved.")
            messagebox.showinfo("Provider Settings", "Provider settings saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save provider settings: {e}")

    # --- Async GUI Actions ---
    def start_aggregation_async(self):
        self.save_gui_config() # Save general config first
        self.save_provider_settings() # Save provider specifics

        if self.aggregator_task and not self.aggregator_task.done():
            self.log("Aggregation is already running.")
            return
        self.log("Starting periodic async aggregation from GUI...")
        # Schedule the aggregator's run_periodically on its own event loop
        self.aggregator_task = asyncio.run_coroutine_threadsafe(
            self.aggregator.run_periodically(status_callback=self.update_status_gui_safe), 
            self.aggregator_loop
        )
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

    def stop_aggregation_async(self):
        self.log("Stopping periodic async aggregation from GUI...")
        self.aggregator.stop() # Signal the running flag
        if self.aggregator_task and not self.aggregator_task.done():
            # Attempt to cancel the asyncio task
            self.aggregator_loop.call_soon_threadsafe(self.aggregator_task.cancel)
            # Note: Cancellation might take time or might not be immediate if the task is in a long sleep or blocking call
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log("Stop signal sent. Aggregation will halt after current cycle/sleep.")

    def run_once_gui_async(self):
        self.save_gui_config()
        self.save_provider_settings()
        self.log("Manual async run initiated from GUI...")
        # Run in a new thread that manages its own small async task, or use run_coroutine_threadsafe
        async def _run_once_task():
            await self.aggregator.run_once()
            self.update_status_gui_safe(self.aggregator.get_status()) # Update status after run
            # Potentially update plot here by fetching data from DB
            self.log("Manual async run finished.")

        asyncio.run_coroutine_threadsafe(_run_once_task(), self.aggregator_loop)

    def update_status_gui_safe(self, status_data):
        """Safely update GUI status from another thread via `after`."""
        self.after(0, self.update_status_gui, status_data) # Schedule on Tkinter main thread

    def update_plot_gui_safe(self, df_for_plot):
        self.after(0, self.update_plot_gui, df_for_plot)

    def update_status_gui(self, status_data): # Runs in Tkinter thread
        # (Similar to previous update_status_gui, using status_data)
        pass # Implement as before

    def update_plot_gui(self, df): # Runs in Tkinter thread
        # (Similar to previous update_plot_gui)
        # This should now fetch data from DB or be passed data suitable for plotting
        self.log("Plot update requested. (Needs DB query implementation for plotting)")
        pass # Implement as before, but consider data source

    def status_update_loop(self): # Runs in Tkinter thread
        if self.status_polling_active and self.winfo_exists():
            # Get status from aggregator (which is thread-safe)
            current_agg_status = self.aggregator.get_status() 
            self.update_status_gui(current_agg_status)
            
            # API status (if API thread is managed by GUI)
            if self.api_thread and self.api_thread.is_alive():
                port = self.aggregator.config.get('rest_api_port', 8008)
                self.api_status_label.config(text=f"API: Running on port {port}", foreground="green")
            else:
                self.api_status_label.config(text="API: Off", foreground="red")
            self.after(3000, self.status_update_loop)

    def start_rest_api(self): # Runs in Tkinter thread
        if not self.api_thread or not self.api_thread.is_alive():
            self.log("Attempting to start REST API...")
            self.save_gui_config() # Ensure API port and key are up-to-date in aggregator.config
            api_runner = AggregatorAPI(self.aggregator) # API uses aggregator's config
            self.api_thread = threading.Thread(target=api_runner.run_api_server, daemon=True)
            self.api_thread.start()
            self.log(f"REST API starting... Check console for uvicorn logs.")
            self.start_api_btn.config(state="disabled")
        else:
            self.log("REST API is already running.")

    def on_close(self): # Runs in Tkinter thread
        self.log("Close button clicked. Shutting down...")
        self.status_polling_active = False
        if messagebox.askokcancel("Quit", "Do you want to quit? This will stop aggregation and API server."):
            self.log("Proceeding with shutdown...")
            # Stop async aggregator
            self.stop_aggregation_async() # This signals and tries to cancel

            # FastAPI/Uvicorn in a daemon thread will exit when main app exits.
            # If more graceful shutdown is needed, uvicorn server needs to be managed.
            
            # Wait for aggregator task to finish if possible (optional, can be complex)
            # if self.aggregator_task:
            #    # This is tricky as join() is blocking and we are in Tkinter thread
            #    pass

            self.log("Exiting application.")
            # Ensure the aggregator loop is stopped if it's managed by this thread
            if self.aggregator_loop.is_running():
                 self.aggregator_loop.call_soon_threadsafe(self.aggregator_loop.stop)
            self.destroy()
        else:
            self.log("Shutdown cancelled.")
            self.status_polling_active = True
            self.status_update_loop() # Resume polling

# --- Main Execution Setup for Async ---
def run_aggregator_event_loop(loop: asyncio.AbstractEventLoop, aggregator: SimpleThreatAggregator, gui_app: AggregatorGUI):
    """Runs the asyncio event loop for the aggregator's background tasks."""
    asyncio.set_event_loop(loop)
    try:
        # The GUI will schedule aggregator.run_periodically onto this loop
        # This loop needs to keep running for those tasks.
        # If no tasks are scheduled by GUI immediately, it might exit.
        # A simple way to keep it running is to have a placeholder task or manage its lifecycle.
        # For now, we rely on the GUI to schedule the main periodic task.
        # If GUI starts aggregator on init, then this loop will have work.
        loop.run_forever()
    except KeyboardInterrupt:
        gui_app.log("Aggregator loop interrupted by Ctrl+C.")
    finally:
        gui_app.log("Aggregator event loop stopping...")
        # Clean up pending tasks
        tasks = [t for t in asyncio.all_tasks(loop=loop) if t is not asyncio.current_task(loop=loop)]
        if tasks:
            gui_app.log(f"Cancelling {len(tasks)} outstanding async tasks...")
            for task in tasks:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        loop.run_until_complete(aggregator.httpx_client.aclose()) # Close httpx client
        loop.close()
        gui_app.log("Aggregator event loop stopped and closed.")


if __name__ == "__main__":
    # Create a new asyncio event loop for the aggregator's background tasks
    aggregator_event_loop = asyncio.new_event_loop()

    # Initialize aggregator (passing the log_callback from GUI later or a default print)
    # For now, aggregator will use its default print for pre-GUI logging
    aggregator = SimpleThreatAggregator(config_path="threat_aggregator_config_v3.json")
    
    # Start the aggregator's event loop in a separate thread
    aggregator_thread = threading.Thread(
        target=run_aggregator_event_loop, 
        args=(aggregator_event_loop, aggregator, None), # Pass None for gui_app initially
        daemon=True
    )
    aggregator_thread.start()

    # Create and run the GUI in the main thread
    # The GUI will interact with the aggregator_event_loop via run_coroutine_threadsafe
    app_gui = AggregatorGUI(aggregator_event_loop, aggregator)
    aggregator.log_callback = app_gui.log # Now aggregator logs to GUI
    # Pass gui_app to aggregator_thread's target if it needs direct access for shutdown logging
    # This is a bit circular, so aggregator.log_callback is simpler.

    app_gui.mainloop()

    # After GUI closes, ensure aggregator loop and thread are stopped
    print("GUI closed. Signaling aggregator event loop to stop...")
    if aggregator_event_loop.is_running():
        aggregator_event_loop.call_soon_threadsafe(aggregator_event_loop.stop)
    
    print("Waiting for aggregator thread to join...")
    aggregator_thread.join(timeout=10) # Wait for the aggregator thread
    if aggregator_thread.is_alive():
        print("Aggregator thread did not join in time.")
    print("Application shutdown complete.")

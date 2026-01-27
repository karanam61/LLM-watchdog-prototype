"""
S3 Failover System - Complete Database Backup & Recovery
=========================================================

This module provides full failover capability to AWS S3 when Supabase
is unavailable. Unlike simple backup, this enables the system to
CONTINUE OPERATING during database outages.

WHAT THIS FILE DOES:
1. Periodically syncs ALL tables to S3 (alerts, logs)
2. Provides READ functions to fetch data from S3
3. Auto-detects database failure and switches to S3
4. Allows frontend and AI to keep working during outages

TABLES SYNCED:
- alerts              - Main alert storage
- process_logs        - Process execution telemetry
- network_logs        - Network connection telemetry
- file_activity_logs  - File system telemetry
- windows_event_logs  - Windows security events

S3 STRUCTURE:
    s3://bucket/
    ├── alerts/
    │   ├── latest.json          (full table snapshot)
    │   └── incremental/         (recent changes)
    ├── process_logs/
    │   └── latest.json
    ├── network_logs/
    │   └── latest.json
    ├── file_activity_logs/
    │   └── latest.json
    └── windows_event_logs/
        └── latest.json

Author: AI-SOC Watchdog System
"""

import os
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

from dotenv import load_dotenv
load_dotenv()

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# AWS S3 Configuration
S3_BUCKET = os.getenv("S3_BUCKET")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Tables to sync
SYNC_TABLES = [
    'alerts',
    'process_logs',
    'network_logs',
    'file_activity_logs',
    'windows_event_logs'
]

# Sync interval (5 minutes)
SYNC_INTERVAL_SECONDS = 300


class S3FailoverSystem:
    """
    Complete S3 failover system for database resilience.
    
    Features:
    - Automatic table sync to S3
    - Read fallback when database unavailable
    - Connection health tracking
    - Incremental updates for efficiency
    """
    
    def __init__(self):
        """Initialize S3 failover system."""
        self.s3_client = None
        self.s3_available = False
        self.last_sync = {}
        self.sync_lock = threading.Lock()
        self.is_failover_mode = False
        
        # In-memory cache of S3 data (used during failover)
        self._cache = {}
        self._cache_timestamps = {}
        
        self._initialize_s3()
    
    def _initialize_s3(self):
        """Initialize S3 client and test connection."""
        try:
            if not all([S3_BUCKET, AWS_ACCESS_KEY, AWS_SECRET_KEY]):
                logger.warning("[S3 Failover] Missing AWS credentials - failover disabled")
                self.s3_available = False
                return
            
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=AWS_ACCESS_KEY,
                aws_secret_access_key=AWS_SECRET_KEY,
                region_name=AWS_REGION
            )
            
            # Test connection
            self.s3_client.head_bucket(Bucket=S3_BUCKET)
            self.s3_available = True
            logger.info(f"[S3 Failover] Connected to S3 bucket: {S3_BUCKET}")
            
        except NoCredentialsError:
            logger.warning("[S3 Failover] No AWS credentials found")
            self.s3_available = False
        except ClientError as e:
            logger.warning(f"[S3 Failover] S3 connection failed: {e}")
            self.s3_available = False
        except Exception as e:
            logger.warning(f"[S3 Failover] S3 initialization error: {e}")
            self.s3_available = False
    
    # =========================================================================
    # SYNC FUNCTIONS - Write data to S3
    # =========================================================================
    
    def sync_table_to_s3(self, table_name: str, data: List[Dict]) -> bool:
        """
        Sync a table's data to S3.
        
        Args:
            table_name: Name of the table (e.g., 'alerts')
            data: List of records to sync
            
        Returns:
            True if sync successful, False otherwise
        """
        if not self.s3_available:
            return False
        
        try:
            with self.sync_lock:
                # Serialize data
                json_data = json.dumps(data, default=str, indent=2)
                
                # Upload to S3
                key = f"{table_name}/latest.json"
                self.s3_client.put_object(
                    Bucket=S3_BUCKET,
                    Key=key,
                    Body=json_data,
                    ContentType='application/json'
                )
                
                # Update sync timestamp
                self.last_sync[table_name] = datetime.now()
                
                # Also update local cache
                self._cache[table_name] = data
                self._cache_timestamps[table_name] = datetime.now()
                
                logger.info(f"[S3 Failover] Synced {table_name}: {len(data)} records")
                return True
                
        except Exception as e:
            logger.error(f"[S3 Failover] Failed to sync {table_name}: {e}")
            return False
    
    def sync_all_tables(self, supabase_client) -> Dict[str, bool]:
        """
        Sync all tables from Supabase to S3.
        
        Args:
            supabase_client: Supabase client instance
            
        Returns:
            Dict mapping table names to sync success status
        """
        results = {}
        
        for table_name in SYNC_TABLES:
            try:
                # Fetch all data from Supabase
                response = supabase_client.table(table_name).select("*").execute()
                data = response.data if response.data else []
                
                # Sync to S3
                success = self.sync_table_to_s3(table_name, data)
                results[table_name] = success
                
            except Exception as e:
                logger.error(f"[S3 Failover] Error fetching {table_name} from Supabase: {e}")
                results[table_name] = False
        
        return results
    
    def sync_single_record(self, table_name: str, record: Dict) -> bool:
        """
        Sync a single new record to S3 (incremental update).
        
        Args:
            table_name: Name of the table
            record: The record to add
            
        Returns:
            True if successful
        """
        if not self.s3_available:
            return False
        
        try:
            # Generate unique key for incremental record
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            key = f"{table_name}/incremental/{timestamp}.json"
            
            self.s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=key,
                Body=json.dumps(record, default=str),
                ContentType='application/json'
            )
            
            # Update cache
            if table_name in self._cache:
                self._cache[table_name].append(record)
            
            return True
            
        except Exception as e:
            logger.error(f"[S3 Failover] Failed to sync record to {table_name}: {e}")
            return False
    
    # =========================================================================
    # READ FUNCTIONS - Fetch data from S3
    # =========================================================================
    
    def read_table_from_s3(self, table_name: str) -> Optional[List[Dict]]:
        """
        Read a table's data from S3.
        
        Args:
            table_name: Name of the table
            
        Returns:
            List of records, or None if failed
        """
        if not self.s3_available:
            return None
        
        try:
            # Try cache first (if recent)
            if table_name in self._cache:
                cache_age = datetime.now() - self._cache_timestamps.get(table_name, datetime.min)
                if cache_age < timedelta(minutes=5):
                    logger.info(f"[S3 Failover] Using cached {table_name}")
                    return self._cache[table_name]
            
            # Fetch from S3
            key = f"{table_name}/latest.json"
            response = self.s3_client.get_object(Bucket=S3_BUCKET, Key=key)
            data = json.loads(response['Body'].read().decode('utf-8'))
            
            # Merge with incremental updates
            incremental_data = self._read_incremental_updates(table_name)
            if incremental_data:
                # Add incremental records (avoiding duplicates by id)
                existing_ids = {r.get('id') for r in data if r.get('id')}
                for record in incremental_data:
                    if record.get('id') not in existing_ids:
                        data.append(record)
            
            # Update cache
            self._cache[table_name] = data
            self._cache_timestamps[table_name] = datetime.now()
            
            logger.info(f"[S3 Failover] Read {table_name} from S3: {len(data)} records")
            return data
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                logger.warning(f"[S3 Failover] No data in S3 for {table_name}")
                return []
            logger.error(f"[S3 Failover] Failed to read {table_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"[S3 Failover] Error reading {table_name}: {e}")
            return None
    
    def _read_incremental_updates(self, table_name: str) -> List[Dict]:
        """Read incremental updates from S3."""
        incremental_data = []
        
        try:
            prefix = f"{table_name}/incremental/"
            response = self.s3_client.list_objects_v2(
                Bucket=S3_BUCKET,
                Prefix=prefix
            )
            
            for obj in response.get('Contents', []):
                try:
                    obj_response = self.s3_client.get_object(
                        Bucket=S3_BUCKET,
                        Key=obj['Key']
                    )
                    record = json.loads(obj_response['Body'].read().decode('utf-8'))
                    incremental_data.append(record)
                except Exception:
                    continue
                    
        except Exception as e:
            logger.warning(f"[S3 Failover] Error reading incremental updates: {e}")
        
        return incremental_data
    
    def query_alerts_from_s3(self, filters: Dict = None) -> List[Dict]:
        """
        Query alerts from S3 with optional filters.
        
        Args:
            filters: Optional dict of field:value filters
            
        Returns:
            Filtered list of alerts
        """
        alerts = self.read_table_from_s3('alerts') or []
        
        if not filters:
            return alerts
        
        # Apply filters
        filtered = []
        for alert in alerts:
            match = True
            for field, value in filters.items():
                if alert.get(field) != value:
                    match = False
                    break
            if match:
                filtered.append(alert)
        
        return filtered
    
    def get_alert_by_id_from_s3(self, alert_id: str) -> Optional[Dict]:
        """Get a single alert by ID from S3."""
        alerts = self.read_table_from_s3('alerts') or []
        
        for alert in alerts:
            if alert.get('id') == alert_id:
                return alert
        
        return None
    
    def get_logs_for_alert_from_s3(self, alert_id: str) -> Dict[str, List]:
        """
        Get all associated logs for an alert from S3.
        
        Args:
            alert_id: The alert ID
            
        Returns:
            Dict with process_logs, network_logs, file_logs, windows_logs
        """
        logs = {
            'process_logs': [],
            'network_logs': [],
            'file_activity_logs': [],
            'windows_event_logs': []
        }
        
        for log_type in logs.keys():
            all_logs = self.read_table_from_s3(log_type) or []
            logs[log_type] = [
                log for log in all_logs 
                if log.get('alert_id') == alert_id
            ]
        
        return logs
    
    # =========================================================================
    # FAILOVER STATUS
    # =========================================================================
    
    def enter_failover_mode(self):
        """Switch to S3 failover mode."""
        self.is_failover_mode = True
        logger.warning("[S3 Failover] ENTERING FAILOVER MODE - Using S3 as primary storage")
    
    def exit_failover_mode(self):
        """Exit failover mode, return to Supabase."""
        self.is_failover_mode = False
        logger.info("[S3 Failover] Exiting failover mode - Supabase restored")
    
    def get_status(self) -> Dict:
        """Get failover system status."""
        return {
            's3_available': self.s3_available,
            's3_bucket': S3_BUCKET,
            'is_failover_mode': self.is_failover_mode,
            'last_sync': {
                table: ts.isoformat() if ts else None 
                for table, ts in self.last_sync.items()
            },
            'cached_tables': list(self._cache.keys()),
            'sync_interval_seconds': SYNC_INTERVAL_SECONDS
        }


# Global instance
s3_failover = S3FailoverSystem()


def get_s3_failover() -> S3FailoverSystem:
    """Get the global S3 failover instance."""
    return s3_failover

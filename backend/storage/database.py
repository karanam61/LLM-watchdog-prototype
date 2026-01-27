"""
Database Module - Supabase Integration with S3 Failover
========================================================

This module handles all database operations for the SOC system using
Supabase (PostgreSQL) as the backend, with automatic failover to AWS S3
when Supabase is unavailable.

WHAT THIS FILE DOES:
1. Initializes Supabase client connection
2. Stores new alerts in the 'alerts' table
3. Updates alerts with AI analysis results
4. Queries forensic logs (process, network, file, Windows events)
5. Provides helper functions for database operations
6. **NEW: Auto-failover to S3 when Supabase is down**

FAILOVER BEHAVIOR:
- All read operations try Supabase first, then fall back to S3
- All write operations write to Supabase AND sync to S3
- When Supabase fails 3 times consecutively, enters failover mode
- Automatically exits failover mode when Supabase recovers

WHY THIS EXISTS:
- Central place for all database operations
- Abstracts Supabase API complexity
- Handles both Service Key (admin) and Anon Key (restricted) modes
- Provides typed functions for type safety
- **Ensures system keeps working during DB outages**

KEY FUNCTIONS:
- store_alert()                 - Insert new alert into database
- update_alert_with_ai_analysis() - Update alert with AI verdict
- query_process_logs()          - Get process execution history
- query_network_logs()          - Get network connection logs
- query_file_activity_logs()    - Get file system activity
- query_windows_event_logs()    - Get Windows security events
- test_connection()             - Verify database connectivity
- get_failover_status()         - Check S3 failover status

DATABASE TABLES USED:
- alerts              - Main alert storage
- process_logs        - Process execution telemetry
- network_logs        - Network connection telemetry
- file_activity_logs  - File system telemetry
- windows_event_logs  - Windows security events

Author: AI-SOC Watchdog System
"""

import os
from dotenv import load_dotenv

load_dotenv()

import logging
logger = logging.getLogger(__name__)

from supabase import create_client, Client

# Import S3 failover system
try:
    from backend.storage.s3_failover import get_s3_failover, S3FailoverSystem
    S3_FAILOVER_AVAILABLE = True
except ImportError:
    S3_FAILOVER_AVAILABLE = False
    logger.warning("[WARNING] S3 failover module not available")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

# Use Service Key (Admin) if available, otherwise fallback to Anon Key
CHOSEN_KEY = SUPABASE_SERVICE_KEY if SUPABASE_SERVICE_KEY else SUPABASE_KEY

if SUPABASE_SERVICE_KEY:
    logger.info("[*] Using Supabase SERVICE KEY (Admin Mode)")
else:
    logger.warning("[WARNING] Using Supabase ANON KEY (Restricted Mode)")

supabase: Client = create_client(SUPABASE_URL, CHOSEN_KEY)

# Failover tracking
_consecutive_failures = 0
_failover_threshold = 3  # Enter failover after 3 consecutive failures
_in_failover_mode = False

def _handle_db_success():
    """Track successful database operation."""
    global _consecutive_failures, _in_failover_mode
    _consecutive_failures = 0
    if _in_failover_mode:
        _in_failover_mode = False
        logger.info("[DB Failover] Supabase restored - exiting failover mode")
        if S3_FAILOVER_AVAILABLE:
            get_s3_failover().exit_failover_mode()

def _handle_db_failure():
    """Track database failure and potentially enter failover mode."""
    global _consecutive_failures, _in_failover_mode
    _consecutive_failures += 1
    
    if _consecutive_failures >= _failover_threshold and not _in_failover_mode:
        _in_failover_mode = True
        logger.warning(f"[DB Failover] Supabase failed {_consecutive_failures} times - ENTERING FAILOVER MODE")
        if S3_FAILOVER_AVAILABLE:
            get_s3_failover().enter_failover_mode()

def is_in_failover_mode():
    """Check if system is in failover mode."""
    return _in_failover_mode

def get_failover_status():
    """Get comprehensive failover status."""
    status = {
        'in_failover_mode': _in_failover_mode,
        'consecutive_failures': _consecutive_failures,
        'failover_threshold': _failover_threshold,
        's3_failover_available': S3_FAILOVER_AVAILABLE
    }
    if S3_FAILOVER_AVAILABLE:
        status['s3_status'] = get_s3_failover().get_status()
    return status

def test_connection():
    """Test if database connection works"""
    try:
        response = supabase.table('alerts').select("*").limit(1).execute()
        logger.info("[OK] Database connection successful!")
        _handle_db_success()
        return True
    except Exception as e:
        logger.error(f"[X] Database connection failed: {e}")
        _handle_db_failure()
        return False
    
def store_alert(parsed_alert, mitre_technique, severity_class):
    """Store alert in Supabase (with S3 backup)"""
    data = {
        'alert_name': parsed_alert.get('alert_name'),
        'severity': parsed_alert.get('severity'),
        'source_ip': parsed_alert.get('source_ip'),
        'dest_ip': parsed_alert.get('dest_ip'),
        'timestamp': parsed_alert.get('timestamp'),
        'description': parsed_alert.get('description'),
        'mitre_technique': mitre_technique,
        'severity_class': severity_class
    }
    
    response = None
    alert_id = None
    
    # Try Supabase first
    try:
        response = supabase.table('alerts').insert(data).execute()
        
        # Determine ID from response (handle list or object)
        if response.data and len(response.data) > 0:
            alert_id = response.data[0]['id']
            
        _handle_db_success()
        print(f"      [INNER TRACE] DB Insert Success: ID {alert_id} | Name: {parsed_alert.get('alert_name')}")
        logger.info(f"[OK] Alert stored in database: {parsed_alert.get('alert_name')}")
        
        # Also sync to S3 for backup
        if S3_FAILOVER_AVAILABLE and alert_id:
            data['id'] = alert_id
            get_s3_failover().sync_single_record('alerts', data)
        
        return response
        
    except Exception as e:
        logger.error(f"[X] Failed to store alert in Supabase: {e}")
        _handle_db_failure()
        
        # If Supabase failed, try S3 as primary storage
        if S3_FAILOVER_AVAILABLE:
            logger.warning("[S3 Fallback] Storing alert directly to S3")
            import uuid
            data['id'] = str(uuid.uuid4())
            if get_s3_failover().sync_single_record('alerts', data):
                # Create a mock response
                class MockResponse:
                    def __init__(self, data):
                        self.data = [data]
                return MockResponse(data)
        
        return None


def get_mitre_severity(technique_id):
    """Get severity for a MITRE technique from database"""
    try:
        response = supabase.table('mitre_severity').select('severity').eq('technique_id', technique_id).execute()
        
        if response.data:
            return response.data[0]['severity']
        else:
            return 'low'  # Default if not found
    except Exception as e:
        logger.error(f"[X] Failed to get MITRE severity: {e}")
        return 'low'

def query_process_logs(alert_id):
    """Query Sysmon process logs for a specific alert ID (with S3 fallback)"""
    # Try Supabase first
    if not _in_failover_mode:
        try:
            response = supabase.table('process_logs').select("*")\
                .eq('alert_id', alert_id)\
                .order('timestamp', desc=True)\
                .limit(50)\
                .execute()
            
            _handle_db_success()
            count = len(response.data) if response.data else 0
            print(f"      [INNER TRACE] DB Query (Process): AlertID={alert_id} -> Found {count} logs")
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"[X] Error querying process logs from Supabase: {e}")
            _handle_db_failure()
    
    # Fallback to S3
    if S3_FAILOVER_AVAILABLE:
        logger.info(f"[S3 Fallback] Querying process_logs from S3 for alert {alert_id}")
        s3 = get_s3_failover()
        logs = s3.get_logs_for_alert_from_s3(alert_id)
        return logs.get('process_logs', [])
    
    return []

def query_network_logs(alert_id):
    """Query Zeek network logs for a specific alert ID (with S3 fallback)"""
    # Try Supabase first
    if not _in_failover_mode:
        try:
            response = supabase.table('network_logs').select("*")\
                .eq('alert_id', alert_id)\
                .order('timestamp', desc=True)\
                .limit(50)\
                .execute()
            
            _handle_db_success()
            count = len(response.data) if response.data else 0
            print(f"      [INNER TRACE] DB Query (Network): AlertID={alert_id} -> Found {count} logs")
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"[X] Error querying network logs from Supabase: {e}")
            _handle_db_failure()
    
    # Fallback to S3
    if S3_FAILOVER_AVAILABLE:
        logger.info(f"[S3 Fallback] Querying network_logs from S3 for alert {alert_id}")
        s3 = get_s3_failover()
        logs = s3.get_logs_for_alert_from_s3(alert_id)
        return logs.get('network_logs', [])
    
    return []

def query_file_activity_logs(alert_id):
    """Query file activity logs (with S3 fallback)"""
    # Try Supabase first
    if not _in_failover_mode:
        try:
            response = supabase.table('file_activity_logs').select("*")\
                .eq('alert_id', alert_id)\
                .order('timestamp', desc=True)\
                .limit(50)\
                .execute()
            
            _handle_db_success()
            count = len(response.data) if response.data else 0
            if count > 0:
                print(f"      [INNER TRACE] DB Query (File): AlertID={alert_id} -> Found {count} logs")
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"[X] Error querying file logs from Supabase: {e}")
            _handle_db_failure()
    
    # Fallback to S3
    if S3_FAILOVER_AVAILABLE:
        logger.info(f"[S3 Fallback] Querying file_activity_logs from S3 for alert {alert_id}")
        s3 = get_s3_failover()
        logs = s3.get_logs_for_alert_from_s3(alert_id)
        return logs.get('file_activity_logs', [])
    
    return []

def query_windows_event_logs(alert_id):
    """Query Windows Security Event logs (with S3 fallback)"""
    # Try Supabase first
    if not _in_failover_mode:
        try:
            response = supabase.table('windows_event_logs').select("*")\
                .eq('alert_id', alert_id)\
                .order('timestamp', desc=True)\
                .limit(50)\
                .execute()
            
            _handle_db_success()
            count = len(response.data) if response.data else 0
            if count > 0:
                print(f"      [INNER TRACE] DB Query (Windows): AlertID={alert_id} -> Found {count} logs")
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"[X] Error querying windows events from Supabase: {e}")
            _handle_db_failure()
    
    # Fallback to S3
    if S3_FAILOVER_AVAILABLE:
        logger.info(f"[S3 Fallback] Querying windows_event_logs from S3 for alert {alert_id}")
        s3 = get_s3_failover()
        logs = s3.get_logs_for_alert_from_s3(alert_id)
        return logs.get('windows_event_logs', [])
    
    return []

def update_alert_with_ai_analysis(alert_id, ai_result):
    """Update alert with AI verdict and evidence"""
    try:
        # Core fields that definitely exist
        data = {
            'ai_verdict': ai_result.get('verdict'),
            'ai_confidence': ai_result.get('confidence'),
            'ai_evidence': ai_result.get('evidence'),
            'ai_reasoning': ai_result.get('reasoning'),
            'ai_recommendation': ai_result.get('recommendation'),
            'status': 'analyzed'
        }
        
        # Try to include chain_of_thought - if column doesn't exist, we'll handle it
        # First attempt with chain_of_thought
        try:
            full_data = {**data, 'ai_chain_of_thought': ai_result.get('chain_of_thought', [])}
            response = supabase.table('alerts').update(full_data).eq('id', alert_id).execute()
            print(f"      [INNER TRACE] DB Update: Alert {alert_id} updated with AI Verdict: {ai_result.get('verdict')}")
            logger.info(f"[OK] Alert {alert_id} updated with AI verdict: {ai_result.get('verdict')}")
            return response
        except Exception as col_err:
            # If chain_of_thought column doesn't exist, update without it
            if 'ai_chain_of_thought' in str(col_err):
                logger.warning(f"[WARNING] ai_chain_of_thought column not found, updating without it")
                response = supabase.table('alerts').update(data).eq('id', alert_id).execute()
                print(f"      [INNER TRACE] DB Update: Alert {alert_id} updated with AI Verdict: {ai_result.get('verdict')}")
                logger.info(f"[OK] Alert {alert_id} updated with AI verdict: {ai_result.get('verdict')}")
                return response
            else:
                raise col_err
                
    except Exception as e:
        logger.error(f"[X] Failed to update alert with AI analysis: {e}")
        return None

def insert_log_batch(table_name, logs):
    """
    Bulk insert logs into a specific table.
    
    Args:
        table_name (str): 'process_logs', 'network_logs', 'file_activity_logs', 'windows_event_logs'
        logs (list): List of dictionaries containing log data
    """
    if not logs:
        return {"count": 0}
        
    try:
        # Validate table name locally to prevent generic errors
        valid_tables = ['process_logs', 'network_logs', 'file_activity_logs', 'windows_event_logs']
        if table_name not in valid_tables:
            logger.error(f"[X] Invalid table name for log insert: {table_name}")
            return None

        response = supabase.table(table_name).insert(logs).execute()
        count = len(response.data) if response.data else 0
        print(f"      [INNER TRACE] DB Insert ({table_name}): Inserted {count} rows")
        return response
    except Exception as e:
        logger.error(f"[X] Failed to insert logs into {table_name}: {e}")
        return None

def get_db_client():
    """Get Supabase client instance"""
    return supabase


def get_all_alerts(limit=100, status_filter=None):
    """Get all alerts (with S3 fallback)"""
    # Try Supabase first
    if not _in_failover_mode:
        try:
            query = supabase.table('alerts').select("*").order('created_at', desc=True).limit(limit)
            if status_filter:
                query = query.eq('status', status_filter)
            response = query.execute()
            
            _handle_db_success()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"[X] Error fetching alerts from Supabase: {e}")
            _handle_db_failure()
    
    # Fallback to S3
    if S3_FAILOVER_AVAILABLE:
        logger.info("[S3 Fallback] Fetching alerts from S3")
        s3 = get_s3_failover()
        alerts = s3.read_table_from_s3('alerts') or []
        
        # Apply filters
        if status_filter:
            alerts = [a for a in alerts if a.get('status') == status_filter]
        
        # Sort by created_at descending
        alerts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return alerts[:limit]
    
    return []


def get_alert_by_id(alert_id):
    """Get a single alert by ID (with S3 fallback)"""
    # Try Supabase first
    if not _in_failover_mode:
        try:
            response = supabase.table('alerts').select("*").eq('id', alert_id).execute()
            _handle_db_success()
            if response.data and len(response.data) > 0:
                return response.data[0]
            return None
        except Exception as e:
            logger.error(f"[X] Error fetching alert {alert_id} from Supabase: {e}")
            _handle_db_failure()
    
    # Fallback to S3
    if S3_FAILOVER_AVAILABLE:
        logger.info(f"[S3 Fallback] Fetching alert {alert_id} from S3")
        return get_s3_failover().get_alert_by_id_from_s3(alert_id)
    
    return None


def trigger_s3_sync():
    """Manually trigger a full sync to S3"""
    if not S3_FAILOVER_AVAILABLE:
        return {'error': 'S3 failover not available'}
    
    s3 = get_s3_failover()
    results = s3.sync_all_tables(supabase)
    return results


if __name__ == '__main__':
    test_connection()
    print(f"\nFailover Status: {get_failover_status()}")
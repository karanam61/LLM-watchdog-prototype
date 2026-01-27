"""
AI-SOC Watchdog - Main Flask Application
==========================================

This is the central entry point for the entire SOC (Security Operations Center) 
automation system. It orchestrates all components of the AI-powered alert analysis
pipeline.

WHAT THIS FILE DOES:
1. Starts the Flask web server (API endpoints for frontend & alert ingestion)
2. Initializes the alert processing queue (priority + standard queues)
3. Launches background workers that continuously process alerts
4. Registers all API blueprints (monitoring, RAG, transparency)
5. Handles alert ingestion from SIEM systems (Splunk, etc.)
6. Coordinates the 6-phase AI analysis pipeline

KEY ENDPOINTS:
- POST /ingest          - Receive new security alerts from SIEM
- GET  /alerts          - List all alerts (for analyst dashboard)
- GET  /queue-status    - Check processing queue status
- PATCH /api/alerts/<id> - Update alert status/notes

BACKGROUND PROCESSES:
- Priority Queue Worker  - Processes critical/high severity alerts first
- Standard Queue Worker  - Processes medium/low severity alerts
- Auto-close logic       - Automatically closes benign low-risk alerts

ARCHITECTURE:
    SIEM Alert -> /ingest -> Parse -> Classify Severity -> Queue
                                                            |
                                                    Background Worker
                                                            |
                                    Gather Logs -> OSINT -> RAG -> AI Analysis
                                                            |
                                                    Store in Supabase
                                                            |
                                                    Frontend Dashboard

Author: AI-SOC Watchdog System
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
import os
import threading
import time

# Import Core Logic
from backend.core.parser import parse_splunk_alert
from backend.core.mitre_mapping import map_to_mitre
from backend.core.Severity import classify_severity
from backend.core.Queue_manager import QueueManager

from backend.storage.database import (
    store_alert, 
    update_alert_with_ai_analysis, 
    query_process_logs,
    query_network_logs,
    query_file_activity_logs,
    query_windows_event_logs,
    supabase, 
    SUPABASE_URL, 
    SUPABASE_KEY,
    get_failover_status,
    trigger_s3_sync,
    is_in_failover_mode,
    get_all_alerts,
    get_alert_by_id
)
from backend.storage.backup import backup_to_s3

# Import S3 Failover System
try:
    from backend.storage.s3_failover import get_s3_failover, S3FailoverSystem
    S3_FAILOVER_ENABLED = True
    print("[OK] S3 Failover System loaded")
except ImportError as e:
    S3_FAILOVER_ENABLED = False
    print(f"[WARNING] S3 Failover System not available: {e}")
from backend.ai.alert_analyzer_final import AlertAnalyzer
from backend.visualizer.console_flow import ConsoleFlowTracker

# Import Monitoring System
from backend.monitoring.system_monitor import monitor
from backend.monitoring.ai_tracer import AIOperationTracer
from backend.monitoring.live_logger import live_logger, log_function_call
from backend.monitoring import shared_state
from backend.monitoring.api import monitoring_bp
from backend.monitoring.rag_api import rag_monitoring_bp
from backend.monitoring.transparency_api import transparency_bp

# Register live_logger in shared state so blueprints can access it
shared_state.set_live_logger(live_logger)

# Auth


# Load environment variables
load_dotenv()

app = Flask(__name__)
# Explicitly allow all origins for robust debugging
CORS(app)

# Store live_logger in app config so blueprints access the same instance
app.config['live_logger'] = live_logger

# Register monitoring blueprints
app.register_blueprint(monitoring_bp)
app.register_blueprint(rag_monitoring_bp)
app.register_blueprint(transparency_bp)

# Initialize AI tracer
ai_tracer = AIOperationTracer(monitor)

# ========================================================
# [DEBUG] GLOBAL DEBUG LOGGING MIDDLEWARE
# ========================================================
@app.before_request
def log_request_info():
    """Log every incoming request"""
    # Skip noisy polling logs from the dashboard
    if request.path == '/api/debug-logs': return
    if request.path == '/alerts' and request.method in ['GET', 'OPTIONS']: return
    
    g.request_start_time = time.time()

    # Capture request details once for structured logging
    body = None
    if request.is_json:
        body = str(request.json)
        if len(body) > 500:
            body = body[:500] + "..."

    print(f"\n[API] [API REQUEST] {request.method} {request.path}")
    print(f"   Headers: {dict(request.headers)}")
    if request.is_json:
        # Truncate long bodies for readability
        print(f"   Body: {body}")

    g.request_body = body

@app.after_request
def log_response_info(response):
    """Log every outgoing response"""
    if request.path == '/api/debug-logs': return response
    if request.path == '/alerts' and request.method in ['GET', 'OPTIONS']: return response
    
    status = response.status_code
    icon = "[OK]" if status < 400 else "[ERROR]"
    print(f"   {icon} [API RESPONSE] Status: {status} | Size: {response.content_length} bytes")

    # Log to live system debug with EDUCATIONAL DETAILS
    duration = None
    if hasattr(g, 'request_start_time'):
        duration = time.time() - g.request_start_time

    # Add educational context for each endpoint
    endpoint_info = get_endpoint_educational_info(request.method, request.path)
    
    live_logger.log(
        'API',
        f"{request.method} {request.path}",
        {
            'status_code': status,
            'query': request.query_string.decode('utf-8', errors='ignore'),
            'body': g.request_body,
            'response_size': response.content_length,
            **endpoint_info  # Include educational details
        },
        status='error' if status >= 400 else 'success',
        duration=duration
    )
    return response

def get_endpoint_educational_info(method, path):
    """
    Returns educational information about what each API endpoint does,
    what functions it calls, and why it exists.
    
    COMPLETE ENDPOINT DOCUMENTATION FOR AI-SOC WATCHDOG
    """
    endpoints = {
        # =====================================================
        # APP.PY ROUTES (Main Application Endpoints)
        # =====================================================
        ('POST', '/ingest'): {
            'endpoint_purpose': 'ALERT INGESTION - Main entry point for all security alerts',
            'file': 'app.py',
            'function': 'ingest_log()',
            'functions_called': [
                '1. parse_splunk_alert(data) - Normalize SIEM format to standard schema',
                '2. map_to_mitre(parsed) - Map alert to MITRE ATT&CK technique using RAG',
                '3. classify_severity(parsed) - Determine CRITICAL_HIGH or MEDIUM_LOW',
                '4. store_alert(parsed, mitre, severity) - INSERT into Supabase alerts table',
                '5. qm.route_alert(parsed, severity) - Route to priority or standard queue'
            ],
            'database_operations': ['INSERT into alerts table'],
            'triggers': 'Background queue processor will pick up alert for AI analysis',
            '_explanation': 'This is THE main entry point. SIEMs (Splunk, Wazuh) POST alerts here. Each alert goes through: parsing → MITRE mapping → severity classification → database storage → queue routing → AI analysis.'
        },
        ('GET', '/alerts'): {
            'endpoint_purpose': 'FETCH ALERTS - Get alerts for Analyst Console',
            'file': 'app.py',
            'function': 'get_alerts()',
            'functions_called': [
                'supabase.table("alerts").select("*").order("created_at").limit(50)'
            ],
            'database_operations': ['SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50'],
            '_explanation': 'Returns the 50 most recent alerts from database. Used by the Analyst Console to display alerts with AI verdicts, allowing analysts to review and close them.'
        },
        ('PATCH', '/api/alerts/<alert_id>'): {
            'endpoint_purpose': 'UPDATE ALERT STATUS - Mark alert as closed/investigating',
            'file': 'app.py',
            'function': 'update_alert_status(alert_id)',
            'functions_called': [
                'supabase.table("alerts").update({"status": new_status}).eq("id", alert_id)'
            ],
            'database_operations': ['UPDATE alerts SET status = ? WHERE id = ?'],
            '_explanation': 'Allows analysts to change alert status (open → investigating → closed). This is how analysts mark alerts as handled after reviewing the AI verdict.'
        },
        ('GET', '/api/logs'): {
            'endpoint_purpose': 'FETCH FORENSIC LOGS - Get detailed logs for investigation',
            'file': 'app.py',
            'function': 'get_logs()',
            'functions_called': [
                'query_process_logs(alert_id) - Get process execution logs',
                'query_network_logs(alert_id) - Get network connection logs',
                'query_file_activity_logs(alert_id) - Get file system logs',
                'query_windows_event_logs(alert_id) - Get Windows security events'
            ],
            'database_operations': ['SELECT FROM process_logs/network_logs/file_activity_logs/windows_event_logs WHERE alert_id = ?'],
            '_explanation': 'Returns forensic evidence logs linked to an alert. These are the same logs the AI uses to make its verdict. Analysts can review this raw evidence.'
        },
        ('GET', '/queue-status'): {
            'endpoint_purpose': 'QUEUE STATUS - Get current queue sizes',
            'file': 'app.py',
            'function': 'queue_status()',
            'functions_called': [
                'len(qm.priority_queue)',
                'len(qm.standard_queue)'
            ],
            'database_operations': [],
            '_explanation': 'Returns the number of alerts waiting in each queue. Priority queue is for CRITICAL_HIGH alerts, standard queue for MEDIUM_LOW.'
        },
        ('POST', '/api/log_event'): {
            'endpoint_purpose': 'LOG USER ACTIVITY - Record analyst actions',
            'file': 'app.py',
            'function': 'log_event()',
            'functions_called': [
                'tracker.log_step(user, action, details)'
            ],
            'database_operations': [],
            '_explanation': 'Records user activity in the flow tracker. Used for audit trails and understanding how analysts interact with the system.'
        },
        ('GET', '/api/debug-logs'): {
            'endpoint_purpose': 'DEBUG LOGS - Get flow tracker logs',
            'file': 'app.py',
            'function': 'get_debug_logs()',
            'functions_called': [
                'Read from logs/flow_debug.log file'
            ],
            'database_operations': [],
            '_explanation': 'Returns the processing flow logs showing how alerts moved through the pipeline. Used by the Transparency Dashboard.'
        },
        
        # =====================================================
        # RAG MONITORING BLUEPRINT ROUTES
        # =====================================================
        ('GET', '/api/rag/stats'): {
            'endpoint_purpose': 'RAG STATISTICS - Knowledge base document counts',
            'file': 'backend/monitoring/rag_monitoring.py',
            'function': 'get_rag_stats()',
            'functions_called': [
                'rag_system.get_collection("mitre_techniques").count()',
                'rag_system.get_collection("historical_alerts").count()',
                '+ 5 more collections...'
            ],
            'database_operations': ['Query 7 ChromaDB vector collections for counts'],
            '_explanation': 'Returns document counts for all 7 RAG collections: MITRE techniques (201), historical alerts, business rules, attack patterns, detection rules, detection signatures, company infrastructure.'
        },
        ('GET', '/api/rag/collections/status'): {
            'endpoint_purpose': 'RAG COLLECTION STATUS - Health check for knowledge base',
            'file': 'backend/monitoring/rag_monitoring.py',
            'function': 'get_collections_status()',
            'functions_called': [
                'chromadb_client.list_collections()',
                'collection.count() for each collection'
            ],
            'database_operations': ['Query ChromaDB metadata'],
            '_explanation': 'Shows health status (healthy/empty/error) for each of the 7 RAG collections. Used to verify the knowledge base is properly seeded.'
        },
        ('POST', '/api/rag/query'): {
            'endpoint_purpose': 'RAG QUERY - Semantic search across knowledge base',
            'file': 'backend/monitoring/rag_monitoring.py',
            'function': 'query_rag()',
            'functions_called': [
                'embeddings.encode(query) - Convert text to 384-dim vector',
                'chromadb.query(embedding, n_results=5) - Vector similarity search',
                'Return top 5 most similar documents'
            ],
            'database_operations': ['Vector similarity search in ChromaDB'],
            '_explanation': 'Performs semantic search to find relevant knowledge. Input: text query. Output: Top 5 similar documents with scores. This is how the AI finds relevant MITRE techniques and historical patterns.'
        },
        
        # =====================================================
        # TRANSPARENCY BLUEPRINT ROUTES
        # =====================================================
        ('GET', '/api/transparency'): {
            'endpoint_purpose': 'AI TRANSPARENCY - Get AI decision explanations',
            'file': 'backend/monitoring/transparency.py',
            'function': 'get_transparency_data()',
            'functions_called': [
                'Get recent AI verdicts with chain_of_thought',
                'Get RAG sources used for each decision',
                'Get confidence scores and evidence'
            ],
            'database_operations': ['SELECT FROM alerts WHERE ai_verdict IS NOT NULL'],
            '_explanation': 'Returns detailed explanations of how the AI made each verdict. Includes: chain of thought reasoning, evidence used, RAG documents retrieved, confidence breakdown.'
        },
        
        # =====================================================
        # MONITORING BLUEPRINT ROUTES
        # =====================================================
        ('GET', '/api/monitoring/logs/categories'): {
            'endpoint_purpose': 'LOG CATEGORIES - Get available log category filters',
            'file': 'backend/monitoring/api.py',
            'function': 'get_log_categories()',
            'functions_called': ['Return static list of categories'],
            'database_operations': [],
            '_explanation': 'Returns list of log categories for filtering: API, WORKER, FUNCTION, AI, RAG, DATABASE, QUEUE, SECURITY, ERROR.'
        }
    }
    
    # Try exact match first
    key = (method, path)
    if key in endpoints:
        return endpoints[key]
    
    # Try prefix matching for dynamic routes (like /api/alerts/<id>)
    for (m, p), info in endpoints.items():
        if '<' in p:  # Dynamic route
            base_path = p.split('<')[0]
            if method == m and path.startswith(base_path):
                return info
        elif method == m and path.startswith(p.rstrip('/')):
            return info
    
    # Default for unknown endpoints
    return {
        'endpoint_purpose': f'{method} {path}',
        '_explanation': f'Endpoint {method} {path} - No detailed documentation available'
    }

# Initialize Systems


# Systems Placeholders (Lazy Loaded)

tracker = None
qm = None
analyzer = None

def get_ai_systems():
    """Lazy load AI systems on first request to speed up startup"""
    global tracker, qm, analyzer
    if analyzer is None:
        print("   [LAZY LOAD] Initializing AI Systems...")
        tracker = ConsoleFlowTracker()
        qm = QueueManager()
        analyzer = AlertAnalyzer(
            config={'daily_budget': 2.00, 'enable_cache': True, 'enable_rag': True},
            tracker=tracker
        )
        print("   [LAZY LOAD] AI Systems Ready.")
    return tracker, qm, analyzer

# Initialize immediately for background thread usage, but don't block main thread indefinitely if we can help it.
# Actually, for "Instant Startup", we should let the first request trigger it, OR start it in a thread.
# But `background_queue_processor` needs them interactively. 
# Better strategy: Initialize `tracker` and `qm` fast (they are light). Load `analyzer` lazy.

print("   [INIT] Loading Flow Tracker & Queue Manager...")
tracker = ConsoleFlowTracker()
qm = QueueManager()
print("   [INIT] Core Systems Ready.")

# Log initialization to Debug Dashboard with FULL educational detail
live_logger.log(
    'WORKER',
    'ConsoleFlowTracker - Initialized',
    {
        'component': 'ConsoleFlowTracker',
        'file': 'backend/core/flow_tracker.py',
        'status': 'ready',
        'purpose': 'Tracks every step of alert processing through the pipeline',
        'functions_available': [
            'log_step() - Records function calls with timing',
            'get_flow() - Returns complete processing history',
            'visualize() - Generates visual flow diagram'
        ],
        '_explanation': 'The Flow Tracker records EVERY step an alert takes from ingestion to verdict. It creates a visual trace you can show to explain how the system works.'
    },
    status='success'
)

live_logger.log(
    'WORKER',
    'QueueManager - Initialized',
    {
        'component': 'QueueManager',
        'file': 'backend/core/Queue_manager.py',
        'status': 'ready',
        'priority_threshold': 75,
        'queues': {
            'priority_queue': 'CRITICAL_HIGH alerts - processed immediately',
            'standard_queue': 'MEDIUM_LOW alerts - processed in order'
        },
        'functions_available': [
            'route_alert(alert, severity) - Routes alert to correct queue',
            'get_next() - Gets next alert for processing',
            'get_queue_status() - Returns queue sizes'
        ],
        '_explanation': 'The Queue Manager routes alerts by priority. Critical alerts (ransomware, data exfil) go to priority queue and are processed immediately. Normal alerts go to standard queue.'
    },
    status='success'
)

# Lazy Analyzer Wrapper
class LazyAnalyzer:
    def __init__(self):
        self._analyzer = None
    
    @property
    def instance(self):
        if self._analyzer is None:
            print("   [LAZY LOAD] Loading Heavy AI Model...")
            self._analyzer = AlertAnalyzer(
                config={'daily_budget': 2.00, 'enable_cache': True, 'enable_rag': True},
                tracker=tracker
            )
        return self._analyzer

    def analyze_alert(self, alert):
        return self.instance.analyze_alert(alert)

analyzer = LazyAnalyzer()



@app.route('/api/log_event', methods=['POST'])
def log_event():
    data = request.json
    user = data.get('user', 'Anonymous')
    action = data.get('action', 'Unknown Action')
    details = data.get('details', '')
    
    # Educational logging for this endpoint
    live_logger.log(
        'FUNCTION',
        'log_event() - User Activity Logging',
        {
            'endpoint': 'POST /api/log_event',
            'file': 'app.py',
            'purpose': 'Record analyst actions for audit trail',
            'parameters': {
                'user': user,
                'action': action,
                'details': details
            },
            'logs_to': 'ConsoleFlowTracker',
            '_explanation': f"Logging user activity: [{user}] {action}. This creates an audit trail of all analyst interactions with the system."
        },
        status='success'
    )
    
    tracker.log_step("User Activity", f"[{user}] {action} {details}")
    return jsonify({"status": "logged"}), 200

@app.route('/api/debug-logs', methods=['GET'])
def get_debug_logs():
    """Stream the actual backend flow logs to the frontend"""
    # Educational logging for this endpoint
    live_logger.log(
        'FUNCTION',
        'get_debug_logs() - Flow Tracker Log Retrieval',
        {
            'endpoint': 'GET /api/debug-logs',
            'file': 'app.py',
            'purpose': 'Return processing flow logs for Transparency Dashboard',
            'reads_from': 'logs/flow_debug.log',
            'returns': 'Last 50 log entries showing alert processing steps',
            '_explanation': 'Returns the flow tracker logs showing how each alert was processed step-by-step. Used by the Transparency Dashboard to show the complete alert lifecycle.'
        },
        status='success'
    )
    
    try:
        log_file = os.path.join("logs", "flow_debug.log")
        if not os.path.exists(log_file):
            return jsonify({"logs": []})
            
        logs = []
        # Read last 50 lines
        with open(log_file, 'r') as f:
            lines = f.readlines()[-50:]
            
        for line in reversed(lines):
            try:
                # Log file is JSONL
                import json
                entry = json.loads(line)
                purpose = entry.get('purpose', '')
                explanation = entry.get('explanation', '')
                message = f"{purpose} ({explanation})" if explanation else purpose
                logs.append({
                    "id": entry.get("timestamp"), # Use timestamp as ID
                    "time": entry.get("timestamp", "").split("T")[-1][:8], # HH:MM:SS
                    "level": "INFO", # Default for visualizer
                    "component": entry.get("file", "").split("/")[-1],
                    "message": message,
                    "details": entry.get("objects")
                })
            except:
                continue
                
        return jsonify({"logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Background processor function
def background_queue_processor():
    """Continuously process queues in background"""
    while True:
        try:
            time.sleep(1) # Check frequently
            
            # Process PRIORITY queue
            while qm.priority_queue:
                try:
                    # Peek to see if we should log
                    if len(qm.priority_queue) > 0:
                        print("\n[PRIORITY] Auto-processing PRIORITY queue item...")
                    
                    alert = qm.get_next_alert()
                    if alert and alert.get('alert_id'):
                        # Check if already analyzed to avoid double-work
                        if alert.get('status') == 'analyzed':
                            continue
                            
                        print(f"[AI] Analyzing Alert ID: {alert['alert_id']}...")

                        live_logger.log(
                            'QUEUE',
                            'Alert Dequeued from Priority Queue',
                            {
                                'alert_id': alert.get('alert_id'),
                                'alert_name': alert.get('alert_name'),
                                'queue': 'priority',
                                'queue_type': 'CRITICAL_HIGH - Immediate Processing',
                                'next_step': 'analyzer.analyze_alert() - Full AI Pipeline',
                                '_explanation': f"Priority alert dequeued! Alert '{alert.get('alert_name')}' will now go through the full AI analysis pipeline with all 26 features."
                            }
                        )
                        
                        # LOG TO VISUALIZER
                        if tracker:
                            tracker.log_step(
                                "app.py", "Background Thread", "Pick Job", 
                                f"Picked {alert['alert_id']} from Priority Queue"
                            )
                        
                        try:
                            # Start monitoring this operation
                            ai_tracer.start_operation(
                                "Alert Analysis",
                                f"Analyzing alert: {alert.get('alert_name', 'Unknown')}",
                                expected_duration=25
                            )
                            
                            live_logger.log(
                                'AI',
                                'analyzer.analyze_alert() - Starting 26-Feature AI Pipeline',
                                {
                                    'alert_id': alert.get('alert_id'),
                                    'alert_name': alert.get('alert_name'),
                                    'pipeline_phases': [
                                        'Phase 1: Security Gates (Features 1-4, 6, 14-17)',
                                        'Phase 2: Optimization (Features 5, 22)',
                                        'Phase 3: Context Building (RAG + Forensic Logs)',
                                        'Phase 4: AI Analysis (Features 9-13 - Claude API)',
                                        'Phase 5: Output Validation (Features 3-4)',
                                        'Phase 6: Observability (Features 18-21)'
                                    ],
                                    '_explanation': 'Starting the complete AI analysis pipeline. The alert will go through 6 phases using 26 security features to determine verdict (benign/suspicious/malicious).'
                                },
                                status='success'
                            )
                            
                            start_time = time.time()
                            ai_result = analyzer.analyze_alert(alert)
                            duration = time.time() - start_time
                            
                            update_alert_with_ai_analysis(alert['alert_id'], ai_result)
                            
                            # AUTO-CLOSE: Benign low/medium severity alerts
                            verdict = ai_result.get('verdict', '').lower()
                            confidence = ai_result.get('confidence', 0)
                            severity_class = alert.get('severity_class', 'MEDIUM_LOW')
                            
                            if verdict == 'benign' and confidence >= 0.7 and severity_class != 'CRITICAL_HIGH':
                                try:
                                    supabase.table('alerts').update({
                                        'status': 'closed',
                                        'auto_closed': True,
                                        'auto_close_reason': f'AI verdict: benign ({confidence:.0%} confidence)'
                                    }).eq('id', alert['alert_id']).execute()
                                    
                                    print(f"[AUTO-CLOSE] Alert {alert['alert_id']} auto-closed (benign, {confidence:.0%})")
                                    live_logger.log(
                                        'AI',
                                        'Auto-Closed Benign Alert',
                                        {
                                            'alert_id': alert['alert_id'],
                                            'verdict': verdict,
                                            'confidence': f"{confidence:.0%}",
                                            'severity': severity_class,
                                            '_explanation': f"Auto-closed as benign with {confidence:.0%} confidence. Low/medium severity alerts that AI determines are benign are automatically closed to reduce analyst workload."
                                        },
                                        status='success'
                                    )
                                except Exception as e:
                                    print(f"[WARNING] Failed to auto-close: {e}")
                            
                            # Log successful completion
                            monitor.log_alert_processed(
                                alert['alert_id'],
                                ai_result.get('verdict', 'unknown'),
                                ai_result.get('confidence', 0),
                                duration,
                                ai_result.get('metadata', {}).get('cost', 0)
                            )
                            
                            ai_tracer.end_operation(
                                success=True,
                                result_summary=f"Verdict: {ai_result.get('verdict')} ({ai_result.get('confidence'):.0%})"
                            )
                            
                            print(f"[OK] Background Analysis Complete: {alert['alert_id']}")

                            live_logger.log(
                                'AI',
                                'AI Analysis Complete - Verdict Determined',
                                {
                                    'alert_id': alert.get('alert_id'),
                                    'alert_name': alert.get('alert_name'),
                                    'verdict': ai_result.get('verdict'),
                                    'confidence': f"{ai_result.get('confidence', 0)*100:.0f}%",
                                    'processing_time': f"{duration:.2f}s",
                                    'cost': ai_result.get('metadata', {}).get('cost', 0),
                                    'evidence_count': len(ai_result.get('evidence', [])),
                                    'has_reasoning': bool(ai_result.get('reasoning')),
                                    '_explanation': f"AI verdict: {ai_result.get('verdict', 'unknown').upper()} with {ai_result.get('confidence', 0)*100:.0f}% confidence. Alert has been fully analyzed through all 6 phases. Result saved to database."
                                },
                                status='success',
                                duration=duration
                            )
                            
                            if tracker:
                                tracker.log_step(
                                    "app.py", "AI Analysis Complete", "Success",
                                    f"Verdict: {ai_result.get('verdict')} ({ai_result.get('confidence')})",
                                    objects_created=ai_result
                                )
                        except Exception as e:
                            print(f"[ERROR] Error analyzing alert {alert['alert_id']}: {e}")
                            live_logger.log(
                                'ERROR',
                                'AI Analysis Failed',
                                {
                                    'alert_id': alert.get('alert_id'),
                                    'alert_name': alert.get('alert_name'),
                                    'error': str(e),
                                    'error_type': type(e).__name__,
                                    '_explanation': f"AI analysis failed for alert. Error: {str(e)}. The alert will remain in queue for retry or manual review."
                                },
                                status='error'
                            )
                            if tracker:
                                tracker.log_step("app.py", "Analysis Error", "Failed", str(e))
                            
                except Exception as inner_e:
                    monitor.log_error(
                        'PRIORITY_QUEUE_ERROR',
                        str(inner_e),
                        context={'queue': 'priority'},
                        severity='ERROR'
                    )
                    print(f"[ERROR] Error in Priority Loop: {inner_e}")
            
            # Process STANDARD queue (Batch optimized)
            while qm.standard_queue:
                try:
                    # Check priority first (Interruption check)
                    if qm.priority_queue:
                        print("⚠️ Priority Interruption! Switching back to Priority Queue.")
                        break # Break standard loop to handle priority
                        
                    alert = qm.get_next_alert()
                    if not alert: break
                    
                    if alert.get('alert_id'):
                         if alert.get('status') == 'analyzed':
                            continue
                            
                         print(f"[AI] Analyzing Standard Alert ID: {alert['alert_id']}...")

                         live_logger.log(
                             'QUEUE',
                             'Dequeued standard alert',
                             {
                                 'alert_id': alert.get('alert_id'),
                                 'alert_name': alert.get('alert_name'),
                                 'queue': 'standard'
                             }
                         )
                         
                         try:
                             start_time = time.time()
                             ai_result = analyzer.analyze_alert(alert)
                             duration = time.time() - start_time
                             update_alert_with_ai_analysis(alert['alert_id'], ai_result)
                             print(f"[OK] Background Analysis Complete: {alert['alert_id']}")

                             live_logger.log(
                                 'AI',
                                 'Alert analyzed',
                                 {
                                     'alert_id': alert.get('alert_id'),
                                     'verdict': ai_result.get('verdict'),
                                     'confidence': ai_result.get('confidence')
                                 },
                                 status='success',
                                 duration=duration
                             )
                             
                             if tracker:
                                 tracker.log_step(
                                     "app.py", "AI Analysis Complete", "Success",
                                     f"Verdict: {ai_result.get('verdict')} ({ai_result.get('confidence')})",
                                     objects_created=ai_result
                                 )

                         except Exception as e:
                             print(f"[ERROR] Error analyzing alert {alert['alert_id']}: {e}")
                             live_logger.log(
                                 'ERROR',
                                 'Alert analysis failed',
                                 {
                                     'alert_id': alert.get('alert_id'),
                                     'error': str(e)
                                 },
                                 status='error'
                             )
                             if tracker:
                                 tracker.log_step("app.py", "Analysis Error", "Failed", str(e))
                             
                except Exception as inner_e:
                    print(f"[ERROR] Error in Standard Loop: {inner_e}")
                    time.sleep(1) # Prevent tight loop on error
                    
        except Exception as e:
             print(f"[ERROR] CRITICAL BACKGROUND THREAD ERROR: {e}")
             time.sleep(5) # Wait before retry to prevent log flooding

# Start background thread
processor_thread = threading.Thread(target=background_queue_processor, daemon=True)
processor_thread.start()
print("[OK] Background queue processor started")

# =========================================================================
# S3 SYNC WORKER - Periodic backup to S3 for failover
# =========================================================================

def background_s3_sync():
    """Periodically sync database to S3 for failover capability"""
    if not S3_FAILOVER_ENABLED:
        print("[WARNING] S3 sync worker not started - failover system not available")
        return
    
    s3 = get_s3_failover()
    if not s3.s3_available:
        print("[WARNING] S3 sync worker not started - S3 not configured")
        return
    
    print("[OK] S3 Sync Worker started - syncing every 5 minutes")
    
    # Initial sync on startup
    time.sleep(10)  # Wait for app to fully initialize
    
    while True:
        try:
            # Only sync if NOT in failover mode (Supabase is working)
            if not is_in_failover_mode():
                print("[S3 Sync] Starting periodic database sync to S3...")
                results = trigger_s3_sync()
                
                success_count = sum(1 for v in results.values() if v)
                total_count = len(results)
                print(f"[S3 Sync] Synced {success_count}/{total_count} tables to S3")
                
                live_logger.log(
                    'DATABASE',
                    'S3 Backup Sync Completed',
                    {
                        'tables_synced': results,
                        'success_count': success_count,
                        'total_tables': total_count,
                        '_explanation': 'Periodic sync of all database tables to AWS S3 for disaster recovery. If Supabase goes down, the system can continue operating using S3 data.'
                    },
                    status='success' if success_count == total_count else 'warning'
                )
            else:
                print("[S3 Sync] Skipped - currently in failover mode (Supabase down)")
            
            # Sync every 5 minutes
            time.sleep(300)
            
        except Exception as e:
            print(f"[S3 Sync] Error: {e}")
            live_logger.log(
                'ERROR',
                'S3 Sync Failed',
                {'error': str(e)},
                status='error'
            )
            time.sleep(60)  # Wait 1 minute before retry

# Start S3 sync thread
if S3_FAILOVER_ENABLED:
    s3_sync_thread = threading.Thread(target=background_s3_sync, daemon=True)
    s3_sync_thread.start()

# Log background thread to Debug Dashboard
live_logger.log(
    'WORKER',
    'BackgroundQueueProcessor - Started',
    {
        'thread': 'daemon',
        'status': 'running',
        'file': 'app.py',
        'purpose': 'Continuously processes alerts from queues and triggers AI analysis',
        'functions_called': [
            'qm.get_next_alert() - Dequeue next alert',
            'analyzer.analyze_alert(alert) - Run full AI pipeline (26 features)',
            'update_alert_with_ai_result() - Save verdict to database'
        ],
        'queues_monitored': {
            'priority_queue': 'CRITICAL_HIGH alerts - processed first, always',
            'standard_queue': 'MEDIUM_LOW alerts - processed when priority is empty'
        },
        '_explanation': 'The Background Queue Processor is a daemon thread that runs forever. It monitors both queues, processes priority alerts first, and triggers the full AI analysis pipeline for each alert. This is what actually calls the AI!'
    },
    status='success'
)

# Log initial database connection
try:
    test_response = supabase.table('alerts').select("id").limit(1).execute()
    alert_count = len(test_response.data) if test_response.data else 0
    live_logger.log(
        'DATABASE',
        'Supabase - Connection Verified',
        {
            'status': 'connected',
            'database': 'Supabase PostgreSQL',
            'test_query': 'SELECT id FROM alerts LIMIT 1',
            'result': 'success',
            'tables_available': ['alerts', 'process_logs', 'network_logs', 'file_activity_logs', 'windows_event_logs'],
            'connection_type': 'Service Key (Admin Mode)',
            '_explanation': 'Supabase is our primary database. It stores all alerts, forensic logs, and AI analysis results. The connection was verified with a test query.'
        },
        status='success'
    )
except Exception as e:
    live_logger.log(
        'DATABASE',
        'Supabase - Connection Failed',
        {
            'error': str(e),
            '_explanation': 'Database connection failed! The system will not function correctly without database access.'
        },
        status='error'
    )

# System Heartbeat - logs system status every 30 seconds for Debug Dashboard visibility
def heartbeat_logger():
    """Background thread that logs system status periodically"""
    import psutil
    while True:
        try:
            time.sleep(30)  # Log every 30 seconds
            
            # Get current system metrics
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            live_logger.log(
                'WORKER',
                'System Heartbeat - Status Check',
                {
                    'cpu_percent': cpu,
                    'memory_percent': memory.percent,
                    'priority_queue_size': len(qm.priority_queue),
                    'standard_queue_size': len(qm.standard_queue),
                    'purpose': 'Periodic health check',
                    '_explanation': f"System healthy. CPU: {cpu}%, Memory: {memory.percent}%. Queues: Priority={len(qm.priority_queue)}, Standard={len(qm.standard_queue)}"
                },
                status='success'
            )
        except Exception as e:
            pass  # Silent fail - just skip this heartbeat

heartbeat_thread = threading.Thread(target=heartbeat_logger, daemon=True)
heartbeat_thread.start()

@app.route('/ingest', methods=['POST'])
def ingest_log():
    """Alert ingestion endpoint - Entry point for all alerts"""
    # Log API call with educational context
    live_logger.log(
        'API',
        'POST /ingest - Alert Received',
        {
            'source_ip': request.remote_addr,
            'content_type': request.content_type,
            '_explanation': 'This is the entry point for all alerts. SIEMs (Splunk, Wazuh) send alerts here via HTTP POST.'
        },
        status='success'
    )
    
    # SECURITY: Require API Key for ingestion
    api_key = request.headers.get('X-API-Key')
    if api_key != os.getenv("INGEST_API_KEY", "secure-ingest-key-123"):
        live_logger.log(
            'SECURITY', 
            'API Key Validation FAILED',
            {
                'ip': request.remote_addr,
                '_explanation': 'Security check failed - invalid or missing API key. All ingestion requests must include a valid X-API-Key header.'
            },
            status='error'
        )
        return jsonify({"error": "Unauthorized: Invalid API Key"}), 401

    live_logger.log(
        'SECURITY',
        'API Key Validated',
        {
            'endpoint': '/ingest',
            '_explanation': 'API key verified. Request is authorized to proceed.'
        },
        status='success'
    )
    
    try:
        data = request.json
        
        live_logger.log(
            'FUNCTION',
            'parse_splunk_alert() - Normalizing SIEM Format',
            {
                'data_keys': list(data.keys()),
                'alert_name': data.get('alert_name', data.get('search_name', 'Unknown')),
                '_explanation': 'parse_splunk_alert() normalizes different SIEM formats (Splunk, Wazuh, etc.) into a standard alert schema.'
            },
            status='success'
        )
        
        tracker.log_step(
            file_name="app.py",
            function="ingest_log",
            purpose="Receive HTTP POST alert",
            explanation="Entry point for the SOAR pipeline. Receives JSON payload from SIEM (Splunk/Wazuh).",
            input_data={"keys": list(data.keys())},
            objects_created={"data": "dict"},
            timing_ms=1
        )
        
        parsed = parse_splunk_alert(data)
        tracker.log_step(
            file_name="backend/core/parser.py", 
            function="parse_splunk_alert",
            purpose="Normalize Splunk format",
            input_data=data,
            objects_created={"parsed": parsed},
            timing_ms=2
        )
        
        live_logger.log(
            'FUNCTION',
            'map_to_mitre() - ATT&CK Technique Mapping',
            {
                'alert_name': parsed.get('alert_name'),
                '_explanation': 'map_to_mitre() maps the alert to MITRE ATT&CK techniques using RAG search over 500+ technique descriptions.'
            },
            status='success'
        )
        
        mitre_technique = map_to_mitre(parsed, tracker=tracker)
        parsed['mitre_technique'] = mitre_technique
        tracker.log_step(
            file_name="backend/core/mitre_mapping.py",
            function="map_to_mitre",
            purpose="Map alert keywords to MITRE ATT&CK technique",
            explanation="Standardizes the attack type (e.g. 'Phishing' -> T1566) for consistent analysis.",
            input_data={"alert_name": parsed.get("alert_name"), "desc": parsed.get("description")},
            objects_created={"technique_id": mitre_technique},
            timing_ms=3
        )
        # print(f"✓ MITRE: {mitre_technique or 'None'}")
        
        live_logger.log(
            'FUNCTION',
            'MITRE Technique Mapped',
            {
                'technique': mitre_technique or 'None detected',
                'alert_name': parsed.get('alert_name'),
                '_explanation': f"Alert mapped to MITRE ATT&CK technique: {mitre_technique or 'No direct mapping found'}"
            },
            status='success' if mitre_technique else 'warning'
        )
        
        live_logger.log(
            'FUNCTION',
            'classify_severity() - Priority Assessment',
            {
                'alert_name': parsed.get('alert_name'),
                'raw_severity': parsed.get('severity'),
                '_explanation': 'classify_severity() determines if this is a CRITICAL_HIGH (urgent, skip queue) or MEDIUM_LOW (normal queue) alert based on keywords and severity scores.'
            },
            status='success'
        )
        
        severity_class = classify_severity(parsed)
        tracker.log_step(
            file_name="backend/core/Severity.py",
            function="classify_severity",
            purpose="Determine severity level (CRITICAL_HIGH vs MEDIUM_LOW)",
            input_data={"severity": parsed.get("severity")},
            objects_created={"class": severity_class},
            timing_ms=1
        )
        
        live_logger.log(
            'FUNCTION',
            'Severity Classified',
            {
                'severity_class': severity_class,
                'queue_target': 'PRIORITY' if severity_class == 'CRITICAL_HIGH' else 'STANDARD',
                '_explanation': f"Alert classified as {severity_class}. Will be routed to {'PRIORITY queue (immediate processing)' if severity_class == 'CRITICAL_HIGH' else 'STANDARD queue'}."
            },
            status='success'
        )
        
        tracker.log_step(
            file_name="backend/core/parser.py",
            function="tokenize",
            purpose="No Tokenization (Auth Removed)",
            explanation="Privacy features disabled as per request.",
            input_data="[Plaintext]",
            objects_created={},
            timing_ms=0
        )
        
        live_logger.log(
            'DATABASE',
            'store_alert() - Persisting to Supabase',
            {
                'table': 'alerts',
                'alert_name': parsed.get('alert_name'),
                'severity': severity_class,
                '_explanation': 'store_alert() saves the normalized alert to Supabase database with all metadata (MITRE technique, severity class, timestamps).'
            },
            status='success'
        )
        
        db_result = store_alert(parsed, mitre_technique, severity_class)
        # Handle db_result which might be a list or object depending on supabase version
        # Assuming store_alert returns data or None
        alert_id = None
        if db_result and hasattr(db_result, 'data') and db_result.data:
            alert_id = db_result.data[0]['id']
        elif db_result and isinstance(db_result, list) and len(db_result) > 0:
             alert_id = db_result[0]['id']
        
        live_logger.log(
            'DATABASE',
            'Alert Stored Successfully',
            {
                'alert_id': alert_id,
                'table': 'alerts',
                '_explanation': f"Alert saved to database with ID: {alert_id}. This ID will be used to track the alert through the AI analysis pipeline."
            },
            status='success' if alert_id else 'error'
        )
            
        tracker.log_step(
            file_name="backend/storage/database.py",
            function="store_alert",
            purpose="Persist tokenized alert to Supabase",
            input_data={"table": "alerts"},
            objects_created={"alert_id": alert_id},
            timing_ms=45
        )
        
        if not alert_id:
            live_logger.log(
                'DATABASE',
                'Fallback to S3 Backup',
                {'reason': 'Database insert failed', '_explanation': 'Primary database failed - backing up alert data to S3 for disaster recovery.'},
                status='warning'
            )
            print("[WARNING]  Database failed, backing up to S3...")
            backup_to_s3({
                **parsed,
                'mitre_technique': mitre_technique,
                'severity_class': severity_class
            })
        else:
            # CRITICAL FIX: Inject ID so AI can fetch logs
            parsed['id'] = alert_id
            parsed['alert_id'] = alert_id # Redundancy for safety
        
        live_logger.log(
            'QUEUE',
            'QueueManager.route_alert() - Routing to Queue',
            {
                'severity_class': severity_class,
                'target_queue': 'PRIORITY' if severity_class == 'CRITICAL_HIGH' else 'STANDARD',
                'alert_id': alert_id,
                '_explanation': f"Routing alert to {'PRIORITY queue (processed immediately by background worker)' if severity_class == 'CRITICAL_HIGH' else 'STANDARD queue (processed in order)'}."
            },
            status='success'
        )
        
        qm.route_alert(parsed, severity_class, tracker=tracker)
        
        live_logger.log(
            'QUEUE',
            'Alert Queued - Awaiting AI Analysis',
            {
                'priority_queue_size': len(qm.priority_queue),
                'standard_queue_size': len(qm.standard_queue),
                '_explanation': f"Alert is now in queue. Background worker will pick it up for AI analysis. Queue sizes: Priority={len(qm.priority_queue)}, Standard={len(qm.standard_queue)}"
            },
            status='success'
        )
        
        tracker.log_step(
            file_name="backend/core/Queue_manager.py",
            function="route_alert",
            purpose=f"Route to {severity_class} queue",
            input_data={"queue_type": "priority" if severity_class == "CRITICAL_HIGH" else "standard"},
            objects_created={"queue_length": len(qm.priority_queue) if severity_class == "CRITICAL_HIGH" else len(qm.standard_queue)},
            timing_ms=1
        )
        
        # -------------------------------------------------------------
        # OFF-LOAD TO BACKGROUND QUEUE (ASYNC)
        # -------------------------------------------------------------
        # We now rely on background_queue_processor to pick this up!
        # This makes the API return instantly.
        
        # if alert_id:
        #     # print("\n[AI] Step 8: AI Analysis (Antigravity Integrated)...")
        #     tracker.log_step(
        #         file_name="backend/ai/alert_analyzer_final.py",
        #         function="analyze_alert",
        #         purpose="Full AI Analysis (26 Features)",
        #         explanation="Orchestrating the 6-phase AI pipeline: Security -> Optimization -> Context -> Analysis -> Validation -> Observability.",
        #         input_data={"alert_id": alert_id},
        #         objects_created={"status": "PROCESSING"},
        #         timing_ms=0
        #     )
        #     
        #     # Add ID to alert for context
        #     tokenized_alert['alert_id'] = alert_id
        #     
        #     # Run Analysis
        #     ai_result = analyzer.analyze_alert(tokenized_alert)
        #     
        #     tracker.log_step(
        #         file_name="backend/ai/alert_analyzer_final.py",
        #         function="COMPLETE",
        #         purpose="AI Verdict Generated",
        #         input_data={"verdict": ai_result.get("verdict"), "confidence": ai_result.get("confidence")},
        #         objects_created={"evidence_count": len(ai_result.get("evidence", []))},
        #         timing_ms=2400 # Simulated or actual delta
        #     )
        #     
        #     # Update Database
        #     update_alert_with_ai_analysis(alert_id, ai_result)
        #     
        #     tracker.log_step(
        #         file_name="backend/storage/database.py",
        #         function="update_alert",
        #         purpose="Persist AI Verdict to DB",
        #         input_data=ai_result,
        #         objects_created={"status": "analyzed"},
        #         timing_ms=35
        #     )
        #     
        #     # print(f"[OK] AI Verdict: {ai_result.get('verdict')}")
        #     # print(f"[OK] Confidence: {ai_result.get('confidence')}")
        # else:
        #     # print("\n⚠️ Skipping AI analysis (no alert_id)")
        #     ai_result = {}
        ai_result = {} # Return empty for now, frontend will poll for updates
            
        tracker.log_step(
            file_name="app.py",
            function="return",
            purpose="Send enriched response to Frontend",
            input_data={"success": True},
            objects_created={"json_response": "dict"},
            timing_ms=1
        )
        # print("\n[OK] SUCCESS - Alert fully processed")
        # print("="*70 + "\n")
        
        return jsonify({
            "status": "processed", 
            "alert_id": alert_id,
            "mitre_technique": mitre_technique,
            "severity": severity_class,
            "ai_analysis": ai_result
        }), 200
        
    except Exception as e:
        print(f"\n[ERROR] ERROR IN /ingest: {e}")
        import traceback
        traceback.print_exc()
        print("="*70 + "\n")
        return jsonify({"error": str(e)}), 500


@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Fetch recent alerts for frontend - DETOKENIZED for analyst"""
    # Educational logging for this endpoint
    live_logger.log(
        'FUNCTION',
        'get_alerts() - Fetching Alerts for Analyst Console',
        {
            'endpoint': 'GET /alerts',
            'file': 'app.py',
            'purpose': 'Retrieve recent alerts from database for Analyst Console display',
            'database_query': 'SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50',
            'parameters': {
                'limit': 50,
                'order_by': 'created_at DESC'
            },
            'returns': 'Array of alert objects with AI verdicts, severity, MITRE techniques',
            '_explanation': 'This endpoint populates the Analyst Console. It fetches the 50 most recent alerts with all their data including AI analysis results.'
        },
        status='success'
    )
    
    try:
        response = supabase.table('alerts').select('*').order('created_at', desc=True).limit(50).execute()
        
        # Detokenize for analyst display
        # Detokenize for analyst display
        detokenized_alerts = response.data
        
        live_logger.log(
            'DATABASE',
            'Alerts Retrieved from Supabase',
            {
                'count': len(detokenized_alerts),
                'table': 'alerts',
                '_explanation': f"Retrieved {len(detokenized_alerts)} alerts from database for Analyst Console."
            },
            status='success'
        )
        
        return jsonify({
            "alerts": detokenized_alerts,
            "count": len(detokenized_alerts)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/alerts/<alert_id>', methods=['PATCH'])
def update_alert_status(alert_id):
    """
    Update alert status or analyst notes
    Supports: status, analyst_notes
    """
    data = request.json
    new_status = data.get('status')
    analyst_notes = data.get('analyst_notes')
    
    # Build update payload
    update_payload = {}
    if new_status:
        update_payload['status'] = new_status
    if analyst_notes is not None:  # Allow empty string to clear notes
        update_payload['analyst_notes'] = analyst_notes
    
    if not update_payload:
        return jsonify({"error": "Status or analyst_notes is required"}), 400
    
    # Educational logging for this endpoint
    live_logger.log(
        'FUNCTION',
        'update_alert_status() - Analyst Update',
        {
            'endpoint': 'PATCH /api/alerts/<alert_id>',
            'file': 'app.py',
            'purpose': 'Allow analysts to change alert status or add notes',
            'parameters': {
                'alert_id': alert_id,
                'updates': update_payload
            },
            'valid_statuses': ['open', 'investigating', 'closed', 'false_positive'],
            '_explanation': f"Analyst is updating alert {alert_id}: {update_payload}"
        },
        status='success'
    )
        
    try:
        # Update in Supabase
        response = supabase.table('alerts').update(update_payload).eq('id', alert_id).execute()
        
        # Log if tracker available
        if tracker:
            tracker.log_step(
                "app.py", 
                "update_alert_status", 
                f"Updated Alert {alert_id}", 
                explanation=f"Updates: {update_payload}"
            )
            
        return jsonify({"success": True, "updates": update_payload, "data": response.data}), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to update alert: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Fetch logs for investigation dashboard"""
    log_type = request.args.get('type')
    alert_id = request.args.get('alert_id') # Changed from hostname/ip to alert_id
    
    # Educational logging for this endpoint
    live_logger.log(
        'FUNCTION',
        'get_logs() - Fetching Forensic Evidence Logs',
        {
            'endpoint': 'GET /api/logs',
            'file': 'app.py',
            'purpose': 'Retrieve forensic logs for alert investigation',
            'parameters': {
                'log_type': log_type,
                'alert_id': alert_id
            },
            'available_log_types': {
                'process': 'query_process_logs(alert_id) - Process execution events',
                'network': 'query_network_logs(alert_id) - Network connections',
                'file': 'query_file_activity_logs(alert_id) - File system changes',
                'windows': 'query_windows_event_logs(alert_id) - Windows security events'
            },
            'database_tables': ['process_logs', 'network_logs', 'file_activity_logs', 'windows_event_logs'],
            '_explanation': f"Fetching {log_type} logs for alert {alert_id}. These are the raw forensic logs the AI analyzed. Analysts can review this evidence to verify the AI verdict."
        },
        status='success'
    )
    
    if not alert_id:
         return jsonify({"error": "alert_id is required"}), 400
    
    print(f"\n🔎 [LOG QUERY] Fetching {log_type} logs for Alert ID: {alert_id}")
    
    try:
        data = []
        if log_type == 'process':
            data = query_process_logs(alert_id)
        elif log_type == 'network':
            data = query_network_logs(alert_id)
        elif log_type == 'file':
            data = query_file_activity_logs(alert_id)
        elif log_type == 'windows':
            data = query_windows_event_logs(alert_id)
        
        # Log the result
        live_logger.log(
            'DATABASE',
            f'Forensic Logs Retrieved - {log_type}',
            {
                'log_type': log_type,
                'alert_id': alert_id,
                'records_found': len(data),
                '_explanation': f"Retrieved {len(data)} {log_type} log records for alert investigation."
            },
            status='success'
        )
            
            
        # DETOKENIZATION FOR ANALYST VIEW
        # Disabled as auth/tokenization is removed
        # for log in data:
            # if log.get('source_ip') and log['source_ip'].startswith(('IP-', 'TOKEN-')):
            #     log['source_ip'] = tokenizer.detokenize(log['source_ip'])
            # if log.get('dest_ip') and log['dest_ip'].startswith(('IP-', 'TOKEN-')):
            #     log['dest_ip'] = tokenizer.detokenize(log['dest_ip'])
            # if log.get('hostname') and log['hostname'].startswith(('HOST-', 'TOKEN-')):
            #     log['hostname'] = tokenizer.detokenize(log['hostname'])
            # if log.get('username') and log['username'].startswith(('USER-', 'TOKEN-')):
            #     log['username'] = tokenizer.detokenize(log['username'])
            
        print(f"   [OK] Found {len(data)} records")
        return jsonify(data)
        
    except Exception as e:
        print(f"   [ERROR] Log Fetch Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/queue-status', methods=['GET'])
def queue_status():
    """Get current queue status"""
    # Educational logging for this endpoint
    live_logger.log(
        'FUNCTION',
        'queue_status() - Queue Status Check',
        {
            'endpoint': 'GET /queue-status',
            'file': 'app.py',
            'purpose': 'Return current queue sizes for monitoring',
            'returns': {
                'priority_count': 'Number of CRITICAL_HIGH alerts waiting',
                'standard_count': 'Number of MEDIUM_LOW alerts waiting'
            },
            'current_values': {
                'priority_queue': len(qm.priority_queue),
                'standard_queue': len(qm.standard_queue)
            },
            '_explanation': f"Currently {len(qm.priority_queue)} priority alerts and {len(qm.standard_queue)} standard alerts in queue. Priority queue is processed first by background worker."
        },
        status='success'
    )
    
    return jsonify({
        "priority_count": len(qm.priority_queue),
        "standard_count": len(qm.standard_queue)
    })


# =========================================================================
# S3 FAILOVER ENDPOINTS
# =========================================================================

@app.route('/api/failover/status', methods=['GET'])
def failover_status():
    """Get S3 failover system status"""
    status = get_failover_status()
    
    live_logger.log(
        'DATABASE',
        'Failover Status Check',
        {
            'endpoint': 'GET /api/failover/status',
            'in_failover_mode': status.get('in_failover_mode', False),
            's3_available': status.get('s3_failover_available', False),
            '_explanation': 'Check the current status of the S3 failover system. If in_failover_mode is True, Supabase is down and we are using S3.'
        }
    )
    
    return jsonify(status)


@app.route('/api/failover/sync', methods=['POST'])
def manual_s3_sync():
    """Manually trigger S3 sync"""
    if not S3_FAILOVER_ENABLED:
        return jsonify({'error': 'S3 failover not enabled'}), 503
    
    live_logger.log(
        'DATABASE',
        'Manual S3 Sync Triggered',
        {
            'endpoint': 'POST /api/failover/sync',
            '_explanation': 'Manually triggering a full sync of all database tables to S3. This ensures S3 has the latest data for failover.'
        }
    )
    
    results = trigger_s3_sync()
    success_count = sum(1 for v in results.values() if v)
    
    return jsonify({
        'success': success_count == len(results),
        'results': results,
        'synced': success_count,
        'total': len(results)
    })


@app.route('/api/failover/test', methods=['POST'])
def test_failover():
    """Test S3 failover by temporarily simulating database failure"""
    if not S3_FAILOVER_ENABLED:
        return jsonify({'error': 'S3 failover not enabled'}), 503
    
    # Test reading from S3
    s3 = get_s3_failover()
    
    tests = {
        's3_connection': s3.s3_available,
        'alerts_readable': False,
        'process_logs_readable': False,
        'network_logs_readable': False
    }
    
    try:
        alerts = s3.read_table_from_s3('alerts')
        tests['alerts_readable'] = alerts is not None
        tests['alerts_count'] = len(alerts) if alerts else 0
    except Exception as e:
        tests['alerts_error'] = str(e)
    
    try:
        process_logs = s3.read_table_from_s3('process_logs')
        tests['process_logs_readable'] = process_logs is not None
        tests['process_logs_count'] = len(process_logs) if process_logs else 0
    except Exception as e:
        tests['process_logs_error'] = str(e)
    
    try:
        network_logs = s3.read_table_from_s3('network_logs')
        tests['network_logs_readable'] = network_logs is not None
        tests['network_logs_count'] = len(network_logs) if network_logs else 0
    except Exception as e:
        tests['network_logs_error'] = str(e)
    
    all_passed = all([
        tests['s3_connection'],
        tests['alerts_readable'],
        tests['process_logs_readable'],
        tests['network_logs_readable']
    ])
    
    live_logger.log(
        'DATABASE',
        'Failover Test Completed',
        {
            'endpoint': 'POST /api/failover/test',
            'all_tests_passed': all_passed,
            'test_results': tests,
            '_explanation': 'Tested ability to read data from S3. If all tests pass, the system can operate during database outages.'
        },
        status='success' if all_passed else 'warning'
    )
    
    return jsonify({
        'success': all_passed,
        'tests': tests,
        'message': 'All failover tests passed!' if all_passed else 'Some tests failed - check results'
    })


def rehydrate_queue():
    """Restores pending alerts from DB to Memory Queue on startup"""
    try:
        print("\n" + "="*50, flush=True)
        print("[RELOAD] [REHYDRATION] STARTING...", flush=True)
        print("   Checking for alerts where status != 'analyzed'", flush=True)
        
        # Broad query: Fetch anything where verdict is still pending (status might be null)
        # CRITICAL FIX: neq('status', 'analyzed') excludes NULL status rows in SQL!
        # We must simply check if ai_verdict is null.
        response = supabase.table('alerts').select("*").is_('ai_verdict', 'null').limit(50).execute()
        
        if response.data:
            print(f"   [QUEUE] FOUND {len(response.data)} ORPHANED ALERTS!", flush=True)
            live_logger.log(
                'QUEUE',
                'Rehydration Found Pending Alerts',
                {'count': len(response.data), 'action': 'requeuing'},
                status='warning'
            )
            
            for alert in response.data:
                # Add alert_id to payload so it can be updated later
                alert['alert_id'] = alert['id'] 
                
                # Re-calculate severity class if missing
                severity_class = alert.get('severity_class', 'MEDIUM')
                
                print(f"   -> Re-queuing: {alert.get('alert_name')} (ID: {alert['id']})", flush=True)
                
                # Route (adding to in-memory queue)
                qm.route_alert(alert, severity_class, tracker=tracker)
                
            print(f"   [OK] REHYDRATION COMPLETE. Queue size: {len(qm.priority_queue) + len(qm.standard_queue)}", flush=True)
            live_logger.log(
                'QUEUE',
                'Rehydration Complete',
                {
                    'priority_queue': len(qm.priority_queue),
                    'standard_queue': len(qm.standard_queue),
                    'source': 'Supabase alerts table',
                    '_explanation': f"Found pending alerts in database. Re-added {len(qm.priority_queue)} priority and {len(qm.standard_queue)} standard alerts to queues for processing."
                },
                status='success'
            )
        else:
            print("   [OK] NO PENDING ALERTS FOUND (Queue clean).", flush=True)
            live_logger.log(
                'QUEUE',
                'Rehydration Complete - No Pending Alerts',
                {
                    'status': 'clean',
                    '_explanation': 'No pending alerts found in database. All previously ingested alerts have been processed. System is ready for new alerts.'
                },
                status='success'
            )
        print("="*50 + "\n", flush=True)
            
    except Exception as e:
        print(f"   [ERROR] REHYDRATION FAILED: {e}", flush=True)

if __name__ == '__main__':
    # Log startup to Debug Dashboard with FULL educational details
    live_logger.log(
        'WORKER',
        'AI-SOC Watchdog - System Starting',
        {
            'version': '1.0',
            'mode': 'development',
            'port': 5000,
            'purpose': 'AI-Powered Security Operations Center Automation',
            'components_initializing': [
                'Flask Web Server - Handles API requests',
                'ConsoleFlowTracker - Tracks alert processing flow',
                'QueueManager - Routes alerts by priority',
                'AlertAnalyzer (lazy) - AI analysis engine with 26 features',
                'RAGSystem - Knowledge base with 7 ChromaDB collections',
                'Supabase - PostgreSQL database connection'
            ],
            'ai_features': '26 security features including prompt injection protection, budget control, MITRE mapping, RAG context, Claude API calls',
            '_explanation': 'AI-SOC Watchdog is starting up. This is the main entry point for the entire system. It initializes all components: web server, queue manager, AI analyzer, RAG system, and database connections.'
        },
        status='success'
    )
    
    rehydrate_queue()
    
    # Log ALL available API endpoints with full documentation
    live_logger.log(
        'API',
        'COMPLETE ENDPOINT DOCUMENTATION - All 15+ API Routes',
        {
            'total_endpoints': 15,
            'app_py_routes': {
                'POST /ingest': 'Alert ingestion from SIEMs → parse → MITRE map → classify → store → queue',
                'GET /alerts': 'Fetch 50 recent alerts for Analyst Console',
                'PATCH /api/alerts/<id>': 'Update alert status (open/investigating/closed)',
                'GET /api/logs': 'Fetch forensic logs (process/network/file/windows) for alert',
                'GET /queue-status': 'Get priority and standard queue sizes',
                'POST /api/log_event': 'Record user activity in flow tracker',
                'GET /api/debug-logs': 'Get flow tracker logs for transparency'
            },
            'rag_blueprint_routes': {
                'GET /api/rag/stats': 'Get document counts for all 7 ChromaDB collections',
                'GET /api/rag/collections/status': 'Health check for each RAG collection',
                'POST /api/rag/query': 'Semantic search across knowledge base'
            },
            'transparency_blueprint': {
                'GET /api/transparency': 'AI decision explanations with chain of thought'
            },
            'monitoring_blueprint': {
                'GET /api/monitoring/logs/recent': 'Recent debug logs (polled by dashboard)',
                'GET /api/monitoring/metrics/dashboard': 'System metrics (CPU, memory, costs)',
                'GET /api/monitoring/logs/categories': 'Available log category filters'
            },
            '_explanation': 'These are ALL the API endpoints available. Each endpoint has a specific purpose in the SOC automation pipeline. Hover/expand any endpoint call in the logs to see what functions it calls.'
        },
        status='success'
    )
    
    # Log server ready with complete details
    live_logger.log(
        'WORKER',
        'Flask Server - Ready to Accept Requests',
        {
            'port': 5000,
            'debug': True,
            'reloader': False,
            'background_threads': [
                'background_queue_processor - Processes alerts from queues, calls AI analyzer',
                'heartbeat_logger - Logs system status every 30 seconds'
            ],
            'registered_blueprints': [
                'monitoring_bp - /api/monitoring/* endpoints',
                'rag_monitoring_bp - /api/rag/* endpoints',
                'transparency_bp - /api/transparency endpoint'
            ],
            '_explanation': 'Flask server is now ready. The system can receive alerts via POST /ingest and serve the React dashboard. All background processors are running.'
        },
        status='success'
    )
    
    print(" [INFO] Starting Flask Server on Port 5000 (Single Process Mode)...", flush=True)
    app.run(debug=True, use_reloader=False, port=5000)
"""
Monitoring API - Flask Endpoints for Performance Dashboard
===========================================================

This module provides Flask API endpoints that serve data to the
Performance Dashboard and Debug Dashboard in the frontend.

WHAT THIS FILE DOES:
1. Serves real-time system metrics (CPU, memory, costs)
2. Serves live operation logs for debug dashboard
3. Serves metrics history for charts
4. Serves AI performance statistics
5. Serves error history for troubleshooting

ENDPOINTS PROVIDED:
- GET /api/monitoring/metrics/dashboard  - Main metrics for Performance Dashboard
- GET /api/monitoring/metrics/history    - Historical data for charts
- GET /api/monitoring/logs/recent        - Recent operations for Debug Dashboard
- GET /api/monitoring/logs/categories    - Available log categories
- GET /api/monitoring/logs/errors        - Recent errors list

FRONTEND CONSUMERS:
- PerformanceDashboard.jsx  - System metrics, charts, AI stats
- DebugDashboard.jsx        - Live operation log stream

Author: AI-SOC Watchdog System
"""
from flask import Blueprint, jsonify, Response, request
import json
import time

# Use relative imports since this is imported by app.py which sets up paths correctly
from .system_monitor import monitor
from .live_logger import live_logger, _GLOBAL_OPERATIONS, _GLOBAL_LOCK

monitoring_bp = Blueprint('monitoring', __name__)

# =============================================================================
# METRICS ENDPOINTS (for System Metrics tab)
# =============================================================================

@monitoring_bp.route('/api/monitoring/metrics/dashboard', methods=['GET'])
def get_metrics_dashboard():
    """Get real-time METRICS dashboard data (CPU, Memory, Budget, etc.)"""
    try:
        data = monitor.get_dashboard_data()
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/api/monitoring/metrics/history', methods=['GET'])
def get_metrics_history():
    """Get metrics history for charts in format expected by frontend"""
    try:
        from flask import request
        hours = int(request.args.get('hours', 24))
        
        # Build history array with combined metrics at each timestamp
        history = []
        cpu_list = list(monitor.metrics['cpu_usage'])[-60:]
        mem_list = list(monitor.metrics['memory_usage'])[-60:]
        alerts_list = list(monitor.metrics['alerts_processed'])[-100:]
        
        # Combine into timeline
        for i, cpu in enumerate(cpu_list):
            mem = mem_list[i] if i < len(mem_list) else {'value': 0}
            alerts_count = len([a for a in alerts_list if a['timestamp'] <= cpu['timestamp']])
            
            history.append({
                'timestamp': cpu['timestamp'],
                'system_metrics': {
                    'cpu_percent': cpu['value'],
                    'memory_percent': mem.get('value', 0)
                },
                'alert_stats': {
                    'total_processed': alerts_count
                }
            })
        
        return jsonify({
            'history': history,
            'cpu': cpu_list,
            'memory': mem_list,
            'alerts': alerts_list,
            'costs': list(monitor.metrics['costs'])[-100:],
            'processing_times': list(monitor.metrics['processing_times'])[-100:]
        })
    except Exception as e:
        return jsonify({'error': str(e), 'history': []}), 500

@monitoring_bp.route('/api/monitoring/metrics/errors', methods=['GET'])
def get_metric_errors():
    """Get error count and active critical errors"""
    try:
        errors = list(monitor.metrics['errors'])[-20:]
        return jsonify({
            'errors': errors,
            'count': len(errors),
            'active_critical': monitor.active_errors
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# LIVE LOGS ENDPOINTS (for System Debug/Live Logs tab)
# =============================================================================

@monitoring_bp.route('/api/monitoring/logs/recent', methods=['GET'])
def get_recent_logs():
    """
    Get recent operation logs with full details
    """
    try:
        limit = int(request.args.get('limit', 100))
        category = request.args.get('category', None)
        
        # Use the global operations deque directly
        with _GLOBAL_LOCK:
            all_ops = list(_GLOBAL_OPERATIONS)
        
        # Filter by category if specified
        if category:
            all_ops = [op for op in all_ops if op.get('category') == category]
        
        # Return last N operations
        logs = all_ops[-limit:]
        
        return jsonify({
            'operations': logs,
            'count': len(logs),
            'categories': ['API', 'WORKER', 'FUNCTION', 'AI', 'RAG', 'DATABASE', 'QUEUE', 'SECURITY', 'ERROR']
        })
    except Exception as e:
        return jsonify({'error': str(e), 'operations': [], 'count': 0}), 500

@monitoring_bp.route('/api/monitoring/logs/stream', methods=['GET'])
def stream_live_logs():
    """
    Server-Sent Events stream for REAL-TIME operation logs
    Client subscribes and gets every new operation as it happens
    """
    def generate():
        last_index = 0
        while True:
            # Get new operations since last check
            operations = live_logger.get_live_stream()
            if len(operations) > last_index:
                for op in operations[last_index:]:
                    # Format for SSE
                    yield f"data: {json.dumps(op)}\\n\\n"
                last_index = len(operations)
            
            time.sleep(0.1)  # Check every 100ms for near-real-time updates
    
    return Response(generate(), mimetype='text/event-stream')

@monitoring_bp.route('/api/monitoring/logs/categories', methods=['GET'])
def get_log_categories():
    """Get available log categories for filtering"""
    try:
        return jsonify({
            'categories': list(live_logger.categories.keys())
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@monitoring_bp.route('/api/monitoring/logs/search', methods=['POST'])
def search_logs():
    """Search logs by keyword"""
    try:
        from flask import request
        data = request.get_json()
        keyword = data.get('keyword', '').lower()
        
        all_logs = live_logger.get_live_stream()
        matching = []
        
        for log in all_logs:
            # Search in operation name, explanation, and details
            if (keyword in log['operation'].lower() or
                keyword in log['explanation'].lower() or
                keyword in str(log['details']).lower()):
                matching.append(log)
        
        return jsonify({
            'results': matching,
            'count': len(matching)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# COMBINED ENDPOINT (for overview)
# =============================================================================

@monitoring_bp.route('/api/monitoring/overview', methods=['GET'])
def get_monitoring_overview():
    """Get complete overview - both metrics and recent logs"""
    try:
        metrics_data = monitor.get_dashboard_data()
        recent_logs = live_logger.get_recent(limit=20)
        
        return jsonify({
            'metrics': metrics_data,
            'recent_logs': recent_logs,
            'timestamp': time.time()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

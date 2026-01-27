"""
System Monitor - Real-Time Performance Tracking
================================================

This module tracks all system metrics including CPU, memory, AI costs,
processing times, and errors for the Performance Dashboard.

WHAT THIS FILE DOES:
1. Collects CPU/memory usage in real-time (psutil)
2. Tracks AI API costs and token usage
3. Records alert processing times
4. Stores error history for debugging
5. Provides dashboard-ready metric summaries

WHY THIS EXISTS:
- Operations need visibility into system health
- Cost tracking prevents budget overruns
- Performance metrics identify bottlenecks
- Error tracking enables rapid debugging

METRICS TRACKED:
- cpu_usage:      Last 60 readings (refreshed every second)
- memory_usage:   Last 60 readings
- api_calls:      Last 100 API call records
- alerts_processed: Last 100 alert processing records
- errors:         Last 50 errors
- ai_operations:  Last 100 AI operation records
- processing_times: Last 100 timing records
- costs:          Last 100 cost records

API ENDPOINT:
    GET /api/monitoring/metrics/dashboard
    Returns: { cpu, memory, alerts_count, total_cost, uptime, ... }

Author: AI-SOC Watchdog System
"""
import psutil
import time
import json
from datetime import datetime
from collections import deque
import threading

class SystemMonitor:
    """
    Real-time monitoring of ALL system operations
    Provides ACTUAL metrics, not fake numbers
    """
    
    def __init__(self):
        # Real metrics storage
        self.metrics = {
            'cpu_usage': deque(maxlen=60),  # Last 60 readings
            'memory_usage': deque(maxlen=60),
            'api_calls': deque(maxlen=100),
            'alerts_processed': deque(maxlen=100),
            'errors': deque(maxlen=50),
            'ai_operations': deque(maxlen=100),
            'processing_times': deque(maxlen=100),
            'costs': deque(maxlen=100)
        }
        
        # Current session stats
        self.session_stats = {
            'started_at': datetime.now(),
            'total_alerts': 0,
            'total_api_calls': 0,
            'total_cost': 0.0,
            'total_errors': 0,
            'alerts_per_minute': 0,
            'avg_processing_time': 0,
            'success_rate': 100.0
        }
        
        # Error tracking
        self.active_errors = []
        
        # Start background monitoring
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        print("[MONITOR] Real-time system monitoring started")
    
    def _monitor_loop(self):
        """Background thread that collects REAL system metrics"""
        while self.monitoring:
            try:
                # Get ACTUAL CPU usage
                cpu = psutil.cpu_percent(interval=1)
                self.metrics['cpu_usage'].append({
                    'timestamp': time.time(),
                    'value': cpu
                })
                
                # Get ACTUAL memory usage
                memory = psutil.virtual_memory()
                self.metrics['memory_usage'].append({
                    'timestamp': time.time(),
                    'value': memory.percent,
                    'used_gb': memory.used / (1024**3),
                    'total_gb': memory.total / (1024**3)
                })
                
                # Calculate alerts per minute
                recent_alerts = [a for a in self.metrics['alerts_processed'] 
                                if time.time() - a['timestamp'] < 60]
                self.session_stats['alerts_per_minute'] = len(recent_alerts)
                
                # Calculate avg processing time
                if self.metrics['processing_times']:
                    times = [t['duration'] for t in self.metrics['processing_times']]
                    self.session_stats['avg_processing_time'] = sum(times) / len(times)
                
                # Calculate success rate
                total = len(self.metrics['alerts_processed'])
                errors = len([e for e in self.metrics['errors'] 
                             if e['type'] == 'alert_failure'])
                if total > 0:
                    self.session_stats['success_rate'] = ((total - errors) / total) * 100
                
            except Exception as e:
                print(f"[MONITOR ERROR] {e}")
            
            time.sleep(1)
    
    def log_ai_operation(self, operation, details, success=True):
        """
        Log every AI operation with full details
        
        Args:
            operation: Name of operation (e.g., "RAG_Query", "API_Call", "Validation")
            details: Dict with operation details
            success: Whether operation succeeded
        """
        entry = {
            'timestamp': time.time(),
            'operation': operation,
            'details': details,
            'success': success
        }
        self.metrics['ai_operations'].append(entry)
        
        # Print to console for visibility
        status = "[OK]" if success else "[FAIL]"
        print(f"{status} {operation}: {json.dumps(details, indent=2)}")
    
    def log_api_call(self, model, tokens_in, tokens_out, cost, duration):
        """Log ACTUAL API call with real costs and tokens"""
        entry = {
            'timestamp': time.time(),
            'model': model,
            'tokens_in': tokens_in,
            'tokens_out': tokens_out,
            'cost': cost,
            'duration': duration
        }
        self.metrics['api_calls'].append(entry)
        self.session_stats['total_api_calls'] += 1
        self.session_stats['total_cost'] += cost
        
        print(f"[API] {model} | In: {tokens_in} | Out: {tokens_out} | Cost: ${cost:.4f} | {duration:.2f}s")
    
    def log_alert_processed(self, alert_id, verdict, confidence, duration, cost):
        """Log complete alert processing with all metrics"""
        entry = {
            'timestamp': time.time(),
            'alert_id': alert_id,
            'verdict': verdict,
            'confidence': confidence,
            'duration': duration,
            'cost': cost
        }
        self.metrics['alerts_processed'].append(entry)
        self.metrics['processing_times'].append({
            'timestamp': time.time(),
            'duration': duration
        })
        self.metrics['costs'].append({
            'timestamp': time.time(),
            'cost': cost
        })
        
        self.session_stats['total_alerts'] += 1
        
        print(f"[ALERT] {alert_id[:8]}... | {verdict.upper()} ({confidence:.0%}) | {duration:.2f}s | ${cost:.4f}")
    
    def log_error(self, error_type, message, context=None, severity='ERROR'):
        """
        Log errors with full context for debugging
        
        Severity levels: ERROR, CRITICAL, WARNING
        """
        entry = {
            'timestamp': time.time(),
            'type': error_type,
            'message': message,
            'context': context or {},
            'severity': severity
        }
        self.metrics['errors'].append(entry)
        self.session_stats['total_errors'] += 1
        
        # Add to active errors if critical
        if severity == 'CRITICAL':
            self.active_errors.append(entry)
        
        print(f"[{severity}] {error_type}: {message}")
        if context:
            print(f"  Context: {json.dumps(context, indent=2)}")
    
    def get_dashboard_data(self):
        """
        Get current dashboard data with REAL metrics
        Returns data in format expected by frontend PerformanceDashboard.jsx
        """
        current_time = time.time()
        uptime = (datetime.now() - self.session_stats['started_at']).total_seconds()
        
        # Get latest metrics
        cpu_current = self.metrics['cpu_usage'][-1]['value'] if self.metrics['cpu_usage'] else 0
        mem_current = self.metrics['memory_usage'][-1] if self.metrics['memory_usage'] else {'value': 0, 'used_gb': 0, 'total_gb': 0}
        
        # Recent activity (last 5 minutes)
        five_min_ago = current_time - 300
        recent_alerts = [a for a in self.metrics['alerts_processed'] if a['timestamp'] > five_min_ago]
        recent_errors = [e for e in self.metrics['errors'] if e['timestamp'] > five_min_ago]
        recent_costs = [c['cost'] for c in self.metrics['costs'] if c['timestamp'] > five_min_ago]
        
        # Calculate verdict distribution from processed alerts
        by_verdict = {}
        for alert in self.metrics['alerts_processed']:
            verdict = alert.get('verdict', 'unknown')
            by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        
        # Calculate total tokens from API calls
        total_input_tokens = sum(call.get('tokens_in', 0) for call in self.metrics['api_calls'])
        total_output_tokens = sum(call.get('tokens_out', 0) for call in self.metrics['api_calls'])
        
        # Return in format expected by frontend
        return {
            # System metrics (CPU, Memory)
            'system_metrics': {
                'cpu_percent': cpu_current,
                'memory_percent': mem_current.get('value', 0),
                'memory_used_gb': mem_current.get('used_gb', 0),
                'memory_total_gb': mem_current.get('total_gb', 0)
            },
            # Alert statistics
            'alert_stats': {
                'total_processed': self.session_stats['total_alerts'],
                'pending_queue': 0,  # Will be updated by queue manager
                'by_verdict': by_verdict
            },
            # Budget info
            'budget': {
                'spent': self.session_stats['total_cost'],
                'remaining': 2.00 - self.session_stats['total_cost'],
                'daily_limit': 2.00
            },
            # AI metrics
            'ai_metrics': {
                'avg_processing_time': self.session_stats['avg_processing_time'],
                'total_cost': self.session_stats['total_cost'],
                'total_requests': self.session_stats['total_api_calls'],
                'total_input_tokens': total_input_tokens,
                'total_output_tokens': total_output_tokens
            },
            # RAG stats
            'rag_stats': {
                'total_queries': self.rag_queries if hasattr(self, 'rag_queries') else 0,
                'avg_query_time': self.avg_rag_time if hasattr(self, 'avg_rag_time') else 0
            },
            # Uptime
            'uptime_seconds': uptime,
            # Errors
            'active_errors': self.active_errors[-5:],
            'latest_operations': list(self.metrics['ai_operations'])[-10:]
        }
    
    def log_rag_query(self, query_time, docs_found):
        """Log RAG query for metrics"""
        if not hasattr(self, 'rag_queries'):
            self.rag_queries = 0
            self.rag_total_time = 0.0
        
        self.rag_queries += 1
        self.rag_total_time += query_time
        self.avg_rag_time = self.rag_total_time / self.rag_queries
    
    def stop(self):
        """Stop monitoring"""
        self.monitoring = False
        self.monitor_thread.join()

# Global monitor instance
monitor = SystemMonitor()

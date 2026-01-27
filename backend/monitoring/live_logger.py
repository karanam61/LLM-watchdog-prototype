"""
Live Operation Logger - Real-Time Debug Dashboard Data
=======================================================

This module captures every operation in the system with full details
for the Debug Dashboard, making the system transparent to operators.

WHAT THIS FILE DOES:
1. Logs every API endpoint call with parameters
2. Logs every function execution with arguments
3. Logs background worker actions
4. Logs AI operations with prompts and responses
5. Logs RAG queries with retrieved documents
6. Provides educational explanations for non-coders

WHY THIS EXISTS:
- Debug dashboard needs live operation feed
- Non-technical users need to understand what's happening
- Troubleshooting requires full operation history
- Audit requirements need complete trails

LOG CATEGORIES:
- API:      API endpoint called
- WORKER:   Background worker action
- FUNCTION: Function executed
- AI:       AI operation (Claude API)
- RAG:      RAG knowledge query
- DATABASE: Database operation
- ERROR:    Error occurred

API ENDPOINT:
    GET /api/monitoring/logs/recent
    Returns: [ { category, operation, details, timestamp }, ... ]

Author: AI-SOC Watchdog System
"""
import time
from datetime import datetime
from collections import deque
import threading
import json
import inspect

class LiveOperationLogger:
    """
    Captures every single operation in the system with full details
    Makes everything visible and understandable for non-coders
    """
    
    def __init__(self):
        # Store last 500 operations
        self.operations = deque(maxlen=500)
        self.lock = threading.Lock()
        
        # Operation categories for filtering
        self.categories = {
            'API': 'API Endpoint Called',
            'WORKER': 'Background Worker Action',
            'FUNCTION': 'Function Executed',
            'AI': 'AI Operation',
            'RAG': 'RAG Knowledge Query',
            'DATABASE': 'Database Operation',
            'QUEUE': 'Queue Management',
            'SECURITY': 'Security Check',
            'ERROR': 'Error Occurred'
        }
        
        print("[LIVE LOGGER] Operation tracking started - capturing everything")
    
    def log(self, category, operation, details, status='success', duration=None):
        """
        Log ANY operation with full context
        
        Args:
            category: One of the category keys above
            operation: What happened (e.g., "POST /ingest", "analyze_alert()", "RAG Query MITRE")
            details: Dict with all relevant info (parameters, results, etc.)
            status: 'success', 'warning', 'error'
            duration: How long it took in seconds
        """
        with self.lock:
            entry = {
                'timestamp': time.time(),
                'datetime': datetime.now().isoformat(),
                'category': category,
                'operation': operation,
                'details': details,
                'status': status,
                'duration': duration,
                'explanation': self._explain_operation(category, operation, details)
            }
            
            self.operations.append(entry)
            
            # Print to console with visual clarity
            self._print_operation(entry)
    
    def _explain_operation(self, category, operation, details):
        """
        Generate human-readable explanation of what happened
        """
        explanations = {
            'API': f"Received web request to {operation}",
            'WORKER': f"Background process {operation}",
            'FUNCTION': f"System executed {operation}",
            'AI': f"AI performed {operation}",
            'RAG': f"Knowledge base searched for {operation}",
            'DATABASE': f"Database {operation}",
            'QUEUE': f"Alert queue {operation}",
            'SECURITY': f"Security system {operation}",
            'ERROR': f"Problem occurred: {operation}"
        }
        
        base = explanations.get(category, operation)
        
        # Add context from details
        if 'alert_id' in details:
            base += f" | Alert: {details['alert_id'][:8]}..."
        if 'verdict' in details:
            base += f" | Result: {details['verdict'].upper()}"
        if 'error' in details:
            base += f" | Error: {details['error']}"
            
        return base
    
    def _print_operation(self, entry):
        """Print operation to console with formatting"""
        # Status icon
        icons = {
            'success': '[OK]',
            'warning': '[WARN]',
            'error': '[FAIL]'
        }
        icon = icons.get(entry['status'], '[INFO]')
        
        # Category badge
        cat_badge = f"[{entry['category']}]"
        
        # Duration if available
        duration_str = f" ({entry['duration']:.2f}s)" if entry['duration'] else ""
        
        print(f"{icon} {cat_badge} {entry['operation']}{duration_str}")
        print(f"     {entry['explanation']}")
        
        # Print key details
        if entry['details']:
            important_keys = ['parameters', 'result', 'error', 'verdict', 'confidence']
            for key in important_keys:
                if key in entry['details']:
                    value = entry['details'][key]
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value)[:100]
                    print(f"     {key}: {value}")
        print()
    
    def get_recent(self, limit=100, category=None):
        """Get recent operations, optionally filtered by category"""
        with self.lock:
            ops = list(self.operations)
            
            if category:
                ops = [op for op in ops if op['category'] == category]
            
            return ops[-limit:]
    
    def get_live_stream(self):
        """Get all operations as they come (for SSE)"""
        with self.lock:
            return list(self.operations)

# Global logger instance
live_logger = LiveOperationLogger()


# Decorator to automatically log function calls
def log_function_call(category='FUNCTION'):
    """
    Decorator that automatically logs every function call with parameters
    
    Usage:
        @log_function_call('AI')
        def my_function(param1, param2):
            ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Get function name and parameters
            func_name = func.__name__
            
            # Get parameter names
            sig = inspect.signature(func)
            params = {}
            
            # Bind arguments to parameter names
            try:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                params = dict(bound.arguments)
                
                # Sanitize sensitive data
                for key in ['password', 'api_key', 'token', 'secret']:
                    if key in params:
                        params[key] = '***REDACTED***'
            except:
                params = {'args': str(args)[:100], 'kwargs': str(kwargs)[:100]}
            
            # Start timing
            start_time = time.time()
            
            # Execute function
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Log success
                live_logger.log(
                    category,
                    f"{func_name}()",
                    {
                        'parameters': params,
                        'status': 'completed'
                    },
                    status='success',
                    duration=duration
                )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Log error
                live_logger.log(
                    'ERROR',
                    f"{func_name}() failed",
                    {
                        'parameters': params,
                        'error': str(e),
                        'error_type': type(e).__name__
                    },
                    status='error',
                    duration=duration
                )
                
                raise  # Re-raise the exception
        
        return wrapper
    return decorator

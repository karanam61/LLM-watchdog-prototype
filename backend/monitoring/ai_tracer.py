"""
AI Operation Tracer - Human-Readable AI Activity Logging
=========================================================

This module traces every AI operation with clear explanations,
making complex AI processing understandable for non-technical users.

WHAT THIS FILE DOES:
1. Tracks start/end of AI operations
2. Records operation duration and results
3. Provides human-readable descriptions
4. Maintains operation stack for nested operations
5. Integrates with SystemMonitor for metrics

WHY THIS EXISTS:
- AI processing is complex and opaque
- Users need to understand what AI is doing
- Debugging requires operation timing
- Transparency builds trust in AI decisions

OPERATION TYPES TRACED:
- Alert Analysis:      Full 6-phase analysis pipeline
- RAG Query:          Knowledge base retrieval
- Context Building:   Assembling prompt context
- API Call:           Claude API request/response
- Verdict Generation: Final decision making

USAGE:
    tracer.start_operation("Alert Analysis", "Analyzing ransomware alert")
    # ... do work ...
    tracer.complete_operation(result={"verdict": "malicious"})

Author: AI-SOC Watchdog System
"""
import time
from datetime import datetime

class AIOperationTracer:
    """
    Traces every AI operation with clear explanations
    Makes complex operations understandable for non-coders
    """
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.current_operation = None
        self.operation_stack = []
    
    def start_operation(self, name, description, expected_duration=None):
        """
        Start tracking an operation
        
        Args:
            name: Operation name (e.g., "Alert Analysis")
            description: Human-readable explanation
            expected_duration: Estimated time in seconds
        """
        op = {
            'name': name,
            'description': description,
            'started_at': time.time(),
            'expected_duration': expected_duration,
            'steps': []
        }
        
        self.operation_stack.append(op)
        self.current_operation = op
        
        print(f"\n{'='*80}")
        print(f"[START] {name}")
        print(f"  What: {description}")
        if expected_duration:
            print(f"  Expected time: ~{expected_duration}s")
        print(f"{'='*80}\n")
        
        self.monitor.log_ai_operation(
            f"START_{name}",
            {'description': description},
            success=True
        )
    
    def add_step(self, step_name, details, status='success'):
        """
        Add a step to current operation
        
        Args:
            step_name: Name of step
            details: What happened (human-readable)
            status: 'success', 'warning', 'error'
        """
        if not self.current_operation:
            return
        
        step = {
            'name': step_name,
            'details': details,
            'status': status,
            'timestamp': time.time()
        }
        self.current_operation['steps'].append(step)
        
        # Visual indicators
        icon = {
            'success': '[OK]',
            'warning': '[WARN]',
            'error': '[FAIL]'
        }.get(status, '[INFO]')
        
        print(f"{icon} {step_name}")
        print(f"     {details}\n")
        
        # Log to monitor
        self.monitor.log_ai_operation(
            f"STEP_{step_name}",
            {'details': details, 'status': status},
            success=(status != 'error')
        )
        
        # If error, log it separately
        if status == 'error':
            self.monitor.log_error(
                f"{self.current_operation['name']}_STEP_FAILED",
                f"{step_name}: {details}",
                context={'operation': self.current_operation['name']},
                severity='ERROR'
            )
    
    def end_operation(self, success=True, result_summary=None):
        """
        End current operation and show summary
        """
        if not self.current_operation:
            return
        
        duration = time.time() - self.current_operation['started_at']
        op = self.operation_stack.pop()
        
        print(f"\n{'='*80}")
        status = "[COMPLETE]" if success else "[FAILED]"
        print(f"{status} {op['name']}")
        print(f"  Duration: {duration:.2f}s")
        
        if op['expected_duration']:
            diff = duration - op['expected_duration']
            if diff > 0:
                print(f"  Performance: {diff:.2f}s slower than expected")
            else:
                print(f"  Performance: {abs(diff):.2f}s faster than expected")
        
        if result_summary:
            print(f"  Result: {result_summary}")
        
        print(f"  Steps completed: {len(op['steps'])}")
        print(f"{'='*80}\n")
        
        # Log completion
        self.monitor.log_ai_operation(
            f"END_{op['name']}",
            {
                'duration': duration,
                'success': success,
                'steps': len(op['steps']),
                'result': result_summary
            },
            success=success
        )
        
        # Update current operation
        self.current_operation = self.operation_stack[-1] if self.operation_stack else None
    
    def explain_error(self, error, context):
        """
        Explain an error in non-technical terms
        
        Args:
            error: Exception or error message
            context: Where/when the error occurred
        """
        # Error translation for non-coders
        error_explanations = {
            'AttributeError': "Tried to access data that doesn't exist",
            'KeyError': "Tried to find something that's not in the data",
            'TypeError': "Data is in wrong format",
            'ValueError': "Data contains invalid values",
            'ConnectionError': "Can't connect to external service",
            'TimeoutError': "Operation took too long",
            'APIError': "External service returned an error",
            'ValidationError': "Data didn't pass security checks"
        }
        
        error_type = type(error).__name__ if hasattr(error, '__name__') else str(type(error).__name__)
        explanation = error_explanations.get(error_type, "Unexpected error occurred")
        
        print(f"\n{'!'*80}")
        print(f"[ERROR] {context}")
        print(f"  What happened: {explanation}")
        print(f"  Technical details: {str(error)}")
        print(f"  What this means: This operation cannot complete successfully")
        print(f"  Impact: The alert may not be analyzed properly")
        print(f"{'!'*80}\n")
        
        # Log detailed error
        self.monitor.log_error(
            error_type,
            str(error),
            context={
                'explanation': explanation,
                'location': context
            },
            severity='CRITICAL' if 'API' in error_type else 'ERROR'
        )

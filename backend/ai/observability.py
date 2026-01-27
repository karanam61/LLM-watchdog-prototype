"""
Observability Module - Audit Logging, Health Checks, Metrics & Feedback
========================================================================

FEATURES IMPLEMENTED:
1. Audit Logging - Complete trail of all AI decisions and actions
2. Health Checks - System status monitoring and diagnostics
3. Metrics Collection - Performance statistics and tracking
4. Feedback Mechanism - Analyst corrections for model improvement

WHY THIS EXISTS:
- Audit trails required for compliance and incident investigation
- Health checks detect failures before they impact operations
- Metrics track system performance and identify bottlenecks
- Feedback enables continuous improvement from analyst expertise

ARCHITECTURE:
    Alert Processing -> Log Decision -> Collect Metrics -> Return
                            [*]               [*]
                      Audit Trail    Performance DB
                            [*]               [*]
                    Compliance/     Dashboards/
                    Investigation      Alerts

Author: AI-SOC Watchdog System
"""

import os
import json
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Comprehensive audit logging for AI decisions.
    
    Feature 1: Logs every AI analysis with full context for:
    - Compliance requirements (SOC 2, ISO 27001)
    - Incident investigation and forensics
    - Model debugging and improvement
    - Accountability and transparency
    
    Logs include:
    - Alert details (anonymized/tokenized)
    - AI verdict and confidence
    - Evidence and reasoning
    - Timestamp and unique ID
    - User feedback (if provided)
    
    Usage:
        audit = AuditLogger()
        audit.log_analysis(alert, ai_response, metadata)
        audit.log_feedback(alert_id, analyst_verdict, notes)
    """
    
    def __init__(self, log_dir: Optional[str] = None):
        """
        Initialize audit logger.
        
        Args:
            log_dir: Directory for audit logs (default: backend/logs/audit/)
        """
        logger.info("[*] Initializing Audit Logger")
        
        # Default log directory
        if log_dir is None:
            backend_dir = Path(__file__).parent.parent
            log_dir = os.path.join(str(backend_dir), "logs", "audit")
        
        self.log_dir = log_dir
        
        # Create directory if doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.stats = {
            'total_logs': 0,
            'analysis_logs': 0,
            'feedback_logs': 0,
            'error_logs': 0
        }
        
        logger.info(f"[OK] Audit Logger ready - Dir: {self.log_dir}")
    
    def log_analysis(
        self,
        alert: Dict[str, Any],
        ai_response: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log AI analysis decision.
        
        Args:
            alert: Original alert (tokenized)
            ai_response: AI analysis result
            metadata: Optional metadata (processing time, model version, etc)
            
        Returns:
            Log entry ID
        """
        logger.info("[*] Logging AI analysis...")
        
        # Generate unique ID
        timestamp = datetime.utcnow()
        log_id = f"analysis_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}"
        
        # Build audit entry
        audit_entry = {
            'log_id': log_id,
            'timestamp': timestamp.isoformat(),
            'log_type': 'ai_analysis',
            'alert': {
                'alert_id': alert.get('alert_id', 'unknown'),
                'alert_name': alert.get('alert_name'),
                'mitre_technique': alert.get('mitre_technique'),
                'severity': alert.get('severity'),
                'source_ip': alert.get('source_ip'),  # Tokenized
                'dest_ip': alert.get('dest_ip'),      # Tokenized
                'hostname': alert.get('hostname'),    # Tokenized
                'username': alert.get('username'),    # Tokenized
                'description': alert.get('description', '')[:500],  # Truncate
                'risk_score': alert.get('risk_score')
            },
            'ai_response': {
                'verdict': ai_response.get('verdict'),
                'confidence': ai_response.get('confidence'),
                'evidence': ai_response.get('evidence', []),
                'reasoning': ai_response.get('reasoning', '')[:1000],  # Truncate
                'recommendation': ai_response.get('recommendation', '')[:500],
                'priority_score': ai_response.get('priority_score')
            },
            'metadata': metadata or {},
            'feedback': None  # Placeholder for future feedback
        }
        
        # Write to file
        log_file = os.path.join(
            self.log_dir,
            f"{timestamp.strftime('%Y%m%d')}_audit.jsonl"
        )
        
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(audit_entry) + '\n')
            
            self.stats['total_logs'] += 1
            self.stats['analysis_logs'] += 1
            
            logger.info(f"[OK] Logged analysis: {log_id}")
            return log_id
        
        except Exception as e:
            self.stats['error_logs'] += 1
            logger.error(f"[ERROR] Failed to write audit log: {e}")
            return log_id
    
    def log_feedback(
        self,
        alert_id: str,
        analyst_verdict: str,
        analyst_notes: Optional[str] = None,
        ai_was_correct: bool = None
    ) -> str:
        """
        Log analyst feedback on AI decision.
        
        Args:
            alert_id: Alert ID from original analysis
            analyst_verdict: Analyst's final verdict
            analyst_notes: Analyst's reasoning/notes
            ai_was_correct: Whether AI verdict matched analyst
            
        Returns:
            Log entry ID
        """
        logger.info("[*] Logging analyst feedback...")
        
        timestamp = datetime.utcnow()
        log_id = f"feedback_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}"
        
        feedback_entry = {
            'log_id': log_id,
            'timestamp': timestamp.isoformat(),
            'log_type': 'analyst_feedback',
            'alert_id': alert_id,
            'analyst_verdict': analyst_verdict,
            'analyst_notes': analyst_notes,
            'ai_was_correct': ai_was_correct
        }
        
        log_file = os.path.join(
            self.log_dir,
            f"{timestamp.strftime('%Y%m%d')}_feedback.jsonl"
        )
        
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(feedback_entry) + '\n')
            
            self.stats['total_logs'] += 1
            self.stats['feedback_logs'] += 1
            
            logger.info(f"[OK] Logged feedback: {log_id}")
            return log_id
        
        except Exception as e:
            self.stats['error_logs'] += 1
            logger.error(f"[ERROR] Failed to write feedback log: {e}")
            return log_id
    
    def get_stats(self) -> Dict[str, int]:
        """Get audit logging statistics."""
        return self.stats.copy()


class HealthMonitor:
    """
    System health monitoring and diagnostics.
    
    Feature 2: Tracks system health indicators:
    - API connectivity (Anthropic, Supabase)
    - Database performance (query times)
    - Queue status (backlogs)
    - Error rates (failures)
    - Resource usage (memory, CPU)
    
    Provides:
    - Real-time health status
    - Diagnostic information
    - Alert thresholds
    - Historical trends
    
    Usage:
        health = HealthMonitor()
        status = health.check_health()
        health.record_api_call(success=True, latency=1.2)
    """
    
    def __init__(self):
        """Initialize health monitor."""
        logger.info("[*] Initializing Health Monitor")
        
        self.health_data = {
            'api_calls': {
                'total': 0,
                'successful': 0,
                'failed': 0,
                'avg_latency': 0.0,
                'total_latency': 0.0
            },
            'database': {
                'queries': 0,
                'failures': 0,
                'avg_query_time': 0.0,
                'total_query_time': 0.0
            },
            'alerts_processed': 0,
            'errors': [],
            'last_check': None
        }
        
        # Health thresholds
        self.thresholds = {
            'api_error_rate': 0.1,      # 10% max
            'db_error_rate': 0.05,       # 5% max
            'api_latency': 5.0,          # 5 seconds max
            'db_query_time': 1.0         # 1 second max
        }
        
        logger.info("[OK] Health Monitor ready")
    
    def check_health(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check.
        
        Returns:
            Dictionary with health status and diagnostics
        """
        logger.info("[CHECK] Checking system health...")
        
        self.health_data['last_check'] = datetime.utcnow().isoformat()
        
        # Calculate metrics
        api_calls = self.health_data['api_calls']
        db_data = self.health_data['database']
        
        api_error_rate = (
            api_calls['failed'] / api_calls['total']
            if api_calls['total'] > 0 else 0
        )
        
        db_error_rate = (
            db_data['failures'] / db_data['queries']
            if db_data['queries'] > 0 else 0
        )
        
        api_avg_latency = (
            api_calls['total_latency'] / api_calls['total']
            if api_calls['total'] > 0 else 0
        )
        
        db_avg_query_time = (
            db_data['total_query_time'] / db_data['queries']
            if db_data['queries'] > 0 else 0
        )
        
        # Determine overall status
        issues = []
        
        if api_error_rate > self.thresholds['api_error_rate']:
            issues.append(f"High API error rate: {api_error_rate:.1%}")
        
        if db_error_rate > self.thresholds['db_error_rate']:
            issues.append(f"High DB error rate: {db_error_rate:.1%}")
        
        if api_avg_latency > self.thresholds['api_latency']:
            issues.append(f"High API latency: {api_avg_latency:.2f}s")
        
        if db_avg_query_time > self.thresholds['db_query_time']:
            issues.append(f"Slow DB queries: {db_avg_query_time:.2f}s")
        
        # Overall status
        if not issues:
            status = "healthy"
            status_emoji = "[OK]"
        elif len(issues) == 1:
            status = "degraded"
            status_emoji = "[WARNING] "
        else:
            status = "unhealthy"
            status_emoji = "[ERROR]"
        
        health_report = {
            'status': status,
            'timestamp': self.health_data['last_check'],
            'metrics': {
                'api': {
                    'total_calls': api_calls['total'],
                    'success_rate': (
                        api_calls['successful'] / api_calls['total']
                        if api_calls['total'] > 0 else 1.0
                    ),
                    'error_rate': api_error_rate,
                    'avg_latency': api_avg_latency
                },
                'database': {
                    'total_queries': db_data['queries'],
                    'success_rate': (
                        (db_data['queries'] - db_data['failures']) / db_data['queries']
                        if db_data['queries'] > 0 else 1.0
                    ),
                    'error_rate': db_error_rate,
                    'avg_query_time': db_avg_query_time
                },
                'alerts_processed': self.health_data['alerts_processed']
            },
            'issues': issues,
            'recent_errors': self.health_data['errors'][-5:]  # Last 5 errors
        }
        
        logger.info(f"{status_emoji} System status: {status}")
        if issues:
            for issue in issues:
                logger.warning(f"  [WARNING]  {issue}")
        
        return health_report
    
    def record_api_call(self, success: bool, latency: float):
        """Record API call metrics."""
        api_calls = self.health_data['api_calls']
        api_calls['total'] += 1
        api_calls['total_latency'] += latency
        
        if success:
            api_calls['successful'] += 1
        else:
            api_calls['failed'] += 1
            self._record_error('api_failure', f"API call failed after {latency:.2f}s")
    
    def record_db_query(self, success: bool, query_time: float):
        """Record database query metrics."""
        db_data = self.health_data['database']
        db_data['queries'] += 1
        db_data['total_query_time'] += query_time
        
        if not success:
            db_data['failures'] += 1
            self._record_error('db_failure', f"DB query failed after {query_time:.2f}s")
    
    def record_alert_processed(self):
        """Increment alerts processed counter."""
        self.health_data['alerts_processed'] += 1
    
    def _record_error(self, error_type: str, message: str):
        """Record error for health monitoring."""
        self.health_data['errors'].append({
            'timestamp': datetime.utcnow().isoformat(),
            'type': error_type,
            'message': message
        })
        
        # Keep only last 100 errors
        if len(self.health_data['errors']) > 100:
            self.health_data['errors'] = self.health_data['errors'][-100:]
    
    def reset_metrics(self):
        """Reset health metrics (for testing or daily resets)."""
        self.health_data['api_calls'] = {
            'total': 0, 'successful': 0, 'failed': 0,
            'avg_latency': 0.0, 'total_latency': 0.0
        }
        self.health_data['database'] = {
            'queries': 0, 'failures': 0,
            'avg_query_time': 0.0, 'total_query_time': 0.0
        }
        self.health_data['alerts_processed'] = 0
        self.health_data['errors'] = []
        logger.info("[OK] Health metrics reset")


class MetricsCollector:
    """
    Performance metrics collection and tracking.
    
    Feature 3: Collects comprehensive performance metrics:
    - Processing times (per alert, per queue)
    - Throughput (alerts/hour, analyses/minute)
    - Accuracy (AI vs analyst agreement)
    - Cost (tokens used, dollars spent)
    - Queue performance (wait times, backlogs)
    
    Provides:
    - Real-time dashboards
    - Historical trends
    - Performance baselines
    - Anomaly detection
    
    Usage:
        metrics = MetricsCollector()
        metrics.record_processing_time(alert_id, duration)
        metrics.record_accuracy(ai_verdict, analyst_verdict)
        stats = metrics.get_metrics()
    """
    
    def __init__(self):
        """Initialize metrics collector."""
        logger.info("[STATS] Initializing Metrics Collector")
        
        self.metrics = {
            'processing': {
                'total_alerts': 0,
                'total_processing_time': 0.0,
                'avg_processing_time': 0.0,
                'min_processing_time': float('inf'),
                'max_processing_time': 0.0
            },
            'accuracy': {
                'ai_decisions': 0,
                'analyst_feedback': 0,
                'agreements': 0,
                'disagreements': 0,
                'accuracy_rate': 0.0
            },
            'cost': {
                'total_input_tokens': 0,
                'total_output_tokens': 0,
                'total_cost': 0.0
            },
            'throughput': {
                'start_time': time.time(),
                'alerts_per_hour': 0.0
            },
            'queue': {
                'priority_processed': 0,
                'standard_processed': 0,
                'avg_wait_time': 0.0
            }
        }
        
        logger.info("[OK] Metrics Collector ready")
    
    def record_processing_time(self, alert_id: str, duration: float, queue_type: str = None):
        """
        Record alert processing time.
        
        Args:
            alert_id: Alert identifier
            duration: Processing time in seconds
            queue_type: 'priority' or 'standard'
        """
        proc = self.metrics['processing']
        proc['total_alerts'] += 1
        proc['total_processing_time'] += duration
        proc['avg_processing_time'] = proc['total_processing_time'] / proc['total_alerts']
        proc['min_processing_time'] = min(proc['min_processing_time'], duration)
        proc['max_processing_time'] = max(proc['max_processing_time'], duration)
        
        # Update queue metrics
        if queue_type:
            queue_key = f"{queue_type}_processed"
            self.metrics['queue'][queue_key] = self.metrics['queue'].get(queue_key, 0) + 1
        
        # Update throughput
        elapsed_hours = (time.time() - self.metrics['throughput']['start_time']) / 3600
        if elapsed_hours > 0:
            self.metrics['throughput']['alerts_per_hour'] = proc['total_alerts'] / elapsed_hours
        
        logger.info(f"[STATS] Recorded: {alert_id} in {duration:.2f}s")
    
    def record_accuracy(self, ai_verdict: str, analyst_verdict: str):
        """
        Record accuracy comparison between AI and analyst.
        
        Args:
            ai_verdict: AI's verdict (malicious/benign/suspicious)
            analyst_verdict: Analyst's final verdict
        """
        acc = self.metrics['accuracy']
        acc['ai_decisions'] += 1
        acc['analyst_feedback'] += 1
        
        if ai_verdict == analyst_verdict:
            acc['agreements'] += 1
            logger.info(f"[OK] Agreement: AI={ai_verdict}, Analyst={analyst_verdict}")
        else:
            acc['disagreements'] += 1
            logger.warning(f"[WARNING]  Disagreement: AI={ai_verdict}, Analyst={analyst_verdict}")
        
        # Calculate accuracy rate
        if acc['analyst_feedback'] > 0:
            acc['accuracy_rate'] = acc['agreements'] / acc['analyst_feedback']
    
    def record_cost(self, input_tokens: int, output_tokens: int, cost: float):
        """
        Record token usage and cost.
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            cost: Cost in dollars
        """
        cost_data = self.metrics['cost']
        cost_data['total_input_tokens'] += input_tokens
        cost_data['total_output_tokens'] += output_tokens
        cost_data['total_cost'] += cost
        
        logger.info(f"[*] Cost: {input_tokens}+{output_tokens} tokens = ${cost:.6f}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary."""
        return {
            'processing': self.metrics['processing'].copy(),
            'accuracy': self.metrics['accuracy'].copy(),
            'cost': self.metrics['cost'].copy(),
            'throughput': self.metrics['throughput'].copy(),
            'queue': self.metrics['queue'].copy(),
            'summary': {
                'total_alerts': self.metrics['processing']['total_alerts'],
                'avg_time': self.metrics['processing']['avg_processing_time'],
                'accuracy': self.metrics['accuracy']['accuracy_rate'],
                'total_cost': self.metrics['cost']['total_cost'],
                'alerts_per_hour': self.metrics['throughput']['alerts_per_hour']
            }
        }
    
    def reset_metrics(self):
        """Reset all metrics (for testing or daily resets)."""
        self.metrics['processing'] = {
            'total_alerts': 0, 'total_processing_time': 0.0,
            'avg_processing_time': 0.0,
            'min_processing_time': float('inf'), 'max_processing_time': 0.0
        }
        self.metrics['accuracy'] = {
            'ai_decisions': 0, 'analyst_feedback': 0,
            'agreements': 0, 'disagreements': 0, 'accuracy_rate': 0.0
        }
        self.metrics['cost'] = {
            'total_input_tokens': 0, 'total_output_tokens': 0, 'total_cost': 0.0
        }
        self.metrics['throughput'] = {
            'start_time': time.time(), 'alerts_per_hour': 0.0
        }
        self.metrics['queue'] = {
            'priority_processed': 0, 'standard_processed': 0, 'avg_wait_time': 0.0
        }
        logger.info("[OK] Metrics reset")


class FeedbackCollector:
    """
    Analyst feedback collection for continuous improvement.
    
    Feature 4: Collects analyst corrections and feedback:
    - Verdict corrections (malicious -> benign)
    - Reasoning improvements
    - False positive patterns
    - New attack indicators
    - System suggestions
    
    Enables:
    - Model fine-tuning
    - Detection rule improvements
    - Baseline updates
    - Continuous learning
    
    Usage:
        feedback = FeedbackCollector()
        feedback.record_correction(alert_id, ai_verdict, analyst_verdict, notes)
        patterns = feedback.get_false_positive_patterns()
    """
    
    def __init__(self, feedback_file: Optional[str] = None):
        """
        Initialize feedback collector.
        
        Args:
            feedback_file: Path to feedback storage file
        """
        logger.info("[*] Initializing Feedback Collector")
        
        # Default feedback file
        if feedback_file is None:
            backend_dir = Path(__file__).parent.parent
            feedback_file = os.path.join(str(backend_dir), "logs", "feedback.jsonl")
        
        self.feedback_file = feedback_file
        
        # Create directory if doesn't exist
        os.makedirs(os.path.dirname(feedback_file), exist_ok=True)
        
        self.feedback_data = []
        
        self.stats = {
            'total_feedback': 0,
            'corrections': 0,
            'confirmations': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
        
        logger.info(f"[OK] Feedback Collector ready - File: {self.feedback_file}")
    
    def record_correction(
        self,
        alert_id: str,
        ai_verdict: str,
        analyst_verdict: str,
        analyst_notes: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Record analyst correction of AI decision.
        
        Args:
            alert_id: Alert identifier
            ai_verdict: AI's original verdict
            analyst_verdict: Analyst's corrected verdict
            analyst_notes: Analyst's explanation
            alert_context: Optional alert details for pattern analysis
            
        Returns:
            Feedback entry ID
        """
        logger.info("[*] Recording analyst feedback...")
        
        timestamp = datetime.utcnow()
        feedback_id = f"feedback_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}"
        
        # Determine feedback type
        if ai_verdict == analyst_verdict:
            feedback_type = 'confirmation'
            self.stats['confirmations'] += 1
            logger.info(f"[OK] Confirmation: {ai_verdict}")
        else:
            feedback_type = 'correction'
            self.stats['corrections'] += 1
            logger.warning(f"[WARNING]  Correction: {ai_verdict} -> {analyst_verdict}")
            
            # Track false positives/negatives
            if ai_verdict == 'malicious' and analyst_verdict == 'benign':
                self.stats['false_positives'] += 1
            elif ai_verdict == 'benign' and analyst_verdict == 'malicious':
                self.stats['false_negatives'] += 1
        
        feedback_entry = {
            'feedback_id': feedback_id,
            'timestamp': timestamp.isoformat(),
            'alert_id': alert_id,
            'feedback_type': feedback_type,
            'ai_verdict': ai_verdict,
            'analyst_verdict': analyst_verdict,
            'analyst_notes': analyst_notes,
            'alert_context': alert_context or {}
        }
        
        # Save to memory
        self.feedback_data.append(feedback_entry)
        
        # Save to file
        try:
            with open(self.feedback_file, 'a') as f:
                f.write(json.dumps(feedback_entry) + '\n')
            
            self.stats['total_feedback'] += 1
            logger.info(f"[OK] Recorded feedback: {feedback_id}")
            return feedback_id
        
        except Exception as e:
            logger.error(f"[ERROR] Failed to write feedback: {e}")
            return feedback_id
    
    def get_false_positive_patterns(self) -> List[Dict[str, Any]]:
        """
        Analyze false positive patterns for model improvement.
        
        Returns:
            List of false positive patterns with frequency
        """
        logger.info("[CHECK] Analyzing false positive patterns...")
        
        false_positives = [
            fb for fb in self.feedback_data
            if fb['ai_verdict'] == 'malicious' and fb['analyst_verdict'] == 'benign'
        ]
        
        if not false_positives:
            logger.info("No false positives found")
            return []
        
        # Group by alert name
        patterns = {}
        for fp in false_positives:
            alert_name = fp.get('alert_context', {}).get('alert_name', 'Unknown')
            if alert_name not in patterns:
                patterns[alert_name] = {
                    'alert_name': alert_name,
                    'count': 0,
                    'examples': []
                }
            patterns[alert_name]['count'] += 1
            patterns[alert_name]['examples'].append({
                'alert_id': fp['alert_id'],
                'notes': fp['analyst_notes']
            })
        
        # Sort by frequency
        sorted_patterns = sorted(
            patterns.values(),
            key=lambda x: x['count'],
            reverse=True
        )
        
        logger.info(f"Found {len(sorted_patterns)} false positive patterns")
        return sorted_patterns
    
    def get_stats(self) -> Dict[str, Any]:
        """Get feedback statistics."""
        return {
            'total_feedback': self.stats['total_feedback'],
            'corrections': self.stats['corrections'],
            'confirmations': self.stats['confirmations'],
            'false_positives': self.stats['false_positives'],
            'false_negatives': self.stats['false_negatives'],
            'correction_rate': (
                self.stats['corrections'] / self.stats['total_feedback']
                if self.stats['total_feedback'] > 0 else 0
            )
        }


# =============================================================================
# UNIFIED OBSERVABILITY CLASS
# =============================================================================

class ObservabilitySystem:
    """
    Unified observability system combining all 4 features.
    
    Provides complete visibility into:
    - What happened (audit logs)
    - How healthy is the system (health checks)
    - How well is it performing (metrics)
    - How accurate is the AI (feedback)
    
    Usage:
        obs = ObservabilitySystem()
        
        # Log AI decision
        obs.log_analysis(alert, ai_response)
        
        # Record metrics
        obs.record_processing(alert_id, duration)
        
        # Get health status
        health = obs.check_health()
        
        # Record analyst feedback
        obs.record_feedback(alert_id, ai_verdict, analyst_verdict)
    """
    
    def __init__(self):
        """Initialize unified observability system."""
        logger.info("[*] Initializing Observability System")
        
        self.audit = AuditLogger()
        self.health = HealthMonitor()
        self.metrics = MetricsCollector()
        self.feedback = FeedbackCollector()
        
        logger.info("[OK] Observability System ready")
    
    def log_analysis(
        self,
        alert: Dict[str, Any],
        ai_response: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log AI analysis (Feature 1)."""
        return self.audit.log_analysis(alert, ai_response, metadata)
    
    def check_health(self) -> Dict[str, Any]:
        """Check system health (Feature 2)."""
        return self.health.check_health()
    
    def record_processing(
        self,
        alert_id: str,
        duration: float,
        queue_type: str = None
    ):
        """Record processing metrics (Feature 3)."""
        self.metrics.record_processing_time(alert_id, duration, queue_type)
    
    def record_feedback(
        self,
        alert_id: str,
        ai_verdict: str,
        analyst_verdict: str,
        analyst_notes: Optional[str] = None
    ) -> str:
        """Record analyst feedback (Feature 4)."""
        # Record in feedback collector
        feedback_id = self.feedback.record_correction(
            alert_id, ai_verdict, analyst_verdict, analyst_notes
        )
        
        # Record in audit logger
        self.audit.log_feedback(alert_id, analyst_verdict, analyst_notes)
        
        # Record accuracy in metrics
        self.metrics.record_accuracy(ai_verdict, analyst_verdict)
        
        return feedback_id
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Get comprehensive observability report."""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'audit': self.audit.get_stats(),
            'health': self.health.check_health(),
            'metrics': self.metrics.get_metrics(),
            'feedback': self.feedback.get_stats()
        }


# =============================================================================
# TEST CODE
# =============================================================================

if __name__ == "__main__":
    """Test observability features."""
    
    print("=" * 70)
    print("OBSERVABILITY MODULE TEST")
    print("=" * 70)
    
    obs = ObservabilitySystem()
    
    # Test 1: Audit logging
    print("\n[TEST 1] Audit Logging")
    print("-" * 70)
    
    test_alert = {
        'alert_id': 'alert_001',
        'alert_name': 'PowerShell Execution',
        'mitre_technique': 'T1059.001',
        'severity': 'critical',
        'source_ip': 'IP-test123',
        'dest_ip': 'IP-test456',
        'hostname': 'HOST-server1',
        'username': 'USER-admin',
        'description': 'Suspicious PowerShell activity detected',
        'risk_score': 95.0
    }
    
    test_response = {
        'verdict': 'malicious',
        'confidence': 0.92,
        'evidence': ['Encoded command', 'Unusual parent process'],
        'reasoning': 'PowerShell spawned from Word with encoded commands',
        'recommendation': 'Isolate host and investigate'
    }
    
    log_id = obs.log_analysis(test_alert, test_response, {'model': 'claude-sonnet-4'})
    print(f"[OK] Logged analysis: {log_id}")
    
    # Test 2: Health monitoring
    print("\n[TEST 2] Health Monitoring")
    print("-" * 70)
    
    # Simulate some API calls
    obs.health.record_api_call(success=True, latency=1.2)
    obs.health.record_api_call(success=True, latency=0.8)
    obs.health.record_api_call(success=False, latency=5.5)
    
    # Simulate DB queries
    obs.health.record_db_query(success=True, query_time=0.15)
    obs.health.record_db_query(success=True, query_time=0.22)
    
    health_report = obs.check_health()
    print(f"Status: {health_report['status']}")
    print(f"API success rate: {health_report['metrics']['api']['success_rate']:.1%}")
    print(f"Issues: {health_report['issues'] if health_report['issues'] else 'None'}")
    
    # Test 3: Metrics collection
    print("\n[TEST 3] Metrics Collection")
    print("-" * 70)
    
    # Simulate alert processing
    obs.record_processing('alert_001', duration=2.3, queue_type='priority')
    obs.record_processing('alert_002', duration=1.8, queue_type='priority')
    obs.record_processing('alert_003', duration=3.1, queue_type='standard')
    
    # Record costs
    obs.metrics.record_cost(input_tokens=1500, output_tokens=800, cost=0.0195)
    
    metrics = obs.metrics.get_metrics()
    print(f"Alerts processed: {metrics['summary']['total_alerts']}")
    print(f"Avg processing time: {metrics['summary']['avg_time']:.2f}s")
    print(f"Total cost: ${metrics['summary']['total_cost']:.4f}")
    
    # Test 4: Feedback collection
    print("\n[TEST 4] Feedback Collection")
    print("-" * 70)
    
    # Correct AI decision
    obs.record_feedback('alert_001', 'malicious', 'malicious', 'AI was correct')
    
    # Incorrect AI decision (false positive)
    obs.record_feedback('alert_002', 'malicious', 'benign', 'False positive - legitimate admin script')
    
    # Another false positive
    obs.record_feedback('alert_003', 'malicious', 'benign', 'Another FP - authorized maintenance')
    
    feedback_stats = obs.feedback.get_stats()
    print(f"Total feedback: {feedback_stats['total_feedback']}")
    print(f"Corrections: {feedback_stats['corrections']}")
    print(f"False positives: {feedback_stats['false_positives']}")
    print(f"Correction rate: {feedback_stats['correction_rate']:.1%}")
    
    # Comprehensive report
    print("\n" + "=" * 70)
    print("COMPREHENSIVE REPORT:")
    print("=" * 70)
    
    report = obs.get_comprehensive_report()
    print(f"\nAudit logs: {report['audit']['analysis_logs']} analyses, {report['audit']['feedback_logs']} feedback")
    print(f"Health: {report['health']['status']}")
    print(f"Metrics: {report['metrics']['summary']['total_alerts']} alerts processed")
    print(f"Feedback: {report['feedback']['total_feedback']} entries")
    
    print("\n" + "=" * 70)
    print("[OK] OBSERVABILITY TEST COMPLETE")
    print("=" * 70)
    
    print("\nFeatures Implemented:")
    print("  1. [OK] Audit logging (analysis + feedback)")
    print("  2. [OK] Health monitoring (API + DB)")
    print("  3. [OK] Metrics collection (performance + cost)")
    print("  4. [OK] Feedback system (corrections + patterns)")

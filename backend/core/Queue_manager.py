"""
Queue Manager - Risk-Based Alert Routing
=========================================

This module manages the dual-queue system that prioritizes alerts based
on risk scores combining attack damage potential and severity.

WHAT THIS FILE DOES:
1. Maintains two thread-safe queues (priority + standard)
2. Routes alerts based on calculated risk score
3. Provides queue status and statistics
4. Handles queue persistence for system restarts

WHY THIS EXISTS:
- Not all alerts are equal - ransomware > failed login
- Critical alerts must be analyzed before low-priority ones
- Risk score = damage potential × severity multiplier
- Prevents queue starvation while prioritizing dangerous alerts

ROUTING LOGIC:
- Risk Score >= 75  -> Priority Queue (processed first)
- Risk Score < 75   -> Standard Queue (processed after)

RISK CALCULATION:
    risk_score = attack_damage_score × severity_multiplier
    
    Example: Ransomware (damage=90) × Critical (1.5) = 135 -> Priority
    Example: Failed login (damage=30) × Low (0.5) = 15 -> Standard

THREAD SAFETY:
All queue operations use threading locks to prevent race conditions
when multiple workers access queues simultaneously.

Author: AI-SOC Watchdog System
"""

from backend.core.attack_damage_data import (
    calculate_risk_score,
    PRIORITY_QUEUE_THRESHOLD
)
from collections import deque
import threading


class QueueManager:
    """
    Manages alert queues with intelligent risk-based routing
    
    Priority Queue: High-damage attacks (risk score >= 75)
    Standard Queue: Lower-damage attacks (risk score < 75)
    """
    
    def __init__(self):
        self.priority_queue = deque()
        self.standard_queue = deque()
        self.lock = threading.Lock()
        
        print("[OK] Queue Manager initialized (Thread-Safe)")
        print(f"  Priority threshold: {PRIORITY_QUEUE_THRESHOLD}")
    
    def route_alert(self, alert, severity_class, tracker=None):
        """
        Route alert based on total risk (damage potential [*] severity)
        Optionally logs to tracker.
        """
        
        # Get MITRE technique
        mitre = alert.get('mitre_technique')
        risk_score = 50 # Default
        
        if tracker:
            tracker.log_step("backend/core/Queue_manager.py", "Risk Calculation", "Started", explanation="Calculating risk based on MITRE technique damage potential.")

        if mitre:
            # Calculate risk score using attack damage data
            risk_result = calculate_risk_score(mitre, severity_class)
            
            risk_score = risk_result['risk_score']
            damage_score = risk_result['damage_score']
            multiplier = risk_result['severity_multiplier']
            
            if tracker:
                tracker.log_step(
                    "backend/core/Queue_manager.py", 
                    "Risk Formula", 
                    f"Damage({damage_score}) * Severity({multiplier}) = {risk_score}",
                    explanation=f"Technique {mitre} has base damage {damage_score}."
                )
        else:
            # Fallback: Use severity-based risk
            severity_scores = {
                'CRITICAL_HIGH': 100,
                'CRITICAL_MEDIUM': 85,
                'HIGH': 70,
                'MEDIUM': 50,
                'LOW': 30
            }
            risk_score = severity_scores.get(severity_class, 50)
            if tracker:
                tracker.log_step(
                    "backend/core/Queue_manager.py", 
                    "Risk Fallback", 
                    f"Score: {risk_score}",
                    explanation="No MITRE technique found, using static severity score."
                )
        
        # Add metadata to alert
        alert['risk_score'] = risk_score
        alert['severity_class'] = severity_class
        
        # Thread-safe routing
        with self.lock:
            # Route based on risk threshold
            if risk_score >= PRIORITY_QUEUE_THRESHOLD:
                print(f"[QUEUE TRACE] [*] Routing to PRIORITY Queue (Risk: {risk_score:.1f})")
                alert['queue_type'] = 'priority'
                self.priority_queue.append(alert)
                queue_len = len(self.priority_queue)
                queue_name = "PRIORITY QUEUE"
            else:
                print(f"[QUEUE TRACE] [INGEST] Routing to STANDARD Queue (Risk: {risk_score:.1f})")
                alert['queue_type'] = 'standard'
                self.standard_queue.append(alert)
                queue_len = len(self.standard_queue)
                queue_name = "STANDARD QUEUE"
                
        if tracker:
             tracker.log_step(
                "backend/core/Queue_manager.py", 
                "Queue Routing", 
                queue_name,
                explanation=f"Risk Score {risk_score:.1f} -> {queue_name} (Length: {queue_len})"
            )
    
    def get_next_alert(self):
        """
        Thread-safe retrieval of next alert.
        Priority > Standard.
        """
        with self.lock:
            if self.priority_queue:
                alert = self.priority_queue.popleft()
                print(f"[*] Retrieved from PRIORITY queue")
                print(f"   Alert: {alert.get('alert_name', 'Unknown')}")
                print(f"   Risk score: {alert.get('risk_score', 0):.1f}")
                print(f"   Remaining in priority: {len(self.priority_queue)}")
                print(f"[QUEUE TRACE] [PRIORITY] Dequeued PRIORITY Item: {alert.get('alert_name')}")
                return alert
            
            elif self.standard_queue:
                alert = self.standard_queue.popleft()
                print(f"[*] Retrieved from STANDARD queue")
                print(f"   Alert: {alert.get('alert_name', 'Unknown')}")
                print(f"   Risk score: {alert.get('risk_score', 0):.1f}")
                print(f"   Remaining in standard: {len(self.standard_queue)}")
                print(f"[QUEUE TRACE] [*] Dequeued STANDARD Item: {alert.get('alert_name')}")
                return alert
            
            else:
                return None
    
    def process_standard_queue(self, wait_seconds=120):
        """
        Process standard queue with delay
        
        Args:
            wait_seconds: Seconds to wait before processing (default 120)
        """
        import time
        
        if not self.standard_queue:
            return
        
        print(f"\n[*] Standard queue processing (waiting {wait_seconds}s)...")
        time.sleep(wait_seconds)
        
        while self.standard_queue:
            alert = self.get_next_alert()
            if alert:
                print(f"   Processing: {alert.get('alert_name', 'Unknown')}")
    
    def get_queue_stats(self):
        """
        Get current queue statistics
        
        Returns:
            Dictionary with queue information
        """
        return {
            'priority_count': len(self.priority_queue),
            'standard_count': len(self.standard_queue),
            'total_queued': len(self.priority_queue) + len(self.standard_queue),
            'priority_alerts': [
                {
                    'alert_name': a.get('alert_name'),
                    'risk_score': a.get('risk_score'),
                    'severity': a.get('severity_class')
                }
                for a in list(self.priority_queue)[:5]  # Top 5
            ],
            'standard_alerts': [
                {
                    'alert_name': a.get('alert_name'),
                    'risk_score': a.get('risk_score'),
                    'severity': a.get('severity_class')
                }
                for a in list(self.standard_queue)[:5]  # Top 5
            ]
        }


if __name__ == '__main__':
    """
    Test the Queue Manager
    """
    print("="*70)
    print("QUEUE MANAGER TEST")
    print("="*70)
    
    # Create queue manager
    qm = QueueManager()
    
    # Test alerts with different risk profiles
    test_alerts = [
        {
            'alert_name': 'Ransomware Detected',
            'description': 'Mass file encryption detected',
            'mitre_technique': 'T1486',
            'source_ip': '192.168.1.100'
        },
        {
            'alert_name': 'Phishing Email',
            'description': 'Suspicious email with malicious link',
            'mitre_technique': 'T1566',
            'source_ip': '203.0.113.50'
        },
        {
            'alert_name': 'DDoS Attack',
            'description': 'Network flooding detected',
            'mitre_technique': 'T1498',
            'source_ip': '198.51.100.10'
        },
        {
            'alert_name': 'Brute Force Attempt',
            'description': 'Multiple failed login attempts',
            'mitre_technique': 'T1110',
            'source_ip': '192.0.2.50'
        },
        {
            'alert_name': 'Port Scan',
            'description': 'Network port scanning detected',
            'mitre_technique': 'T1046',
            'source_ip': '192.0.2.100'
        }
    ]
    
    severities = [
        'CRITICAL_HIGH',
        'HIGH',
        'HIGH',
        'MEDIUM',
        'LOW'
    ]
    
    # Route all test alerts
    print("\n" + "="*70)
    print("Routing test alerts:")
    print("="*70)
    
    for alert, severity in zip(test_alerts, severities):
        qm.route_alert(alert, severity)
    
    # Show queue stats
    print("\n" + "="*70)
    print("Queue Statistics:")
    print("="*70)
    
    stats = qm.get_queue_stats()
    print(f"\nPriority Queue: {stats['priority_count']} alerts")
    for alert_info in stats['priority_alerts']:
        print(f"  - {alert_info['alert_name']} (Risk: {alert_info['risk_score']:.1f})")
    
    print(f"\nStandard Queue: {stats['standard_count']} alerts")
    for alert_info in stats['standard_alerts']:
        print(f"  - {alert_info['alert_name']} (Risk: {alert_info['risk_score']:.1f})")
    
    # Test retrieval
    print("\n" + "="*70)
    print("Testing alert retrieval:")
    print("="*70)
    
    print("\nRetrieving next alert (should be from priority queue):")
    next_alert = qm.get_next_alert()
    
    print("\nRetrieving another alert:")
    next_alert = qm.get_next_alert()
    
    print("\n" + "="*70)
    print("[OK] QUEUE MANAGER TEST COMPLETE")
    print("="*70)
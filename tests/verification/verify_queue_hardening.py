import sys
import os
import threading
import time
from collections import deque
from pathlib import Path

# Add path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(PROJECT_ROOT))

from backend.core.Queue_manager import QueueManager, PRIORITY_QUEUE_THRESHOLD

def test_queue_hardening():
    print("Testing QueueManager Hardening...")
    
    qm = QueueManager()
    
    # 1. Verify Data Structure
    if isinstance(qm.priority_queue, deque):
        print("   Priority Queue is a deque (O(1) pops)")
    else:
        print(f"   Priority Queue is {type(qm.priority_queue)}")
        
    if isinstance(qm.standard_queue, deque):
        print("   Standard Queue is a deque")
    else:
        print(f"   Standard Queue is {type(qm.standard_queue)}")
        
    # 2. Verify Thread Safety (checking lock existence)
    if hasattr(qm, 'lock') and isinstance(qm.lock, type(threading.Lock())):
         print("   Thread Lock detected")
    else:
         print("   NO lock detected!")

    # 3. Functional Test
    print("   Testing Routing...")
    alert_high = {"alert_name": "Critical", "mitre_technique": "T1486"} # Ransomware presumably
    # We need to simulate severity_class since we can't easily mock calculate_risk_score entirely without proper setup, 
    # but route_alert calculates it.
    # T1486 is High impact.
    
    qm.route_alert(alert_high, "CRITICAL_HIGH")
    
    if len(qm.priority_queue) == 1:
        print("   Routed to Priority Queue")
    else:
        print("   Routing failed")
        
    # 3.5 Stats Test (Verify Slicing Fix)
    print("   Testing Stats (Slicing fix)...")
    try:
        stats = qm.get_queue_stats()
        print(f"   Stats generated: {stats['priority_count']} priority alerts")
    except Exception as e:
        print(f"   Stats failed: {e}")

    # 4. Retrieval Test
    retrieved = qm.get_next_alert()
    if retrieved and retrieved['alert_name'] == "Critical":
        print("   Retrieval Successful (popleft)")
    else:
        print("   Retrieval failed")

if __name__ == "__main__":
    test_queue_hardening()

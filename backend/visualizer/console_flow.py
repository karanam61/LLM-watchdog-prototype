"""
Console Flow Tracker - Visual Pipeline Progress Display
========================================================

This module provides real-time visual feedback of the alert processing
pipeline in the console/terminal.

WHAT THIS FILE DOES:
1. Displays processing steps with visual ASCII separators
2. Shows timing information for each phase
3. Logs all activity to logs/flow_debug.log
4. Makes pipeline flow visible for debugging

WHY THIS EXISTS:
- Helps developers see what's happening during processing
- Debugging complex multi-phase pipelines needs visibility
- Provides timing data for performance analysis
- Creates audit trail in log files

VISUAL OUTPUT EXAMPLE:
    ======================================================================
    [*] AI-SOC WATCHDOG - Alert Analysis Pipeline
    ======================================================================
    [STEP 1] Parsing alert...
    [STEP 2] Classifying severity...
    [STEP 3] Gathering forensic logs...
    ...

Author: AI-SOC Watchdog System
"""

import logging
import sys
import json
import time
from datetime import datetime
from pathlib import Path

# Setup logging
log_dir = Path(__file__).parent.parent.parent / "logs"
log_dir.mkdir(exist_ok=True)
log_file = log_dir / "flow_debug.log"

# Configure logger to write to file ONLY (we handle console print manually for visuals)
logging.basicConfig(
    filename=str(log_file),
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    filemode='w' # Overwrite for fresh run
)

class ConsoleFlowTracker:
    """
    Visualizes the flow of the AI-SOC Watchdog in real-time.
    """
    
    def __init__(self):
        self.step_count = 0
        self.start_time = time.time()
        print("\n" + "="*70)
        print("[START] AI-SOC WATCHDOG - FLOW TRACKER INITIALIZED")
        print("="*70 + "\n")
        logging.info("Visualizer Initialized")

    def log_step(self, file_name, function, purpose, explanation=None, input_data=None, objects_created=None, timing_ms=None):
        """
        Log a step in the process.
        """
        self.step_count += 1
        
        # 1. VISUAL OUTPUT (For Console)
        print(f"\n+-- [OK] STEP {self.step_count}: {function} ------------------------")
        print(f"| File:    {file_name}")
        print(f"| Purpose: {purpose}")
        if explanation:
            print(f"| [INFO] Note:  {explanation}")
        
        if input_data:
            print("| [INPUT] Input:")
            # Trucate long inputs
            s = json.dumps(input_data, default=str)
            if len(s) > 100: s = s[:100] + "..."
            print(f"|   {s}")
            
        if objects_created:
            print("| [OBJECTS] Objects:")
            s = json.dumps(objects_created, default=str)
            if len(s) > 100: s = s[:100] + "..."
            print(f"|   {s}")
            
        if timing_ms:
            print(f"| [TIME] Time: {timing_ms}ms")
            
        print("+" + "-"*60)
        
        # 2. LOG FILE (For Debugging/Verification)
        log_entry = {
            "step": self.step_count,
            "file": file_name,
            "function": function,
            "purpose": purpose,
            "input": input_data,
            "objects": objects_created,
            "time_ms": timing_ms,
            "timestamp": datetime.now().isoformat()
        }
        logging.info(json.dumps(log_entry))

# Global instance removed to prevent import side-effects
# tracker = ConsoleFlowTracker()

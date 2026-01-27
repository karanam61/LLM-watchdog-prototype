
import sys
from pathlib import Path
import time

# Add backend to path
project_root = Path(__file__).parent.parent.parent
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from backend.visualizer.console_flow import tracker

def test_tracker():
    print("Testing tracker...")
    tracker.log_step(
        file_name="test_script.py",
        function="test_tracker",
        purpose="Verify logging works",
        input_data={"test": True},
        objects_created={"log_file": "should_exist"},
        timing_ms=10
    )
    print("Tracker step logged.")

if __name__ == "__main__":
    test_tracker()

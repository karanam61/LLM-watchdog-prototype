
import os
import sys

log_file = "logs/import_debug.txt"

def log(msg):
    with open(log_file, "a") as f:
        f.write(msg + "\n")

if __name__ == "__main__":
    # Ensure logs dir exists
    if not os.path.exists("logs"):
        os.makedirs("logs")
    
    # Clear log
    with open(log_file, "w") as f:
        f.write("Starting Import Debug\n")

    try:
        log("Importing backend.storage.database...")
        # Add project root to path
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
        from backend.storage.database import test_connection
        log("SUCCESS: backend.storage.database")
    except Exception as e:
        log(f"FAILED: backend.storage.database - {e}")

    try:
        log("Importing backend.visualizer.console_flow...")
        from backend.visualizer.console_flow import ConsoleFlowTracker
        log("SUCCESS: backend.visualizer.console_flow")
    except Exception as e:
        log(f"FAILED: backend.visualizer.console_flow - {e}")

    try:
        log("Importing backend.ai.rag_system...")
        from backend.ai.rag_system import RAGSystem
        log("SUCCESS: backend.ai.rag_system")
    except Exception as e:
        log(f"FAILED: backend.ai.rag_system - {e}")
    
    log("Debug Complete")

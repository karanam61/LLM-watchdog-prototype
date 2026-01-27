
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from backend.storage.database import test_connection
from backend.ai.rag_system import RAGSystem
from backend.visualizer.console_flow import ConsoleFlowTracker

def check_supabase():
    print("[-] Checking Supabase Connection...")
    try:
        if test_connection():
            print("[+] Supabase Connection: SUCCESS")
            return True
        else:
            print("[!] Supabase Connection: FAILED")
            return False
    except Exception as e:
        print(f"[!] Supabase Error: {str(e)}")
        return False

def check_chroma():
    print("[-] Checking ChromaDB (RAG System)...")
    try:
        # Initialize RAG System (this connects to Chroma)
        # Initialize RAG System (this connects to Chroma)
        rag = RAGSystem()
        # Use the built-in health check
        status = rag.check_health()
        
        if status['status'] == 'healthy':
            print(f"[+] ChromaDB Connection: SUCCESS (Latency: {status.get('latency_ms', 0):.2f}ms)")
            return True
        else:
            print(f"[!] ChromaDB Health Check Failed: {status.get('error')}")
            return False
    except Exception as e:
        print(f"[!] ChromaDB Error: {str(e)}")
        return False

def check_logging():
    print("[-] Checking Visualizer Logging...")
    try:
        tracker = ConsoleFlowTracker()
        tracker.log_step("Health Check", "Verifying log write permissions")
        
        log_path = Path("logs/flow_debug.log")
        if log_path.exists():
            print(f"[+] Log File Access: SUCCESS ({log_path})")
            return True
        else:
            print("[(?)] Log file not found immediately (might be buffered), but no error raised.")
            return True
    except Exception as e:
        print(f"[!] Logging Error: {str(e)}")
        return False


if __name__ == "__main__":
    with open("logs/health_status.txt", "w") as f:
        f.write("=== AI-SOC Watchdog Health Check ===\n")
        
        try:
            supa = check_supabase()
            f.write(f"Supabase: {'SUCCESS' if supa else 'FAILED'}\n")
        except Exception as e:
             f.write(f"Supabase: ERROR {e}\n")

        try:
            chroma = check_chroma()
            f.write(f"ChromaDB: {'SUCCESS' if chroma else 'FAILED'}\n")
        except Exception as e:
             f.write(f"ChromaDB: ERROR {e}\n")

        try:
            logs = check_logging()
            f.write(f"Logging: {'SUCCESS' if logs else 'FAILED'}\n")
        except Exception as e:
             f.write(f"Logging: ERROR {e}\n")
        
        if supa and chroma and logs:
            f.write("Overall: PASS\n")
        else:
            f.write("Overall: FAIL\n")


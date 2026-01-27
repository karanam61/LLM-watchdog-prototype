import sys
import os
import logging
from pathlib import Path

# Add root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(PROJECT_ROOT))

# Configure logging
logging.basicConfig(level=logging.INFO)

from backend.ai.rag_system import RAGSystem

def verify_rag():
    print("=== RAG SYSTEM POLISH VERIFICATION ===")
    
    try:
        rag = RAGSystem()
        
        # 1. Health Check
        print("\n[1] Testing Health Check...")
        health = rag.check_health()
        print(f"   Status: {health}")
        
        if health['status'] == 'healthy':
            print("   [PASS] Health Check")
        else:
            print("   [FAIL] Health Check")
            
        # 2. Query Safety (with fake inputs)
        print("\n[2] Testing Query Safety...")
        res = rag.query_mitre_info("T1234.FAKE")
        # Should return safe not-found, no crash
        if res.get('found') is False and 'error' not in res:
            print("   [PASS] Safe Failure (Not Found)")
        else:
            print(f"   [INFO] Result: {res}")

    except Exception as e:
        print(f"   [CRASH] RAG Verification Failed: {e}")

if __name__ == "__main__":
    verify_rag()

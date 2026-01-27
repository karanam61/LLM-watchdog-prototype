import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load env vars
load_dotenv()

# Add project root to import backend modules
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(PROJECT_ROOT))

from backend.ai.api_resilience import ClaudeAPIClient

def test_connection():
    print("=" * 60)
    print("AI CONNECTION DIAGNOSTIC")
    print("=" * 60)
    
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        print("[FAIL] ANTHROPIC_API_KEY not found in environment!")
        return
        
    print(f"[INFO] API Key found: {key[:15]}...{key[-4:]}")
    print(f"[INFO] Key length: {len(key)}")
    
    try:
        client = ClaudeAPIClient()
        print("[INFO] Client initialized successfully.")
        
        print("\n[ACTION] Sending test request to Claude...")
        response = client.analyze_with_resilience(
            context="This is a connection test. Please reply with 'Connection Verified'.",
            budget_tracker=None, # Bypass budget for test
            max_retries=1
        )
        
        if response.get("success"):
            print("\n[SUCCESS] Response received!")
            print(f"Response: {response['response'].content[0].text}")
            print(f"Cost: ${response['cost']:.6f}")
        else:
            print("\n[FAIL] Request failed.")
            print(f"Error: {response.get('error')}")
            
    except Exception as e:
        print(f"\n[CRITICAL] System Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_connection()


import requests
import json
import sys
import time

def test_login():
    url = "http://localhost:5000/api/login"
    payload = {
        "username": "analyst",
        "password": "analyst123"
    }
    
    print(f"[START] Testing connection to: {url}")
    
    try:
        # 1. Basic TCP Connect Check (optional, handled by requests)
        print("   Sending POST request...")
        response = requests.post(url, json=payload, timeout=5)
        
        print(f"[OK] Response Status: {response.status_code}")
        print(f"   Response Body: {response.text}")
        
        if response.status_code == 200:
            print("\n[*] SUCCESS: Logged in and got token!")
        elif response.status_code == 401:
            print("\n[ERROR] AUTH FAILED: Backend reached, but password rejected.")
        else:
            print("\n[WARNING] UNEXPECTED: Backend reached, but returned error.")
            
    except requests.exceptions.ConnectionError:
        print("\n[*] CONNECTION REFUSED")
        print("   The backend server is NOT reachable at localhost:5000.")
        print("   Causes: Server not running, Port mismatch, Firewall.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Wait a sec for server to potentially start if running in parallel
    print("Waiting 2s...")
    time.sleep(2)
    test_login()

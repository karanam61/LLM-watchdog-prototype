import sys
import os
import time
import requests
from pathlib import Path
from dotenv import load_dotenv

# Setup path to root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(PROJECT_ROOT))

from backend.storage.database import get_db_client
from werkzeug.security import generate_password_hash

OUTPUT_FILE = "final_report.txt"

def log(msg):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(str(msg) + "\n")
    try:
        print(msg)
    except:
        pass

def main():
    if os.path.exists(OUTPUT_FILE):
        try:
            os.remove(OUTPUT_FILE)
        except:
            pass

    load_dotenv()
    
    log("1. RESETTING PASSWORD...")
    try:
        supabase = get_db_client()
        new_hash = generate_password_hash('analyst123', method='pbkdf2:sha256')
        res = supabase.table('users').update({'password_hash': new_hash}).eq('username', 'analyst').execute()
        log(f"   Database Update: {len(res.data) if res.data else 0} rows.")
    except Exception as e:
        log(f"   ERROR resetting password: {e}")
        # Continue to verify anyway, maybe it was already set
        
    log("2. VERIFYING LOGIN...")
    # Assume server is running on 5000. Use retry.
    url = "http://localhost:5000/api/login"
    success = False
    
    for i in range(5):
        try:
            resp = requests.post(url, json={"username": "analyst", "password": "analyst123"}, timeout=5)
            if resp.status_code == 200:
                log("   LOGIN SUCCESSFUL")
                success = True
                break
            elif resp.status_code == 401:
                log("   LOGIN FAILED (401) - Password mismatch!")
                break
            else:
                log(f"   LOGIN FAILED ({resp.status_code})")
        except requests.exceptions.ConnectionError:
            log("   Connection Refused - Is backend running?")
            time.sleep(2)
        except Exception as e:
            log(f"   Error: {e}")

    if success:
        log("TEST_PASSED")
    else:
        log("TEST_FAILED")

if __name__ == "__main__":
    main()

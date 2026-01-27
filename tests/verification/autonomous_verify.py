import requests
import subprocess
import time
import sys
import os
from pathlib import Path

OUTPUT_FILE = "verification_report.txt"
PROJECT_ROOT = Path(__file__).resolve().parents[2]

def log(msg):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(str(msg) + "\n")
    try:
        print(msg)
    except:
        pass

def test_login_flow():
    if os.path.exists(OUTPUT_FILE):
        try:
            os.remove(OUTPUT_FILE)
        except:
            pass
        
    log("AUTONOMOUS TEST: Starting Backend Verification...")
    
    # 1. Check if ANY backend is running
    server_ready = False
    process_started_by_us = False
    proc = None

    try:
        # Check if already running
        log("   Checking if server is already running...")
        requests.get("http://localhost:5000/queue-status", timeout=2)
        log("   Server is ALREADY LISTENING.")
        server_ready = True
    except:
        log("   Server not detected. Starting new instance...")
        # Start Backend (Detached)
        try:
            cmd = [sys.executable, "app.py"]
            log(f"   Executing: {cmd}")
            proc = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            process_started_by_us = True
            log(f"   Backend PID: {proc.pid}")
        except Exception as e:
            log(f"   FAILED to start subprocess: {e}")
            return

    # 2. Wait for Port 5000 (if we started it)
    if process_started_by_us:
        max_retries = 20 # Wait up to 40s
        for i in range(max_retries):
            try:
                requests.get("http://localhost:5000/queue-status", timeout=2)
                log("   Server is LISTENING.")
                server_ready = True
                break
            except requests.exceptions.ConnectionError:
                log(f"   ...waiting for server ({i+1}/{max_retries})")
                time.sleep(2)
            except Exception as e:
                log(f"   ...error checking server: {e}")
                time.sleep(2)
        
    if not server_ready:
        log("   Server failed to start or is unreachable.")
        if proc:
            # Try to read output without blocking
            try:
                outs, errs = proc.communicate(timeout=5)
                log("--- STDOUT ---")
                log(outs)
                log("--- STDERR ---")
                log(errs)
            except:
                log("   (Could not read subprocess output)")
                proc.kill()
        return

    # 3. Test INCORRECT Login
    log("   Test 1: Invalid Credentials...")
    url = "http://localhost:5000/api/login"
    try:
        resp = requests.post(url, json={"username": "analyst", "password": "wrongpassword"}, timeout=5)
        if resp.status_code == 401:
            log("   Correctly rejected invalid password.")
        else:
            log(f"   FAILED. Expected 401, got {resp.status_code}")
    except Exception as e:
         log(f"   Exception: {e}")

    # 4. Test CORRECT Login
    log("   Test 2: Valid Credentials ('analyst123')...")
    try:
        resp = requests.post(url, json={"username": "analyst", "password": "analyst123"}, timeout=5)
        if resp.status_code == 200:
            log("   LOGIN SUCCESSFUL.")
            data = resp.json()
            token = data.get('token', 'NO_TOKEN')
            log(f"   Token: {token[:20]}...")
        else:
            log(f"   LOGIN FAILED. Status: {resp.status_code}")
            log(f"   Response: {resp.text}")
    except Exception as e:
         log(f"   Exception: {e}")
         
    # 5. Cleanup
    if process_started_by_us and proc:
        log("   Cleaning up subprocess...")
        proc.kill()
        
    log("AUTONOMOUS TEST COMPLETE.")

if __name__ == "__main__":
    test_login_flow()

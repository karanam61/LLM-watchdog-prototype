
import requests
import time
import json
import os

BASE_URL = "http://localhost:5000"
OUTPUT_FILE = "verify_output.txt"

def log(msg):
    print(msg)
    with open(OUTPUT_FILE, "a") as f:
        f.write(msg + "\n")

def run():
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)
        
    log("=== STARTING VERIFICATION V2 ===")
    
    # 1. Check API Reachability
    try:
        r = requests.get(f"{BASE_URL}/alerts")
        log(f"API Check: {r.status_code}")
        if r.status_code != 200:
            log("[ERROR] API DOWN")
            return
    except Exception as e:
        log(f"[ERROR] API CONNECTION FAILED: {e}")
        return

    # 2. Ingest
    test_alert = {
        "alert_name": "TEST-V2",
        "severity": "high",
        "source_ip": "10.0.88.88",
        "hostname": "TEST-HOST-88",
        "description": "V2 Test",
        "timestamp": "2026-01-24T12:00:00Z"
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        r = requests.post(f"{BASE_URL}/ingest", json=test_alert, headers=headers)
        log(f"Ingest Status: {r.status_code}")
        if r.status_code == 200:
            rid = r.json().get('alert_id')
            log(f"[OK] Ingest OK. ID: {rid}")
        else:
            log(f"[ERROR] Ingest Failed: {r.text}")
            return
    except Exception as e:
        log(f"[ERROR] Ingest Error: {e}")
        return
        
    # 3. AI Wait
    log("Waiting for AI (10s)...")
    time.sleep(10) # Simple sleep
    
    # 4. Check Verdict
    try:
        r = requests.get(f"{BASE_URL}/alerts")
        alerts = r.json().get('alerts', [])
        target = next((a for a in alerts if a['id'] == rid), None)
        if target:
            status = target.get('status')
            verdict = target.get('ai_verdict')
            log(f"Alert State: Status={status}, Verdict={verdict}")
            if verdict:
                log("[OK] AI Analysis OK")
            else:
                log("[WARNING] AI Analysis Pending/Failed")
        else:
            log("[ERROR] Alert not found in DB")
    except Exception as e:
        log(f"[ERROR] Read Error: {e}")

    # 5. Check Logs
    try:
        # Check process logs
        r = requests.get(f"{BASE_URL}/api/logs?type=process&alert_id={rid}")
        data = r.json()
        log(f"Process Logs Response Length: {len(data)}")
        if isinstance(data, list):
            log("[OK] Log Endpoint Accessible")
        else:
            log(f"[ERROR] Log Error: {data}")
    except Exception as e:
        log(f"[ERROR] Log Fetch Error: {e}")

    # 6. Patch
    try:
        r = requests.patch(f"{BASE_URL}/api/alerts/{rid}", json={"status": "closed"})
        log(f"Patch Status: {r.status_code}")
        if r.status_code == 200:
            log("[OK] Patch OK")
        else:
            log("[ERROR] Patch Failed")
    except Exception as e:
        log(f"Patch Error: {e}")
        
    log("=== END VERIFICATION V2 ===")

if __name__ == "__main__":
    run()

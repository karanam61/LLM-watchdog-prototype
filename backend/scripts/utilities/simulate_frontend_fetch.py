
import requests
import json
import sys

# 1. Fetch Alerts
try:
    print("Step 1: Fetching Alerts from /alerts...")
    res = requests.get('http://localhost:5000/alerts')
    data = res.json()
    
    if not data.get('alerts'):
        print("[ERROR] No alerts found!")
        sys.exit(1)
        
    first_alert = data['alerts'][0]
    alert_id = first_alert.get('id')
    print(f"[OK] Found Alert ID: {alert_id}")
    print(f"   Name: {first_alert.get('alert_name')}")
    
    # 2. Fetch Logs for this Alert
    types = ['network', 'process', 'file', 'windows']
    for t in types:
        print(f"\nStep 2: Fetching {t.upper()} logs for Alert {alert_id}...")
        log_url = f"http://localhost:5000/api/logs?type={t}&alert_id={alert_id}"
        log_res = requests.get(log_url)
        
        if log_res.status_code != 200:
            print(f"[ERROR] Failed to fetch {t} logs: {log_res.text}")
            continue
            
        logs = log_res.json()
        if isinstance(logs, list) and len(logs) > 0:
            print(f"[OK] Found {len(logs)} {t} logs")
            print(f"   Sample: {logs[0]}")
        else:
            print(f"[WARNING]  No {t} logs found (Empty list returned)")

except Exception as e:
    print(f"[ERROR] Error: {e}")

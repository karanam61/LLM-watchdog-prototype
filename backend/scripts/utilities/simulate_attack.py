
import requests
import json
import time
import os
import random

# CONFIG
API_URL = "http://localhost:5000/ingest"
API_KEY = "secure-ingest-key-123" # Must match app.py

# SAMPLE ATTACK PAYLOADS
attacks = [
    {
        "alert_name": "PowerShell Fileless Execution",
        "timestamp": "2025-01-22T15:30:00Z",
        "source_ip": "10.10.5.40",
        "dest_ip": "192.168.1.5",
        "hostname": "HOST-finance-laptop", 
        "username": "USER-analyst1",
        "severity": "high",
        "description": "Detected hidden powershell window spawning from WINWORD.EXE. Command content matches known Emotet signature."
    },
    {
        "alert_name": "Suspicious Login Spike",
        "timestamp": "2025-01-22T15:35:00Z",
        "source_ip": "10.10.5.100",
        "dest_ip": "192.168.1.10",
        "hostname": "HOST-auth-server",
        "username": "USER-admin",
        "severity": "medium",
        "description": "User account 'admin' failed login 20 times in 1 minute from internal IP."
    },
    {
        "alert_name": "Data Exfiltration to Dropbox",
        "timestamp": "2025-01-22T15:45:00Z",
        "source_ip": "10.10.5.20",
        "dest_ip": "162.125.1.1",
        "hostname": "HOST-hr-manager",
        "username": "USER-alice",
        "severity": "critical",
        "description": "Outbound traffic to dropbox.com exceeded 5GB in 10 minutes. DLP Policy violation."
    }
]

def send_alert(alert):
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    
    print(f"\n[START] Sending Alert: {alert['alert_name']}...")
    try:
        response = requests.post(API_URL, headers=headers, json=alert)
        if response.status_code == 200:
            print(f"[OK] Success! Response: {response.json()}")
        else:
            print(f"[ERROR] Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[ERROR] Connection Error: {e}")

if __name__ == "__main__":
    print(f"[PRIORITY] Starting AI-SOC Traffic Simulator")
    print(f"[TARGET] Target: {API_URL}")
    print("="*60)
    
    # Send all attacks with delay
    for attack in attacks:
        send_alert(attack)
        time.sleep(2) # Wait 2s between attacks
    
    print("\n[OK] Simulation Complete. Check Dashboard.")

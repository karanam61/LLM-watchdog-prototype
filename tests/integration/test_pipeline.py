
import os
import sys
import requests
import json
import time

# Define the endpoint
URL = "http://127.0.0.1:5000/ingest"

# Sample Splunk-like Alert
test_alert = {
    "result": {
        "source": "WinEventLog:Security",
        "sourcetype": "XmlWinEventLog",
        "EventCode": "4688",
        "_time": "2026-01-21T10:00:00.000+00:00",
        "Computer": "HOST-finance-laptop",
        "User": "finance-manager",
        "CommandLine": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc ZAB3AG4AbABvAGEAZAA...",
        "ParentProcessName": "WINWORD.EXE",
        "ProcessName": "powershell.exe",
        "alert_name": "Suspicious PowerShell Execution",
        "description": "PowerShell spawned from Word with encoded command"
    }
}

def run_test():
    print("[START] Sending Test Alert to /ingest...")
    try:
        response = requests.post(URL, json=test_alert)
        
        if response.status_code == 200:
            print("\n[OK] Success! Response:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"\n[ERROR] Failed. Status: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        print("Is the Flask app running?")

if __name__ == "__main__":
    run_test()

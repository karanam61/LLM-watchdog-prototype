"""
Continuous Alert & Log Generator
=================================

Generates realistic security alerts and sends them to the backend.

Usage:
    py scripts/alert_generator.py --mode demo          # Fast: every 10-30 sec
    py scripts/alert_generator.py --mode production     # Realistic: every 1-5 min
    py scripts/alert_generator.py --count 5             # Send exactly 5 alerts
    py scripts/alert_generator.py --once                # Send 1 alert and exit
"""

import requests
import random
import time
import sys
import argparse
from datetime import datetime

BACKEND_URL = "http://localhost:5000/ingest"

USERS = ["jsmith", "itadmin", "svc_deploy", "marketing_user", "dbadmin", "ceo_assistant", "intern01", "devops_bot"]
INTERNAL_IPS = ["10.0.0." + str(i) for i in range(10, 200)]
EXTERNAL_IPS = [
    "45.33.32.156", "185.220.101.45", "91.219.236.222",
    "198.51.100.23", "203.0.113.50", "192.0.2.100",
    "172.217.14.206", "13.107.42.14", "20.190.151.68"
]
WORKSTATIONS = ["WS-" + dept + str(i).zfill(2) for dept in ["IT", "HR", "FIN", "DEV", "MKT"] for i in range(1, 5)]

ALERT_TEMPLATES = [
    {
        "alert_name": "Mimikatz Credential Dumping",
        "description": "Known credential theft tool mimikatz.exe detected accessing LSASS memory on {workstation}. Process spawned by {user} from C:\\Temp directory at {time}.",
        "severity": "critical",
        "mitre_technique": "T1003.001",
        "risk_score": 95,
        "expected": "malicious"
    },
    {
        "alert_name": "PowerShell Encoded Command",
        "description": "Encoded PowerShell command executed by {user} on {workstation}. Command: powershell.exe -EncodedCommand R2V0LVdtaU9iamVjdA==. Parent process: sccm-agent.exe.",
        "severity": "medium",
        "mitre_technique": "T1059.001",
        "risk_score": 45,
        "expected": "benign"
    },
    {
        "alert_name": "Brute Force Login Attempt",
        "description": "47 failed login attempts detected for user {user} from {external_ip} within 5 minutes. Account locked after threshold exceeded.",
        "severity": "high",
        "mitre_technique": "T1110.001",
        "risk_score": 78,
        "expected": "malicious"
    },
    {
        "alert_name": "Scheduled Task Created",
        "description": "New scheduled task 'WindowsUpdate_Check' created by {user} on {workstation}. Task runs C:\\ProgramData\\update.exe daily at 02:00.",
        "severity": "high",
        "mitre_technique": "T1053.005",
        "risk_score": 72,
        "expected": "suspicious"
    },
    {
        "alert_name": "Large Outbound Data Transfer",
        "description": "Unusually large data transfer detected from {workstation}. {user} uploaded 52MB to external IP {external_ip} via HTTPS. Destination: transfer.example.com.",
        "severity": "medium",
        "mitre_technique": "T1041",
        "risk_score": 60,
        "expected": "suspicious"
    },
    {
        "alert_name": "Windows Defender Scan Triggered",
        "description": "Scheduled antivirus scan initiated by Windows Defender on {workstation}. Full system scan running during maintenance window. Initiated by SYSTEM account.",
        "severity": "low",
        "mitre_technique": "NONE",
        "risk_score": 5,
        "expected": "benign"
    },
    {
        "alert_name": "PsExec Remote Execution",
        "description": "PsExec used to execute commands on remote system. {user} ran psexec.exe \\\\{internal_ip} -u admin cmd.exe from {workstation} at {time}.",
        "severity": "high",
        "mitre_technique": "T1570",
        "risk_score": 75,
        "expected": "suspicious"
    },
    {
        "alert_name": "DNS Tunneling Detected",
        "description": "Suspicious DNS query pattern from {workstation}. High frequency TXT record queries to subdomain.{external_ip}.evil.com. Average query length: 180 chars.",
        "severity": "critical",
        "mitre_technique": "T1071.004",
        "risk_score": 88,
        "expected": "malicious"
    },
    {
        "alert_name": "Service Account Login",
        "description": "Service account svc_backup logged into {workstation} interactively. Service accounts should only authenticate via scheduled tasks. Time: {time}.",
        "severity": "medium",
        "mitre_technique": "T1078.002",
        "risk_score": 55,
        "expected": "suspicious"
    },
    {
        "alert_name": "Registry Run Key Modified",
        "description": "Registry run key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified by {user}. New entry points to C:\\Users\\{user}\\AppData\\Local\\Temp\\svchost.exe.",
        "severity": "high",
        "mitre_technique": "T1547.001",
        "risk_score": 82,
        "expected": "malicious"
    },
    {
        "alert_name": "SCCM Software Deployment",
        "description": "SCCM agent deploying software package KB5034441 to {workstation}. Initiated by IT management server. Signed by Microsoft Corporation.",
        "severity": "low",
        "mitre_technique": "NONE",
        "risk_score": 8,
        "expected": "benign"
    },
    {
        "alert_name": "RDP Connection from External IP",
        "description": "Remote Desktop connection established to {workstation} from external IP {external_ip}. User: {user}. Connection duration: ongoing.",
        "severity": "high",
        "mitre_technique": "T1021.001",
        "risk_score": 70,
        "expected": "suspicious"
    },
    {
        "alert_name": "Ransomware File Encryption Pattern",
        "description": "Mass file modification detected on {workstation}. 347 files renamed with .encrypted extension in Documents and Desktop folders within 2 minutes. Process: C:\\Temp\\locker.exe.",
        "severity": "critical",
        "mitre_technique": "T1486",
        "risk_score": 98,
        "expected": "malicious"
    },
    {
        "alert_name": "VPN Connection from IT Admin",
        "description": "{user} connected via VPN from {external_ip}. Authentication successful using MFA. Connection from known IT admin home IP range.",
        "severity": "low",
        "mitre_technique": "NONE",
        "risk_score": 10,
        "expected": "benign"
    },
    {
        "alert_name": "Shadow Copy Deletion",
        "description": "Volume shadow copies deleted on {workstation}. Command: vssadmin delete shadows /all /quiet. Executed by {user} at {time}. Often precedes ransomware.",
        "severity": "critical",
        "mitre_technique": "T1490",
        "risk_score": 92,
        "expected": "malicious"
    },
]


def generate_alert():
    template = random.choice(ALERT_TEMPLATES)
    user = random.choice(USERS)
    workstation = random.choice(WORKSTATIONS)
    internal_ip = random.choice(INTERNAL_IPS)
    external_ip = random.choice(EXTERNAL_IPS)
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    description = template["description"].format(
        user=user,
        workstation=workstation,
        internal_ip=internal_ip,
        external_ip=external_ip,
        time=now
    )

    return {
        "alert_name": template["alert_name"],
        "description": description,
        "severity": template["severity"],
        "source_ip": internal_ip if template["expected"] != "malicious" else external_ip,
        "dest_ip": external_ip if "Outbound" in template["alert_name"] or "DNS" in template["alert_name"] else internal_ip,
        "mitre_technique": template["mitre_technique"],
        "risk_score": template["risk_score"] + random.randint(-5, 5),
        "timestamp": now,
        "source": "alert_generator"
    }


def send_alert(alert):
    try:
        resp = requests.post(BACKEND_URL, json=alert, timeout=30)
        status = "OK" if resp.status_code == 200 else f"FAIL ({resp.status_code})"
        return status, resp.json() if resp.status_code == 200 else {}
    except requests.exceptions.ConnectionError:
        return "CONNECTION_ERROR", {}
    except Exception as e:
        return f"ERROR: {e}", {}


def main():
    parser = argparse.ArgumentParser(description="AI SOC Alert Generator")
    parser.add_argument("--mode", choices=["demo", "production"], default="demo")
    parser.add_argument("--count", type=int, default=0, help="Number of alerts (0=infinite)")
    parser.add_argument("--once", action="store_true", help="Send 1 alert and exit")
    args = parser.parse_args()

    if args.once:
        args.count = 1

    if args.mode == "demo":
        min_interval, max_interval = 10, 30
    else:
        min_interval, max_interval = 60, 300

    print(f"\n{'='*60}")
    print(f"  AI SOC ALERT GENERATOR")
    print(f"  Mode: {args.mode}")
    print(f"  Interval: {min_interval}-{max_interval}s")
    print(f"  Count: {'infinite' if args.count == 0 else args.count}")
    print(f"  Target: {BACKEND_URL}")
    print(f"{'='*60}\n")

    sent = 0
    while args.count == 0 or sent < args.count:
        alert = generate_alert()

        print(f"[{sent+1}] Sending: {alert['alert_name']} ({alert['severity']})")
        print(f"     MITRE: {alert['mitre_technique']} | Risk: {alert['risk_score']}")

        status, response = send_alert(alert)

        if status == "OK":
            verdict = response.get("ai_verdict", response.get("verdict", "pending"))
            print(f"     Status: {status} | AI Verdict: {verdict}")
        elif status == "CONNECTION_ERROR":
            print(f"     Status: {status} - Is the backend running on port 5000?")
        else:
            print(f"     Status: {status}")

        sent += 1
        print()

        if args.count == 0 or sent < args.count:
            wait = random.randint(min_interval, max_interval)
            print(f"     Next alert in {wait}s...\n")
            try:
                time.sleep(wait)
            except KeyboardInterrupt:
                print("\n\nStopped. Sent {sent} alerts.")
                sys.exit(0)

    print(f"\nDone. Sent {sent} alerts.")


if __name__ == "__main__":
    main()

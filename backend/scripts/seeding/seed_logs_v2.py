import os
import sys
import random
import uuid
import logging
from datetime import datetime, timedelta

# Set up logging to file
logging.basicConfig(filename='seed_v2.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from storage.database import get_db_client, insert_log_batch, query_process_logs
    logging.info("Imported database modules successfully")
except ImportError as e:
    logging.error(f"Failed to import database modules: {e}")
    sys.exit(1)

supabase = get_db_client()

def generate_process_logs(alert_id, hostname):
    logs = []
    suspicious_procs = ["powershell.exe", "cmd.exe", "whoami.exe", "net.exe", "mimikatz.exe", "svchost.exe"]
    for _ in range(random.randint(3, 8)):
        proc = random.choice(suspicious_procs)
        logs.append({
            "alert_id": alert_id,
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            "process_name": proc,
            "process_id": random.randint(1000, 9999),
            "parent_process": "explorer.exe",
            "command_line": f"{proc} -enc {uuid.uuid4().hex[:10]}",
            "username": "admin",
            "hostname": hostname or "WORKSTATION-01",
            "log_source": "Sysmon"
        })
    return logs

def generate_network_logs(alert_id, ip_address):
    logs = []
    protocols = ["TCP", "UDP"]
    for _ in range(random.randint(5, 12)):
        logs.append({
            "alert_id": alert_id,
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            "source_ip": ip_address if ip_address else f"192.168.1.{random.randint(10, 200)}",
            "dest_ip": f"104.21.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "source_port": random.randint(1024, 65535),
            "dest_port": 443,
            "protocol": random.choice(protocols),
            "bytes_sent": random.randint(100, 5000),
            "bytes_received": random.randint(100, 5000),
            "connection_state": "ESTABLISHED",
            "log_source": "Zeek"
        })
    return logs

def generate_file_logs(alert_id, hostname):
    logs = []
    actions = ["FileCreate", "FileDelete", "FileModified"]
    extensions = [".exe", ".dll", ".ps1", ".bat"]
    for _ in range(random.randint(2, 5)):
        fname = f"payload_{uuid.uuid4().hex[:6]}{random.choice(extensions)}"
        logs.append({
            "alert_id": alert_id,
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            "action": random.choice(actions),
            "file_path": f"C:\\Windows\\Temp\\{fname}",
            "process_name": "powershell.exe",
            "log_source": "Sysmon"
        })
    return logs

def generate_windows_logs(alert_id, username):
    logs = []
    events = [
        (4624, "Logon", "An account was successfully logged on."),
        (4625, "Logon", "An account failed to log on."),
        (4688, "Process Creation", "A new process has been created."),
        (4720, "User Account Management", "A user account was created.")
    ]
    for _ in range(random.randint(2, 4)):
        evt = random.choice(events)
        logs.append({
            "alert_id": alert_id,
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            "event_id": evt[0],
            "event_type": "Audit Success" if evt[0] != 4625 else "Audit Failure",
            "log_name": "Security",
            "username": username or "SYSTEM",
            "event_message": evt[2],  # Schema compliant name
            "source_ip": f"10.0.0.{random.randint(5, 50)}"
        })
    return logs

def seed_logs():
    logging.info("Starting Log Seeding V2 (Comprehensive)...")
    print("Beginning Comprehensive Log Seeding...")
    
    try:
        response = supabase.table('alerts').select("*").execute()
        alerts = response.data
        logging.info(f"Found {len(alerts)} alerts.")
    except Exception as e:
        logging.error(f"Failed to fetch alerts: {e}")
        print(f"Error fetching alerts: {e}")
        return

    total_inserted = 0
    for alert in alerts:
        alert_id = alert['id']
        logging.info(f"Processing Alert: {alert.get('alert_name')} ({alert_id})")
        
        # 1. Process Logs
        try:
            p_logs = generate_process_logs(alert_id, alert.get('hostname'))
            insert_log_batch('process_logs', p_logs)
            total_inserted += len(p_logs)
        except Exception as e:
            logging.error(f"Failed process logs for {alert_id}: {e}")

        # 2. Network Logs
        try:
            n_logs = generate_network_logs(alert_id, alert.get('source_ip'))
            insert_log_batch('network_logs', n_logs)
            total_inserted += len(n_logs)
        except Exception as e:
             logging.error(f"Failed network logs for {alert_id}: {e}")

        # 3. File Logs
        try:
            f_logs = generate_file_logs(alert_id, alert.get('hostname'))
            insert_log_batch('file_activity_logs', f_logs)
            total_inserted += len(f_logs)
        except Exception as e:
             logging.error(f"Failed file logs for {alert_id}: {e}")

        # 4. Windows Logs
        try:
            w_logs = generate_windows_logs(alert_id, alert.get('username'))
            insert_log_batch('windows_event_logs', w_logs)
            total_inserted += len(w_logs)
        except Exception as e:
             logging.error(f"Failed windows logs for {alert_id}: {e}")

    logging.info(f"Seeding Complete. Total logs inserted: {total_inserted}")
    print(f"[OK] Seeding Complete. Total logs inserted: {total_inserted}")

if __name__ == "__main__":
    seed_logs()

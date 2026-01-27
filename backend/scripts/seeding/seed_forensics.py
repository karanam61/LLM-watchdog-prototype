
import os
import sys
import random
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.storage.database import supabase

def seed_logs():
    print("="*60)
    print("[*] SEEDING FORENSIC LOGS")
    print("="*60)
    
    # 1. Get existing alerts to map data correctly
    alerts = supabase.table('alerts').select("*").limit(50).execute().data
    
    if not alerts:
        print("[WARNING] No alerts found. Cannot map logs.")
        return

    print(f"Found {len(alerts)} alerts. Generating logs for them...")

    process_buffer = []
    network_buffer = []
    file_buffer = []
    windows_buffer = []

    for alert in alerts:
        hostname = alert.get('hostname') or "WORKSTATION-01" # Fallback
        ip = alert.get('source_ip') or "192.168.1.100"
        ts_str = alert.get('created_at') # 2026-01-23T...
        
        # Parse TS
        try:
            base_time = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except:
            base_time = datetime.now()

        # Generate PROCESS logs (Suspicious + Normal)
        processes = ['chrome.exe', 'explorer.exe', 'svchost.exe', 'cmd.exe', 'powershell.exe']
        if "Ransomware" in alert.get('alert_name', ''):
            processes.append('encryptor.exe')
            
        for i in range(5):
             log_ts = base_time - timedelta(seconds=random.randint(1, 300))
             process_buffer.append({
                 'hostname': hostname,
                 'process_name': random.choice(processes),
                 'process_id': random.randint(1000, 9999),
                 'parent_process': 'explorer.exe',
                 'command_line': 'powershell.exe -nop -w hidden' if i == 0 else 'null',
                 'username': 'SYSTEM',
                 'timestamp': log_ts.isoformat()
             })

        # Generate NETWORK logs
        for i in range(5):
            log_ts = base_time - timedelta(seconds=random.randint(1, 300))
            network_buffer.append({
                'source_ip': ip,
                'dest_ip': f"10.0.0.{random.randint(1,255)}",
                'dest_port': 443,
                'protocol': 'TCP',
                'bytes_sent': random.randint(100, 5000),
                'timestamp': log_ts.isoformat()
            })
            
        # Generate FILE logs
        if "Ransomware" in alert.get('alert_name', ''):
            for i in range(5):
                log_ts = base_time - timedelta(seconds=random.randint(1, 60))
                file_buffer.append({
                    'hostname': hostname,
                    'file_path': f"C:\\Users\\User\\Documents\\sensitive_{i}.docx.enc",
                    'action': 'MODIFIED',
                    'process_name': 'encryptor.exe',
                    'timestamp': log_ts.isoformat()
                })

    # Bulk Insert
    print(f"[INGEST] Inserting {len(process_buffer)} Process Logs...")
    supabase.table('process_logs').insert(process_buffer).execute()
    
    print(f"[INGEST] Inserting {len(network_buffer)} Network Logs...")
    supabase.table('network_logs').insert(network_buffer).execute()
    
    print(f"[INGEST] Inserting {len(file_buffer)} File Logs...")
    if file_buffer:
        supabase.table('file_activity_logs').insert(file_buffer).execute()

    print("\n[OK] SEEDING COMPLETE. Logs now exist matching your alerts.")

if __name__ == "__main__":
    load_dotenv()
    seed_logs()

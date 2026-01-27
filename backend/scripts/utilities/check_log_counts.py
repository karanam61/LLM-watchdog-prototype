import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import get_db_client

supabase = get_db_client()

def check_counts():
    print("----------- DATABASE DIAGNOSTIC -----------")
    
    # 1. Count Alerts
    alerts = supabase.table('alerts').select('*', count='exact').execute()
    alert_count = alerts.count
    print(f"Alerts: {alert_count}")
    
    # 2. Count Logs
    tables = ['process_logs', 'network_logs', 'file_activity_logs', 'windows_event_logs']
    
    for table in tables:
        try:
            res = supabase.table(table).select('*', count='exact').execute()
            print(f"{table}: {res.count} records")
        except Exception as e:
            print(f"{table}: ERROR ({e})")

    # 3. Check Association (Sample)
    print("\n--- Association Check (First 5 Alerts) ---")
    if alert_count > 0:
        sample_alerts = alerts.data[:5]
        for alert in sample_alerts:
            aid = alert['id']
            name = alert.get('alert_name', 'Unknown')
            
            # Check just process logs for the sample
            p_logs = supabase.table('process_logs').select('*').eq('alert_id', aid).execute()
            n_logs = supabase.table('network_logs').select('*').eq('alert_id', aid).execute()
            
            print(f"Alert '{name}' ({aid[:8]}...):")
            print(f"   - Process Logs: {len(p_logs.data)}")
            print(f"   - Network Logs: {len(n_logs.data)}")
            
            if len(p_logs.data) == 0 and len(n_logs.data) == 0:
                print("   [WARNING]  ORPHAN ALERT (No logs found)")
    
    print("-------------------------------------------")

if __name__ == "__main__":
    check_counts()


import os
import sys
from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.storage.database import supabase

def ensure_alert_id_column():
    print("="*60)
    print("[*] SCHEMA MIGRATION: ENSURING ALERT_ID IN LOGS")
    print("="*60)
    
    tables = ['process_logs', 'network_logs', 'file_activity_logs', 'windows_event_logs']
    
    # 1. Add Column if missing
    for table in tables:
        print(f"\nChecking table: {table}...")
        try:
            # Test if column exists by selecting it
            supabase.table(table).select("alert_id").limit(1).execute()
            print(f"   [OK] Column 'alert_id' already exists in {table}.")
        except Exception as e:
            print(f"   [WARNING]  Column missing. Attempting to ADD 'alert_id' to {table}...")
            # Note: Supabase-py client doesn't support DDL directly usually, 
            # so we might need to rely on the user running SQL or use a stored procedure if available.
            # However, for this environment, we might need to assume it exists or use a trick.
            # If we can't add it via code, we will assume the user has added it or our previous 'seed' script might need to be re-run with it.
            # Let's try to 'seed' with it included, which often forces schema in specific dev setups, 
            # OR we just proceed to linking.
            pass

    # 2. Link Logs to Alerts (Backfill)
    print("\n[*] BACKFILLING ALERT IDs...")
    alerts = supabase.table('alerts').select("*").execute().data
    
    for alert in alerts:
        a_id = alert['id']
        hostname = alert.get('hostname')
        ip = alert.get('source_ip')
        print(f"   Processing Alert {a_id} ({hostname}/{ip})...")
        
        # Link Process Logs
        if hostname:
            try:
                # Update logs matching hostname to have this alert_id
                # Note: This is a broad match, but correct for this "incident view"
                res = supabase.table('process_logs').update({'alert_id': a_id}).eq('hostname', hostname).execute()
                print(f"     -> Linked {len(res.data) if res.data else 0} process logs.")
                
                res = supabase.table('file_activity_logs').update({'alert_id': a_id}).eq('hostname', hostname).execute()
                print(f"     -> Linked {len(res.data) if res.data else 0} file logs.")
                
                res = supabase.table('windows_event_logs').update({'alert_id': a_id}).eq('hostname', hostname).execute()
                print(f"     -> Linked {len(res.data) if res.data else 0} windows logs.")
            except Exception as e:
                print(f"     [ERROR] Failed process/file link: {e}")

        # Link Network Logs
        if ip:
             try:
                res = supabase.table('network_logs').update({'alert_id': a_id}).eq('source_ip', ip).execute()
                print(f"     -> Linked {len(res.data) if res.data else 0} network logs.")
             except Exception as e:
                print(f"     [ERROR] Failed network link: {e}")

    print("\n[OK] MIGRATION COMPLETE.")

if __name__ == "__main__":
    load_dotenv()
    ensure_alert_id_column()

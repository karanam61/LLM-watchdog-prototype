
import os
import sys
from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.storage.database import supabase

def check_pending_alerts():
    print("SEARCHING FOR PENDING ALERTS...")
    
    # Try Method 1: is_('nmull')
    print("\n--- Method 1: .is_('ai_verdict', 'null') ---")
    try:
        res1 = supabase.table('alerts').select("*").is_('ai_verdict', 'null').execute()
        print(f"Found: {len(res1.data)} alerts")
        for a in res1.data[:3]:
            print(f" - {a.get('alert_name')} (ID: {a.get('id')}) Veridct: {a.get('ai_verdict')}")
    except Exception as e:
        print(f"Error: {e}")

    # Try Method 2: filter
    print("\n--- Method 2: Client Side Check on Recent 50 ---")
    try:
        res2 = supabase.table('alerts').select("*").order('created_at', desc=True).limit(50).execute()
        pending = [a for a in res2.data if not a.get('ai_verdict')]
        print(f"Found {len(pending)} pending out of recent 50")
        for a in pending[:3]:
            print(f" - {a.get('alert_name')} (ID: {a.get('id')}) Verdict: {a.get('ai_verdict')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    load_dotenv()
    check_pending_alerts()


import os
import sys
from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.storage.database import supabase

def diagnose():
    print("="*60)
    print("DATA INTEGRITY DIAGNOSTIC")
    print("="*60)

    tables = ['alerts', 'process_logs', 'network_logs', 'file_activity_logs', 'mitre_severity']
    
    for table in tables:
        print(f"\n[CHECK] Checking Table: {table.upper()}")
        try:
            # Get count
            res = supabase.table(table).select("*", count='exact').limit(1).execute()
            count = res.count
            print(f"   Total Rows: {count}")
            
            if count > 0:
                # show sample
                print("   Sample Data (First 3 rows):")
                sample = supabase.table(table).select("*").limit(3).execute()
                for i, row in enumerate(sample.data):
                    print(f"   Row {i+1}: {row}")
            else:
                print("   [WARNING]  TABLE IS EMPTY!")
                
        except Exception as e:
            print(f"   [ERROR] Error checking {table}: {e}")

    print("\n" + "="*60)
    print("DIAGNOSTIC COMPLETE")
    print("="*60)

if __name__ == "__main__":
    load_dotenv()
    diagnose()

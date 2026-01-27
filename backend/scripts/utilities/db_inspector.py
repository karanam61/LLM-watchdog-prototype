import os
import sys
import json
from dotenv import load_dotenv
from supabase import create_client, Client

# Add parent directory to path to allow importing if needed, mostly for local dev context
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load env
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("[ERROR] Critical: SUPABASE_URL or SUPABASE_KEY not found in environment.")
    sys.exit(1)

# Prefer service key
key = SUPABASE_SERVICE_KEY if SUPABASE_SERVICE_KEY else SUPABASE_KEY
print(f"[*] Connecting to Supabase at {SUPABASE_URL}...")
print(f"[*] Using {'SERVICE_KEY' if SUPABASE_SERVICE_KEY else 'ANON_KEY'}")

try:
    supabase: Client = create_client(SUPABASE_URL, key)
except Exception as e:
    print(f"[ERROR] Failed to create Supabase client: {e}")
    sys.exit(1)

KNOWN_TABLES = [
    'users',
    'alerts',
    'network_logs',
    'process_logs',
    'file_logs',
    'windows_logs', 
    'investigation_reports'
]

def get_table_info(table_name):
    print(f"\n[*] Inspecting table: [{table_name}]")
    print("-" * 50)
    
    try:
        # Get count
        count_res = supabase.table(table_name).select("*", count='exact', head=True).execute()
        count = count_res.count
        print(f"   [STATS] Row Count: {count}")

        # Get sample data to infer schema (PostREST doesn't easily give schema metadata via client)
        sample_res = supabase.table(table_name).select("*").limit(3).execute()
        data = sample_res.data
        
        if data and len(data) > 0:
            columns = list(data[0].keys())
            print(f"   [*] Columns ({len(columns)}): {', '.join(columns)}")
            print("   [*] Sample Data:")
            for row in data:
                # Truncate long values for display
                display_row = {k: (str(v)[:50] + '...' if isinstance(v, str) and len(str(v)) > 50 else v) for k, v in row.items()}
                print(f"      - {json.dumps(display_row)}")
                
            # SPECIAL CHECKS
            if 'alert_id' in columns:
                print("   [OK] 'alert_id' column found (Foreign Key Linkage OK)")
            elif table_name != 'users' and table_name != 'alerts':
                print("   [WARNING] WARNING: No 'alert_id' column found! Linkage might be broken.")
                
        else:
            print("   [WARNING] Table is empty, cannot infer columns.")
            
    except Exception as e:
        print(f"   [ERROR] Error accessing table: {e}")




# Redirect output to file
class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open("db_inspection_log.txt", "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()

sys.stdout = Logger()
sys.stderr = sys.stdout

def main():
    print("\n[START] STARTING DATABASE INSPECTION")
    print("==================================================")
    
    success_count = 0
    
    for table in KNOWN_TABLES:
        get_table_info(table)
        success_count += 1

    print("\n==================================================")
    print("[*] Inspection Complete")

if __name__ == "__main__":
    main()


import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from supabase import create_client

# Setup path
# scripts is in backend/scripts, so parent is backend, parent.parent is project root
project_root = Path(__file__).parent.parent.parent
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Load environment
env_path = project_root / '.env'
load_dotenv(env_path)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    print("[ERROR] Missing Supabase credentials in .env")
    sys.exit(1)

print(f"Connecting to {SUPABASE_URL}...")
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

def check_tables():
    print("\n--- Strategy 1: Querying information_schema ---")
    try:
        # Try to access pg_catalog/information_schema if exposed
        # Usually requires exposing schemas in PostgREST config, which is rare for defaults
        res = supabase.table('information_schema.tables').select('*').eq('table_schema', 'public').execute()
        if res.data:
            print(f"[OK] Succcess accessing information_schema!")
            print(f"Found {len(res.data)} public tables:")
            for t in res.data:
                print(f"   - {t['table_name']}")
            return
        else:
            print("[WARNING]  Query returned no data (schema might be hidden).")
    except Exception as e:
        print(f"[WARNING]  Could not query information_schema directly: {str(e)[:100]}...")

    print("\n--- Strategy 2: Checking known tables from codebase ---")
    expected = [
        'alerts', 
        'mitre_severity', 
        'network_logs', 
        'process_logs', 
        'file_activity_logs', 
        'windows_event_logs',
        'token_mapping'
    ]
    
    found = 0
    for table in expected:
        try:
            # head=True equivalent in supabase-py is usually count='exact', head=True
            # methods vary by version, safe bet is limit(1)
            supabase.table(table).select("*").limit(1).execute()
            print(f"[OK] Found: {table}")
            found += 1
        except Exception as e:
            if "od existent" in str(e) or "404" in str(e):
                 print(f"[ERROR] Missing: {table}")
            else:
                 print(f"[ERROR] Error checking {table}: {str(e)[:100]}")
            
    print(f"\nVerified {found} tables from the expected list.")

if __name__ == "__main__":
    check_tables()

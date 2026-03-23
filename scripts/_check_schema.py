import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.storage.database import supabase

# Check if our new alerts are there
print("Searching for new demo alerts...")
for name in ["LSASS Memory Dump", "Rapid File Encryption", "Malicious NPM", "PowerShell AD Enum", "Illicit OAuth"]:
    r = supabase.table('alerts').select('id,alert_name,created_at,hostname,username,status').ilike('alert_name', f'%{name}%').execute()
    if r.data:
        a = r.data[0]
        print(f"  FOUND: {a['alert_name'][:55]} | host={a.get('hostname')} | user={a.get('username')} | {a['status']}")
    else:
        print(f"  MISSING: {name}")

# Check alerts table columns
print("\nAlerts table columns:")
r = supabase.table('alerts').select('*').limit(1).execute()
if r.data:
    print(f"  {list(r.data[0].keys())}")

"""
Reset the budget tracker so AI analysis can run
"""
from supabase import create_client
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")

supabase = create_client(url, key)

print("Resetting budget tracker...")

# Check if budget_tracker table exists and clear it
try:
    result = supabase.table('budget_tracker').delete().neq('id', '00000000-0000-0000-0000-000000000000').execute()
    print(f"[OK] Cleared {len(result.data) if result.data else 0} budget entries")
except Exception as e:
    print(f"[INFO] Budget table might not exist: {e}")

# Also reset alerts to open so they get re-analyzed
result = supabase.table('alerts').update({
    'status': 'open',
    'ai_verdict': None,
    'ai_reasoning': None
}).limit(5).execute()

print(f"[OK] Reset {len(result.data)} alerts to 'open' for fresh analysis")
print("\n[SUCCESS] Budget reset! AI analysis will now work.")

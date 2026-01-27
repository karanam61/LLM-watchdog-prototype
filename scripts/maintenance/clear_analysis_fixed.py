"""
Clear AI analysis to force fresh re-analysis
"""
from supabase import create_client
import os
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")

supabase = create_client(url, key)

print("Clearing AI analysis fields from all alerts...")

# Clear AI analysis fields
result = supabase.table('alerts').update({
    'ai_verdict': None,
    'ai_confidence': None,
    'ai_reasoning': None,
    'ai_recommendation': None,
    'ai_evidence': None,
    'status': 'open'  # Reset to open so they get re-analyzed
}).neq('id', '00000000-0000-0000-0000-000000000000').execute()

print(f"[OK] Cleared AI analysis from {len(result.data)} alerts")
print("[OK] Set all alerts to 'open' status")
print("\n✅ Now refresh your dashboard and click any alert!")
print("   It will trigger FRESH analysis with the fixed code.")

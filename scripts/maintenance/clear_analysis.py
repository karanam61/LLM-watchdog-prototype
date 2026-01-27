"""
Clear all stored AI analysis results to force fresh re-analysis
"""
from supabase import create_client
import os
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")

supabase = create_client(url, key)

print("Clearing all analysis results from alerts table...")

# Update all alerts to remove stored analysis
result = supabase.table('alerts').update({
    'analysis': None,
    'verdict': None,
    'confidence': None,
    'reasoning': None,
    'recommendation': None,
    'evidence': None
}).neq('id', '00000000-0000-0000-0000-000000000000').execute()

print(f"[OK] Cleared analysis from {len(result.data)} alerts")
print("\nNow the system will re-analyze alerts when you click them!")

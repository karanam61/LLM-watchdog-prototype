"""Clear ERROR verdicts and reset for re-analysis"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase

print("=" * 80)
print("CLEARING ERROR VERDICTS FOR RE-ANALYSIS")
print("=" * 80)

# Get all alerts with ERROR verdict
response = supabase.table('alerts').select('id, alert_name, ai_verdict, ai_reasoning').eq('ai_verdict', 'ERROR').execute()
error_alerts = response.data

print(f"\nFound {len(error_alerts)} alerts with ERROR verdict")

if error_alerts:
    print("\nClearing AI analysis to force re-processing...")
    
    # Update all ERROR alerts
    result = supabase.table('alerts').update({
        'ai_verdict': None,
        'ai_confidence': None,
        'ai_reasoning': None,
        'ai_evidence': None,
        'ai_recommendation': None,
        'status': 'open'
    }).eq('ai_verdict', 'ERROR').execute()
    
    print(f"[OK] Cleared {len(error_alerts)} alerts")
    print("\nThese alerts will be re-analyzed by the queue processor.")
    print("Wait 30-60 seconds for the background queue to process them.")
else:
    print("\n[OK] No ERROR alerts found")

print("\n" + "=" * 80)

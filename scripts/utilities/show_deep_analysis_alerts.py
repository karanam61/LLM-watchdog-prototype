"""Show which specific alerts have deep analysis"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase

print("=" * 80)
print("ALERTS WITH DEEP AI ANALYSIS (8+ EVIDENCE POINTS)")
print("=" * 80)

# Get all alerts with deep analysis
response = supabase.table('alerts').select('*').order('created_at', desc=True).execute()
alerts = response.data

deep_analysis = []
for alert in alerts:
    evidence = alert.get('ai_evidence') or []
    reasoning = alert.get('ai_reasoning') or ''
    
    if len(evidence) >= 8 and len(reasoning) >= 500:
        deep_analysis.append(alert)

print(f"\nTotal with deep analysis: {len(deep_analysis)}\n")

for i, alert in enumerate(deep_analysis, 1):
    print(f"{i}. {alert['alert_name']}")
    print(f"   ID: {alert['id']}")
    print(f"   Verdict: {alert.get('ai_verdict')} ({alert.get('ai_confidence')})")
    print(f"   Evidence: {len(alert.get('ai_evidence', []))} points")
    print(f"   Reasoning: {len(alert.get('ai_reasoning', ''))} characters")
    print()

print("=" * 80)
print("REFRESH YOUR DASHBOARD to see these updated alerts!")
print("The alert you clicked on will show the new deep analysis.")
print("=" * 80)

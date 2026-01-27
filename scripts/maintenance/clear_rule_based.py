"""Clear rule-based/fallback alerts for proper AI analysis"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase

print("=" * 80)
print("CLEARING RULE-BASED/FALLBACK ALERTS")
print("=" * 80)

# Get all alerts
response = supabase.table('alerts').select('id, alert_name, ai_verdict, ai_reasoning, ai_evidence').execute()
all_alerts = response.data

# Find rule-based alerts
rule_based = []
for alert in all_alerts:
    reasoning = alert.get('ai_reasoning') or ''
    evidence = alert.get('ai_evidence') or []
    
    if 'rule-based' in reasoning.lower() or 'fallback' in reasoning.lower():
        rule_based.append(alert)
    elif alert.get('ai_verdict') and len(evidence) < 5 and len(reasoning) < 200:
        # Shallow analysis
        rule_based.append(alert)

print(f"\nFound {len(rule_based)} alerts with rule-based/shallow analysis:")
for alert in rule_based:
    print(f"  - {alert['alert_name']} ({alert['id'][:8]}...)")

if rule_based:
    print(f"\nClearing these {len(rule_based)} alerts for proper AI re-analysis...")
    
    for alert in rule_based:
        supabase.table('alerts').update({
            'ai_verdict': None,
            'ai_confidence': None,
            'ai_reasoning': None,
            'ai_evidence': None,
            'ai_recommendation': None,
            'status': 'open'
        }).eq('id', alert['id']).execute()
    
    print(f"[OK] Cleared {len(rule_based)} alerts")
else:
    print("\n[OK] No rule-based alerts found")

print("\n" + "=" * 80)

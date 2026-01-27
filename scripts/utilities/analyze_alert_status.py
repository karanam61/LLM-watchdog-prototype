"""Check current state of all alerts in database"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase

print("=" * 80)
print("CHECKING ALL ALERTS STATUS")
print("=" * 80)

# Get all alerts
response = supabase.table('alerts').select('*').order('created_at', desc=False).execute()
alerts = response.data

print(f"\nTotal alerts: {len(alerts)}")

# Categorize alerts
no_verdict = []
error_verdict = []
rule_based = []
proper_ai = []
tokenization_errors = []

for alert in alerts:
    verdict = alert.get('ai_verdict')
    reasoning = alert.get('ai_reasoning', '')
    evidence = alert.get('ai_evidence', [])
    
    if verdict is None:
        no_verdict.append(alert)
    elif verdict == 'ERROR':
        error_verdict.append(alert)
        # Check if it's a tokenization error
        if 'tokenized' in reasoning.lower() or 'tokenization' in reasoning.lower():
            tokenization_errors.append(alert)
    elif 'rule-based' in reasoning.lower() or 'fallback' in reasoning.lower():
        rule_based.append(alert)
    elif len(evidence) >= 5 and len(reasoning) >= 200:
        proper_ai.append(alert)
    else:
        # Shallow AI analysis
        rule_based.append(alert)

print("\n" + "=" * 80)
print("BREAKDOWN")
print("=" * 80)
print(f"No verdict yet: {len(no_verdict)}")
print(f"ERROR verdict: {len(error_verdict)}")
print(f"  - Tokenization errors: {len(tokenization_errors)}")
print(f"Rule-based/Fallback: {len(rule_based)}")
print(f"Proper deep AI analysis: {len(proper_ai)}")

if tokenization_errors:
    print("\n" + "=" * 80)
    print("TOKENIZATION ERROR EXAMPLES")
    print("=" * 80)
    for i, alert in enumerate(tokenization_errors[:3], 1):
        print(f"\n{i}. Alert: {alert['alert_name']}")
        print(f"   ID: {alert['id']}")
        print(f"   Username: {alert.get('username', 'N/A')}")
        print(f"   Hostname: {alert.get('hostname', 'N/A')}")
        print(f"   Source IP: {alert.get('source_ip', 'N/A')}")
        print(f"   Error: {alert.get('ai_reasoning', 'N/A')[:200]}")

if error_verdict:
    print("\n" + "=" * 80)
    print("ERROR VERDICT EXAMPLES (NON-TOKENIZATION)")
    print("=" * 80)
    for i, alert in enumerate([a for a in error_verdict if a not in tokenization_errors][:3], 1):
        print(f"\n{i}. Alert: {alert['alert_name']}")
        print(f"   ID: {alert['id']}")
        print(f"   Error: {alert.get('ai_reasoning', 'N/A')[:200]}")

if rule_based:
    print("\n" + "=" * 80)
    print("RULE-BASED/SHALLOW ANALYSIS EXAMPLES")
    print("=" * 80)
    for i, alert in enumerate(rule_based[:3], 1):
        print(f"\n{i}. Alert: {alert['alert_name']}")
        print(f"   ID: {alert['id']}")
        print(f"   Verdict: {alert.get('ai_verdict')}")
        print(f"   Evidence count: {len(alert.get('ai_evidence', []))}")
        print(f"   Reasoning length: {len(alert.get('ai_reasoning', ''))}")
        print(f"   Reasoning: {alert.get('ai_reasoning', 'N/A')[:200]}")

if proper_ai:
    print("\n" + "=" * 80)
    print("PROPER DEEP AI ANALYSIS EXAMPLES")
    print("=" * 80)
    for i, alert in enumerate(proper_ai[:2], 1):
        print(f"\n{i}. Alert: {alert['alert_name']}")
        print(f"   ID: {alert['id']}")
        print(f"   Verdict: {alert.get('ai_verdict')}")
        print(f"   Confidence: {alert.get('ai_confidence')}")
        print(f"   Evidence count: {len(alert.get('ai_evidence', []))}")
        print(f"   Reasoning length: {len(alert.get('ai_reasoning', ''))}")
        print(f"   First 3 evidence:")
        for e in alert.get('ai_evidence', [])[:3]:
            print(f"     - {e}")

print("\n" + "=" * 80)

"""
Test live AI analysis with real alerts from database
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase

print("=" * 70)
print("TESTING LIVE AI ANALYSIS")
print("=" * 70)

# Get one alert that hasn't been analyzed or has shallow analysis
print("\n[1] Fetching alerts...")
response = supabase.table('alerts').select('*').limit(5).execute()
alerts = response.data

if not alerts:
    print("[ERROR] No alerts found in database")
    sys.exit(1)

print(f"[OK] Found {len(alerts)} alerts")

# Find best candidate for testing
test_alert = None
for alert in alerts:
    reasoning = alert.get('ai_reasoning', '')
    if not reasoning or len(reasoning) < 300 or 'rule-based' in reasoning.lower():
        test_alert = alert
        break

if not test_alert:
    test_alert = alerts[0]  # Just use first one

print(f"\n[2] Selected alert: {test_alert['alert_name']}")
print(f"    Alert ID: {test_alert['id']}")
print(f"    Severity: {test_alert['severity']}")
print(f"    Current verdict: {test_alert.get('ai_verdict', 'None')}")
print(f"    Current reasoning length: {len(test_alert.get('ai_reasoning', ''))}")

# Clear the AI analysis to force re-analysis
print(f"\n[3] Clearing AI analysis to force fresh analysis...")
supabase.table('alerts').update({
    'ai_verdict': None,
    'ai_confidence': None,
    'ai_reasoning': None,
    'ai_evidence': None,
    'ai_recommendation': None,
    'status': 'open'
}).eq('id', test_alert['id']).execute()

print("[OK] AI analysis cleared")

# Wait a moment for queue processing
print("\n[4] Waiting for queue processor to analyze (30 seconds)...")
import time
time.sleep(30)

# Fetch updated alert
print("\n[5] Fetching updated alert...")
updated = supabase.table('alerts').select('*').eq('id', test_alert['id']).execute()
if updated.data:
    result = updated.data[0]
    
    print("\n" + "=" * 70)
    print("ANALYSIS RESULTS")
    print("=" * 70)
    print(f"\nVerdict: {result.get('ai_verdict', 'None')}")
    print(f"Confidence: {result.get('ai_confidence', 'None')}")
    
    evidence = result.get('ai_evidence', [])
    print(f"\nEvidence ({len(evidence)} points):")
    for i, e in enumerate(evidence[:10], 1):
        print(f"  {i}. {e}")
    
    reasoning = result.get('ai_reasoning', '')
    print(f"\nReasoning ({len(reasoning)} characters):")
    print(reasoning[:500] + "..." if len(reasoning) > 500 else reasoning)
    
    recommendation = result.get('ai_recommendation', '')
    print(f"\nRecommendation:")
    print(recommendation)
    
    # Check if it's deep analysis
    print("\n" + "=" * 70)
    print("QUALITY CHECK")
    print("=" * 70)
    
    is_deep = True
    issues = []
    
    if len(evidence) < 5:
        is_deep = False
        issues.append(f"Evidence count too low: {len(evidence)} (need 5+)")
    
    if len(reasoning) < 200:
        is_deep = False
        issues.append(f"Reasoning too short: {len(reasoning)} chars (need 200+)")
    
    if 'rule-based' in reasoning.lower() or 'fallback' in reasoning.lower():
        is_deep = False
        issues.append("Using fallback/rule-based analysis")
    
    if result.get('ai_verdict') is None:
        is_deep = False
        issues.append("No AI verdict - analysis may have failed")
    
    if is_deep:
        print("[OK] DEEP AI ANALYSIS CONFIRMED!")
        print("  - Evidence: {} points".format(len(evidence)))
        print("  - Reasoning: {} characters".format(len(reasoning)))
        print("  - Verdict: {}".format(result.get('ai_verdict')))
    else:
        print("[WARNING] Analysis is NOT deep enough:")
        for issue in issues:
            print(f"  - {issue}")
else:
    print("[ERROR] Could not fetch updated alert")

print("\n" + "=" * 70)

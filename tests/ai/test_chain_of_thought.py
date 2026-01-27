"""Test the chain of thought feature"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.storage.database import supabase

print("=" * 80)
print("TESTING CHAIN OF THOUGHT FEATURE")
print("=" * 80)

# Clear one alert for re-analysis
print("\nClearing 1 alert for chain of thought test...")
response = supabase.table('alerts').select('id, alert_name').limit(1).execute()
if response.data:
    test_alert = response.data[0]
    
    supabase.table('alerts').update({
        'ai_verdict': None,
        'ai_confidence': None,
        'ai_reasoning': None,
        'ai_evidence': None,
        'ai_chain_of_thought': None,
        'ai_recommendation': None,
        'status': 'open'
    }).eq('id', test_alert['id']).execute()
    
    print(f"[OK] Cleared alert: {test_alert['alert_name']}")
    print(f"     ID: {test_alert['id']}")
    print("\nWaiting 30 seconds for AI analysis with chain of thought...")
    
    import time
    time.sleep(30)
    
    # Fetch the analyzed alert
    result = supabase.table('alerts').select('*').eq('id', test_alert['id']).execute()
    if result.data:
        analyzed = result.data[0]
        
        print("\n" + "=" * 80)
        print("CHAIN OF THOUGHT ANALYSIS")
        print("=" * 80)
        
        chain = analyzed.get('ai_chain_of_thought')
        
        if chain and len(chain) > 0:
            print(f"\n[OK] Chain of Thought has {len(chain)} steps:\n")
            
            for step in chain:
                print(f"STEP {step.get('step')}:")
                print(f"  Observation: {step.get('observation')}")
                print(f"  Analysis:    {step.get('analysis')}")
                print(f"  Conclusion:  {step.get('conclusion')}")
                print()
            
            print("=" * 80)
            print("Final Reasoning:")
            print(analyzed.get('ai_reasoning'))
            
            print("\n[SUCCESS] Chain of thought is working!")
        else:
            print("\n[WARNING] No chain of thought found - may still be processing or feature not yet applied")
            print(f"Verdict: {analyzed.get('ai_verdict')}")
            print(f"Evidence count: {len(analyzed.get('ai_evidence', []))}")
    else:
        print("[ERROR] Could not fetch analyzed alert")
else:
    print("[ERROR] No alerts found")

print("\n" + "=" * 80)

"""
Force trigger AI analysis on a real alert from database
This will show us EXACTLY what's happening
"""
from supabase import create_client
import os
from dotenv import load_dotenv
import sys

load_dotenv()

# Import the analyzer
sys.path.insert(0, 'C:\\Users\\karan\\Desktop\\AI Project')
from backend.ai.alert_analyzer_final import AlertAnalyzer

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")
supabase = create_client(url, key)

print("="*70)
print("LIVE ALERT ANALYSIS TEST")
print("="*70)

# Get first alert
result = supabase.table('alerts').select('*').limit(1).execute()

if not result.data:
    print("[ERROR] No alerts in database!")
else:
    alert = result.data[0]
    print(f"\n[TEST] Analyzing: {alert['alert_name']}")
    print(f"  Alert ID: {alert['id']}")
    print(f"  Severity: {alert['severity']}")
    
    # Initialize analyzer
    print("\n[STEP 1] Initializing analyzer...")
    analyzer = AlertAnalyzer()
    
    # Run analysis
    print("\n[STEP 2] Running AI analysis...")
    print("-"*70)
    
    result = analyzer.analyze_alert(alert)
    
    print("-"*70)
    print("\n[RESULT]")
    print(f"  Success: {result.get('success')}")
    print(f"  Verdict: {result.get('verdict')}")
    print(f"  Confidence: {result.get('confidence')}")
    print(f"  Evidence: {len(result.get('evidence', []))} items")
    print(f"  Reasoning: {result.get('reasoning')[:200]}...")
    
    # Check if it used fallback
    if 'fallback' in result.get('reasoning', '').lower() or 'rule-based' in result.get('reasoning', '').lower():
        print("\n[WARNING] Used FALLBACK - AI not actually called!")
    else:
        print("\n[SUCCESS] Real AI analysis!")
        
print("\n" + "="*70)

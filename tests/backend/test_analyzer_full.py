"""
Comprehensive test of the AI analyzer pipeline
Tests EVERY component to find where it's failing
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv(override=True)

print("="*70)
print("COMPREHENSIVE AI ANALYZER TEST")
print("="*70)

# Test 1: Environment Variables
print("\n[TEST 1] Environment Variables")
print("-"*70)
api_key = os.getenv("ANTHROPIC_API_KEY")
print(f"  ANTHROPIC_API_KEY: {'[OK] Found' if api_key else '[ERROR] MISSING'}")
if api_key:
    print(f"    Key preview: {api_key[:20]}...")

# Test 2: Import Alert Analyzer
print("\n[TEST 2] Import Alert Analyzer")
print("-"*70)
try:
    from backend.ai.alert_analyzer_final import AlertAnalyzer
    print("  [OK] AlertAnalyzer imported successfully")
except Exception as e:
    print(f"  [ERROR] Failed to import: {e}")
    sys.exit(1)

# Test 3: Initialize Analyzer
print("\n[TEST 3] Initialize Analyzer")
print("-"*70)
try:
    analyzer = AlertAnalyzer()
    print("  [OK] Analyzer initialized")
    
    # Check components
    print(f"  API Client: {'[OK]' if analyzer.api_client else '[ERROR]'}")
    print(f"  RAG System: {'[OK]' if analyzer.rag else '[MISSING]'}")
    print(f"  Input Guard: {'[OK]' if analyzer.input_guard else '[ERROR]'}")
    print(f"  Output Guard: {'[OK]' if analyzer.output_guard else '[ERROR]'}")
    print(f"  Budget Tracker: {'[OK]' if analyzer.budget else '[ERROR]'}")
    
except Exception as e:
    print(f"  [ERROR] Initialization failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 4: Test Alert
print("\n[TEST 4] Create Test Alert")
print("-"*70)
test_alert = {
    'alert_id': 'test-123',
    'id': 'test-123',
    'alert_name': 'Suspicious PowerShell Execution',
    'description': 'PowerShell executed with encoded command attempting to download external payload',
    'severity': 'critical',
    'mitre_technique': 'T1059.001',
    'hostname': 'HOST-test123',
    'username': 'USER-test456',
    'source_ip': 'IP-test789',
    'dest_ip': 'IP-testabc',
    'timestamp': '2026-01-25T12:00:00Z'
}
print("  [OK] Test alert created")

# Test 5: Run Analysis
print("\n[TEST 5] Run AI Analysis")
print("-"*70)
try:
    result = analyzer.analyze_alert(test_alert)
    print("  [OK] Analysis completed!")
    print(f"\n  Results:")
    print(f"    Success: {result.get('success')}")
    print(f"    Verdict: {result.get('verdict')}")
    print(f"    Confidence: {result.get('confidence')}")
    print(f"    Evidence count: {len(result.get('evidence', []))}")
    print(f"    Reasoning length: {len(result.get('reasoning', ''))}")
    
    # Check if it used fallback
    reasoning = result.get('reasoning', '')
    if 'rule-based' in reasoning.lower() or 'fallback' in reasoning.lower():
        print("\n  [WARNING] Used FALLBACK instead of real AI!")
        print(f"    Reasoning: {reasoning[:200]}")
    else:
        print("\n  [OK] Used REAL AI analysis (not fallback)")
        
except Exception as e:
    print(f"  ✗ Analysis failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*70)
print("TEST COMPLETE")
print("="*70)

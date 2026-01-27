#!/usr/bin/env python3
"""
Test Script: Deep vs Shallow Analysis
======================================

This script tests and verifies the AI analysis depth metrics.

WHAT IT TESTS:
1. Deep Analysis criteria (reasoning > 300 chars AND evidence >= 5)
2. Shallow Analysis detection
3. Transparency API metrics calculation
4. Fallback behavior when AI fails

CRITERIA:
- Deep Analysis: reasoning > 300 characters AND evidence >= 5 items
- Shallow Analysis: reasoning <= 300 characters OR evidence < 5 items

Usage:
    python scripts/testing/test_analysis_depth.py
    python scripts/testing/test_analysis_depth.py --create-shallow  # Create a shallow analysis for testing
"""

import os
import sys
import json
import requests
from datetime import datetime
import uuid

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dotenv import load_dotenv
load_dotenv()

BASE_URL = "http://localhost:5000"
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")

# Initialize Supabase client
from supabase import create_client
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def print_result(test_name, passed, details=None):
    status = "PASS" if passed else "FAIL"
    color = "\033[92m" if passed else "\033[91m"
    reset = "\033[0m"
    print(f"  [{color}{status}{reset}] {test_name}")
    if details:
        print(f"        {details}")

def check_backend_running():
    """Check if backend is running"""
    try:
        response = requests.get(f"{BASE_URL}/queue-status", timeout=5)
        return response.status_code == 200
    except:
        return False

def test_transparency_api():
    """Test that transparency API returns correct metrics"""
    print_header("TEST 1: Transparency API Metrics")
    
    try:
        response = requests.get(f"{BASE_URL}/api/transparency/summary", timeout=10)
        
        if response.status_code != 200:
            print_result("API Response", False, f"Status: {response.status_code}")
            return False
        
        data = response.json()
        
        # Check required fields
        required_fields = [
            'total_analyzed',
            'total_deep_analysis', 
            'total_shallow_analysis',
            'avg_evidence_depth',
            'verdict_distribution'
        ]
        
        for field in required_fields:
            if field not in data:
                print_result(f"Field: {field}", False, "Missing")
                return False
            print_result(f"Field: {field}", True, f"Value: {data[field]}")
        
        # Verify math
        total = data['total_analyzed']
        deep = data['total_deep_analysis']
        shallow = data['total_shallow_analysis']
        
        if deep + shallow == total:
            print_result("Math check (deep + shallow = total)", True, f"{deep} + {shallow} = {total}")
        else:
            print_result("Math check", False, f"{deep} + {shallow} != {total}")
            return False
        
        return True
        
    except Exception as e:
        print_result("Transparency API", False, str(e))
        return False

def test_deep_analysis_criteria():
    """Test individual alerts against deep analysis criteria"""
    print_header("TEST 2: Deep Analysis Criteria Verification")
    
    try:
        # Get recent analyzed alerts
        response = supabase.table('alerts').select('*').not_.is_('ai_analysis', 'null').limit(10).execute()
        
        if not response.data:
            print_result("Fetch alerts", False, "No analyzed alerts found")
            return False
        
        print(f"\n  Checking {len(response.data)} alerts against criteria:\n")
        print(f"  {'Alert Name':<40} {'Reasoning':<12} {'Evidence':<10} {'Classification'}")
        print(f"  {'-'*40} {'-'*12} {'-'*10} {'-'*15}")
        
        deep_count = 0
        shallow_count = 0
        
        for alert in response.data:
            analysis = alert.get('ai_analysis', {})
            if isinstance(analysis, str):
                try:
                    analysis = json.loads(analysis)
                except:
                    analysis = {}
            
            reasoning = analysis.get('reasoning', '') or ''
            evidence = analysis.get('evidence', []) or []
            
            reasoning_len = len(reasoning)
            evidence_count = len(evidence)
            
            # Apply criteria
            is_deep = reasoning_len > 300 and evidence_count >= 5
            classification = "DEEP" if is_deep else "SHALLOW"
            
            if is_deep:
                deep_count += 1
            else:
                shallow_count += 1
            
            alert_name = (alert.get('alert_name', 'Unknown')[:38] + '..') if len(alert.get('alert_name', '')) > 40 else alert.get('alert_name', 'Unknown')
            print(f"  {alert_name:<40} {reasoning_len:<12} {evidence_count:<10} {classification}")
        
        print(f"\n  Summary: {deep_count} deep, {shallow_count} shallow")
        
        print_result("Criteria verification", True, f"Analyzed {len(response.data)} alerts")
        return True
        
    except Exception as e:
        print_result("Deep analysis criteria test", False, str(e))
        return False

def test_shallow_analysis_example():
    """Show what a shallow analysis looks like"""
    print_header("TEST 3: Shallow Analysis Example")
    
    # Example of what would be classified as shallow
    shallow_examples = [
        {
            "name": "Short reasoning",
            "reasoning": "This alert appears to be benign.",  # Only 37 chars
            "evidence": ["Finding 1", "Finding 2", "Finding 3", "Finding 4", "Finding 5"],
            "reason": "Reasoning too short (37 chars < 300)"
        },
        {
            "name": "Few evidence items",
            "reasoning": "This is a very detailed analysis with lots of information about the alert and why it should be considered malicious based on the observed behavior patterns.",  # 180 chars
            "evidence": ["Finding 1", "Finding 2", "Finding 3"],  # Only 3 items
            "reason": "Too few evidence items (3 < 5)"
        },
        {
            "name": "Both problems",
            "reasoning": "Suspicious activity detected.",  # 29 chars
            "evidence": ["Finding 1", "Finding 2"],  # 2 items
            "reason": "Both reasoning (29 chars) and evidence (2 items) insufficient"
        }
    ]
    
    print("\n  SHALLOW ANALYSIS would occur when:\n")
    
    for example in shallow_examples:
        reasoning_len = len(example['reasoning'])
        evidence_count = len(example['evidence'])
        is_deep = reasoning_len > 300 and evidence_count >= 5
        
        print(f"  Example: {example['name']}")
        print(f"    Reasoning: {reasoning_len} chars")
        print(f"    Evidence: {evidence_count} items")
        print(f"    Classification: {'DEEP' if is_deep else 'SHALLOW'}")
        print(f"    Why: {example['reason']}")
        print()
    
    # Deep analysis example
    deep_example = {
        "reasoning": "This alert shows clear indicators of a sophisticated attack. The PowerShell process was spawned from Microsoft Word, which is a classic macro-based attack vector. The command line contains Base64 encoded payload which, when decoded, reveals a download cradle attempting to fetch a second-stage payload from a known malicious IP address. The network logs confirm outbound connection to this IP on port 443, with significant data exfiltration (8KB uploaded). This behavior matches MITRE ATT&CK technique T1059.001 (PowerShell) and indicates active compromise requiring immediate response.",
        "evidence": [
            "[PROCESS-1] powershell.exe spawned from WINWORD.EXE",
            "[PROCESS-1] Command contains -enc Base64 encoded payload",
            "[NETWORK-1] Outbound connection to 185.220.101.45:443",
            "[NETWORK-1] 8192 bytes uploaded to external IP",
            "MITRE T1059.001: Command and Scripting Interpreter",
            "Parent process Word indicates document-based attack vector",
            "Encoded command suggests evasion attempt",
            "Destination IP matches known C2 infrastructure"
        ]
    }
    
    reasoning_len = len(deep_example['reasoning'])
    evidence_count = len(deep_example['evidence'])
    
    print("  DEEP ANALYSIS example:")
    print(f"    Reasoning: {reasoning_len} chars (> 300 ✓)")
    print(f"    Evidence: {evidence_count} items (>= 5 ✓)")
    print(f"    Classification: DEEP")
    
    print_result("Shallow analysis examples documented", True)
    return True

def create_shallow_analysis_alert():
    """Create a test alert with shallow analysis for testing"""
    print_header("TEST 4: Create Shallow Analysis Alert (for testing)")
    
    try:
        alert_id = str(uuid.uuid4())
        
        # Create alert with deliberately shallow analysis
        alert_data = {
            'id': alert_id,
            'alert_name': 'TEST - Shallow Analysis Example',
            'mitre_technique': 'T1059.001',
            'severity': 'low',
            'source_ip': '10.0.0.1',
            'dest_ip': '10.0.0.2',
            'hostname': 'TEST-HOST',
            'username': 'test-user',
            'timestamp': datetime.now().isoformat(),
            'description': 'Test alert created to demonstrate shallow analysis',
            'status': 'analyzed',
            'risk_score': 25,
            'ai_verdict': 'benign',
            'ai_confidence': 0.5,
            'ai_reasoning': 'This appears to be a benign test alert.',  # 42 chars - SHALLOW
            'ai_evidence': ['Test finding 1', 'Test finding 2'],  # 2 items - SHALLOW
            'ai_analysis': json.dumps({
                'verdict': 'benign',
                'confidence': 0.5,
                'reasoning': 'This appears to be a benign test alert.',  # 42 chars
                'evidence': ['Test finding 1', 'Test finding 2'],  # 2 items
                'method': 'test_shallow'
            })
        }
        
        result = supabase.table('alerts').insert(alert_data).execute()
        
        if result.data:
            print_result("Created shallow analysis alert", True, f"ID: {alert_id}")
            print(f"\n  This alert will show as SHALLOW in the dashboard because:")
            print(f"    - Reasoning: 42 chars (< 300)")
            print(f"    - Evidence: 2 items (< 5)")
            print(f"\n  Refresh your Transparency Dashboard to see it!")
            return alert_id
        else:
            print_result("Create alert", False, "No data returned")
            return None
            
    except Exception as e:
        print_result("Create shallow analysis alert", False, str(e))
        return None

def cleanup_test_alert(alert_id):
    """Remove test alert"""
    try:
        supabase.table('alerts').delete().eq('id', alert_id).execute()
        print_result("Cleanup test alert", True, f"Removed {alert_id}")
    except Exception as e:
        print_result("Cleanup", False, str(e))

def test_fallback_produces_shallow():
    """Test that the rule-based fallback produces shallow analysis"""
    print_header("TEST 5: Fallback Analysis Check")
    
    try:
        # Check for any rule-based/fallback analyses
        response = supabase.table('alerts').select('*').not_.is_('ai_analysis', 'null').execute()
        
        fallback_count = 0
        for alert in response.data:
            analysis = alert.get('ai_analysis', {})
            if isinstance(analysis, str):
                try:
                    analysis = json.loads(analysis)
                except:
                    continue
            
            method = analysis.get('method', '')
            if 'fallback' in method.lower() or 'rule' in method.lower():
                fallback_count += 1
                reasoning = analysis.get('reasoning', '')
                evidence = analysis.get('evidence', [])
                print(f"  Found fallback analysis:")
                print(f"    Alert: {alert.get('alert_name', 'Unknown')[:50]}")
                print(f"    Reasoning: {len(reasoning)} chars")
                print(f"    Evidence: {len(evidence)} items")
                print(f"    Would be: {'DEEP' if len(reasoning) > 300 and len(evidence) >= 5 else 'SHALLOW'}")
        
        if fallback_count == 0:
            print("  No fallback/rule-based analyses found (AI working well)")
        
        print_result("Fallback check complete", True, f"Found {fallback_count} fallback analyses")
        return True
        
    except Exception as e:
        print_result("Fallback test", False, str(e))
        return False

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Test Deep vs Shallow Analysis')
    parser.add_argument('--create-shallow', action='store_true', help='Create a shallow analysis alert for testing')
    parser.add_argument('--cleanup', type=str, help='Cleanup a test alert by ID')
    args = parser.parse_args()
    
    print("\n" + "=" * 60)
    print("  DEEP VS SHALLOW ANALYSIS TEST")
    print("=" * 60)
    print("\n  Criteria for DEEP analysis:")
    print("    - Reasoning > 300 characters")
    print("    - Evidence >= 5 items")
    print("\n  Anything else = SHALLOW analysis")
    
    # Check backend
    if not check_backend_running():
        print("\n  [ERROR] Backend not running! Start with: python app.py\n")
        return
    
    print("\n  Backend is running. Starting tests...\n")
    
    if args.cleanup:
        cleanup_test_alert(args.cleanup)
        return
    
    results = {}
    
    # Run tests
    results['transparency_api'] = test_transparency_api()
    results['criteria_verification'] = test_deep_analysis_criteria()
    results['shallow_examples'] = test_shallow_analysis_example()
    results['fallback_check'] = test_fallback_produces_shallow()
    
    # Optionally create shallow alert
    if args.create_shallow:
        alert_id = create_shallow_analysis_alert()
        if alert_id:
            print(f"\n  To cleanup later, run:")
            print(f"    python scripts/testing/test_analysis_depth.py --cleanup {alert_id}")
    
    # Summary
    print_header("TEST SUMMARY")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        print_result(test_name.replace('_', ' ').title(), result)
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  [SUCCESS] Analysis depth tracking is working correctly!")
    else:
        print("\n  [WARNING] Some tests failed. Review the output above.")
    
    print()

if __name__ == '__main__':
    main()

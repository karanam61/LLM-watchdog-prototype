"""
Test script to verify all frontend dashboards are working correctly
"""
import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_endpoints():
    """Test all API endpoints used by the frontend"""
    
    print("\n" + "="*60)
    print("TESTING FRONTEND API ENDPOINTS")
    print("="*60)
    
    tests = {
        "Alerts": "/alerts",
        "System Metrics Dashboard": "/api/monitoring/metrics/dashboard",
        "Metrics History": "/api/monitoring/metrics/history?hours=24",
        "Error Logs": "/api/monitoring/metrics/errors?limit=10",
        "Recent Live Logs": "/api/monitoring/logs/recent?limit=50",
        "Log Categories": "/api/monitoring/logs/categories",
        "RAG Stats": "/api/rag/stats",
        "RAG Collections": "/api/rag/collections/status",
        "Transparency Summary": "/api/transparency/summary"
    }
    
    results = {}
    
    for name, endpoint in tests.items():
        try:
            print(f"\n[TEST] {name}")
            print(f"  Endpoint: {endpoint}")
            
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Status: SUCCESS (200)")
                
                # Print summary of data
                if isinstance(data, dict):
                    print(f"  Keys: {', '.join(data.keys())}")
                elif isinstance(data, list):
                    print(f"  Items: {len(data)}")
                
                results[name] = "PASS"
            else:
                print(f"  Status: FAILED ({response.status_code})")
                print(f"  Error: {response.text[:200]}")
                results[name] = "FAIL"
                
        except requests.exceptions.ConnectionError:
            print(f"  Status: CONNECTION ERROR - Backend not running")
            results[name] = "ERROR"
        except Exception as e:
            print(f"  Status: ERROR - {str(e)}")
            results[name] = "ERROR"
    
    # Test alert-specific endpoints
    print(f"\n[TEST] Alert-Specific Endpoints")
    try:
        alerts_res = requests.get(f"{BASE_URL}/alerts", timeout=5)
        if alerts_res.status_code == 200:
            alerts = alerts_res.json().get('alerts', [])
            if alerts:
                alert_id = alerts[0]['id']
                print(f"  Testing with Alert ID: {alert_id}")
                
                # Test RAG usage
                rag_res = requests.get(f"{BASE_URL}/api/rag/usage/{alert_id}", timeout=5)
                if rag_res.status_code == 200:
                    print(f"  RAG Usage: PASS")
                    results["RAG Usage (Alert)"] = "PASS"
                else:
                    print(f"  RAG Usage: FAIL ({rag_res.status_code})")
                    results["RAG Usage (Alert)"] = "FAIL"
                
                # Test transparency proof
                proof_res = requests.get(f"{BASE_URL}/api/transparency/proof/{alert_id}", timeout=5)
                if proof_res.status_code == 200:
                    print(f"  Transparency Proof: PASS")
                    results["Transparency Proof (Alert)"] = "PASS"
                else:
                    print(f"  Transparency Proof: FAIL ({proof_res.status_code})")
                    results["Transparency Proof (Alert)"] = "FAIL"
            else:
                print(f"  No alerts available for testing")
                results["RAG Usage (Alert)"] = "SKIP"
                results["Transparency Proof (Alert)"] = "SKIP"
    except Exception as e:
        print(f"  Error testing alert-specific endpoints: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v == "PASS")
    failed = sum(1 for v in results.values() if v == "FAIL")
    errors = sum(1 for v in results.values() if v == "ERROR")
    skipped = sum(1 for v in results.values() if v == "SKIP")
    total = len(results)
    
    for name, result in results.items():
        status_symbol = {
            "PASS": "[+]",
            "FAIL": "[-]",
            "ERROR": "[!]",
            "SKIP": "[~]"
        }.get(result, "[?]")
        print(f"{status_symbol} {name}: {result}")
    
    print(f"\nTotal: {total} | Passed: {passed} | Failed: {failed} | Errors: {errors} | Skipped: {skipped}")
    
    if passed == total - skipped:
        print("\nALL TESTS PASSED!")
        return True
    else:
        print("\nSOME TESTS FAILED - Check backend logs")
        return False

if __name__ == "__main__":
    print("\nWaiting 3 seconds for backend to be ready...")
    time.sleep(3)
    
    success = test_endpoints()
    
    if success:
        print("\n" + "="*60)
        print("FRONTEND SHOULD BE READY!")
        print("="*60)
        print("\nAccess the dashboards at:")
        print("  - Analyst Console:     http://localhost:5173/analyst")
        print("  - System Metrics:      http://localhost:5173/performance")
        print("  - System Debug:        http://localhost:5173/debug")
        print("  - RAG Visualization:   http://localhost:5173/rag")
        print("  - AI Transparency:     http://localhost:5173/transparency")
        print("\n" + "="*60)

"""
Test RAG Monitoring API
"""
import requests
import json

print("=" * 80)
print("TESTING RAG MONITORING API")
print("=" * 80)

backend_url = "http://localhost:5000"

# Get a recent alert
print("\n[1] Getting recent alert...")
try:
    response = requests.get(f"{backend_url}/alerts")
    if response.status_code == 200:
        alerts = response.json()
        if alerts:
            alert_id = alerts[0]['id']
            print(f"[OK] Found alert: {alerts[0]['alert_name']}")
            print(f"     ID: {alert_id[:16]}...")
            
            # Test RAG usage endpoint
            print(f"\n[2] Testing /api/rag/usage/{alert_id[:8]}...")
            response = requests.get(f"{backend_url}/api/rag/usage/{alert_id}")
            if response.status_code == 200:
                data = response.json()
                print("[OK] RAG Usage API working!")
                print(f"\nAlert: {data['alert_name']}")
                print(f"\nRAG Queries:")
                for q in data['queries']:
                    status = "[FOUND]" if q['found'] else "[NOT FOUND]"
                    used = "[USED]" if q['used'] else "[UNUSED]"
                    print(f"  {status} {used} {q['source']}")
                print(f"\nStatistics:")
                print(f"  Sources Found: {data['stats']['sources_found']}")
                print(f"  Sources Used: {data['stats']['sources_used']}")
                print(f"  Usage Rate: {data['stats']['usage_rate']:.1f}%")
            else:
                print(f"[FAIL] Status {response.status_code}: {response.text}")
        else:
            print("[WARN] No alerts found")
    else:
        print(f"[FAIL] Status {response.status_code}")
except Exception as e:
    print(f"[ERROR] {e}")

# Test overall RAG stats
print(f"\n[3] Testing /api/rag/stats...")
try:
    response = requests.get(f"{backend_url}/api/rag/stats")
    if response.status_code == 200:
        data = response.json()
        print("[OK] RAG Stats API working!")
        print(f"\nTotal Alerts: {data['total_alerts']}")
        print(f"\nRAG Mentions:")
        for source, count in data['rag_mentions'].items():
            rate = data['rag_usage_rates'][source]
            print(f"  {source.capitalize()}: {count} alerts ({rate:.1f}%)")
    else:
        print(f"[FAIL] Status {response.status_code}: {response.text}")
except Exception as e:
    print(f"[ERROR] {e}")

# Test collections status
print(f"\n[4] Testing /api/rag/collections/status...")
try:
    response = requests.get(f"{backend_url}/api/rag/collections/status")
    if response.status_code == 200:
        data = response.json()
        print("[OK] Collections Status API working!")
        print(f"\nTotal Collections: {data['total_collections']}")
        print(f"Active Collections: {data['active_collections']}")
        print(f"\nCollections:")
        for coll in data['collections']:
            if coll['status'] == 'active':
                count = coll.get('document_count', 'unknown')
                print(f"  [ACTIVE] {coll['name']}: {count} documents")
            else:
                print(f"  [ERROR] {coll['name']}: {coll.get('error', 'unknown error')}")
    else:
        print(f"[FAIL] Status {response.status_code}: {response.text}")
except Exception as e:
    print(f"[ERROR] {e}")

print("\n" + "=" * 80)
print("RAG MONITORING API TEST COMPLETE")
print("=" * 80)
print("\nAvailable RAG endpoints:")
print("  GET /api/rag/usage/<alert_id> - Detailed RAG usage for specific alert")
print("  GET /api/rag/stats - Overall RAG statistics")
print("  GET /api/rag/collections/status - RAG collection health")
print("=" * 80)

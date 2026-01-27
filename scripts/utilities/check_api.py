"""Test backend on correct port"""
import requests

for port in [5000, 5001]:
    try:
        print(f"\nTesting port {port}...")
        response = requests.get(f"http://localhost:{port}/alerts", timeout=3)
        if response.status_code == 200:
            data = response.json()
            print(f"[OK] Backend responding on port {port}!")
            print(f"[OK] Got {data.get('count', len(data))} alerts")
            
            # Show first alert with AI analysis
            alerts = data.get('alerts', data)
            if alerts and len(alerts) > 0:
                first = alerts[0]
                print(f"\nFirst Alert:")
                print(f"  Name: {first.get('alert_name')}")
                print(f"  Verdict: {first.get('ai_verdict')}")
                print(f"  Confidence: {first.get('ai_confidence')}")
                print(f"  Evidence count: {len(first.get('ai_evidence', []))}")
                print(f"  Reasoning length: {len(first.get('ai_reasoning', ''))}")
            break
    except Exception as e:
        print(f"[ERROR] Port {port}: {e}")

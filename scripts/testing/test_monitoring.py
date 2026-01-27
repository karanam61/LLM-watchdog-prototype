"""
Test the monitoring system - Shows both metrics and live logs
"""
import requests
import time

print("=" * 80)
print("TESTING MONITORING SYSTEM")
print("=" * 80)

backend_url = "http://localhost:5000"

print("\n[TEST 1] System Metrics Dashboard")
print("-" * 80)
try:
    response = requests.get(f"{backend_url}/api/monitoring/metrics/dashboard")
    if response.status_code == 200:
        data = response.json()
        print("[OK] Metrics endpoint responding")
        print(f"\nSystem Metrics:")
        print(f"  CPU: {data['system']['cpu_percent']:.1f}%")
        print(f"  Memory: {data['system']['memory_used_gb']:.2f} GB ({data['system']['memory_percent']:.1f}%)")
        print(f"  Uptime: {data['system']['uptime_seconds']:.0f}s")
        
        print(f"\nSession Stats:")
        print(f"  Total Alerts: {data['session']['total_alerts']}")
        print(f"  Total API Calls: {data['session']['total_api_calls']}")
        print(f"  Total Cost: ${data['session']['total_cost']:.4f}")
        print(f"  Success Rate: {data['session']['success_rate']:.1f}%")
        print(f"  Alerts/Minute: {data['session']['alerts_per_minute']}")
    else:
        print(f"[FAIL] Status {response.status_code}")
except Exception as e:
    print(f"[ERROR] {e}")

print("\n[TEST 2] Live Operation Logs")
print("-" * 80)
try:
    response = requests.get(f"{backend_url}/api/monitoring/logs/recent?limit=10")
    if response.status_code == 200:
        data = response.json()
        print(f"[OK] Logs endpoint responding - {data['count']} operations")
        
        print("\nRecent Operations:")
        for i, log in enumerate(data['logs'][-5:], 1):
            status_icon = {'success': '[OK]', 'error': '[FAIL]', 'warning': '[WARN]'}.get(log['status'], '[INFO]')
            duration = f" ({log['duration']:.2f}s)" if log['duration'] else ""
            print(f"\n{i}. {status_icon} [{log['category']}] {log['operation']}{duration}")
            print(f"   {log['explanation']}")
    else:
        print(f"[FAIL] Status {response.status_code}")
except Exception as e:
    print(f"[ERROR] {e}")

print("\n[TEST 3] Log Categories")
print("-" * 80)
try:
    response = requests.get(f"{backend_url}/api/monitoring/logs/categories")
    if response.status_code == 200:
        data = response.json()
        print("[OK] Available log categories:")
        for key, desc in data['categories'].items():
            print(f"  {key}: {desc}")
    else:
        print(f"[FAIL] Status {response.status_code}")
except Exception as e:
    print(f"[ERROR] {e}")

print("\n[TEST 4] Filtered Logs (AI operations only)")
print("-" * 80)
try:
    response = requests.get(f"{backend_url}/api/monitoring/logs/recent?category=AI&limit=5")
    if response.status_code == 200:
        data = response.json()
        print(f"[OK] Found {data['count']} AI operations")
        for log in data['logs']:
            print(f"  - {log['operation']}: {log['explanation']}")
    else:
        print(f"[FAIL] Status {response.status_code}")
except Exception as e:
    print(f"[ERROR] {e}")

print("\n" + "=" * 80)
print("MONITORING SYSTEM TEST COMPLETE")
print("=" * 80)
print("\nEndpoints ready for frontend:")
print("  Metrics: /api/monitoring/metrics/dashboard")
print("  Metrics History: /api/monitoring/metrics/history")
print("  Live Logs: /api/monitoring/logs/recent")
print("  Live Stream: /api/monitoring/logs/stream (SSE)")
print("  Search: /api/monitoring/logs/search (POST)")
print("\n" + "=" * 80)

"""Test the Debug Dashboard API endpoints"""
import urllib.request
import json

print("Testing Debug Dashboard API...")

# Test 1: Get recent logs
try:
    url = 'http://localhost:5000/api/monitoring/logs/recent'
    response = urllib.request.urlopen(url)
    data = json.loads(response.read().decode())
    print(f"\n[1] /api/monitoring/logs/recent:")
    print(f"    operations count: {len(data.get('operations', []))}")
    print(f"    categories: {data.get('categories', [])}")
    print(f"    debug_logger_id: {data.get('debug_logger_id', 'NOT FOUND')}")
    if data.get('operations'):
        print(f"    First operation: {data['operations'][0]}")
    print(f"    Full response: {json.dumps(data, indent=2)[:500]}")
except Exception as e:
    print(f"    ERROR: {e}")

# Test 2: Get categories
try:
    url = 'http://localhost:5000/api/monitoring/logs/categories'
    response = urllib.request.urlopen(url)
    data = json.loads(response.read().decode())
    print(f"\n[2] /api/monitoring/logs/categories:")
    print(f"    categories: {data}")
except Exception as e:
    print(f"    ERROR: {e}")

print("\nDone!")

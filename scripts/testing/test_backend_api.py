"""Quick test to check if backend API is responding"""
import requests
import time

backend_url = "http://localhost:5001"

print("Testing backend API...")
try:
    response = requests.get(f"{backend_url}/alerts", timeout=5)
    print(f"[OK] Backend responding: Status {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"[OK] Got {len(data)} alerts from API")
except requests.exceptions.ConnectionError:
    print("[ERROR] Backend not responding - connection refused")
except requests.exceptions.Timeout:
    print("[ERROR] Backend timeout")
except Exception as e:
    print(f"[ERROR] {e}")

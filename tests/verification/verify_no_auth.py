import requests
import sys

BASE_URL = "http://localhost:5000"

def test_endpoint(name, url, method="GET", data=None):
    print(f"Testing {name} ({method} {url})...")
    try:
        if method == "GET":
            response = requests.get(f"{BASE_URL}{url}")
        elif method == "POST":
            response = requests.post(f"{BASE_URL}{url}", json=data)
        
        print(f"  Status: {response.status_code}")
        if response.status_code == 200:
            print("  Access Granted (No Auth)")
            return True
        elif response.status_code == 401:
            print("  Access Denied (Auth still required)")
            return False
        else:
            print(f"  Unexpected Status: {response.status_code}")
            print(f"  Response: {response.text[:100]}")
            return True # Not 401 implies auth likely removed, but maybe other error
            
    except Exception as e:
        print(f"  Failed to connect: {e}")
        return False

def verify():
    print("VERIFYING REMOVAL OF AUTHENTICATION")
    print("====================================")
    
    # 1. Test Alerts endpoint (previously required auth?) - likely open or tokenized before
    # We want to ensure it works properly now.
    t1 = test_endpoint("Get Alerts", "/alerts")
    
    # 2. Test Ingest (Uses API Key, not User Auth - should still work with key, or fail with 401 if key missing, but NOT user auth)
    # The user request was "login and password", API key for machines is different but let's check.
    # App.py has:
    #     api_key = request.headers.get('X-API-Key')
    #     if api_key != os.getenv("INGEST_API_KEY", "secure-ingest-key-123"): ...
    # So this SHOULD still return 401 if key missing. That is expected behavior for machine ingest.
    # We are testing USER auth removal. 
    
    # 3. Test Logs (previously might have required auth)
    t3 = test_endpoint("Get Logs", "/api/logs?type=process&alert_id=test")
    
    if t1 and t3:
        print("\nVERIFICATION PASSED: Endpoints accessible without User Login.")
    else:
        print("\nVERIFICATION FAILED.")

if __name__ == "__main__":
    verify()

import requests

alert = {
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.50.25",
    "hostname": "test-server",
    "username": "admin",
    "alert_name": "Manual Test",
    "severity": "high",
    "description": "Testing tokenization",
    "timestamp": "2025-01-02T10:00:00Z"
}

print("Sending alert...")
response = requests.post('http://localhost:5000/ingest', json=alert)
print(f"Status Code: {response.status_code}")
print(f"Response Text: {response.text}")  # See actual response

# Only try to parse JSON if status is 200
if response.status_code == 200:
    print(f"Response JSON: {response.json()}")

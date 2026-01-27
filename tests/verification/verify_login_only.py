import requests
import json
import time

LOG_FILE = "login_status.txt"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(str(msg) + "\n")

def check():
    url = "http://localhost:5000/api/login"
    log("Checking login...")
    try:
        resp = requests.post(url, json={"username": "analyst", "password": "analyst123"}, timeout=5)
        log(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            log("SUCCESS")
        elif resp.status_code == 401:
            log("FAILED_AUTH")
        else:
            log(f"FAILED_OTHER (Status: {resp.status_code}, Text: {resp.text})")
    except Exception as e:
        log(f"ERROR: {e}")

if __name__ == "__main__":
    check()

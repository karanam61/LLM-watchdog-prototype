#!/usr/bin/env python3
"""
Queue all pending alerts for AI analysis.
Run this after test scripts to trigger processing.
"""

import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_SERVICE_KEY') or os.getenv('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

BASE_URL = "http://localhost:5000"
API_KEY = os.getenv('INGEST_API_KEY', 'secure-ingest-key-123')

print("="*60)
print("QUEUEING PENDING ALERTS FOR ANALYSIS")
print("="*60)

# Get alerts that haven't been analyzed yet
response = supabase.table('alerts').select('*').is_('ai_verdict', 'null').execute()
pending = response.data

print(f"Found {len(pending)} pending alerts")

if not pending:
    print("No pending alerts to queue.")
    exit(0)

# Re-ingest each alert to add it to the queue
headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
queued = 0

for alert in pending:
    try:
        # Send to /ingest to route through queue
        payload = {
            "alert_name": alert.get('alert_name'),
            "severity": alert.get('severity', 'medium'),
            "description": alert.get('description', ''),
            "source_ip": alert.get('source_ip'),
            "dest_ip": alert.get('dest_ip'),
            "hostname": alert.get('hostname'),
            "username": alert.get('username'),
            "mitre_technique": alert.get('mitre_technique'),
            "existing_id": alert.get('id')  # Flag to update existing
        }
        
        # For now, just trigger reanalyze endpoint if it exists
        resp = requests.post(
            f"{BASE_URL}/api/alerts/{alert['id']}/reanalyze",
            headers=headers,
            timeout=5
        )
        
        if resp.status_code == 200:
            queued += 1
            print(f"  [QUEUED] {alert['alert_name'][:50]}")
        else:
            print(f"  [SKIP] {alert['alert_name'][:50]} - {resp.status_code}")
            
    except Exception as e:
        print(f"  [ERROR] {alert['alert_name'][:30]} - {e}")

print("-"*60)
print(f"Queued: {queued}/{len(pending)} alerts")
print("Alerts should now be processing. Check the backend logs.")
print("="*60)

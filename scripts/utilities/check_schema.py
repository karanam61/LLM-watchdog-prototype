"""
Check what columns actually exist in alerts table
"""
from supabase import create_client
import os
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")

supabase = create_client(url, key)

print("Fetching one alert to see the actual columns...")

# Get one alert to see columns
result = supabase.table('alerts').select('*').limit(1).execute()

if result.data:
    print("\nColumns in alerts table:")
    for key in result.data[0].keys():
        print(f"  - {key}")
    
    print("\n\nSample alert data:")
    alert = result.data[0]
    print(f"  ID: {alert.get('id')}")
    print(f"  Alert Name: {alert.get('alert_name')}")
    print(f"  Status: {alert.get('status')}")
    print(f"  Verdict: {alert.get('verdict')}")
    print(f"  Reasoning: {alert.get('reasoning', 'N/A')[:100]}...")
else:
    print("No alerts found!")

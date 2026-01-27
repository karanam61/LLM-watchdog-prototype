"""
STEP-BY-STEP VERIFICATION: Frontend-Backend Connection
Goal: Verify logs display correctly in AnalystDashboard
"""

from backend.storage.database import supabase
import json

print("\n" + "="*60)
print("STEP 1: CHECK DATABASE STATE")
print("="*60)

# 1. Count alerts
alerts_res = supabase.table('alerts').select('*', count='exact').limit(5).execute()
alert_count = len(alerts_res.data) if alerts_res.data else 0
print(f"\n✓ Total Alerts in DB: {alert_count}")

if alert_count == 0:
    print("❌ NO ALERTS FOUND. Need to generate test data first.")
    exit(1)

# 2. Pick first alert
first_alert = alerts_res.data[0]
alert_id = first_alert['id']
alert_name = first_alert['alert_name']

print(f"\n✓ Sample Alert:")
print(f"   ID: {alert_id}")
print(f"   Name: {alert_name}")
print(f"   Source IP: {first_alert.get('source_ip', 'N/A')}")
print(f"   Hostname: {first_alert.get('hostname', 'N/A')}")

# 3. Check logs for this alert
print(f"\n" + "="*60)
print(f"STEP 2: CHECK LOGS FOR ALERT {alert_id}")
print("="*60)

log_types = {
    'network_logs': 'Network',
    'process_logs': 'Process',
    'file_activity_logs': 'File',
    'windows_event_logs': 'Windows'
}

total_logs = 0
for table, label in log_types.items():
    res = supabase.table(table).select('*', count='exact').eq('alert_id', alert_id).execute()
    count = len(res.data) if res.data else 0
    total_logs += count
    
    status = "✓" if count > 0 else "⚠️"
    print(f"{status} {label} Logs: {count}")
    
    if count > 0 and res.data:
        print(f"   Sample: {res.data[0]}")

print(f"\n{'='*60}")
print(f"TOTAL LOGS FOR THIS ALERT: {total_logs}")
print(f"{'='*60}")

if total_logs == 0:
    print("\n❌ PROBLEM FOUND: Alert has NO associated logs!")
    print("   This is why Investigation panel is empty.")
    print("\n   SOLUTION: Run generate_all_alerts.py to create proper test data")
else:
    print(f"\n✅ SUCCESS: Alert has {total_logs} logs")
    print("   Logs should display in frontend Investigation panel")

# 4. Test API endpoint simulation
print(f"\n" + "="*60)
print("STEP 3: SIMULATE FRONTEND API CALL")
print("="*60)

from backend.storage.database import query_network_logs, query_process_logs

network = query_network_logs(alert_id)
process = query_process_logs(alert_id)

print(f"\nAPI: /api/logs?type=network&alert_id={alert_id}")
print(f"   Would return: {len(network)} logs")

print(f"\nAPI: /api/logs?type=process&alert_id={alert_id}")
print(f"   Would return: {len(process)} logs")

# 5. Check if tokenized
print(f"\n" + "="*60)
print("STEP 4: VERIFY TOKENIZATION")
print("="*60)

if first_alert.get('source_ip', '').startswith(('IP-', 'TOKEN-')):
    print("✓ Data is TOKENIZED in DB (correct)")
    print(f"   Example: {first_alert.get('source_ip')}")
else:
    print("⚠️  Data is NOT tokenized (might be raw)")

print("\n" + "="*60)
print("NEXT STEPS:")
print("="*60)
print("1. If logs = 0: Run 'python backend/scripts/generate_all_alerts.py --limit 3'")
print("2. Start backend: 'python app.py'")
print("3. Start frontend: 'cd soc-dashboard && npm run dev'")
print("4. Open http://localhost:5173")
print("5. Click an alert to expand")
print("6. Click 'Process Logs' or 'Network Logs' tab")
print("="*60)

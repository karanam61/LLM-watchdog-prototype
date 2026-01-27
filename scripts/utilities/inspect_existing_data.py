"""
SUPABASE DATA INSPECTOR
==========================
Checks your 33 existing alerts and their log associations
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from backend.storage.database import supabase

print("="*70)
print("INSPECTING EXISTING SUPABASE DATA")
print("="*70)

# ============================================================================
# STEP 1: Fetch All Alerts
# ============================================================================
print("\n[STEP 1] Fetching all alerts...")

try:
    result = supabase.table('alerts').select('*').order('created_at', desc=True).execute()
    alerts = result.data
    print(f"[OK] Found {len(alerts)} alerts in database")
except Exception as e:
    print(f"[ERROR] Failed to fetch alerts: {e}")
    sys.exit(1)

# ============================================================================
# STEP 2: Analyze Each Alert
# ============================================================================
print("\n[STEP 2] Checking log associations for each alert...")
print("-" * 70)

log_types = [
    ('process_logs', 'Process'),
    ('network_logs', 'Network'),
    ('file_activity_logs', 'File'),
    ('windows_event_logs', 'Windows')
]

alerts_with_logs = 0
alerts_without_logs = 0
orphaned_alerts = []

for i, alert in enumerate(alerts, 1):
    alert_id = alert['id']
    alert_name = alert['alert_name'][:40]
    ai_verdict = alert.get('ai_verdict') or 'PENDING'
    status = alert.get('status') or 'open'
    
    # Count logs for this alert
    total_logs = 0
    log_breakdown = {}
    
    for table, name in log_types:
        try:
            log_result = supabase.table(table).select('*').eq('alert_id', alert_id).execute()
            count = len(log_result.data)
            log_breakdown[name] = count
            total_logs += count
        except Exception as e:
            log_breakdown[name] = f"Error: {e}"
    
    # Display result
    if total_logs > 0:
        alerts_with_logs += 1
        print(f"\n[OK] [{i:2d}] {alert_name}")
        print(f"    ID: {alert_id[:16]}...")
        print(f"    AI: {ai_verdict:<12} | Status: {status}")
        print(f"    Logs: {total_logs} total")
        for name, count in log_breakdown.items():
            if isinstance(count, int) and count > 0:
                print(f"      - {name}: {count}")
    else:
        alerts_without_logs += 1
        orphaned_alerts.append({
            'id': alert_id,
            'name': alert_name,
            'mitre': alert.get('mitre_technique', 'N/A'),
            'severity': alert.get('severity_class', 'N/A')
        })
        print(f"\n[WARNING] [{i:2d}] {alert_name}")
        print(f"    ID: {alert_id[:16]}...")
        print(f"    [!] NO LOGS FOUND (Investigation panel will be empty)")

# ============================================================================
# STEP 3: Summary & Recommendations
# ============================================================================
print("\n" + "="*70)
print("SUMMARY")
print("="*70)

print(f"\nAlert Statistics:")
print(f"  Total Alerts:           {len(alerts)}")
print(f"  Alerts WITH logs:       {alerts_with_logs} [OK]")
print(f"  Alerts WITHOUT logs:    {alerts_without_logs} [WARNING]")

if alerts_without_logs > 0:
    print(f"\n[WARNING] {alerts_without_logs} alerts have NO associated logs!")
    print(f"   These will show empty Investigation panels.")
    
    print(f"\nORPHANED ALERTS (No logs):")
    for i, orphan in enumerate(orphaned_alerts[:10], 1):  # Show first 10
        print(f"  {i}. {orphan['name']}")
        print(f"     ID: {orphan['id'][:16]}...")
        print(f"     MITRE: {orphan['mitre']} | Severity: {orphan['severity']}")
    
    if len(orphaned_alerts) > 10:
        print(f"  ... and {len(orphaned_alerts) - 10} more")

# ============================================================================
# STEP 4: AI Analysis Status
# ============================================================================
print("\n" + "="*70)
print("AI ANALYSIS STATUS")
print("="*70)

ai_status = {
    'analyzed': 0,
    'pending': 0,
    'error': 0,
    'skipped': 0
}

for alert in alerts:
    verdict = alert.get('ai_verdict')
    if verdict in ['MALICIOUS', 'BENIGN', 'SUSPICIOUS']:
        ai_status['analyzed'] += 1
    elif verdict in ['ERROR']:
        ai_status['error'] += 1
    elif verdict in ['SKIPPED']:
        ai_status['skipped'] += 1
    else:
        ai_status['pending'] += 1

print(f"\n  [OK] Analyzed:  {ai_status['analyzed']}")
print(f"  [WAIT] Pending:   {ai_status['pending']}")
print(f"  [ERROR] Error:     {ai_status['error']}")
print(f"  [SKIP] Skipped:   {ai_status['skipped']}")

if ai_status['pending'] > 0:
    print(f"\n[INFO] {ai_status['pending']} alerts are waiting for AI analysis.")
    print(f"   These will be processed when backend starts.")

# ============================================================================
# STEP 5: Recommendations
# ============================================================================
print("\n" + "="*70)
print("RECOMMENDATIONS")
print("="*70)

if alerts_with_logs >= 5:
    print("\n[OK] You have enough alerts with logs to test the system!")
    print("\nNext Steps:")
    print("  1. Start backend:  py app.py")
    print("  2. Start frontend: cd soc-dashboard && npm run dev")
    print("  3. Open browser:   http://localhost:5173")
    print("  4. Click alerts with logs to view Investigation panel")
    print(f"  5. Wait for AI analysis on {ai_status['pending']} pending alerts")
    
elif alerts_without_logs > 20:
    print("\n[WARNING] Most alerts don't have logs!")
    print("\nSOLUTIONS:")
    print("\n  Option 1: Generate NEW test data with guaranteed logs")
    print("    py scripts/data/generate_test_data.py")
    print("\n  Option 2: Clear old data and start fresh")
    print("    (Delete alerts in Supabase, then run scripts/data/generate_test_data.py)")

else:
    print("\n[OK] System looks good!")
    print(f"   {alerts_with_logs} alerts have logs and will work fine.")
    
    if alerts_without_logs > 0:
        print(f"\n[INFO] {alerts_without_logs} orphaned alerts detected")
        print(f"   These won't show logs but won't break the system")

# ============================================================================
# STEP 6: Sample Alerts for Testing
# ============================================================================
print("\n" + "="*70)
print("SAMPLE ALERTS FOR TESTING")
print("="*70)

print("\nAlerts you can click to see logs (first 5):")
tested = 0
for alert in alerts:
    if tested >= 5:
        break
    
    alert_id = alert['id']
    
    # Quick check for logs
    has_logs = False
    log_count = 0
    try:
        net_logs = supabase.table('network_logs').select('id').eq('alert_id', alert_id).execute()
        proc_logs = supabase.table('process_logs').select('id').eq('alert_id', alert_id).execute()
        log_count = len(net_logs.data) + len(proc_logs.data)
        if log_count > 0:
            has_logs = True
    except:
        pass
    
    if has_logs:
        tested += 1
        icon = "[OK]" if has_logs else "[NO LOGS]"
        print(f"  {icon} {alert['alert_name'][:50]} ({log_count} logs)")

print("\n" + "="*70)
print(f"INSPECTION COMPLETE - {alerts_with_logs} alerts ready to use")
print("="*70 + "\n")

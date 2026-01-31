#!/usr/bin/env python3
"""
Test Script for New AI Features
================================
Tests the structured prompting, systematic questions, and feedback loop.

Sends REALISTIC alerts with correlated forensic logs.

Usage:
    python scripts/test_new_features.py --url https://your-railway-url.up.railway.app
    python scripts/test_new_features.py --url http://localhost:5000
"""

import requests
import json
import time
import argparse
from datetime import datetime, timedelta

# =============================================================================
# REALISTIC TEST SCENARIOS
# =============================================================================

SCENARIOS = [
    {
        "name": "BENIGN - IT Admin PowerShell",
        "alert": {
            "alert_name": "PowerShell Execution Detected",
            "severity": "medium",
            "source_ip": "10.0.1.50",
            "dest_ip": "10.0.1.10",
            "hostname": "WS-IT-ADMIN-01",
            "username": "admin_jsmith",
            "description": "PowerShell.exe executed with command-line arguments",
            "timestamp": datetime.now().isoformat()
        },
        "logs": {
            "process_logs": [
                {
                    "process_name": "powershell.exe",
                    "parent_process": "explorer.exe",
                    "command_line": "powershell.exe -Command Get-ADUser -Filter * | Export-CSV users.csv",
                    "user": "admin_jsmith",
                    "timestamp": datetime.now().isoformat(),
                    "pid": 4521,
                    "signature": "Microsoft Windows Publisher"
                }
            ],
            "network_logs": [
                {
                    "src_ip": "10.0.1.50",
                    "dst_ip": "10.0.1.10",
                    "dst_port": 389,
                    "protocol": "LDAP",
                    "bytes_sent": 1024,
                    "timestamp": datetime.now().isoformat()
                }
            ],
            "windows_logs": [
                {
                    "event_id": 4624,
                    "event_type": "Logon Success",
                    "user": "admin_jsmith",
                    "logon_type": 2,
                    "workstation": "WS-IT-ADMIN-01",
                    "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat()
                }
            ]
        },
        "expected_verdict": "benign"
    },
    {
        "name": "MALICIOUS - Credential Dumping",
        "alert": {
            "alert_name": "LSASS Memory Access Detected",
            "severity": "critical",
            "source_ip": "10.0.5.120",
            "dest_ip": "10.0.5.120",
            "hostname": "SRV-FINANCE-DB",
            "username": "svc_backup",
            "description": "Process accessed LSASS memory - potential credential theft",
            "timestamp": datetime.now().isoformat()
        },
        "logs": {
            "process_logs": [
                {
                    "process_name": "procdump64.exe",
                    "parent_process": "cmd.exe",
                    "command_line": "procdump64.exe -ma lsass.exe lsass.dmp",
                    "user": "svc_backup",
                    "timestamp": datetime.now().isoformat(),
                    "pid": 8832,
                    "signature": "Unsigned"
                },
                {
                    "process_name": "cmd.exe",
                    "parent_process": "powershell.exe",
                    "command_line": "cmd.exe /c procdump64.exe -ma lsass.exe",
                    "user": "svc_backup",
                    "timestamp": (datetime.now() - timedelta(seconds=30)).isoformat(),
                    "pid": 7720
                }
            ],
            "file_logs": [
                {
                    "file_path": "C:\\Windows\\Temp\\lsass.dmp",
                    "action": "CREATE",
                    "size_bytes": 52428800,
                    "user": "svc_backup",
                    "timestamp": datetime.now().isoformat()
                }
            ],
            "network_logs": [
                {
                    "src_ip": "10.0.5.120",
                    "dst_ip": "185.234.72.19",
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "bytes_sent": 52000000,
                    "timestamp": (datetime.now() + timedelta(minutes=2)).isoformat()
                }
            ],
            "windows_logs": [
                {
                    "event_id": 10,
                    "event_type": "Process Access",
                    "source_process": "procdump64.exe",
                    "target_process": "lsass.exe",
                    "access_mask": "0x1FFFFF",
                    "timestamp": datetime.now().isoformat()
                }
            ]
        },
        "expected_verdict": "malicious"
    },
    {
        "name": "SUSPICIOUS - Unusual Service Account Activity",
        "alert": {
            "alert_name": "Service Account Interactive Logon",
            "severity": "high",
            "source_ip": "10.0.3.88",
            "dest_ip": "10.0.3.88",
            "hostname": "WS-SALES-042",
            "username": "svc_sqlreport",
            "description": "Service account used for interactive RDP session",
            "timestamp": datetime.now().isoformat()
        },
        "logs": {
            "windows_logs": [
                {
                    "event_id": 4624,
                    "event_type": "Logon Success",
                    "user": "svc_sqlreport",
                    "logon_type": 10,
                    "source_ip": "192.168.1.200",
                    "workstation": "WS-SALES-042",
                    "timestamp": datetime.now().isoformat()
                },
                {
                    "event_id": 4672,
                    "event_type": "Special Privileges Assigned",
                    "user": "svc_sqlreport",
                    "privileges": "SeDebugPrivilege, SeBackupPrivilege",
                    "timestamp": datetime.now().isoformat()
                }
            ],
            "process_logs": [
                {
                    "process_name": "mstsc.exe",
                    "parent_process": "explorer.exe",
                    "command_line": "mstsc.exe /v:WS-SALES-042",
                    "user": "unknown",
                    "timestamp": (datetime.now() - timedelta(minutes=1)).isoformat()
                }
            ]
        },
        "expected_verdict": "suspicious"
    }
]


def seed_logs_for_alert(base_url: str, alert_id: int, logs: dict):
    """Seed forensic logs into database for the alert."""
    # This would normally insert into Supabase directly
    # For now, we'll note that logs should be seeded
    print(f"   📝 Logs to seed for alert {alert_id}:")
    for log_type, entries in logs.items():
        print(f"      - {log_type}: {len(entries)} entries")


def send_alert(base_url: str, alert: dict) -> dict:
    """Send an alert to the ingest endpoint."""
    url = f"{base_url}/ingest"
    try:
        response = requests.post(url, json=alert, timeout=30)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def submit_feedback(base_url: str, alert_id: int, verdict: str, notes: str) -> dict:
    """Submit analyst feedback on an alert."""
    url = f"{base_url}/api/alerts/{alert_id}/feedback"
    try:
        response = requests.post(url, json={
            "analyst_verdict": verdict,
            "analyst_notes": notes
        }, timeout=10)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def get_feedback_stats(base_url: str) -> dict:
    """Get AI accuracy statistics."""
    url = f"{base_url}/api/feedback/stats"
    try:
        response = requests.get(url, timeout=10)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def check_health(base_url: str) -> dict:
    """Check system health including new components."""
    url = f"{base_url}/api/health"
    try:
        response = requests.get(url, timeout=10)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def run_tests(base_url: str, include_feedback: bool = True):
    """Run all test scenarios."""
    print("\n" + "="*70)
    print("🧪 AI-SOC WATCHDOG - NEW FEATURES TEST")
    print("="*70)
    
    # 1. Health Check
    print("\n📊 Step 1: Health Check")
    health = check_health(base_url)
    print(f"   Status: {health.get('status', 'unknown')}")
    components = health.get('components', {})
    for comp, status in components.items():
        icon = "✅" if status in ['running', 'connected', 'ready', 'configured'] else "⚠️"
        print(f"   {icon} {comp}: {status}")
    
    # 2. Send Test Alerts
    print("\n📨 Step 2: Sending Test Alerts")
    alert_ids = []
    
    for scenario in SCENARIOS:
        print(f"\n   🎯 {scenario['name']}")
        result = send_alert(base_url, scenario['alert'])
        
        if 'error' in result:
            print(f"      ❌ Error: {result['error']}")
            continue
        
        alert_id = result.get('alert_id')
        alert_ids.append({
            'id': alert_id,
            'expected': scenario['expected_verdict'],
            'name': scenario['name']
        })
        
        print(f"      ✅ Alert ID: {alert_id}")
        print(f"      📋 MITRE: {result.get('mitre_technique', 'N/A')}")
        print(f"      ⚡ Severity: {result.get('severity', 'N/A')}")
        
        # Note about logs
        seed_logs_for_alert(base_url, alert_id, scenario.get('logs', {}))
    
    # 3. Wait for AI processing
    print("\n⏳ Step 3: Waiting for AI Analysis (30 seconds)...")
    time.sleep(30)
    
    # 4. Test Feedback Loop
    if include_feedback and alert_ids:
        print("\n📝 Step 4: Testing Feedback Loop")
        
        # Submit feedback on first alert (should be benign)
        if len(alert_ids) >= 1:
            alert = alert_ids[0]
            print(f"\n   Submitting feedback for Alert {alert['id']}...")
            feedback_result = submit_feedback(
                base_url, 
                alert['id'], 
                "benign", 
                "Confirmed IT admin running standard AD query during business hours"
            )
            if 'error' in feedback_result:
                print(f"      ❌ Error: {feedback_result['error']}")
            else:
                print(f"      ✅ Feedback submitted")
                print(f"      AI was correct: {feedback_result.get('ai_was_correct', 'N/A')}")
        
        # Submit feedback on second alert (should be malicious)
        if len(alert_ids) >= 2:
            alert = alert_ids[1]
            print(f"\n   Submitting feedback for Alert {alert['id']}...")
            feedback_result = submit_feedback(
                base_url, 
                alert['id'], 
                "malicious", 
                "Confirmed credential theft - procdump on LSASS with exfiltration"
            )
            if 'error' in feedback_result:
                print(f"      ❌ Error: {feedback_result['error']}")
            else:
                print(f"      ✅ Feedback submitted")
                print(f"      AI was correct: {feedback_result.get('ai_was_correct', 'N/A')}")
    
    # 5. Get Feedback Stats
    print("\n📈 Step 5: AI Accuracy Statistics")
    stats = get_feedback_stats(base_url)
    if 'error' in stats:
        print(f"   ❌ Error: {stats['error']}")
    else:
        print(f"   Total Reviewed: {stats.get('total_reviewed', 0)}")
        print(f"   Accuracy: {stats.get('accuracy', 'N/A')}%")
        print(f"   Correct: {stats.get('correct', 0)}")
        print(f"   Incorrect: {stats.get('incorrect', 0)}")
    
    print("\n" + "="*70)
    print("✅ TEST COMPLETE")
    print("="*70)
    print("\n📌 Next Steps:")
    print("   1. Check dashboard to see alerts with AI verdicts")
    print("   2. Look at AI Transparency page for investigation_answers")
    print("   3. Send more alerts to see feedback loop in action")
    print("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test new AI features")
    parser.add_argument("--url", default="http://localhost:5000", help="Backend URL")
    parser.add_argument("--no-feedback", action="store_true", help="Skip feedback tests")
    args = parser.parse_args()
    
    run_tests(args.url, include_feedback=not args.no_feedback)

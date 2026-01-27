#!/usr/bin/env python3
"""
Volume & False Positive Test Script
====================================

Tests:
1. Benign alerts (false positive testing)
2. Volume testing (100 alerts)
3. Mixed severity testing
4. Auto-close verification

Usage:
    python scripts/test_volume_and_benign.py --benign       # Send benign alerts only
    python scripts/test_volume_and_benign.py --volume 100   # Send 100 mixed alerts
    python scripts/test_volume_and_benign.py --mixed        # Send mixed severity alerts
    python scripts/test_volume_and_benign.py --all          # Run all tests
"""

import requests
import time
import random
import argparse
from datetime import datetime

BASE_URL = "http://localhost:5000"
API_KEY = "secure-ingest-key-123"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

# =============================================================================
# BENIGN ALERT TEMPLATES (Should NOT be marked as malicious)
# =============================================================================
BENIGN_ALERTS = [
    {
        "alert_name": "Windows Update Service Started",
        "severity": "low",
        "description": "Windows Update service wuauserv started as scheduled",
        "source_ip": "10.0.0.50",
        "dest_ip": "10.0.0.1",
        "hostname": "IT-WORKSTATION-001",
        "username": "SYSTEM",
        "mitre_technique": None
    },
    {
        "alert_name": "Scheduled Task Created - IT Maintenance",
        "severity": "low",
        "description": "IT admin created scheduled task for disk cleanup",
        "source_ip": "10.0.0.5",
        "dest_ip": "10.0.0.10",
        "hostname": "IT-ADMIN-PC",
        "username": "admin.jones",
        "mitre_technique": None
    },
    {
        "alert_name": "User Logged In from VPN",
        "severity": "low",
        "description": "Remote user authenticated via corporate VPN during business hours",
        "source_ip": "192.168.100.15",
        "dest_ip": "10.0.0.1",
        "hostname": "FINANCE-WS-003",
        "username": "john.smith",
        "mitre_technique": None
    },
    {
        "alert_name": "Software Installation - Microsoft Office",
        "severity": "medium",
        "description": "Microsoft Office 365 installed by IT deployment",
        "source_ip": "10.0.0.5",
        "dest_ip": "10.0.0.100",
        "hostname": "HR-LAPTOP-002",
        "username": "SYSTEM",
        "mitre_technique": None
    },
    {
        "alert_name": "Antivirus Signature Update",
        "severity": "low",
        "description": "Defender antivirus signatures updated automatically",
        "source_ip": "10.0.0.75",
        "dest_ip": "23.193.96.100",  # Microsoft IP
        "hostname": "SALES-PC-005",
        "username": "SYSTEM",
        "mitre_technique": None
    },
    {
        "alert_name": "File Share Access - Shared Drive",
        "severity": "low",
        "description": "User accessed shared network drive during work hours",
        "source_ip": "10.0.0.45",
        "dest_ip": "10.0.0.200",
        "hostname": "FINANCE-WS-001",
        "username": "sarah.wilson",
        "mitre_technique": None
    },
    {
        "alert_name": "Group Policy Update Applied",
        "severity": "low",
        "description": "Domain Group Policy refresh completed successfully",
        "source_ip": "10.0.0.1",
        "dest_ip": "10.0.0.50",
        "hostname": "IT-SERVER-DC01",
        "username": "SYSTEM",
        "mitre_technique": None
    },
    {
        "alert_name": "Backup Service Running",
        "severity": "low",
        "description": "Nightly backup job started as scheduled at 2 AM",
        "source_ip": "10.0.0.200",
        "dest_ip": "10.0.0.250",
        "hostname": "BACKUP-SERVER-001",
        "username": "SYSTEM",
        "mitre_technique": None
    },
    {
        "alert_name": "DNS Query - Internal Domain",
        "severity": "low",
        "description": "Normal DNS query for internal corporate domain",
        "source_ip": "10.0.0.80",
        "dest_ip": "10.0.0.1",
        "hostname": "DEV-WORKSTATION-003",
        "username": "mike.developer",
        "mitre_technique": None
    },
    {
        "alert_name": "Remote Desktop Connection - IT Support",
        "severity": "medium",
        "description": "IT helpdesk connected via RDP to assist user",
        "source_ip": "10.0.0.5",
        "dest_ip": "10.0.0.90",
        "hostname": "IT-HELPDESK-001",
        "username": "helpdesk.admin",
        "mitre_technique": None
    }
]

# =============================================================================
# MALICIOUS ALERT TEMPLATES (Should be marked as malicious/suspicious)
# =============================================================================
MALICIOUS_ALERTS = [
    {
        "alert_name": "PowerShell Download Cradle - Possible Malware",
        "severity": "critical",
        "description": "PowerShell executed encoded command with download from external IP",
        "source_ip": "10.20.1.45",
        "dest_ip": "185.220.101.45",  # Tor exit node
        "hostname": "FINANCE-WS-001",
        "username": "john.doe",
        "mitre_technique": "T1059.001"
    },
    {
        "alert_name": "Mimikatz Credential Dumping Detected",
        "severity": "critical",
        "description": "Mimikatz.exe detected dumping LSASS credentials",
        "source_ip": "10.0.0.150",
        "dest_ip": "10.0.0.1",
        "hostname": "COMPROMISED-PC-001",
        "username": "attacker",
        "mitre_technique": "T1003.001"
    },
    {
        "alert_name": "Data Exfiltration via DNS Tunneling",
        "severity": "high",
        "description": "Large DNS queries to suspicious domain detected",
        "source_ip": "10.0.0.120",
        "dest_ip": "23.129.64.10",
        "hostname": "RESEARCH-SERVER-001",
        "username": "SYSTEM",
        "mitre_technique": "T1048.003"
    },
    {
        "alert_name": "Ransomware File Encryption Pattern",
        "severity": "critical",
        "description": "Mass file encryption with .locked extension detected",
        "source_ip": "10.0.0.99",
        "dest_ip": "10.0.0.200",
        "hostname": "ACCOUNTING-WS-002",
        "username": "ransomware.exe",
        "mitre_technique": "T1486"
    },
    {
        "alert_name": "Lateral Movement - PsExec Detected",
        "severity": "high",
        "description": "PsExec used to execute commands on remote system",
        "source_ip": "10.0.0.50",
        "dest_ip": "10.0.0.100",
        "hostname": "INFECTED-PC-001",
        "username": "admin",
        "mitre_technique": "T1570"
    }
]


def send_alert(alert, verbose=True):
    """Send a single alert to the backend"""
    try:
        response = requests.post(
            f"{BASE_URL}/ingest",
            headers=HEADERS,
            json=alert,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if verbose:
                print(f"  [OK] {alert['alert_name'][:40]:<40} -> ID: {data.get('alert_id', 'N/A')[:8]}...")
            return True, data
        else:
            if verbose:
                print(f"  [ERROR] {alert['alert_name'][:40]:<40} -> {response.status_code}: {response.text[:50]}")
            return False, None
    except Exception as e:
        if verbose:
            print(f"  [ERROR] {alert['alert_name'][:40]:<40} -> {str(e)[:50]}")
        return False, None


def test_benign_alerts():
    """Test that benign alerts are NOT marked as malicious"""
    print("\n" + "="*70)
    print("TEST: BENIGN ALERTS (False Positive Detection)")
    print("="*70)
    print("Sending alerts that should be marked as BENIGN...")
    print("-"*70)
    
    success = 0
    failed = 0
    
    for alert in BENIGN_ALERTS:
        ok, _ = send_alert(alert)
        if ok:
            success += 1
        else:
            failed += 1
        time.sleep(0.5)  # Small delay between alerts
    
    print("-"*70)
    print(f"RESULTS: {success} sent, {failed} failed")
    print("CHECK: After AI analysis, these should have verdict = BENIGN")
    print("="*70)
    return success, failed


def test_malicious_alerts():
    """Test that malicious alerts ARE marked correctly"""
    print("\n" + "="*70)
    print("TEST: MALICIOUS ALERTS (True Positive Detection)")
    print("="*70)
    print("Sending alerts that should be marked as MALICIOUS/SUSPICIOUS...")
    print("-"*70)
    
    success = 0
    failed = 0
    
    for alert in MALICIOUS_ALERTS:
        ok, _ = send_alert(alert)
        if ok:
            success += 1
        else:
            failed += 1
        time.sleep(0.5)
    
    print("-"*70)
    print(f"RESULTS: {success} sent, {failed} failed")
    print("CHECK: After AI analysis, these should have verdict = MALICIOUS or SUSPICIOUS")
    print("="*70)
    return success, failed


def test_volume(count=100):
    """Volume test - send many alerts quickly"""
    print("\n" + "="*70)
    print(f"TEST: VOLUME ({count} alerts)")
    print("="*70)
    print("Testing system stability under load...")
    print("-"*70)
    
    all_alerts = BENIGN_ALERTS + MALICIOUS_ALERTS
    
    success = 0
    failed = 0
    start_time = time.time()
    
    for i in range(count):
        # Mix of benign and malicious
        alert = random.choice(all_alerts).copy()
        # Add uniqueness
        alert['alert_name'] = f"[Vol-{i+1}] {alert['alert_name']}"
        
        ok, _ = send_alert(alert, verbose=(i % 10 == 0))  # Only print every 10th
        if ok:
            success += 1
        else:
            failed += 1
        
        if i % 10 == 0:
            print(f"  Progress: {i+1}/{count} alerts sent...")
    
    duration = time.time() - start_time
    rate = count / duration
    
    print("-"*70)
    print(f"RESULTS:")
    print(f"  Total: {count} alerts")
    print(f"  Success: {success}")
    print(f"  Failed: {failed}")
    print(f"  Duration: {duration:.2f}s")
    print(f"  Rate: {rate:.2f} alerts/second")
    print("="*70)
    return success, failed


def test_mixed_severity():
    """Test mixed severity levels for auto-close behavior"""
    print("\n" + "="*70)
    print("TEST: MIXED SEVERITY (Auto-Close Detection)")
    print("="*70)
    print("Testing that LOW/MEDIUM benign alerts are auto-closed...")
    print("-"*70)
    
    mixed_alerts = [
        {"alert_name": "Low Sev Benign - Disk Cleanup", "severity": "low", "description": "Scheduled disk cleanup", "source_ip": "10.0.0.1", "hostname": "SERVER-01"},
        {"alert_name": "Low Sev Benign - Log Rotation", "severity": "low", "description": "Log rotation completed", "source_ip": "10.0.0.1", "hostname": "SERVER-01"},
        {"alert_name": "Medium Sev Benign - Software Update", "severity": "medium", "description": "Chrome updated automatically", "source_ip": "10.0.0.50", "hostname": "WORKSTATION-05"},
        {"alert_name": "Medium Sev Benign - Network Scan by IT", "severity": "medium", "description": "Nmap scan from IT admin subnet", "source_ip": "10.0.0.5", "hostname": "IT-ADMIN-PC"},
        {"alert_name": "Critical Malicious - Ransomware", "severity": "critical", "description": "File encryption detected", "source_ip": "10.0.0.99", "hostname": "INFECTED-PC", "mitre_technique": "T1486"},
    ]
    
    success = 0
    for alert in mixed_alerts:
        ok, _ = send_alert(alert)
        if ok:
            success += 1
        time.sleep(0.5)
    
    print("-"*70)
    print(f"RESULTS: {success}/{len(mixed_alerts)} sent")
    print("CHECK: Low/Medium severity BENIGN alerts should be auto-closed")
    print("CHECK: Critical alerts should remain open for analyst review")
    print("="*70)
    return success


def main():
    parser = argparse.ArgumentParser(description='AI-SOC Watchdog Test Suite')
    parser.add_argument('--benign', action='store_true', help='Test benign alerts')
    parser.add_argument('--malicious', action='store_true', help='Test malicious alerts')
    parser.add_argument('--volume', type=int, metavar='N', help='Volume test with N alerts')
    parser.add_argument('--mixed', action='store_true', help='Test mixed severity')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("AI-SOC WATCHDOG - COMPREHENSIVE TEST SUITE")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Backend: {BASE_URL}")
    print("="*70)
    
    # Check backend is running
    try:
        requests.get(f"{BASE_URL}/queue-status", timeout=5)
        print("[OK] Backend is running")
    except:
        print("[ERROR] Backend is not running! Start it first:")
        print("  cd 'c:\\Users\\karan\\Desktop\\AI Project'")
        print("  python app.py")
        return
    
    if args.all or (not any([args.benign, args.malicious, args.volume, args.mixed])):
        test_benign_alerts()
        time.sleep(2)
        test_malicious_alerts()
        time.sleep(2)
        test_mixed_severity()
        time.sleep(2)
        test_volume(50)  # Smaller volume for full test
    else:
        if args.benign:
            test_benign_alerts()
        if args.malicious:
            test_malicious_alerts()
        if args.mixed:
            test_mixed_severity()
        if args.volume:
            test_volume(args.volume)
    
    print("\n" + "="*70)
    print("TEST SUITE COMPLETE")
    print("="*70)
    print("\nNext Steps:")
    print("1. Check Analyst Dashboard for alert verdicts")
    print("2. Verify benign alerts marked as BENIGN")
    print("3. Verify malicious alerts marked as MALICIOUS/SUSPICIOUS")
    print("4. Check if low/medium benign alerts were auto-closed")
    print("5. Review AI Dashboard for detailed analysis")
    print("="*70)


if __name__ == '__main__':
    main()

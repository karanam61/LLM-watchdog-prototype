"""
Interactive Alert Tester - Easy way to test the AI analysis pipeline
=====================================================================

This script provides an interactive way to:
1. Send predefined test alerts (known malicious, known benign, novel)
2. Create custom alerts on the fly
3. Watch the AI analysis in real-time
4. Compare expected vs actual verdicts

Usage:
    python scripts/test_alerts_interactive.py
    
Or with a specific server:
    python scripts/test_alerts_interactive.py --url http://localhost:5000

Author: AI-SOC Watchdog System
"""

import requests
import json
import time
import argparse
from datetime import datetime


# =============================================================================
# TEST ALERT CATEGORIES
# =============================================================================

# Alerts where we KNOW the expected verdict
KNOWN_MALICIOUS_ALERTS = [
    {
        "name": "Mimikatz Credential Dump",
        "expected_verdict": "malicious",
        "expected_confidence_min": 0.85,
        "alert": {
            "alert_name": "LSASS Memory Access - Credential Dumping",
            "description": "mimikatz.exe accessed lsass.exe memory. Process spawned from cmd.exe with encoded PowerShell parent. Outbound connection to 185.220.101.45:443 detected immediately after.",
            "severity": "critical",
            "hostname": "FINANCE-PC-001",
            "username": "unknown",
            "source_ip": "10.0.5.101",
            "dest_ip": "185.220.101.45",
            "mitre_technique": "T1003.001"
        }
    },
    {
        "name": "Ransomware Encryption Activity",
        "expected_verdict": "malicious",
        "expected_confidence_min": 0.90,
        "alert": {
            "alert_name": "Mass File Encryption Detected",
            "description": "Process 'svchost_update.exe' (unsigned, from TEMP folder) is encrypting files at rapid pace. Shadow copies deleted via vssadmin. Ransom note 'README_DECRYPT.txt' created.",
            "severity": "critical",
            "hostname": "FILESERVER-01",
            "username": "SYSTEM",
            "source_ip": "10.0.1.50",
            "mitre_technique": "T1486"
        }
    },
    {
        "name": "C2 Beacon Activity",
        "expected_verdict": "malicious",
        "expected_confidence_min": 0.80,
        "alert": {
            "alert_name": "Periodic Outbound Beaconing Detected",
            "description": "rundll32.exe making HTTP requests every 60 seconds to random subdomains of suspicious .xyz domain. Payload contains base64 encoded system information.",
            "severity": "high",
            "hostname": "HR-LAPTOP-003",
            "username": "j.smith",
            "source_ip": "10.0.8.33",
            "dest_ip": "45.33.32.156",
            "mitre_technique": "T1071.001"
        }
    }
]

KNOWN_BENIGN_ALERTS = [
    {
        "name": "IT Admin PowerShell Usage",
        "expected_verdict": "benign",
        "expected_confidence_min": 0.75,
        "alert": {
            "alert_name": "PowerShell Script Execution",
            "description": "powershell.exe executed Get-ADUser cmdlet to query Active Directory. Executed by IT admin during business hours from IT department workstation.",
            "severity": "medium",
            "hostname": "IT-ADMIN-WS-01",
            "username": "admin.rodriguez",
            "source_ip": "10.0.5.15",
            "mitre_technique": "T1059.001"
        }
    },
    {
        "name": "Windows Update Activity",
        "expected_verdict": "benign",
        "expected_confidence_min": 0.85,
        "alert": {
            "alert_name": "TrustedInstaller Process Activity",
            "description": "TrustedInstaller.exe and wuauclt.exe performing Windows Update installation. KB5034441 security patch being applied during scheduled maintenance window.",
            "severity": "low",
            "hostname": "RECEPTION-PC-01",
            "username": "SYSTEM",
            "source_ip": "10.0.3.25",
            "mitre_technique": "T1195.002"
        }
    },
    {
        "name": "Scheduled Antivirus Scan",
        "expected_verdict": "benign",
        "expected_confidence_min": 0.85,
        "alert": {
            "alert_name": "Windows Defender Full Scan",
            "description": "MsMpEng.exe initiated scheduled full system scan at 2:00 AM. Normal antivirus maintenance activity during off-hours maintenance window.",
            "severity": "low",
            "hostname": "DEV-SERVER-02",
            "username": "SYSTEM",
            "source_ip": "10.0.20.10",
            "mitre_technique": "T1518.001"
        }
    }
]

# Alerts that are NOVEL - AI should indicate lower confidence or uncertainty
NOVEL_ALERTS = [
    {
        "name": "Unknown Application Crash",
        "expected_verdict": "uncertain",  # Could be benign or suspicious
        "novelty_reason": "Custom internal application, no historical data",
        "alert": {
            "alert_name": "Internal App 'FinanceCalc v3.2' Memory Exception",
            "description": "Custom internal application FinanceCalc.exe crashed with memory access violation. No network activity detected. First occurrence of this error.",
            "severity": "medium",
            "hostname": "ACCT-PC-007",
            "username": "m.chen",
            "source_ip": "10.0.12.77"
        }
    },
    {
        "name": "New Cloud Service Connection",
        "expected_verdict": "uncertain",
        "novelty_reason": "New SaaS service, not in baseline",
        "alert": {
            "alert_name": "Outbound Connection to Unknown Cloud Service",
            "description": "Chrome.exe connecting to api.newservice-analytics.io. Domain registered 30 days ago. Traffic appears to be JSON data uploads every 5 minutes.",
            "severity": "medium",
            "hostname": "MARKETING-PC-003",
            "username": "s.johnson",
            "source_ip": "10.0.9.45",
            "dest_ip": "104.21.55.123"
        }
    },
    {
        "name": "Unusual But Possibly Legitimate Script",
        "expected_verdict": "uncertain",
        "novelty_reason": "Developer activity, context-dependent",
        "alert": {
            "alert_name": "Python Script Network Scanner Activity",
            "description": "python.exe from user's development folder running network scan on internal subnet. User is developer, but no change ticket found.",
            "severity": "medium",
            "hostname": "DEV-WS-012",
            "username": "developer.kim",
            "source_ip": "10.0.20.112",
            "mitre_technique": "T1046"
        }
    }
]


# =============================================================================
# TEST FUNCTIONS
# =============================================================================

def send_alert(base_url: str, alert_data: dict, timeout: int = 30) -> dict:
    """Send an alert to the /ingest endpoint and return response"""
    try:
        response = requests.post(
            f"{base_url}/ingest",
            json=alert_data,
            headers={"Content-Type": "application/json"},
            timeout=timeout
        )
        return {
            "success": response.status_code == 200,
            "status_code": response.status_code,
            "data": response.json() if response.status_code == 200 else None,
            "error": None if response.status_code == 200 else response.text
        }
    except Exception as e:
        return {
            "success": False,
            "status_code": None,
            "data": None,
            "error": str(e)
        }


def wait_for_analysis(base_url: str, alert_id: str, max_wait: int = 120) -> dict:
    """Poll the alert until AI analysis is complete"""
    print(f"\n⏳ Waiting for AI analysis (max {max_wait}s)...", end="", flush=True)
    
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            response = requests.get(f"{base_url}/alerts", timeout=10)
            if response.status_code == 200:
                alerts = response.json().get("alerts", [])
                for alert in alerts:
                    if str(alert.get("id")) == str(alert_id):
                        if alert.get("ai_verdict"):
                            print(" ✓")
                            return {
                                "success": True,
                                "alert": alert,
                                "wait_time": time.time() - start_time
                            }
            print(".", end="", flush=True)
            time.sleep(2)
        except:
            print("x", end="", flush=True)
            time.sleep(2)
    
    print(" ✗ (timeout)")
    return {"success": False, "error": "Timeout waiting for analysis"}


def run_test(base_url: str, test_case: dict, wait_for_result: bool = True) -> dict:
    """Run a single test case"""
    alert = test_case["alert"]
    name = test_case["name"]
    expected_verdict = test_case.get("expected_verdict")
    expected_confidence = test_case.get("expected_confidence_min", 0.5)
    
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    print(f"Alert: {alert['alert_name']}")
    print(f"Expected: {expected_verdict} (confidence ≥ {expected_confidence})")
    
    # Send alert
    result = send_alert(base_url, alert)
    
    if not result["success"]:
        print(f"❌ FAILED TO SEND: {result['error']}")
        return {"passed": False, "reason": "Send failed"}
    
    alert_id = result["data"].get("alert_id")
    print(f"✓ Alert created: {alert_id}")
    
    if not wait_for_result:
        return {"passed": None, "alert_id": alert_id, "reason": "Not waiting for result"}
    
    # Wait for analysis
    analysis = wait_for_analysis(base_url, alert_id)
    
    if not analysis["success"]:
        print(f"❌ ANALYSIS TIMEOUT")
        return {"passed": False, "reason": "Analysis timeout"}
    
    # Compare results
    alert_data = analysis["alert"]
    actual_verdict = alert_data.get("ai_verdict", "").lower()
    actual_confidence = alert_data.get("ai_confidence", 0)
    
    print(f"\n📊 RESULTS:")
    print(f"   Verdict:    {actual_verdict.upper()}")
    print(f"   Confidence: {actual_confidence:.0%}")
    print(f"   Wait time:  {analysis['wait_time']:.1f}s")
    
    # Evaluate
    if expected_verdict == "uncertain":
        # For novel alerts, we expect lower confidence or suspicious verdict
        passed = actual_confidence < 0.8 or actual_verdict == "suspicious"
        if passed:
            print(f"✓ PASS: AI showed appropriate uncertainty")
        else:
            print(f"⚠ CONCERN: AI may be overconfident on novel alert")
    else:
        verdict_match = actual_verdict == expected_verdict
        confidence_ok = actual_confidence >= expected_confidence
        passed = verdict_match and confidence_ok
        
        if passed:
            print(f"✓ PASS: Verdict and confidence match expectations")
        else:
            if not verdict_match:
                print(f"❌ FAIL: Expected {expected_verdict}, got {actual_verdict}")
            if not confidence_ok:
                print(f"❌ FAIL: Confidence {actual_confidence:.0%} below threshold {expected_confidence:.0%}")
    
    return {
        "passed": passed,
        "expected_verdict": expected_verdict,
        "actual_verdict": actual_verdict,
        "actual_confidence": actual_confidence,
        "alert_id": alert_id
    }


def run_test_suite(base_url: str, category: str = "all"):
    """Run a suite of tests"""
    tests = []
    
    if category in ["all", "malicious"]:
        tests.extend([("MALICIOUS", t) for t in KNOWN_MALICIOUS_ALERTS])
    if category in ["all", "benign"]:
        tests.extend([("BENIGN", t) for t in KNOWN_BENIGN_ALERTS])
    if category in ["all", "novel"]:
        tests.extend([("NOVEL", t) for t in NOVEL_ALERTS])
    
    print(f"\n{'='*60}")
    print(f"RUNNING TEST SUITE: {len(tests)} tests")
    print(f"{'='*60}")
    
    results = []
    for category, test in tests:
        result = run_test(base_url, test)
        result["category"] = category
        result["name"] = test["name"]
        results.append(result)
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(1 for r in results if r.get("passed") == True)
    failed = sum(1 for r in results if r.get("passed") == False)
    skipped = sum(1 for r in results if r.get("passed") is None)
    
    print(f"Passed:  {passed}/{len(results)}")
    print(f"Failed:  {failed}/{len(results)}")
    print(f"Skipped: {skipped}/{len(results)}")
    
    if failed > 0:
        print(f"\nFailed tests:")
        for r in results:
            if r.get("passed") == False:
                print(f"  - {r['name']}: {r.get('reason', 'See above')}")
    
    return results


def interactive_mode(base_url: str):
    """Interactive menu for testing"""
    while True:
        print(f"\n{'='*60}")
        print("AI-SOC WATCHDOG - ALERT TESTER")
        print(f"{'='*60}")
        print(f"Server: {base_url}")
        print(f"\n1. Run ALL tests (malicious + benign + novel)")
        print("2. Run MALICIOUS alert tests only")
        print("3. Run BENIGN alert tests only")
        print("4. Run NOVEL alert tests only")
        print("5. Send CUSTOM alert")
        print("6. Quick health check")
        print("0. Exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            run_test_suite(base_url, "all")
        elif choice == "2":
            run_test_suite(base_url, "malicious")
        elif choice == "3":
            run_test_suite(base_url, "benign")
        elif choice == "4":
            run_test_suite(base_url, "novel")
        elif choice == "5":
            custom_alert(base_url)
        elif choice == "6":
            health_check(base_url)
        else:
            print("Invalid choice")


def custom_alert(base_url: str):
    """Create and send a custom alert"""
    print("\n--- CREATE CUSTOM ALERT ---")
    
    alert = {
        "alert_name": input("Alert name: ").strip() or "Custom Test Alert",
        "description": input("Description: ").strip() or "Test alert from interactive tester",
        "severity": input("Severity (critical/high/medium/low) [medium]: ").strip() or "medium",
        "hostname": input("Hostname [TEST-PC-001]: ").strip() or "TEST-PC-001",
        "username": input("Username [test.user]: ").strip() or "test.user",
        "source_ip": input("Source IP [10.0.0.100]: ").strip() or "10.0.0.100"
    }
    
    dest_ip = input("Dest IP (optional): ").strip()
    if dest_ip:
        alert["dest_ip"] = dest_ip
    
    mitre = input("MITRE Technique (optional, e.g., T1059.001): ").strip()
    if mitre:
        alert["mitre_technique"] = mitre
    
    print(f"\nSending: {json.dumps(alert, indent=2)}")
    
    test_case = {
        "name": "Custom Alert",
        "alert": alert,
        "expected_verdict": "unknown"
    }
    
    wait = input("\nWait for AI analysis? (y/n) [y]: ").strip().lower() != "n"
    run_test(base_url, test_case, wait_for_result=wait)


def health_check(base_url: str):
    """Quick health check"""
    print("\n--- HEALTH CHECK ---")
    
    try:
        # API health
        r = requests.get(f"{base_url}/api/health", timeout=10)
        health = r.json()
        print(f"API Status: {health.get('status', 'unknown')}")
        print(f"Components: {json.dumps(health.get('components', {}), indent=2)}")
        
        # Queue status
        r = requests.get(f"{base_url}/queue-status", timeout=10)
        queue = r.json()
        print(f"\nQueue Status:")
        print(f"  Priority: {queue.get('priority_count', 0)}")
        print(f"  Standard: {queue.get('standard_count', 0)}")
        
    except Exception as e:
        print(f"❌ Health check failed: {e}")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-SOC Watchdog Alert Tester")
    parser.add_argument("--url", default="http://localhost:5000", help="API base URL")
    parser.add_argument("--test", choices=["all", "malicious", "benign", "novel"], 
                        help="Run specific test suite and exit")
    args = parser.parse_args()
    
    if args.test:
        run_test_suite(args.url, args.test)
    else:
        interactive_mode(args.url)

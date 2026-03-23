"""
SIEM Emulator - AI-Powered Alert & Log Generator
==================================================

Uses Claude API to generate realistic, correlated security scenarios
with semi-raw logs that look like actual SIEM output.

This is NOT the analyzer. This is the SIEM that feeds the analyzer.

Flow:
    Claude (as SIEM) generates scenario → Alert + Raw Logs
    Script sends alert to /ingest → Gets alert_id back
    Script inserts logs into Supabase with that alert_id
    Main analyzer picks it up and processes it

Usage:
    py scripts/siem_emulator.py --once               # Generate 1 scenario
    py scripts/siem_emulator.py --count 5             # Generate 5 scenarios
    py scripts/siem_emulator.py --continuous          # Keep generating
    py scripts/siem_emulator.py --scenario malicious  # Force malicious scenario
    py scripts/siem_emulator.py --scenario benign     # Force benign scenario
    py scripts/siem_emulator.py --scenario mixed      # Mix of both
"""

import os
import sys
import json
import time
import random
import argparse
import requests
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

import anthropic

BACKEND_URL = "http://localhost:5000/ingest"

SIEM_PROMPT = """You are a SIEM system (Splunk/Elastic) generating realistic security telemetry for TechCorp Solutions.

Generate a complete security scenario with ONE alert and matching forensic logs across ALL 4 log types.

SCENARIO TYPE: {scenario_type}

REQUIREMENTS:
- The alert must be realistic, something a real SIEM would fire
- Generate 4-8 process logs showing the FULL process chain (parent → child → grandchild)
- Generate 3-6 network logs showing connections RELATED to the alert (not random)
- Generate 2-4 file activity logs showing file operations tied to the scenario
- Generate 3-5 Windows event logs with proper Event IDs
- All logs must be CORRELATED - they tell ONE story together
- Timestamps must be sequential and make sense (process starts, then network, then file)
- ALL IPs, hostnames, usernames MUST come from the infrastructure below
- Logs should look like raw SIEM output, NOT polished explanations

=========================================================================
TECHCORP SOLUTIONS - COMPANY INFRASTRUCTURE (USE ONLY THESE)
=========================================================================

COMPANY: TechCorp Solutions | Financial Services & Technology | 250 employees
DOMAIN: TECHCORP
COMPLIANCE: SOC2, PCI-DSS, GDPR, HIPAA

NETWORK SUBNETS:
- 10.20.1.0/24  - Finance VLAN (restricted internet, enhanced monitoring)
- 10.20.2.0/24  - IT VLAN (full internet, enhanced monitoring)
- 10.20.3.0/24  - Engineering VLAN (full internet, standard monitoring)
- 10.20.4.0/24  - HR VLAN (restricted internet, enhanced monitoring)
- 10.20.5.0/24  - Sales VLAN (full internet, standard monitoring)
- 10.20.10.0/24 - Server VLAN (restricted, enhanced monitoring)
- 10.20.100.0/24 - Guest WiFi (isolated)
- 10.20.200.0/24 - DMZ (public-facing, enhanced monitoring)

EMPLOYEES (use these exact names, IPs, hostnames):
- john.doe       | 10.20.1.45  | FINANCE-LAPTOP-01    | Finance Manager       | wire transfer approval | CRITICAL
- sarah.smith     | 10.20.2.10  | IT-ADMIN-WORKSTATION | Sr IT Admin           | domain admin          | CRITICAL
- mike.johnson    | 10.20.4.23  | HR-DESKTOP-03        | HR Coordinator        | employee records      | HIGH
- emily.chen      | 10.20.1.52  | FINANCE-LAPTOP-02    | Sr Financial Analyst  | financial reporting   | HIGH
- david.kumar     | 10.20.2.15  | IT-ENG-WORKSTATION-01| Security Analyst      | SIEM/EDR access       | CRITICAL
- lisa.martinez   | 10.20.5.30  | SALES-LAPTOP-01      | VP Sales              | CRM admin             | HIGH
- james.wilson    | 10.20.3.45  | DEV-WORKSTATION-01   | Engineering Lead      | production deploy     | CRITICAL
- amanda.lee      | 10.20.4.15  | HR-LAPTOP-01         | HR Director           | all PII access        | CRITICAL

SERVICE ACCOUNTS:
- svc_backup   | Veeam backup service
- svc_deploy   | CI/CD deployment
- svc_monitor  | Monitoring agent

SERVERS (use these exact hostnames and IPs):
- DC-PRIMARY-01  | 10.20.10.100 | Domain Controller (Windows Server 2022) | CRITICAL
- DC-BACKUP-01   | 10.20.10.101 | Backup DC (Windows Server 2022) | CRITICAL
- DB-PRIMARY-01  | 10.20.10.5   | PostgreSQL 15 customer database | CRITICAL
- DB-REPLICA-01  | 10.20.10.6   | DB read replica | CRITICAL
- DB-ANALYTICS-01| 10.20.10.7   | Analytics/BI database | HIGH
- FILE-SERVER-01 | 10.20.10.50  | File shares (Windows Server 2022) | HIGH
- BACKUP-SERVER-01| 10.20.10.60 | Veeam backup server | CRITICAL
- WEB-PROD-01    | 10.20.200.10 | Nginx web server (DMZ) | HIGH
- WEB-PROD-02    | 10.20.200.11 | Nginx web server (DMZ, load balanced) | HIGH
- API-GATEWAY-01 | 10.20.200.20 | Kong API Gateway (DMZ) | CRITICAL
- DEV-DB-01      | 10.20.10.70  | Development database | MEDIUM
- TEST-ENV-01    | 10.20.10.80  | QA/staging environment | LOW

KNOWN MALICIOUS IPs (use for attack scenarios):
- 203.0.113.50, 198.51.100.25, 192.0.2.100, 185.220.101.45, 91.203.45.78, 45.142.212.61

KNOWN C2 DOMAINS:
- evil-malware.com, c2-server.net, malicious-command.xyz, backdoor-control.org

BUSINESS HOURS: 9am-5pm EST Monday-Friday
MAINTENANCE WINDOWS: Saturday 2am-6am EST
PEAK TRANSACTIONS: 10am-2pm EST

IF MALICIOUS: Show a real attack chain targeting TechCorp infrastructure. Use actual server names and employee accounts.
IF BENIGN: Show legitimate IT activity (sarah.smith doing admin work, svc_backup running, SCCM deployments) that LOOKS suspicious.
IF AMBIGUOUS: Show activity that could be a compromised employee or legitimate work - let the evidence be unclear.

Return ONLY valid JSON in this exact format:

{{
  "alert": {{
    "alert_name": "Name matching a real SIEM detection rule",
    "description": "What the SIEM detection rule triggered on",
    "severity": "critical|high|medium|low",
    "source_ip": "IP",
    "dest_ip": "IP",
    "mitre_technique": "T####.###",
    "risk_score": 0-100,
    "hostname": "HOSTNAME",
    "username": "username"
  }},
  "process_logs": [
    {{
      "timestamp": "ISO8601",
      "process_name": "process.exe",
      "process_id": 1234,
      "parent_process": "parent.exe",
      "command_line": "full command line as SIEM would capture it",
      "username": "DOMAIN\\user",
      "hostname": "HOSTNAME",
      "file_path": "C:\\full\\path\\to\\process.exe",
      "log_source": "Sysmon",
      "integrity_level": "High|Medium|Low|System",
      "hash": "SHA256 hash"
    }}
  ],
  "network_logs": [
    {{
      "timestamp": "ISO8601",
      "source_ip": "IP",
      "dest_ip": "IP",
      "source_port": 12345,
      "dest_port": 443,
      "protocol": "TCP|UDP",
      "bytes_sent": 1024,
      "bytes_received": 2048,
      "connection_state": "ESTABLISHED|SYN_SENT|CLOSED",
      "log_source": "Zeek",
      "service": "http|https|dns|smb",
      "duration": 1.5
    }}
  ],
  "file_activity_logs": [
    {{
      "timestamp": "ISO8601",
      "action": "FileCreate|FileModified|FileDelete|FileRename",
      "file_path": "C:\\full\\path",
      "process_name": "process.exe",
      "file_hash": "SHA256 if available",
      "file_size": 1024,
      "log_source": "Sysmon"
    }}
  ],
  "windows_event_logs": [
    {{
      "timestamp": "ISO8601",
      "event_id": 4624,
      "event_type": "Audit Success|Audit Failure",
      "log_name": "Security",
      "username": "DOMAIN\\user",
      "event_message": "Detailed event description as Windows would log it",
      "source_ip": "IP if applicable",
      "logon_type": 3
    }}
  ]
}}

CRITICAL: Make the logs tell a STORY. Each log should connect to the next. 
A process spawns, it makes network connections, it creates files, Windows logs the authentication.
The analyst should be able to trace the entire chain from start to finish."""


def generate_scenario(client, scenario_type="mixed"):
    if scenario_type == "mixed":
        scenario_type = random.choice(["malicious", "benign", "ambiguous"])
    
    prompt = SIEM_PROMPT.format(scenario_type=scenario_type.upper())
    
    print(f"\n[SIEM] Generating {scenario_type.upper()} scenario via Claude...")
    
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        text = response.content[0].text
        
        # Extract JSON
        start = text.find('{')
        end = text.rfind('}')
        if start == -1 or end == -1:
            print("[ERROR] No JSON in Claude response")
            return None
        
        data = json.loads(text[start:end+1])
        
        process_count = len(data.get('process_logs', []))
        network_count = len(data.get('network_logs', []))
        file_count = len(data.get('file_activity_logs', []))
        event_count = len(data.get('windows_event_logs', []))
        
        print(f"[SIEM] Generated: {data['alert']['alert_name']}")
        print(f"[SIEM] Logs: {process_count} process, {network_count} network, {file_count} file, {event_count} windows events")
        print(f"[SIEM] Scenario: {scenario_type} | Severity: {data['alert']['severity']}")
        
        return data
        
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON parse failed: {e}")
        print(f"[DEBUG] Raw response: {text[:500]}")
        return None
    except Exception as e:
        print(f"[ERROR] Claude API failed: {e}")
        return None


def send_alert(alert_data):
    try:
        alert = {
            "alert_name": alert_data['alert_name'],
            "description": alert_data['description'],
            "severity": alert_data['severity'],
            "source_ip": alert_data.get('source_ip', 'unknown'),
            "dest_ip": alert_data.get('dest_ip', 'unknown'),
            "mitre_technique": alert_data.get('mitre_technique', 'UNKNOWN'),
            "risk_score": alert_data.get('risk_score', 50),
            "hostname": alert_data.get('hostname', ''),
            "username": alert_data.get('username', ''),
            "timestamp": datetime.now().isoformat(),
            "source": "siem_emulator"
        }
        
        resp = requests.post(BACKEND_URL, json=alert, timeout=60)
        
        if resp.status_code == 200:
            result = resp.json()
            alert_id = result.get('alert_id') or result.get('id')
            print(f"[INGEST] Alert sent. ID: {alert_id}")
            return alert_id, result
        else:
            print(f"[ERROR] Ingest failed: {resp.status_code} - {resp.text[:200]}")
            return None, None
            
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to backend. Is it running on port 5000?")
        return None, None
    except Exception as e:
        print(f"[ERROR] Send failed: {e}")
        return None, None


def insert_logs(alert_id, scenario_data):
    from backend.storage.database import insert_log_batch
    
    if not alert_id:
        print("[SKIP] No alert_id, skipping log insertion")
        return
    
    # Ensure alert_id is integer
    try:
        alert_id = int(alert_id)
    except (ValueError, TypeError):
        print(f"[WARN] alert_id '{alert_id}' is not an integer, using as-is")
    
    log_tables = {
        'process_logs': scenario_data.get('process_logs', []),
        'network_logs': scenario_data.get('network_logs', []),
        'file_activity_logs': scenario_data.get('file_activity_logs', []),
        'windows_event_logs': scenario_data.get('windows_event_logs', [])
    }
    
    total_inserted = 0
    
    for table_name, logs in log_tables.items():
        if not logs:
            continue
        
        # Add alert_id to each log and clean fields
        for log in logs:
            log['alert_id'] = alert_id
            # Remove fields that might not be in the DB schema
            for extra_field in ['hash', 'file_hash', 'file_size', 'integrity_level', 
                               'service', 'duration', 'logon_type']:
                log.pop(extra_field, None)
        
        try:
            result = insert_log_batch(table_name, logs)
            count = len(logs)
            total_inserted += count
            print(f"[DB] Inserted {count} logs into {table_name}")
        except Exception as e:
            print(f"[ERROR] Failed to insert into {table_name}: {e}")
    
    print(f"[DB] Total logs inserted: {total_inserted}")


def run_scenario(client, scenario_type="mixed"):
    print("\n" + "="*60)
    print(f"  SIEM EMULATOR - New Scenario")
    print(f"  Time: {datetime.now().strftime('%H:%M:%S')}")
    print("="*60)
    
    # Step 1: Generate scenario with Claude
    scenario = generate_scenario(client, scenario_type)
    if not scenario:
        print("[FAILED] Could not generate scenario")
        return False
    
    # Step 2: Send alert to backend
    alert_id, result = send_alert(scenario['alert'])
    if not alert_id:
        print("[FAILED] Could not send alert")
        return False
    
    # Step 3: Insert correlated logs into Supabase
    insert_logs(alert_id, scenario)
    
    # Step 4: Show result
    ai_verdict = result.get('ai_verdict') or result.get('verdict', 'pending')
    ai_confidence = result.get('ai_confidence') or result.get('confidence', 0)
    
    print(f"\n[RESULT] Alert: {scenario['alert']['alert_name']}")
    print(f"[RESULT] AI Verdict: {ai_verdict}")
    print(f"[RESULT] AI Confidence: {ai_confidence}")
    print(f"[RESULT] Alert ID: {alert_id}")
    print("="*60)
    
    return True


def main():
    parser = argparse.ArgumentParser(description="SIEM Emulator - AI-Powered Alert Generator")
    parser.add_argument("--once", action="store_true", help="Generate 1 scenario and exit")
    parser.add_argument("--count", type=int, default=0, help="Number of scenarios (0=infinite)")
    parser.add_argument("--continuous", action="store_true", help="Keep generating")
    parser.add_argument("--scenario", choices=["malicious", "benign", "ambiguous", "mixed"], 
                       default="mixed", help="Type of scenario to generate")
    parser.add_argument("--interval", type=int, default=30, help="Seconds between scenarios")
    args = parser.parse_args()
    
    if args.once:
        args.count = 1
    
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("[ERROR] ANTHROPIC_API_KEY not set in .env")
        sys.exit(1)
    
    client = anthropic.Anthropic(api_key=api_key)
    
    print(f"\n{'#'*60}")
    print(f"#  SIEM EMULATOR")
    print(f"#  Scenario type: {args.scenario}")
    print(f"#  Count: {'infinite' if args.count == 0 and args.continuous else args.count or 1}")
    print(f"#  Interval: {args.interval}s")
    print(f"#  Backend: {BACKEND_URL}")
    print(f"{'#'*60}")
    
    generated = 0
    
    while True:
        success = run_scenario(client, args.scenario)
        if success:
            generated += 1
        
        if args.count > 0 and generated >= args.count:
            break
        
        if not args.continuous and args.count == 0:
            break
        
        print(f"\n[WAIT] Next scenario in {args.interval}s... (Ctrl+C to stop)")
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n\nStopped. Generated {generated} scenarios.")
            sys.exit(0)
    
    print(f"\nDone. Generated {generated} scenarios total.")


if __name__ == "__main__":
    main()

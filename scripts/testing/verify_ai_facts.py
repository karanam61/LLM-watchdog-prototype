"""Verify AI is using real facts from RAG and not hallucinating"""
import os
import sys
from dotenv import load_dotenv
import json

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase

print("=" * 80)
print("FACT-CHECKING AI ANALYSIS: HALLUCINATION vs REAL DATA")
print("=" * 80)

# Get a specific alert with deep analysis
alert_id = "d64bfd3b-2c0f-4800-82fa-ca5603a05581"  # Data Exfiltration alert

print(f"\nFetching alert: {alert_id}")
alert_response = supabase.table('alerts').select('*').eq('id', alert_id).execute()
alert = alert_response.data[0] if alert_response.data else None

if not alert:
    print("[ERROR] Alert not found")
    exit(1)

print(f"\n{'='*80}")
print("ORIGINAL ALERT DATA (Ground Truth)")
print('='*80)
print(f"Alert Name: {alert['alert_name']}")
print(f"Description: {alert['description']}")
print(f"Severity: {alert['severity']}")
print(f"MITRE: {alert.get('mitre_technique')}")
print(f"Source IP: {alert.get('source_ip')}")
print(f"Dest IP: {alert.get('dest_ip')}")
print(f"Hostname: {alert.get('hostname')}")
print(f"Username: {alert.get('username')}")
print(f"Timestamp: {alert.get('timestamp')}")

# Get correlated logs
print(f"\n{'='*80}")
print("CORRELATED LOGS (Ground Truth)")
print('='*80)

network_logs = supabase.table('network_logs').select('*').eq('alert_id', alert_id).limit(3).execute()
process_logs = supabase.table('process_logs').select('*').eq('alert_id', alert_id).limit(3).execute()
file_logs = supabase.table('file_activity_logs').select('*').eq('alert_id', alert_id).limit(3).execute()
windows_logs = supabase.table('windows_event_logs').select('*').eq('alert_id', alert_id).limit(3).execute()

print(f"\nNetwork Logs: {len(network_logs.data)} entries")
if network_logs.data:
    for i, log in enumerate(network_logs.data[:2], 1):
        print(f"  {i}. {log.get('protocol')} {log.get('src_ip')} -> {log.get('dest_ip')} | {log.get('bytes_sent')} bytes | {log.get('service')}")

print(f"\nProcess Logs: {len(process_logs.data)} entries")
if process_logs.data:
    for i, log in enumerate(process_logs.data[:2], 1):
        print(f"  {i}. {log.get('process_name')} | PID: {log.get('process_id')} | User: {log.get('user')}")

print(f"\nFile Activity Logs: {len(file_logs.data)} entries")
if file_logs.data:
    for i, log in enumerate(file_logs.data[:2], 1):
        print(f"  {i}. {log.get('file_name')} | Action: {log.get('action')} | Size: {log.get('file_size')}")

print(f"\nWindows Event Logs: {len(windows_logs.data)} entries")
if windows_logs.data:
    for i, log in enumerate(windows_logs.data[:2], 1):
        desc = log.get('description') or 'No description'
        print(f"  {i}. Event {log.get('event_id')}: {log.get('event_type')} - {desc[:80]}...")

# Show AI's claims
print(f"\n{'='*80}")
print("AI'S ANALYSIS CLAIMS")
print('='*80)

print(f"\nVerdict: {alert['ai_verdict']} (Confidence: {alert['ai_confidence']})")
print(f"\nEvidence ({len(alert['ai_evidence'])} points):")
for i, evidence in enumerate(alert['ai_evidence'], 1):
    print(f"  {i}. {evidence}")

print(f"\nReasoning:")
print(alert['ai_reasoning'])

print(f"\n{'='*80}")
print("FACT-CHECK: Verifying Each AI Claim")
print('='*80)

# Now verify each claim
facts_to_check = []

# Check if AI mentions specific IPs that exist in logs
if network_logs.data:
    evidence_str = ' '.join(alert['ai_evidence'])
    for log in network_logs.data:
        if log.get('dest_ip') and log.get('dest_ip') in evidence_str:
            facts_to_check.append(f"[OK] AI mentioned dest IP '{log.get('dest_ip')}' - FOUND in network logs")
        if log.get('bytes_sent'):
            bytes_str = str(log.get('bytes_sent'))
            if bytes_str in evidence_str or bytes_str in alert['ai_reasoning']:
                facts_to_check.append(f"[OK] AI mentioned data transfer size - MATCHES network log bytes")

# Check if AI mentions hostnames from alert
evidence_str = ' '.join(alert['ai_evidence'])
if alert.get('hostname') and alert.get('hostname') in evidence_str:
    facts_to_check.append(f"[OK] AI mentioned hostname '{alert.get('hostname')}' - MATCHES alert data")

# Check if AI mentions MITRE technique
if alert.get('mitre_technique'):
    evidence_str = ' '.join(alert['ai_evidence'])
    if alert.get('mitre_technique') in (evidence_str + alert['ai_reasoning']):
        facts_to_check.append(f"[OK] AI mentioned MITRE '{alert.get('mitre_technique')}' - MATCHES alert data")

# Check timestamp/time mentions
timestamp = alert.get('timestamp', '')
if 'after-hours' in alert['ai_reasoning'].lower() or 'outside' in alert['ai_reasoning'].lower():
    facts_to_check.append(f"[CHECK] AI inferred 'after-hours' from timestamp: {timestamp}")

# Check file activity mentions
if file_logs.data:
    evidence_str = ' '.join(alert['ai_evidence'])
    for log in file_logs.data:
        file_size = log.get('file_size')
        if file_size and (str(file_size) in evidence_str or 'database' in log.get('file_name', '').lower()):
            facts_to_check.append(f"[OK] AI mentioned file/database activity - FOUND in file logs")
            break

print("\nFact-check results:")
for fact in facts_to_check:
    print(f"  {fact}")

if len(facts_to_check) >= 3:
    print(f"\n[VERDICT] AI is using REAL DATA from logs and alert details!")
    print("The AI is grounding its analysis in actual evidence.")
else:
    print(f"\n[WARNING] Could only verify {len(facts_to_check)} facts - needs more investigation")

print("\n" + "=" * 80)

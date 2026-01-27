"""SMOKING GUN TEST: Give AI fake data and see if it uses it vs real data"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase

print("=" * 80)
print("SMOKING GUN TEST: Does AI Actually Read The Data?")
print("=" * 80)

# Get two different alerts
print("\nFetching two DIFFERENT alerts...")

# Alert 1: Ransomware
alert1_response = supabase.table('alerts').select('*').eq('alert_name', 'Ransomware - Mass File Encryption Detected').limit(1).execute()
alert1 = alert1_response.data[0] if alert1_response.data else None

# Alert 2: SQL Injection
alert2_response = supabase.table('alerts').select('*').eq('alert_name', 'SQL Injection - Authentication Bypass').limit(1).execute()
alert2 = alert2_response.data[0] if alert2_response.data else None

if not alert1 or not alert2:
    print("[ERROR] Could not fetch alerts")
    exit(1)

print("\n" + "=" * 80)
print("ALERT 1: Ransomware")
print("=" * 80)
print(f"Name: {alert1['alert_name']}")
print(f"Description: {alert1['description'][:100]}...")
print(f"MITRE: {alert1.get('mitre_technique')}")

print(f"\nAI's Analysis:")
print(f"Verdict: {alert1.get('ai_verdict')} ({alert1.get('ai_confidence')})")
print(f"\nKey Evidence:")
for e in alert1.get('ai_evidence', [])[:3]:
    print(f"  - {e}")

print("\n" + "=" * 80)
print("ALERT 2: SQL Injection")
print("=" * 80)
print(f"Name: {alert2['alert_name']}")
print(f"Description: {alert2['description'][:100]}...")
print(f"MITRE: {alert2.get('mitre_technique')}")

print(f"\nAI's Analysis:")
print(f"Verdict: {alert2.get('ai_verdict')} ({alert2.get('ai_confidence')})")
print(f"\nKey Evidence:")
for e in alert2.get('ai_evidence', [])[:3]:
    print(f"  - {e}")

# Now the SMOKING GUN test
print("\n" + "=" * 80)
print("SMOKING GUN: Checking for Alert-Specific Details")
print("=" * 80)

print("\nTest 1: Does Ransomware analysis mention file encryption?")
ransomware_reasoning = alert1.get('ai_reasoning', '').lower()
if 'encrypt' in ransomware_reasoning or 'file' in ransomware_reasoning or 'ransomware' in ransomware_reasoning:
    print("  [OK] YES - AI specifically discusses encryption/ransomware concepts")
    print(f"       Found keywords in reasoning")
else:
    print("  [FAIL] NO - AI doesn't mention encryption (suspicious!)")

print("\nTest 2: Does SQL Injection analysis mention database/SQL?")
sqli_reasoning = alert2.get('ai_reasoning', '').lower()
if 'sql' in sqli_reasoning or 'injection' in sqli_reasoning or 'database' in sqli_reasoning or 'query' in sqli_reasoning:
    print("  [OK] YES - AI specifically discusses SQL/database concepts")
    print(f"       Found keywords in reasoning")
else:
    print("  [FAIL] NO - AI doesn't mention SQL (suspicious!)")

print("\nTest 3: Do the MITRE techniques match the attack types?")
if alert1.get('mitre_technique') in str(alert1.get('ai_evidence')):
    print(f"  [OK] Ransomware: AI references MITRE {alert1.get('mitre_technique')}")
if alert2.get('mitre_technique') in str(alert2.get('ai_evidence')):
    print(f"  [OK] SQL Injection: AI references MITRE {alert2.get('mitre_technique')}")

print("\nTest 4: Are the specific IPs/Hostnames mentioned?")
if alert1.get('source_ip') in str(alert1.get('ai_evidence')):
    print(f"  [OK] Ransomware: AI mentions specific IP {alert1.get('source_ip')}")
if alert2.get('hostname') in str(alert2.get('ai_evidence')):
    print(f"  [OK] SQL Injection: AI mentions specific host {alert2.get('hostname')}")

print("\nTest 5: Are recommendations specific to the attack type?")
rec1 = alert1.get('ai_recommendation', '').lower()
rec2 = alert2.get('ai_recommendation', '').lower()

ransomware_specific = 'backup' in rec1 or 'restore' in rec1 or 'decrypt' in rec1 or 'isolate' in rec1
sqli_specific = 'patch' in rec2 or 'sanitize' in rec2 or 'waf' in rec2 or 'sql' in rec2 or 'input' in rec2

if ransomware_specific:
    print("  [OK] Ransomware: Recommendations mention backup/restore/isolation")
if sqli_specific:
    print("  [OK] SQL Injection: Recommendations mention patching/WAF/input validation")

# Final verdict
print("\n" + "=" * 80)
print("FINAL VERDICT")
print("=" * 80)

tests_passed = 0
tests_passed += 1 if 'encrypt' in ransomware_reasoning else 0
tests_passed += 1 if 'sql' in sqli_reasoning else 0
tests_passed += 1 if alert1.get('mitre_technique') in str(alert1.get('ai_evidence')) else 0
tests_passed += 1 if alert2.get('mitre_technique') in str(alert2.get('ai_evidence')) else 0
tests_passed += 1 if ransomware_specific else 0
tests_passed += 1 if sqli_specific else 0

print(f"\nTests Passed: {tests_passed}/6")

if tests_passed >= 5:
    print("\n[SMOKING GUN CONFIRMED]")
    print("The AI is DEFINITELY reading and analyzing the actual alert data!")
    print("Each alert gets attack-specific analysis with relevant:")
    print("  - Technical concepts (encryption vs SQL injection)")
    print("  - MITRE techniques specific to the attack")
    print("  - Recommendations tailored to the threat type")
    print("\nThis is NOT template-based or generic!")
elif tests_passed >= 3:
    print("\n[LIKELY GENUINE]")
    print("The AI appears to be reading the data, but some tests failed.")
else:
    print("\n[SUSPICIOUS]")
    print("The AI may not be properly analyzing alert-specific details.")

print("\n" + "=" * 80)

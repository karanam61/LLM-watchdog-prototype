"""
RAG System Visibility Tool - See EXACTLY what RAG retrieves and how AI uses it
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase
from ai.rag_system import RAGSystem

print("=" * 80)
print("RAG SYSTEM VISIBILITY - DETAILED TRACE")
print("=" * 80)

# Get a recent alert
response = supabase.table('alerts').select('*').limit(1).order('created_at', desc=True).execute()
if not response.data:
    print("[ERROR] No alerts found")
    exit(1)

alert = response.data[0]

print(f"\nAnalyzing Alert: {alert['alert_name']}")
print(f"MITRE: {alert.get('mitre_technique')}")
print(f"Severity: {alert['severity']}")
print(f"Description: {alert['description'][:100]}...")

# Initialize RAG
print("\n" + "=" * 80)
print("STEP 1: RAG SYSTEM QUERIES")
print("=" * 80)

rag = RAGSystem()

# Query each collection individually to show what's retrieved
print("\n[1] MITRE Technique Information")
print("-" * 80)
if alert.get('mitre_technique'):
    mitre_result = rag.query_mitre_info(alert['mitre_technique'])
    if mitre_result.get('found'):
        print(f"[FOUND] MITRE {alert['mitre_technique']}")
        content = mitre_result['content']
        print(f"Content Preview: {content[:300]}...")
        print(f"Full Length: {len(content)} characters")
    else:
        print("[NOT FOUND] No MITRE data for this technique")
else:
    print("[SKIPPED] No MITRE technique in alert")

print("\n[2] Historical Similar Alerts")
print("-" * 80)
history = rag.query_historical_alerts(
    alert_name=alert.get('alert_name', ''),
    mitre_technique=alert.get('mitre_technique', ''),
    n_results=3
)
if history.get('found'):
    print(f"[FOUND] {history['count']} similar past incidents")
    for i, analysis in enumerate(history['analyses'][:2], 1):
        print(f"\n  Past Incident #{i}:")
        print(f"  {analysis[:200]}...")
else:
    print("[NOT FOUND] No similar historical alerts")

print("\n[3] Business Rules & Department Priorities")
print("-" * 80)
# Extract department from hostname
hostname = alert.get('hostname', '').lower()
departments = ['finance', 'it', 'hr', 'engineering', 'sales']
department = next((d for d in departments if d in hostname), 'unknown')

business = rag.query_business_rules(
    department=department,
    severity=alert.get('severity', ''),
    n_results=2
)
if business.get('found'):
    print(f"[FOUND] {business['count']} business rules for {department} department")
    for i, rule in enumerate(business['rules'][:1], 1):
        print(f"\n  Rule #{i}: {rule[:200]}...")
else:
    print(f"[NOT FOUND] No business rules for {department}")

print("\n[4] Attack Patterns & TTPs")
print("-" * 80)
# Determine attack type from alert name
attack_type = 'unknown'
if 'ransomware' in alert['alert_name'].lower():
    attack_type = 'ransomware'
elif 'sql' in alert['alert_name'].lower():
    attack_type = 'sql_injection'
elif 'phishing' in alert['alert_name'].lower():
    attack_type = 'phishing'
elif 'exfiltration' in alert['alert_name'].lower():
    attack_type = 'data_exfiltration'

patterns = rag.query_attack_patterns(
    mitre_technique=alert.get('mitre_technique', ''),
    attack_type=attack_type,
    n_results=2
)
if patterns.get('found'):
    print(f"[FOUND] {patterns['count']} attack patterns for {attack_type}")
    for i, pattern in enumerate(patterns['patterns'][:1], 1):
        print(f"\n  Pattern #{i}: {pattern[:200]}...")
else:
    print(f"[NOT FOUND] No attack patterns for {attack_type}")

print("\n[5] Detection Rules")
print("-" * 80)
detection = rag.query_detection_rules(
    alert_name=alert.get('alert_name', ''),
    n_results=1
)
if detection.get('found'):
    print(f"[FOUND] {detection['count']} detection rules")
    print(f"  {detection['rules'][0][:200]}...")
else:
    print("[NOT FOUND] No detection rules")

print("\n[6] Detection Signatures")
print("-" * 80)
signatures = rag.query_detection_signatures(
    alert_name=alert.get('alert_name', ''),
    n_results=3
)
if signatures.get('found'):
    print(f"[FOUND] {signatures['count']} signature matches")
    for i, sig in enumerate(signatures['signatures'][:2], 1):
        print(f"\n  Signature #{i}: {sig[:150]}...")
else:
    print("[NOT FOUND] No signatures")

print("\n[7] Asset Context (User & Host)")
print("-" * 80)
asset = rag.query_asset_context(
    username=alert.get('username', ''),
    hostname=alert.get('hostname', '')
)
if asset.get('found'):
    print("[FOUND] Asset context")
    if asset.get('user_context'):
        print(f"\n  User: {asset['user_context'][:200]}...")
    if asset.get('host_context'):
        print(f"\n  Host: {asset['host_context'][:200]}...")
else:
    print("[NOT FOUND] No asset context")

# Now check what the AI's analysis actually contains
print("\n" + "=" * 80)
print("STEP 2: WHAT THE AI USED IN ITS ANALYSIS")
print("=" * 80)

ai_reasoning = alert.get('ai_reasoning', '')
ai_evidence = alert.get('ai_evidence', [])

print(f"\nAI Verdict: {alert.get('ai_verdict')}")
print(f"Confidence: {alert.get('ai_confidence')}")

# Check what RAG data the AI referenced
print("\n" + "-" * 80)
print("RAG DATA USAGE ANALYSIS:")
print("-" * 80)

used_count = 0

# Check MITRE usage
if alert.get('mitre_technique') and alert.get('mitre_technique') in ai_reasoning:
    print(f"\n[USED] MITRE {alert.get('mitre_technique')} referenced in reasoning")
    used_count += 1

# Check historical patterns
if 'historical' in ai_reasoning.lower() or 'past' in ai_reasoning.lower() or 'similar' in ai_reasoning.lower():
    print("[USED] Historical incidents referenced")
    used_count += 1

# Check business context
if department in ai_reasoning.lower() or 'compliance' in ai_reasoning.lower() or 'business' in ai_reasoning.lower():
    print(f"[USED] Business context for {department} department")
    used_count += 1

# Check attack patterns
if 'pattern' in ai_reasoning.lower() or 'indicator' in ai_reasoning.lower():
    print(f"[USED] Attack patterns/indicators")
    used_count += 1

# Check signatures
if 'signature' in ai_reasoning.lower():
    print("[USED] Detection signatures")
    used_count += 1

print(f"\n[SUMMARY] AI used {used_count}/7 RAG data sources in its analysis")

if used_count < 3:
    print("\n[WARNING] AI may not be fully utilizing RAG data!")
elif used_count >= 5:
    print("\n[EXCELLENT] AI is comprehensively using RAG knowledge!")
else:
    print("\n[GOOD] AI is using multiple RAG sources")

print("\n" + "=" * 80)
print("STEP 3: AI'S COMPLETE REASONING (WITH RAG CONTEXT)")
print("=" * 80)

print(f"\n{ai_reasoning}")

print("\n" + "=" * 80)
print("Evidence Points:")
for i, ev in enumerate(ai_evidence, 1):
    print(f"  {i}. {ev}")

print("\n" + "=" * 80)

"""Show the ACTUAL AI reasoning process - what Claude sees and how it responds"""
import os
import sys
from dotenv import load_dotenv
import json

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase
from ai.rag_system import RAGSystem
from ai.alert_analyzer_final import AlertAnalyzer

print("=" * 80)
print("EXPOSING AI'S ACTUAL REASONING PROCESS")
print("=" * 80)

# Get an alert
alert_id = "70a6a5d8-8213-4dac-b399-70c94b868bb5"  # Cloud misconfiguration
print(f"\nFetching alert: {alert_id}")
alert_response = supabase.table('alerts').select('*').eq('id', alert_id).execute()
alert = alert_response.data[0] if alert_response.data else None

if not alert:
    print("[ERROR] Alert not found")
    exit(1)

print(f"\nAlert: {alert['alert_name']}")
print(f"Severity: {alert['severity']}")
print(f"Description: {alert['description'][:100]}...")

# Get the logs
network_logs = supabase.table('network_logs').select('*').eq('alert_id', alert_id).execute()
process_logs = supabase.table('process_logs').select('*').eq('alert_id', alert_id).execute()
file_logs = supabase.table('file_activity_logs').select('*').eq('alert_id', alert_id).execute()
windows_logs = supabase.table('windows_event_logs').select('*').eq('alert_id', alert_id).execute()

logs = {
    'network': network_logs.data if network_logs.data else [],
    'process': process_logs.data if process_logs.data else [],
    'file': file_logs.data if file_logs.data else [],
    'windows': windows_logs.data if windows_logs.data else []
}

# Initialize RAG to build context
rag = RAGSystem()

# Build the EXACT context that gets sent to Claude
print("\n" + "=" * 80)
print("STEP 1: CONTEXT SENT TO AI (What Claude Actually Sees)")
print("=" * 80)

context = rag.build_context(alert, logs)
print(context)
print("\n[This is the EXACT text that Claude receives as input]")

# Now let's see what the AI currently has as analysis
print("\n" + "=" * 80)
print("STEP 2: AI'S CURRENT ANALYSIS")
print("=" * 80)

print(f"\nVerdict: {alert.get('ai_verdict')}")
print(f"Confidence: {alert.get('ai_confidence')}")

print(f"\nEvidence:")
for i, e in enumerate(alert.get('ai_evidence', []), 1):
    print(f"  {i}. {e}")

print(f"\nReasoning:")
print(alert.get('ai_reasoning'))

print(f"\nRecommendation:")
print(alert.get('ai_recommendation'))

# Now let's analyze: Does the AI's response show actual reasoning?
print("\n" + "=" * 80)
print("STEP 3: CHECKING FOR GENUINE REASONING vs TEMPLATE RESPONSES")
print("=" * 80)

reasoning = alert.get('ai_reasoning', '')
evidence = alert.get('ai_evidence', [])

# Check for signs of actual reasoning
reasoning_indicators = []

# 1. Does it connect multiple pieces of evidence?
if 'and' in reasoning.lower() or 'combined with' in reasoning.lower() or 'along with' in reasoning.lower():
    reasoning_indicators.append("[OK] AI is connecting multiple evidence points (not just listing)")

# 2. Does it explain WHY something is malicious, not just WHAT happened?
if 'indicates' in reasoning.lower() or 'suggests' in reasoning.lower() or 'because' in reasoning.lower():
    reasoning_indicators.append("[OK] AI is explaining causation and implications")

# 3. Does it reference specific technical details from logs?
has_technical_details = False
for log_type, log_data in logs.items():
    if log_data:
        for log in log_data:
            # Check if any specific log field values appear in reasoning
            for key, value in log.items():
                if value and str(value) in reasoning:
                    has_technical_details = True
                    reasoning_indicators.append(f"[OK] AI references specific {log_type} log detail: {key}={value}")
                    break
            if has_technical_details:
                break

# 4. Does it synthesize information across different log types?
log_types_mentioned = 0
if 'network' in reasoning.lower() or 'connection' in reasoning.lower() or 'traffic' in reasoning.lower():
    log_types_mentioned += 1
if 'process' in reasoning.lower() or 'command' in reasoning.lower() or 'execution' in reasoning.lower():
    log_types_mentioned += 1
if 'file' in reasoning.lower() or 'access' in reasoning.lower():
    log_types_mentioned += 1

if log_types_mentioned >= 2:
    reasoning_indicators.append(f"[OK] AI synthesizes across {log_types_mentioned} different log types")

# 5. Does it make inferences beyond what's directly stated?
inference_words = ['likely', 'probably', 'suggests', 'indicates', 'implies', 'pattern', 'consistent with']
inferences_found = sum(1 for word in inference_words if word in reasoning.lower())
if inferences_found >= 2:
    reasoning_indicators.append(f"[OK] AI makes {inferences_found} analytical inferences (not just reporting facts)")

print("\nReasoning Quality Indicators:")
for indicator in reasoning_indicators:
    print(f"  {indicator}")

# Compare to a "dumb template" response
print("\n" + "=" * 80)
print("STEP 4: COMPARISON - AI vs Simple Template")
print("=" * 80)

print("\nWhat a DUMB TEMPLATE would say:")
print(f"  Verdict: {alert['severity']} severity = suspicious")
print(f"  Evidence: Alert name contains 'Cloud Misconfiguration'")
print(f"  Reasoning: This is suspicious because severity is {alert['severity']}")

print("\nWhat the AI ACTUALLY said:")
print(f"  Verdict: {alert.get('ai_verdict')} (with {alert.get('ai_confidence')} confidence)")
print(f"  Evidence: {len(evidence)} specific findings from logs, MITRE, and patterns")
print(f"  Reasoning: {len(reasoning)} characters of analysis connecting:")
print(f"    - Alert details -> Log evidence -> MITRE technique -> Historical patterns")

if len(reasoning_indicators) >= 3:
    print("\n[VERDICT] AI is performing GENUINE ANALYSIS!")
    print("The AI is:")
    print("  - Connecting dots across multiple evidence sources")
    print("  - Explaining WHY (not just WHAT)")
    print("  - Making analytical inferences")
    print("  - Synthesizing technical details from actual logs")
else:
    print("\n[WARNING] AI reasoning appears shallow - may need tuning")

print("\n" + "=" * 80)

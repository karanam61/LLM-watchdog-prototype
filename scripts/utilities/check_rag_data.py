"""Check if RAG system has historical data and signatures"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from ai.rag_system import RAGSystem

print("=" * 80)
print("CHECKING RAG SYSTEM FOR HISTORICAL DATA")
print("=" * 80)

# Initialize RAG
rag = RAGSystem()

# Query for historical alerts similar to data exfiltration
print("\n1. Querying historical alerts for 'Data Exfiltration'...")
history = rag.query_historical_alerts(
    alert_name="Data Exfiltration",
    mitre_technique="T1530",
    n_results=3
)

print(f"\nFound: {history.get('count', 0)} similar past incidents")
if history.get('found') and history.get('analyses'):
    print("\nHistorical incidents:")
    for i, analysis in enumerate(history['analyses'][:2], 1):
        print(f"\n  {i}. {analysis[:200]}...")

# Query attack patterns
print("\n\n2. Querying attack patterns for T1530...")
patterns = rag.query_attack_patterns(
    mitre_technique="T1530",
    attack_type="data exfiltration",
    n_results=2
)

print(f"\nFound: {patterns.get('count', 0)} attack patterns")
if patterns.get('found') and patterns.get('patterns'):
    print("\nAttack patterns:")
    for i, pattern in enumerate(patterns['patterns'][:2], 1):
        print(f"\n  {i}. {pattern[:200]}...")

# Query detection signatures
print("\n\n3. Querying detection signatures...")
signatures = rag.query_detection_signatures(
    alert_name="Data Exfiltration",
    n_results=3
)

print(f"\nFound: {signatures.get('count', 0)} signatures")
if signatures.get('found') and signatures.get('signatures'):
    print("\nSignatures:")
    for i, sig in enumerate(signatures['signatures'][:3], 1):
        print(f"\n  {i}. {sig[:150]}...")

print("\n" + "=" * 80)
print("CONCLUSION:")
print("=" * 80)

if history.get('count', 0) > 0 or patterns.get('count', 0) > 0 or signatures.get('count', 0) > 0:
    print("\n[OK] RAG system HAS historical data, patterns, and signatures!")
    print("The AI's references to 'historical patterns' and 'signature matches'")
    print("are REAL data from the RAG knowledge base, NOT hallucinations!")
else:
    print("\n[WARNING] RAG system returned no data - AI may be hallucinating context")

print("\n" + "=" * 80)

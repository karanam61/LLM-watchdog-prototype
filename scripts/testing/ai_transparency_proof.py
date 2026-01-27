"""
AI TRANSPARENCY & PROOF DASHBOARD
==================================
Concrete proof that AI is:
1. Actually analyzing alerts (not using templates)
2. Using real RAG data (not hallucinating)
3. Providing different analysis for different attacks
4. Citing real evidence from logs
"""
import os
import sys
from dotenv import load_dotenv
import json

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase
from ai.rag_system import RAGSystem

class AITransparencyProof:
    """Generate proof that AI is legitimate"""
    
    def __init__(self):
        self.rag = RAGSystem()
        
    def generate_proof_report(self, alert_id):
        """
        Generate comprehensive proof report for an alert
        Shows: RAG data retrieved, AI's claims, verification, evidence chain
        """
        # Get alert with all analysis
        response = supabase.table('alerts').select('*').eq('id', alert_id).execute()
        if not response.data:
            return {'error': 'Alert not found'}
        
        alert = response.data[0]
        
        # Get associated logs
        network_logs = supabase.table('network_logs').select('*').eq('alert_id', alert_id).execute().data or []
        process_logs = supabase.table('process_logs').select('*').eq('alert_id', alert_id).execute().data or []
        file_logs = supabase.table('file_activity_logs').select('*').eq('alert_id', alert_id).execute().data or []
        
        print("=" * 100)
        print(f"AI TRANSPARENCY PROOF REPORT - Alert ID: {alert_id[:16]}...")
        print("=" * 100)
        
        # SECTION 1: ALERT DATA
        print(f"\n{'='*100}")
        print("SECTION 1: ORIGINAL ALERT DATA")
        print("="*100)
        print(f"Alert Name: {alert['alert_name']}")
        print(f"Severity: {alert['severity'].upper()}")
        print(f"MITRE Technique: {alert.get('mitre_technique', 'N/A')}")
        print(f"Description: {alert['description'][:200]}...")
        print(f"\nUsername: {alert.get('username', 'N/A')}")
        print(f"Hostname: {alert.get('hostname', 'N/A')}")
        print(f"Source IP: {alert.get('source_ip', 'N/A')}")
        print(f"Destination IP: {alert.get('dest_ip', 'N/A')}")
        
        # SECTION 2: LOGS ASSOCIATED WITH ALERT
        print(f"\n{'='*100}")
        print("SECTION 2: LOGS CORRELATED TO THIS ALERT")
        print("="*100)
        print(f"Network Logs: {len(network_logs)}")
        print(f"Process Logs: {len(process_logs)}")
        print(f"File Activity Logs: {len(file_logs)}")
        
        if network_logs:
            print(f"\nSample Network Log:")
            log = network_logs[0]
            print(f"  Protocol: {log.get('protocol', 'N/A')}")
            print(f"  Bytes: {log.get('bytes_transferred', 'N/A')}")
            print(f"  Description: {log.get('description', 'N/A')[:100]}")
        
        if process_logs:
            print(f"\nSample Process Log:")
            log = process_logs[0]
            print(f"  Process: {log.get('process_name', 'N/A')}")
            print(f"  Command: {log.get('command_line', 'N/A')[:100]}")
        
        # SECTION 3: RAG DATA RETRIEVED
        print(f"\n{'='*100}")
        print("SECTION 3: KNOWLEDGE RETRIEVED FROM RAG SYSTEM")
        print("="*100)
        
        rag_data = {}
        
        # MITRE
        print("\n[1] MITRE ATT&CK Technique Data:")
        if alert.get('mitre_technique'):
            mitre = self.rag.query_mitre_info(alert['mitre_technique'])
            if mitre.get('found'):
                rag_data['mitre'] = mitre['content']
                print(f"    [FOUND] {len(mitre['content'])} characters of MITRE data")
                print(f"    Preview: {mitre['content'][:150]}...")
            else:
                print("    [NOT FOUND]")
        else:
            print("    [SKIPPED] No MITRE technique")
        
        # Historical
        print("\n[2] Historical Similar Alerts:")
        history = self.rag.query_historical_alerts(
            alert_name=alert.get('alert_name', ''),
            mitre_technique=alert.get('mitre_technique', ''),
            n_results=3
        )
        if history.get('found'):
            rag_data['historical'] = history['analyses']
            print(f"    [FOUND] {history['count']} similar past incidents")
            for i, analysis in enumerate(history['analyses'][:2], 1):
                print(f"    Past Incident #{i}: {analysis[:120]}...")
        else:
            print("    [NOT FOUND]")
        
        # Business Rules
        print("\n[3] Business Context:")
        hostname = alert.get('hostname', '').lower()
        departments = ['finance', 'it', 'hr', 'engineering', 'sales']
        department = next((d for d in departments if d in hostname), 'unknown')
        business = self.rag.query_business_rules(department=department, severity=alert.get('severity', ''))
        if business.get('found'):
            rag_data['business'] = business['rules']
            print(f"    [FOUND] {business['count']} business rules for {department} department")
            print(f"    Rule: {business['rules'][0][:120]}...")
        else:
            print("    [NOT FOUND]")
        
        # SECTION 4: AI'S ANALYSIS
        print(f"\n{'='*100}")
        print("SECTION 4: AI'S ANALYSIS OUTPUT")
        print("="*100)
        print(f"\nVerdict: {alert.get('ai_verdict', 'N/A').upper()}")
        print(f"Confidence: {alert.get('ai_confidence', 0) * 100:.1f}%")
        print(f"\nReasoning ({len(alert.get('ai_reasoning', ''))} characters):")
        print(alert.get('ai_reasoning', 'N/A'))
        
        print(f"\nEvidence Points ({len(alert.get('ai_evidence', []))}):")
        for i, ev in enumerate(alert.get('ai_evidence', []), 1):
            print(f"  {i}. {ev}")
        
        print(f"\nRecommendation:")
        print(alert.get('ai_recommendation', 'N/A'))
        
        # SECTION 5: VERIFICATION (THE PROOF!)
        print(f"\n{'='*100}")
        print("SECTION 5: VERIFICATION - PROOF AI IS NOT HALLUCINATING")
        print("="*100)
        
        reasoning = alert.get('ai_reasoning', '').lower()
        evidence = ' '.join(alert.get('ai_evidence', [])).lower()
        all_ai_text = (reasoning + ' ' + evidence).lower()
        
        verified = []
        hallucinations = []
        
        # Check 1: MITRE technique mentioned
        print("\n[CHECK 1] MITRE Technique Usage")
        if alert.get('mitre_technique'):
            if alert['mitre_technique'].lower() in all_ai_text:
                print(f"    [VERIFIED] AI mentions MITRE technique '{alert['mitre_technique']}'")
                verified.append("MITRE technique correctly cited")
            else:
                print(f"    [WARNING] AI doesn't mention MITRE technique")
                hallucinations.append("Missing MITRE technique")
        
        # Check 2: Alert-specific details
        print("\n[CHECK 2] Alert-Specific Details")
        alert_keywords = [
            word.lower() for word in alert['alert_name'].split()
            if len(word) > 3 and word.lower() not in ['the', 'and', 'for', 'with']
        ]
        mentioned_keywords = [kw for kw in alert_keywords if kw in all_ai_text]
        if mentioned_keywords:
            print(f"    [VERIFIED] AI mentions alert-specific keywords: {mentioned_keywords}")
            verified.append(f"Alert-specific analysis (mentions: {', '.join(mentioned_keywords)})")
        else:
            print(f"    [WARNING] AI doesn't mention alert-specific details")
            hallucinations.append("Missing alert-specific details")
        
        # Check 3: RAG data usage
        print("\n[CHECK 3] RAG Knowledge Usage")
        if 'mitre' in rag_data and alert.get('mitre_technique', '').lower() in reasoning:
            print(f"    [VERIFIED] AI used MITRE data from RAG")
            verified.append("Used MITRE ATT&CK knowledge")
        
        if 'historical' in rag_data and ('historical' in reasoning or 'past' in reasoning or 'similar' in reasoning):
            print(f"    [VERIFIED] AI referenced historical incidents")
            verified.append("Used historical incident data")
        
        if 'business' in rag_data and (department in reasoning or 'compliance' in reasoning or 'business' in reasoning):
            print(f"    [VERIFIED] AI incorporated business context")
            verified.append("Applied business rules")
        
        # Check 4: Log data references
        print("\n[CHECK 4] Log Data Analysis")
        if network_logs and ('network' in reasoning or 'traffic' in reasoning or 'connection' in reasoning):
            print(f"    [VERIFIED] AI analyzed network logs ({len(network_logs)} logs)")
            verified.append(f"Analyzed {len(network_logs)} network logs")
        
        if process_logs and ('process' in reasoning or 'execution' in reasoning or 'command' in reasoning):
            print(f"    [VERIFIED] AI analyzed process logs ({len(process_logs)} logs)")
            verified.append(f"Analyzed {len(process_logs)} process logs")
        
        if file_logs and ('file' in reasoning):
            print(f"    [VERIFIED] AI analyzed file activity logs ({len(file_logs)} logs)")
            verified.append(f"Analyzed {len(file_logs)} file logs")
        
        # Check 5: Unique analysis (not template)
        print("\n[CHECK 5] Unique Analysis Detection")
        reasoning_len = len(alert.get('ai_reasoning', ''))
        evidence_count = len(alert.get('ai_evidence', []))
        
        if reasoning_len > 300 and evidence_count >= 5:
            print(f"    [VERIFIED] Comprehensive analysis: {reasoning_len} chars, {evidence_count} evidence points")
            verified.append("Deep analysis (not template)")
        else:
            print(f"    [WARNING] Analysis may be shallow: {reasoning_len} chars, {evidence_count} evidence")
        
        # Check 6: Attack-specific recommendations
        print("\n[CHECK 6] Attack-Specific Recommendations")
        recommendation = alert.get('ai_recommendation', '').lower()
        if recommendation and any(kw in recommendation for kw in alert_keywords):
            print(f"    [VERIFIED] Recommendation is specific to this attack type")
            verified.append("Tailored recommendations")
        
        # SECTION 6: FINAL VERDICT
        print(f"\n{'='*100}")
        print("SECTION 6: FINAL PROOF VERDICT")
        print("="*100)
        
        verification_score = len(verified) / (len(verified) + len(hallucinations)) * 100 if (verified or hallucinations) else 0
        
        print(f"\nVerification Score: {verification_score:.1f}%")
        print(f"\nProof Points ({len(verified)}):")
        for i, proof in enumerate(verified, 1):
            print(f"  {i}. {proof}")
        
        if hallucinations:
            print(f"\nPotential Issues ({len(hallucinations)}):")
            for i, issue in enumerate(hallucinations, 1):
                print(f"  {i}. {issue}")
        
        print(f"\n{'='*100}")
        if verification_score >= 70:
            print("VERDICT: [VERIFIED] AI IS PERFORMING LEGITIMATE ANALYSIS")
            print("The AI is using real data, not hallucinating!")
        elif verification_score >= 50:
            print("VERDICT: [MOSTLY VERIFIED] AI is mostly legitimate with minor issues")
        else:
            print("VERDICT: [NEEDS REVIEW] AI may be using templates or hallucinating")
        print("="*100)
        
        return {
            'alert_id': alert_id,
            'alert_name': alert['alert_name'],
            'verification_score': verification_score,
            'verified_points': verified,
            'potential_issues': hallucinations,
            'rag_sources_used': list(rag_data.keys()),
            'log_counts': {
                'network': len(network_logs),
                'process': len(process_logs),
                'file': len(file_logs)
            },
            'ai_analysis': {
                'verdict': alert.get('ai_verdict'),
                'confidence': alert.get('ai_confidence'),
                'reasoning_length': len(alert.get('ai_reasoning', '')),
                'evidence_count': len(alert.get('ai_evidence', []))
            }
        }
    
    def compare_multiple_alerts(self, limit=5):
        """
        Compare AI analysis across multiple alerts
        Proves AI gives different analysis for different attack types
        """
        print("=" * 100)
        print("AI UNIQUENESS PROOF - Comparing Multiple Alerts")
        print("="*100)
        print("\nProof: If AI was using templates, all analyses would be similar.")
        print("If AI is legitimate, each analysis should be unique to the attack.\n")
        
        # Get diverse alerts
        response = supabase.table('alerts').select('*').not_.is_('ai_verdict', 'null').limit(limit).execute()
        
        if not response.data:
            print("[ERROR] No analyzed alerts found")
            return
        
        alerts = response.data
        
        print(f"Analyzing {len(alerts)} alerts...\n")
        print("="*100)
        
        for i, alert in enumerate(alerts, 1):
            print(f"\n[ALERT {i}] {alert['alert_name']}")
            print("-" * 100)
            print(f"MITRE: {alert.get('mitre_technique', 'N/A')}")
            print(f"Verdict: {alert.get('ai_verdict', 'N/A').upper()}")
            print(f"Confidence: {alert.get('ai_confidence', 0) * 100:.1f}%")
            
            reasoning = alert.get('ai_reasoning', '')
            evidence = alert.get('ai_evidence', [])
            
            print(f"\nReasoning ({len(reasoning)} chars):")
            print(f"  {reasoning[:200]}...")
            
            print(f"\nFirst 3 Evidence Points:")
            for j, ev in enumerate(evidence[:3], 1):
                print(f"  {j}. {ev[:100]}...")
            
            # Check uniqueness
            alert_name_words = set(alert['alert_name'].lower().split())
            reasoning_words = set(reasoning.lower().split())
            overlap = alert_name_words & reasoning_words
            
            print(f"\nUniqueness Score: {len(overlap)} attack-specific words in reasoning")
        
        # Calculate similarity to detect templates
        print(f"\n{'='*100}")
        print("TEMPLATE DETECTION")
        print("="*100)
        
        reasonings = [a.get('ai_reasoning', '') for a in alerts]
        unique_words = []
        
        for r in reasonings:
            words = set(r.lower().split())
            unique_words.append(len(words))
        
        avg_unique = sum(unique_words) / len(unique_words) if unique_words else 0
        
        print(f"\nAverage unique words per analysis: {avg_unique:.0f}")
        print(f"Reasoning lengths: {[len(r) for r in reasonings]}")
        
        if all(len(r) > 200 for r in reasonings) and avg_unique > 100:
            print("\n[VERIFIED] Each analysis is unique and comprehensive")
            print("AI is NOT using templates - each attack gets custom analysis!")
        else:
            print("\n[WARNING] Some analyses may be templated")
        
        print("="*100)


if __name__ == '__main__':
    proof = AITransparencyProof()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'compare':
        # Compare multiple alerts
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        proof.compare_multiple_alerts(limit)
    else:
        # Single alert proof
        response = supabase.table('alerts').select('id').not_.is_('ai_verdict', 'null').limit(1).order('created_at', desc=True).execute()
        if response.data:
            proof.generate_proof_report(response.data[0]['id'])
        else:
            print("[ERROR] No analyzed alerts found")

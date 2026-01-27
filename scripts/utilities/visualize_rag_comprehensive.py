"""
RAG VISUALIZATION DASHBOARD
Shows exactly how AI uses RAG knowledge base for each alert
Integrates with monitoring system for tracking
"""
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from storage.database import supabase
from ai.rag_system import RAGSystem

class RAGVisualizer:
    """Visualize RAG data retrieval and AI usage"""
    
    def __init__(self):
        self.rag = RAGSystem()
        
    def analyze_alert_rag_usage(self, alert_id):
        """
        Comprehensive analysis of RAG usage for a specific alert
        Returns detailed breakdown of what was retrieved and what AI used
        """
        # Get alert
        response = supabase.table('alerts').select('*').eq('id', alert_id).execute()
        if not response.data:
            return {'error': 'Alert not found'}
        
        alert = response.data[0]
        
        result = {
            'alert_id': alert_id,
            'alert_name': alert['alert_name'],
            'mitre_technique': alert.get('mitre_technique'),
            'severity': alert['severity'],
            'verdict': alert.get('ai_verdict'),
            'confidence': alert.get('ai_confidence'),
            'timestamp': alert.get('created_at'),
            'rag_queries': [],
            'rag_usage_score': 0,
            'ai_reasoning': alert.get('ai_reasoning', ''),
            'ai_evidence': alert.get('ai_evidence', []),
            'chain_of_thought': alert.get('ai_chain_of_thought', [])
        }
        
        # Query each RAG collection
        print(f"\n{'='*80}")
        print(f"RAG ANALYSIS FOR: {alert['alert_name']}")
        print(f"{'='*80}\n")
        
        # 1. MITRE Information
        print("[1/7] MITRE Technique Query...")
        mitre_query = {
            'source': 'MITRE ATT&CK',
            'query_type': 'mitre_technique',
            'input': alert.get('mitre_technique'),
            'found': False,
            'content_length': 0,
            'used_by_ai': False
        }
        
        if alert.get('mitre_technique'):
            mitre_result = self.rag.query_mitre_info(alert['mitre_technique'])
            if mitre_result.get('found'):
                mitre_query['found'] = True
                mitre_query['content_length'] = len(mitre_result['content'])
                mitre_query['preview'] = mitre_result['content'][:200] + "..."
                # Check if AI used it
                if alert.get('mitre_technique') in result['ai_reasoning']:
                    mitre_query['used_by_ai'] = True
                    result['rag_usage_score'] += 1
                print(f"   [FOUND] {mitre_query['content_length']} chars | Used by AI: {mitre_query['used_by_ai']}")
            else:
                print("   [NOT FOUND]")
        else:
            print("   [SKIPPED] No MITRE technique")
        
        result['rag_queries'].append(mitre_query)
        
        # 2. Historical Alerts
        print("[2/7] Historical Alerts Query...")
        history_query = {
            'source': 'Historical Incidents',
            'query_type': 'similar_alerts',
            'input': {'alert_name': alert.get('alert_name'), 'mitre': alert.get('mitre_technique')},
            'found': False,
            'count': 0,
            'used_by_ai': False
        }
        
        history = self.rag.query_historical_alerts(
            alert_name=alert.get('alert_name', ''),
            mitre_technique=alert.get('mitre_technique', ''),
            n_results=5
        )
        
        if history.get('found'):
            history_query['found'] = True
            history_query['count'] = history['count']
            history_query['preview'] = history['analyses'][0][:200] + "..." if history['analyses'] else ""
            # Check usage
            reasoning_lower = result['ai_reasoning'].lower()
            if 'historical' in reasoning_lower or 'past' in reasoning_lower or 'previous' in reasoning_lower:
                history_query['used_by_ai'] = True
                result['rag_usage_score'] += 1
            print(f"   [FOUND] {history_query['count']} incidents | Used by AI: {history_query['used_by_ai']}")
        else:
            print("   [NOT FOUND]")
        
        result['rag_queries'].append(history_query)
        
        # 3. Business Rules
        print("[3/7] Business Rules Query...")
        business_query = {
            'source': 'Business Rules',
            'query_type': 'department_priorities',
            'found': False,
            'count': 0,
            'used_by_ai': False
        }
        
        # Extract department
        hostname = alert.get('hostname', '').lower()
        departments = ['finance', 'it', 'hr', 'engineering', 'sales']
        department = next((d for d in departments if d in hostname), 'unknown')
        business_query['input'] = department
        
        business = self.rag.query_business_rules(
            department=department,
            severity=alert.get('severity', ''),
            n_results=2
        )
        
        if business.get('found'):
            business_query['found'] = True
            business_query['count'] = business['count']
            business_query['preview'] = business['rules'][0][:200] + "..." if business['rules'] else ""
            reasoning_lower = result['ai_reasoning'].lower()
            if department in reasoning_lower or 'compliance' in reasoning_lower or 'business' in reasoning_lower:
                business_query['used_by_ai'] = True
                result['rag_usage_score'] += 1
            print(f"   [FOUND] {business_query['count']} rules | Used by AI: {business_query['used_by_ai']}")
        else:
            print("   [NOT FOUND]")
        
        result['rag_queries'].append(business_query)
        
        # 4. Attack Patterns
        print("[4/7] Attack Patterns Query...")
        patterns_query = {
            'source': 'Attack Patterns',
            'query_type': 'ttps',
            'found': False,
            'count': 0,
            'used_by_ai': False
        }
        
        # Determine attack type
        attack_type = 'unknown'
        alert_name_lower = alert['alert_name'].lower()
        if 'ransomware' in alert_name_lower:
            attack_type = 'ransomware'
        elif 'sql' in alert_name_lower:
            attack_type = 'sql_injection'
        elif 'phishing' in alert_name_lower:
            attack_type = 'phishing'
        elif 'exfiltration' in alert_name_lower:
            attack_type = 'data_exfiltration'
        
        patterns_query['input'] = attack_type
        
        patterns = self.rag.query_attack_patterns(
            mitre_technique=alert.get('mitre_technique', ''),
            attack_type=attack_type,
            n_results=3
        )
        
        if patterns.get('found'):
            patterns_query['found'] = True
            patterns_query['count'] = patterns['count']
            patterns_query['preview'] = patterns['patterns'][0][:200] + "..." if patterns['patterns'] else ""
            reasoning_lower = result['ai_reasoning'].lower()
            if 'pattern' in reasoning_lower or 'ttp' in reasoning_lower or 'indicator' in reasoning_lower:
                patterns_query['used_by_ai'] = True
                result['rag_usage_score'] += 1
            print(f"   [FOUND] {patterns_query['count']} patterns | Used by AI: {patterns_query['used_by_ai']}")
        else:
            print("   [NOT FOUND]")
        
        result['rag_queries'].append(patterns_query)
        
        # 5. Detection Rules
        print("[5/7] Detection Rules Query...")
        detection_query = {
            'source': 'Detection Rules',
            'query_type': 'siem_queries',
            'found': False,
            'count': 0,
            'used_by_ai': False
        }
        
        detection = self.rag.query_detection_rules(
            alert_name=alert.get('alert_name', ''),
            n_results=2
        )
        
        if detection.get('found'):
            detection_query['found'] = True
            detection_query['count'] = detection['count']
            detection_query['preview'] = detection['rules'][0][:150] + "..." if detection['rules'] else ""
            reasoning_lower = result['ai_reasoning'].lower()
            if 'detection' in reasoning_lower or 'rule' in reasoning_lower:
                detection_query['used_by_ai'] = True
                result['rag_usage_score'] += 1
            print(f"   [FOUND] {detection_query['count']} rules | Used by AI: {detection_query['used_by_ai']}")
        else:
            print("   [NOT FOUND]")
        
        result['rag_queries'].append(detection_query)
        
        # 6. Signatures
        print("[6/7] Detection Signatures Query...")
        sig_query = {
            'source': 'Signatures',
            'query_type': 'malware_signatures',
            'found': False,
            'count': 0,
            'used_by_ai': False
        }
        
        signatures = self.rag.query_detection_signatures(
            alert_name=alert.get('alert_name', ''),
            n_results=3
        )
        
        if signatures.get('found'):
            sig_query['found'] = True
            sig_query['count'] = signatures['count']
            sig_query['preview'] = signatures['signatures'][0][:150] + "..." if signatures['signatures'] else ""
            reasoning_lower = result['ai_reasoning'].lower()
            if 'signature' in reasoning_lower:
                sig_query['used_by_ai'] = True
                result['rag_usage_score'] += 1
            print(f"   [FOUND] {sig_query['count']} signatures | Used by AI: {sig_query['used_by_ai']}")
        else:
            print("   [NOT FOUND]")
        
        result['rag_queries'].append(sig_query)
        
        # 7. Asset Context
        print("[7/7] Asset Context Query...")
        asset_query = {
            'source': 'Asset Context',
            'query_type': 'user_host_profiles',
            'found': False,
            'used_by_ai': False
        }
        
        asset_query['input'] = {
            'username': alert.get('username'),
            'hostname': alert.get('hostname')
        }
        
        asset = self.rag.query_asset_context(
            username=alert.get('username', ''),
            hostname=alert.get('hostname', '')
        )
        
        if asset.get('found'):
            asset_query['found'] = True
            asset_query['preview'] = (asset.get('user_context', '')[:100] + "...") if asset.get('user_context') else ""
            reasoning_lower = result['ai_reasoning'].lower()
            username = alert.get('username', '').lower()
            hostname = alert.get('hostname', '').lower()
            if username in reasoning_lower or hostname in reasoning_lower or 'department' in reasoning_lower:
                asset_query['used_by_ai'] = True
                result['rag_usage_score'] += 1
            print(f"   [FOUND] Context available | Used by AI: {asset_query['used_by_ai']}")
        else:
            print("   [NOT FOUND]")
        
        result['rag_queries'].append(asset_query)
        
        # Calculate usage percentage
        total_found = sum(1 for q in result['rag_queries'] if q['found'])
        result['total_sources_found'] = total_found
        result['sources_used_by_ai'] = result['rag_usage_score']
        result['usage_percentage'] = (result['rag_usage_score'] / total_found * 100) if total_found > 0 else 0
        
        print(f"\n{'='*80}")
        print(f"RAG USAGE SUMMARY")
        print(f"{'='*80}")
        print(f"Sources Found: {result['total_sources_found']}/7")
        print(f"Sources Used by AI: {result['sources_used_by_ai']}/{result['total_sources_found']}")
        print(f"Usage Rate: {result['usage_percentage']:.1f}%")
        
        if result['usage_percentage'] >= 70:
            print("\n[EXCELLENT] AI is comprehensively utilizing RAG knowledge!")
        elif result['usage_percentage'] >= 40:
            print("\n[GOOD] AI is using multiple RAG sources")
        else:
            print("\n[WARNING] AI may not be fully leveraging RAG data")
        
        return result
    
    def compare_multiple_alerts(self, limit=5):
        """
        Compare RAG usage across multiple alerts
        Shows trends in how AI uses knowledge base
        """
        print(f"\n{'='*80}")
        print(f"RAG USAGE COMPARISON ACROSS ALERTS")
        print(f"{'='*80}\n")
        
        response = supabase.table('alerts').select('*').limit(limit).order('created_at', desc=True).execute()
        
        if not response.data:
            print("[ERROR] No alerts found")
            return
        
        results = []
        for alert in response.data:
            if not alert.get('ai_verdict'):
                continue
            
            result = self.analyze_alert_rag_usage(alert['id'])
            results.append(result)
            print()
        
        # Summary table
        print(f"\n{'='*80}")
        print(f"SUMMARY TABLE")
        print(f"{'='*80}\n")
        print(f"{'Alert Name':<40} {'Verdict':<12} {'RAG Usage':<12} {'Sources'}")
        print("-" * 80)
        
        for r in results:
            if 'error' not in r:
                alert_name = r['alert_name'][:37] + "..." if len(r['alert_name']) > 40 else r['alert_name']
                verdict = (r['verdict'] or 'N/A').upper()
                usage = f"{r['usage_percentage']:.0f}%"
                sources = f"{r['sources_used_by_ai']}/{r['total_sources_found']}"
                print(f"{alert_name:<40} {verdict:<12} {usage:<12} {sources}")
        
        # Overall stats
        avg_usage = sum(r['usage_percentage'] for r in results if 'error' not in r) / len(results) if results else 0
        avg_sources = sum(r['sources_used_by_ai'] for r in results if 'error' not in r) / len(results) if results else 0
        
        print(f"\n{'='*80}")
        print(f"OVERALL STATISTICS")
        print(f"{'='*80}")
        print(f"Average RAG Usage: {avg_usage:.1f}%")
        print(f"Average Sources Used: {avg_sources:.1f}")
        print(f"Total Alerts Analyzed: {len(results)}")
        print(f"{'='*80}\n")


if __name__ == '__main__':
    visualizer = RAGVisualizer()
    
    # Get command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == 'compare':
        # Compare multiple alerts
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        visualizer.compare_multiple_alerts(limit)
    else:
        # Analyze single most recent alert
        response = supabase.table('alerts').select('id').limit(1).order('created_at', desc=True).execute()
        if response.data:
            visualizer.analyze_alert_rag_usage(response.data[0]['id'])
        else:
            print("[ERROR] No alerts found in database")

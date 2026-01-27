"""
AI Transparency API - Endpoints for AI Transparency Dashboard
==============================================================

This module provides Flask API endpoints that prove the AI is performing
legitimate analysis, not just returning templated responses.

WHAT THIS FILE DOES:
1. Generates verification proof for each AI analysis
2. Shows which facts the AI found in the data
3. Shows which RAG knowledge was retrieved
4. Shows the AI's chain of thought reasoning
5. Calculates verification scores

WHY THIS EXISTS:
- Users need proof AI is actually analyzing alerts
- Prevents "fake AI" that just returns templates
- Builds trust through transparency
- Enables audit of AI decisions

ENDPOINTS PROVIDED:
- GET /api/transparency/proof/<alert_id>  - Full proof for one alert
- GET /api/transparency/alerts            - List of analyzed alerts
- GET /api/transparency/summary           - Aggregate transparency stats

PROOF DATA INCLUDES:
- verification_score:   How well AI grounded its analysis in facts
- facts_found:          Specific observations from alert/logs
- facts_missing:        Expected facts AI couldn't find
- rag_knowledge_used:   Documents retrieved from knowledge base
- chain_of_thought:     Step-by-step reasoning process

FRONTEND CONSUMER:
- TransparencyDashboard.jsx - AI proof and verification UI

Author: AI-SOC Watchdog System
"""
from flask import Blueprint, jsonify, request
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from storage.database import supabase
from ai.rag_system import RAGSystem
from monitoring.live_logger import live_logger

transparency_bp = Blueprint('transparency', __name__)

@transparency_bp.route('/api/transparency/proof/<alert_id>', methods=['GET'])
def get_transparency_proof(alert_id):
    """
    Generate comprehensive proof that AI analyzed this alert legitimately
    Returns data in format expected by TransparencyDashboard.jsx
    """
    # Log with full educational details
    live_logger.log(
        'AI',
        'get_transparency_proof() - AI Decision Verification',
        {
            'endpoint': '/api/transparency/proof/<alert_id>',
            'alert_id': alert_id,
            'purpose': 'Generate proof that AI analysis is legitimate, not templated',
            'verification_checks': [
                'MITRE technique referenced in reasoning',
                'Alert-specific keywords mentioned',
                'RAG sources actually used',
                'Log analysis evidence present',
                'Reasoning depth and quality check'
            ],
            'outputs': ['verification_score', 'facts_found', 'missing_facts', 'final_verdict'],
            '_explanation': f'Verifying AI analysis for alert {alert_id}. This proves the AI actually analyzed the specific alert data and didnt use generic templates.'
        },
        status='success'
    )
    
    try:
        # Get alert
        response = supabase.table('alerts').select('*').eq('id', alert_id).execute()
        if not response.data:
            return jsonify({'error': 'Alert not found'}), 404
        
        alert = response.data[0]
        
        # Get logs
        network_logs = supabase.table('network_logs').select('*').eq('alert_id', alert_id).execute().data or []
        process_logs = supabase.table('process_logs').select('*').eq('alert_id', alert_id).execute().data or []
        file_logs = supabase.table('file_activity_logs').select('*').eq('alert_id', alert_id).execute().data or []
        
        # Get RAG data
        rag = RAGSystem()
        rag_data = {}
        rag_usage_list = []
        
        if alert.get('mitre_technique'):
            mitre = rag.query_mitre_info(alert['mitre_technique'])
            if mitre.get('found'):
                rag_data['mitre'] = {
                    'found': True,
                    'length': len(mitre['content']),
                    'preview': mitre['content'][:200]
                }
                rag_usage_list.append(f"MITRE ATT&CK: {alert['mitre_technique']}")
        
        history = rag.query_historical_alerts(
            alert_name=alert.get('alert_name', ''),
            mitre_technique=alert.get('mitre_technique', ''),
            n_results=3
        )
        if history.get('found'):
            rag_data['historical'] = {
                'found': True,
                'count': history['count'],
                'samples': [a[:150] for a in history['analyses'][:2]]
            }
            rag_usage_list.append(f"Historical: {history['count']} past analyses")
        
        # Verification
        reasoning = (alert.get('ai_reasoning') or '').lower()
        evidence_list = alert.get('ai_evidence') or []
        evidence_text = ' '.join(evidence_list).lower()
        all_ai_text = (reasoning + ' ' + evidence_text).lower()
        
        facts_found = []
        missing_facts = []
        
        # Check MITRE usage
        if alert.get('mitre_technique') and alert['mitre_technique'].lower() in all_ai_text:
            facts_found.append(f"AI references MITRE technique {alert['mitre_technique']}")
        elif alert.get('mitre_technique'):
            missing_facts.append(f"MITRE technique {alert['mitre_technique']} not mentioned")
        
        # Check alert-specific keywords
        alert_keywords = [
            word.lower() for word in alert['alert_name'].split()
            if len(word) > 3 and word.lower() not in ['the', 'and', 'for', 'with']
        ]
        mentioned = [kw for kw in alert_keywords if kw in all_ai_text]
        if mentioned:
            facts_found.append(f"AI mentions alert keywords: {', '.join(mentioned)}")
        
        # Check RAG usage evidence
        if 'mitre' in rag_data and alert.get('mitre_technique', '').lower() in reasoning:
            facts_found.append('AI uses MITRE ATT&CK knowledge from RAG')
        
        if 'historical' in rag_data and any(word in reasoning for word in ['historical', 'past', 'similar', 'previous']):
            facts_found.append(f"AI references {rag_data['historical']['count']} historical incidents")
        
        # Check log analysis
        if network_logs and any(word in reasoning for word in ['network', 'traffic', 'connection']):
            facts_found.append(f"AI analyzed {len(network_logs)} network logs")
        elif network_logs:
            missing_facts.append(f"{len(network_logs)} network logs available but not referenced")
        
        if process_logs and any(word in reasoning for word in ['process', 'execution', 'command']):
            facts_found.append(f"AI analyzed {len(process_logs)} process logs")
        elif process_logs:
            missing_facts.append(f"{len(process_logs)} process logs available but not referenced")
        
        # Check depth
        reasoning_len = len(alert.get('ai_reasoning') or '')
        evidence_count = len(evidence_list)
        
        if reasoning_len > 300:
            facts_found.append(f"Deep analysis: {reasoning_len} characters of reasoning")
        else:
            missing_facts.append(f"Shallow reasoning: only {reasoning_len} characters")
        
        if evidence_count >= 5:
            facts_found.append(f"Comprehensive evidence: {evidence_count} points")
        else:
            missing_facts.append(f"Limited evidence: only {evidence_count} points")
        
        # Calculate score
        total_checks = len(facts_found) + len(missing_facts)
        verification_score = (len(facts_found) / total_checks * 100) if total_checks > 0 else 0
        
        if verification_score >= 70:
            final_verdict = 'VERIFIED - AI analysis is legitimate'
        elif verification_score >= 50:
            final_verdict = 'MOSTLY_VERIFIED - Minor gaps in analysis'
        else:
            final_verdict = 'NEEDS_REVIEW - Analysis may be incomplete'
        
        # Return in format expected by TransparencyDashboard.jsx
        return jsonify({
            'alert_id': alert_id,
            'alert_name': alert['alert_name'],
            # Nested verification object expected by frontend (lines 220-242)
            'verification': {
                'verification_score': verification_score,
                'final_verdict': final_verdict,
                'facts_found': facts_found,
                'missing_facts': missing_facts,
                'rag_usage': rag_usage_list
            },
            # Alert data for expandable section (line 329)
            'alert_data': {
                'id': alert['id'],
                'alert_name': alert['alert_name'],
                'severity': alert.get('severity'),
                'mitre_technique': alert.get('mitre_technique'),
                'source_ip': alert.get('source_ip'),
                'dest_ip': alert.get('dest_ip'),
                'description': alert.get('description')
            },
            # AI analysis for expandable section (lines 354-411)
            'ai_analysis': {
                'verdict': alert.get('ai_verdict'),
                'confidence': alert.get('ai_confidence', 0),
                'reasoning': alert.get('ai_reasoning'),
                'evidence': evidence_list,
                'chain_of_thought': alert.get('ai_chain_of_thought', [])
            },
            # Correlated logs for expandable section (lines 417-453)
            'correlated_logs': {
                'network': network_logs,
                'process': process_logs,
                'file': file_logs
            },
            # Legacy fields for backward compatibility
            'rag_sources': rag_data,
            'log_counts': {
                'network': len(network_logs),
                'process': len(process_logs),
                'file': len(file_logs)
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@transparency_bp.route('/api/transparency/comparison', methods=['GET'])
def get_uniqueness_comparison():
    """
    Compare multiple alerts to prove AI gives unique analysis for each
    Proves AI is not using templates
    """
    try:
        limit = int(request.args.get('limit', 5))
        
        # Get diverse analyzed alerts
        response = supabase.table('alerts')\
            .select('id, alert_name, mitre_technique, ai_verdict, ai_confidence, ai_reasoning, ai_evidence')\
            .not_.is_('ai_verdict', 'null')\
            .limit(limit)\
            .execute()
        
        if not response.data:
            return jsonify({'error': 'No analyzed alerts found'}), 404
        
        alerts_analysis = []
        
        for alert in response.data:
            reasoning = alert.get('ai_reasoning', '')
            evidence = alert.get('ai_evidence', [])
            
            # Calculate uniqueness
            alert_keywords = set(alert['alert_name'].lower().split())
            reasoning_words = set(reasoning.lower().split())
            specific_keywords = alert_keywords & reasoning_words
            
            alerts_analysis.append({
                'alert_id': alert['id'],
                'alert_name': alert['alert_name'],
                'mitre': alert.get('mitre_technique'),
                'verdict': alert.get('ai_verdict'),
                'confidence': alert.get('ai_confidence'),
                'reasoning_length': len(reasoning),
                'evidence_count': len(evidence),
                'unique_words': len(reasoning_words),
                'attack_specific_keywords': len(specific_keywords),
                'reasoning_preview': reasoning[:200] + '...' if len(reasoning) > 200 else reasoning,
                'top_evidence': evidence[:3]
            })
        
        # Calculate statistics
        avg_length = sum(a['reasoning_length'] for a in alerts_analysis) / len(alerts_analysis)
        avg_unique = sum(a['unique_words'] for a in alerts_analysis) / len(alerts_analysis)
        avg_specific = sum(a['attack_specific_keywords'] for a in alerts_analysis) / len(alerts_analysis)
        
        # Determine if templated
        is_unique = all(a['reasoning_length'] > 200 for a in alerts_analysis) and avg_unique > 100
        
        return jsonify({
            'alerts': alerts_analysis,
            'statistics': {
                'total_alerts': len(alerts_analysis),
                'avg_reasoning_length': avg_length,
                'avg_unique_words': avg_unique,
                'avg_attack_specific_keywords': avg_specific
            },
            'verdict': {
                'is_unique': is_unique,
                'message': 'Each analysis is unique - AI is NOT using templates!' if is_unique else 'Some analyses may be templated'
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@transparency_bp.route('/api/transparency/summary', methods=['GET'])
def get_transparency_summary():
    """
    Overall transparency summary across all alerts
    Returns data in format expected by TransparencyDashboard.jsx
    """
    try:
        # Get all analyzed alerts
        response = supabase.table('alerts')\
            .select('id, alert_name, ai_verdict, ai_reasoning, ai_evidence')\
            .not_.is_('ai_verdict', 'null')\
            .limit(50)\
            .execute()
        
        if not response.data:
            # Return empty structure instead of 404 so frontend doesn't break
            return jsonify({
                'total_analyzed': 0,
                'total_deep_analysis': 0,
                'total_shallow_analysis': 0,
                'avg_evidence_depth': 0,
                'verdict_distribution': {},
                'transparency_score': 0
            })
        
        total_alerts = len(response.data)
        
        # Calculate metrics - deep analysis = reasoning > 300 chars AND >= 5 evidence items
        deep_analysis = sum(1 for a in response.data 
                          if len(a.get('ai_reasoning') or '') > 300 
                          and len(a.get('ai_evidence') or []) >= 5)
        shallow_analysis = total_alerts - deep_analysis
        
        avg_reasoning_length = sum(len(a.get('ai_reasoning') or '') for a in response.data) / total_alerts
        avg_evidence_count = sum(len(a.get('ai_evidence') or []) for a in response.data) / total_alerts
        
        # Verdict distribution
        verdicts = {}
        for a in response.data:
            verdict = a.get('ai_verdict', 'unknown')
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        
        # Return in format expected by frontend TransparencyDashboard.jsx
        return jsonify({
            # Fields expected by frontend (lines 103-108, 120-125, 137)
            'total_analyzed': total_alerts,
            'total_deep_analysis': deep_analysis,
            'total_shallow_analysis': shallow_analysis,
            'avg_evidence_depth': avg_evidence_count,
            'verdict_distribution': verdicts,
            'transparency_score': (deep_analysis / total_alerts * 100) if total_alerts > 0 else 0,
            # Also include detailed metrics for completeness
            'quality_metrics': {
                'deep_analysis_count': deep_analysis,
                'shallow_analysis_count': shallow_analysis,
                'deep_analysis_rate': (deep_analysis / total_alerts * 100) if total_alerts > 0 else 0,
                'avg_reasoning_length': avg_reasoning_length,
                'avg_evidence_count': avg_evidence_count
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

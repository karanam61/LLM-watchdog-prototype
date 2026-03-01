"""
Transparency Verifier - Validates AI's explanations are grounded and consistent
===============================================================================

This module verifies that the AI's transparency outputs are:
1. GROUNDED - Citations reference real data we provided
2. CONSISTENT - Reasoning matches the verdict
3. HONEST - Uncertainty is acknowledged where appropriate

WHY THIS EXISTS:
LLMs can generate plausible-sounding explanations that don't reflect
their actual reasoning. This module catches:
- Hallucinated evidence (citing logs that don't exist)
- Logical contradictions (benign verdict with "attack" in reasoning)
- Overconfidence (high confidence with weak evidence)
- Missing acknowledgment of uncertainty

Author: AI-SOC Watchdog System
"""

import re
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of transparency verification"""
    is_trustworthy: bool
    grounding_score: float  # 0-1, how much evidence is real
    consistency_score: float  # 0-1, logical consistency
    issues: List[str]
    warnings: List[str]
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_trustworthy': self.is_trustworthy,
            'grounding_score': self.grounding_score,
            'consistency_score': self.consistency_score,
            'issues': self.issues,
            'warnings': self.warnings,
            'details': self.details,
            'overall_trust_score': (self.grounding_score + self.consistency_score) / 2
        }


class TransparencyVerifier:
    """
    Verifies AI transparency claims against actual data.
    
    USAGE:
        verifier = TransparencyVerifier()
        result = verifier.verify(ai_response, logs_provided, alert)
        
        if not result.is_trustworthy:
            # Flag for human review
            # Log the issues
    """
    
    def __init__(self):
        # Attack-related keywords that shouldn't appear in benign explanations
        self.attack_keywords = [
            'malware', 'attack', 'exploit', 'malicious', 'ransomware',
            'credential theft', 'exfiltration', 'c2', 'command and control',
            'lateral movement', 'privilege escalation', 'persistence'
        ]
        
        # Benign-related keywords that shouldn't appear in malicious explanations
        self.benign_keywords = [
            'legitimate', 'authorized', 'normal operation', 'routine',
            'maintenance', 'scheduled', 'expected behavior', 'false positive'
        ]
    
    def verify(
        self,
        ai_response: Dict[str, Any],
        logs_provided: Dict[str, List],
        alert: Dict[str, Any]
    ) -> VerificationResult:
        """
        Comprehensive verification of AI transparency.
        
        Args:
            ai_response: The full AI analysis response
            logs_provided: The logs we gave to the AI
            alert: The original alert
            
        Returns:
            VerificationResult with scores and issues
        """
        issues = []
        warnings = []
        details = {}
        
        # 1. Verify evidence grounding
        grounding = self._verify_grounding(ai_response, logs_provided)
        details['grounding'] = grounding
        if grounding['hallucinated'] > 0:
            issues.append(f"AI cited {grounding['hallucinated']} log entries that don't exist")
        
        # 2. Verify logical consistency
        consistency = self._verify_consistency(ai_response)
        details['consistency'] = consistency
        issues.extend(consistency['issues'])
        warnings.extend(consistency['warnings'])
        
        # 3. Verify confidence calibration
        calibration = self._verify_confidence_calibration(ai_response)
        details['calibration'] = calibration
        warnings.extend(calibration['warnings'])
        
        # 4. Verify transparency completeness
        completeness = self._verify_transparency_completeness(ai_response)
        details['completeness'] = completeness
        if not completeness['is_complete']:
            warnings.append(f"Missing transparency fields: {completeness['missing']}")
        
        # Calculate scores
        grounding_score = grounding['grounding_score'] if grounding['total_citations'] > 0 else 1.0
        consistency_score = 1.0 - (len(consistency['issues']) * 0.2)  # -0.2 per issue
        consistency_score = max(0, consistency_score)
        
        # Overall trustworthiness
        is_trustworthy = (
            grounding_score >= 0.8 and
            len(issues) == 0 and
            consistency_score >= 0.6
        )
        
        result = VerificationResult(
            is_trustworthy=is_trustworthy,
            grounding_score=round(grounding_score, 2),
            consistency_score=round(consistency_score, 2),
            issues=issues,
            warnings=warnings,
            details=details
        )
        
        logger.info(f"[VERIFY] Transparency check: trustworthy={is_trustworthy}, "
                   f"grounding={grounding_score:.0%}, consistency={consistency_score:.0%}")
        
        return result
    
    def _verify_grounding(
        self,
        ai_response: Dict[str, Any],
        logs_provided: Dict[str, List]
    ) -> Dict[str, Any]:
        """Verify that cited evidence actually exists in the logs we provided"""
        
        # Extract all text that might contain citations
        evidence = ai_response.get('evidence', [])
        reasoning = ai_response.get('reasoning', '')
        chain_of_thought = ai_response.get('chain_of_thought', [])
        
        # Combine all text
        all_text = ' '.join(evidence) + ' ' + reasoning
        for step in chain_of_thought:
            if isinstance(step, dict):
                all_text += ' ' + str(step.get('finding', ''))
        
        # Extract log citations like [PROCESS-1], [NETWORK-2], etc.
        citation_pattern = r'\[([A-Z]+)-(\d+)\]'
        citations = re.findall(citation_pattern, all_text)
        
        result = {
            'total_citations': len(citations),
            'verified': 0,
            'hallucinated': 0,
            'citation_details': []
        }
        
        # Map log types to our keys
        log_type_map = {
            'PROCESS': 'process_logs',
            'NETWORK': 'network_logs',
            'FILE': 'file_logs',
            'WINDOWS': 'windows_logs'
        }
        
        for log_type, index_str in citations:
            index = int(index_str)
            log_key = log_type_map.get(log_type)
            
            if log_key and log_key in logs_provided:
                logs = logs_provided.get(log_key, [])
                if index <= len(logs):
                    result['verified'] += 1
                    result['citation_details'].append({
                        'citation': f'[{log_type}-{index}]',
                        'status': 'verified',
                        'exists': True
                    })
                else:
                    result['hallucinated'] += 1
                    result['citation_details'].append({
                        'citation': f'[{log_type}-{index}]',
                        'status': 'HALLUCINATED',
                        'exists': False,
                        'reason': f'Only {len(logs)} {log_key} provided, but cited #{index}'
                    })
            else:
                # Unknown log type
                result['citation_details'].append({
                    'citation': f'[{log_type}-{index}]',
                    'status': 'unknown_type',
                    'exists': None
                })
        
        # Calculate grounding score
        if result['total_citations'] > 0:
            result['grounding_score'] = result['verified'] / result['total_citations']
        else:
            result['grounding_score'] = 1.0  # No citations to verify
            
        return result
    
    def _verify_consistency(self, ai_response: Dict[str, Any]) -> Dict[str, Any]:
        """Check for logical contradictions in the AI's explanation"""
        
        issues = []
        warnings = []
        
        verdict = ai_response.get('verdict', '').lower()
        confidence = ai_response.get('confidence', 0)
        reasoning = ai_response.get('reasoning', '').lower()
        transparency = ai_response.get('transparency', {})
        
        verdict_factors = transparency.get('verdict_factors', {})
        supporting = verdict_factors.get('supporting', [])
        opposing = verdict_factors.get('opposing', [])
        decisive = verdict_factors.get('decisive_factor', '').lower()
        
        confidence_breakdown = transparency.get('confidence_breakdown', {})
        uncertainty_sources = transparency.get('uncertainty_sources', [])
        
        # Check 1: Verdict vs reasoning keywords
        if verdict == 'benign':
            attack_mentions = [kw for kw in self.attack_keywords if kw in reasoning]
            if attack_mentions and 'false positive' not in reasoning and 'not' not in reasoning[:50]:
                warnings.append(f"Benign verdict but reasoning mentions: {attack_mentions[:3]}")
        
        if verdict == 'malicious':
            benign_mentions = [kw for kw in self.benign_keywords if kw in reasoning]
            if benign_mentions:
                warnings.append(f"Malicious verdict but reasoning mentions: {benign_mentions[:3]}")
        
        # Check 2: Decisive factor should align with verdict
        if verdict == 'benign' and any(kw in decisive for kw in ['malware', 'attack', 'malicious']):
            issues.append("CONTRADICTION: Benign verdict but decisive factor indicates attack")
        
        if verdict == 'malicious' and any(kw in decisive for kw in ['legitimate', 'authorized', 'normal']):
            issues.append("CONTRADICTION: Malicious verdict but decisive factor indicates legitimacy")
        
        # Check 3: High confidence should have strong evidence
        evidence_strength = confidence_breakdown.get('evidence_strength', 'unknown')
        if confidence > 0.85 and evidence_strength == 'weak':
            issues.append("INCONSISTENT: High confidence (>85%) but evidence marked as weak")
        
        # Check 4: Uncertainty sources should exist if confidence is low
        if confidence < 0.6 and len(uncertainty_sources) == 0:
            warnings.append("Low confidence but no uncertainty sources listed")
        
        # Check 5: Opposing factors should exist for non-definitive verdicts
        if verdict == 'suspicious' and len(opposing) == 0:
            warnings.append("Suspicious verdict typically has opposing factors")
        
        # Check 6: Supporting factors should exist
        if len(supporting) == 0:
            issues.append("No supporting factors listed for verdict")
        
        return {
            'issues': issues,
            'warnings': warnings,
            'checks_passed': 6 - len(issues)
        }
    
    def _verify_confidence_calibration(self, ai_response: Dict[str, Any]) -> Dict[str, Any]:
        """Check if confidence is appropriately calibrated"""
        
        warnings = []
        
        confidence = ai_response.get('confidence', 0)
        knowledge_level = ai_response.get('knowledge_level', 'unknown')
        confidence_exceeds = ai_response.get('confidence_exceeds_context', False)
        
        transparency = ai_response.get('transparency', {})
        confidence_breakdown = transparency.get('confidence_breakdown', {})
        
        context_completeness = confidence_breakdown.get('context_completeness', 'unknown')
        pattern_familiarity = confidence_breakdown.get('pattern_familiarity', 'unknown')
        
        # Check 1: Novel patterns should have lower confidence
        if pattern_familiarity == 'novel' and confidence > 0.8:
            warnings.append("Novel pattern but confidence >80% - may be overconfident")
        
        # Check 2: Limited context should reduce confidence
        if context_completeness == 'limited' and confidence > 0.75:
            warnings.append("Limited context but confidence >75% - verify reasoning")
        
        # Check 3: Flag when confidence exceeds what context supports
        if confidence_exceeds:
            warnings.append("AI confidence exceeds typical ceiling for this knowledge level")
        
        return {
            'warnings': warnings,
            'confidence': confidence,
            'knowledge_level': knowledge_level,
            'calibration_concerns': len(warnings) > 0
        }
    
    def _verify_transparency_completeness(self, ai_response: Dict[str, Any]) -> Dict[str, Any]:
        """Check if all transparency fields are populated"""
        
        transparency = ai_response.get('transparency', {})
        
        required_fields = [
            ('verdict_factors', dict),
            ('verdict_factors.supporting', list),
            ('verdict_factors.opposing', list),
            ('verdict_factors.decisive_factor', str),
            ('confidence_breakdown', dict),
            ('alternative_hypothesis', str),
            ('uncertainty_sources', list)
        ]
        
        missing = []
        
        for field_path, expected_type in required_fields:
            parts = field_path.split('.')
            value = transparency
            
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            
            if value is None:
                missing.append(field_path)
            elif not isinstance(value, expected_type):
                missing.append(f"{field_path} (wrong type)")
            elif isinstance(value, (list, str)) and len(value) == 0:
                if field_path not in ['verdict_factors.opposing', 'uncertainty_sources']:
                    # These CAN be empty legitimately
                    missing.append(f"{field_path} (empty)")
        
        return {
            'is_complete': len(missing) == 0,
            'missing': missing,
            'completeness_score': 1 - (len(missing) / len(required_fields))
        }


# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

def verify_ai_transparency(
    ai_response: Dict[str, Any],
    logs_provided: Dict[str, List],
    alert: Dict[str, Any]
) -> VerificationResult:
    """
    Quick function to verify AI transparency.
    
    Returns VerificationResult with trust scores and issues.
    """
    verifier = TransparencyVerifier()
    return verifier.verify(ai_response, logs_provided, alert)


# =============================================================================
# TEST
# =============================================================================

if __name__ == "__main__":
    print("="*60)
    print("TRANSPARENCY VERIFIER TEST")
    print("="*60)
    
    # Test with a good response
    good_response = {
        'verdict': 'malicious',
        'confidence': 0.92,
        'evidence': [
            '[PROCESS-1] mimikatz.exe executed',
            '[NETWORK-1] connection to known C2'
        ],
        'reasoning': 'This is a credential theft attack. [PROCESS-1] shows mimikatz execution.',
        'chain_of_thought': [
            {'step': 1, 'finding': '[PROCESS-1] mimikatz detected'}
        ],
        'transparency': {
            'verdict_factors': {
                'supporting': ['mimikatz is known malware', 'C2 connection detected'],
                'opposing': ['Could be security testing'],
                'decisive_factor': 'mimikatz.exe accessing LSASS is definitive credential theft'
            },
            'confidence_breakdown': {
                'evidence_strength': 'strong',
                'context_completeness': 'complete',
                'pattern_familiarity': 'known'
            },
            'alternative_hypothesis': 'Authorized penetration test',
            'what_would_change_verdict': 'Approved pen test ticket',
            'uncertainty_sources': ['Cannot verify if authorized testing']
        }
    }
    
    logs = {
        'process_logs': [{'name': 'mimikatz.exe'}],
        'network_logs': [{'dest_ip': '185.220.101.45'}]
    }
    
    print("\n--- Test 1: Good Response ---")
    result = verify_ai_transparency(good_response, logs, {})
    print(f"Trustworthy: {result.is_trustworthy}")
    print(f"Grounding: {result.grounding_score:.0%}")
    print(f"Consistency: {result.consistency_score:.0%}")
    print(f"Issues: {result.issues}")
    print(f"Warnings: {result.warnings}")
    
    # Test with hallucinated evidence
    bad_response = {
        'verdict': 'malicious',
        'confidence': 0.95,
        'evidence': [
            '[PROCESS-1] mimikatz.exe executed',
            '[PROCESS-5] another bad process',  # HALLUCINATED - we only provided 1
            '[NETWORK-10] suspicious connection'  # HALLUCINATED
        ],
        'reasoning': 'Attack detected based on [PROCESS-5] and [NETWORK-10].',
        'transparency': {
            'verdict_factors': {
                'supporting': [],  # Empty - bad
                'opposing': [],
                'decisive_factor': ''  # Empty - bad
            },
            'confidence_breakdown': {
                'evidence_strength': 'weak',  # But confidence is 95% - inconsistent!
                'context_completeness': 'limited',
                'pattern_familiarity': 'novel'
            },
            'alternative_hypothesis': '',
            'uncertainty_sources': []
        }
    }
    
    print("\n--- Test 2: Bad Response (Hallucinations) ---")
    result = verify_ai_transparency(bad_response, logs, {})
    print(f"Trustworthy: {result.is_trustworthy}")
    print(f"Grounding: {result.grounding_score:.0%}")
    print(f"Consistency: {result.consistency_score:.0%}")
    print(f"Issues: {result.issues}")
    print(f"Warnings: {result.warnings}")
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)

"""
Novelty Detector - Determines if an alert is known, partially known, or novel
=============================================================================

This module analyzes an alert BEFORE sending it to the AI to determine
how much context we have for it. This enables:

1. Honest confidence calibration (AI knows when it's guessing)
2. Different prompts for known vs novel alerts
3. Flagging novel alerts for human review regardless of verdict
4. Continuous learning - novel alerts that turn out to be important
   can be added to the knowledge base

KNOWLEDGE LEVELS:
- KNOWN: We have MITRE mapping, historical data, and business rules
- PARTIAL: Some context available but gaps exist
- NOVEL: Unfamiliar alert type with little/no historical precedent
- INSUFFICIENT: Critical data missing, cannot analyze properly

Author: AI-SOC Watchdog System
"""

from typing import Dict, Any, Tuple, List
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class KnowledgeLevel(Enum):
    """
    Levels of knowledge confidence about an alert.
    This tells the AI how much it can trust its analysis.
    """
    KNOWN = "known"           # Strong historical/RAG context
    PARTIAL = "partial"       # Some context, but gaps exist
    NOVEL = "novel"           # Unfamiliar pattern, exploratory analysis
    INSUFFICIENT = "insufficient"  # Cannot make determination


@dataclass
class NoveltyAssessment:
    """
    Result of novelty detection.
    This is passed to the AI to inform its analysis approach.
    """
    knowledge_level: KnowledgeLevel
    confidence_ceiling: float  # Max confidence AI should claim
    signals: Dict[str, bool]   # What context we found/didn't find
    missing_context: List[str] # What we wish we had
    recommendations: List[str] # How to handle this alert
    prompt_modifier: str       # Additional instructions for AI
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "knowledge_level": self.knowledge_level.value,
            "confidence_ceiling": self.confidence_ceiling,
            "signals": self.signals,
            "missing_context": self.missing_context,
            "recommendations": self.recommendations,
            "prompt_modifier": self.prompt_modifier
        }


class NoveltyDetector:
    """
    Analyzes alerts to determine how much prior knowledge we have.
    
    This runs BEFORE the AI analysis to:
    1. Query RAG for relevant context
    2. Check for historical similar alerts
    3. Identify knowledge gaps
    4. Set appropriate confidence ceilings
    
    USAGE:
        detector = NoveltyDetector(rag_system)
        assessment = detector.assess(alert, rag_results, logs)
        
        # Pass assessment to AI for honest analysis
        prompt += assessment.prompt_modifier
    """
    
    def __init__(self, rag_system=None):
        """
        Initialize with optional RAG system reference.
        
        Args:
            rag_system: RAGSystem instance for querying knowledge base
        """
        self.rag = rag_system
        
        # Known alert patterns (common security alerts we understand well)
        self.known_patterns = {
            "powershell": ["T1059.001", "T1059"],
            "credential": ["T1003", "T1003.001", "T1003.002"],
            "ransomware": ["T1486", "T1490"],
            "lateral": ["T1021", "T1570", "T1550"],
            "phishing": ["T1566", "T1566.001", "T1566.002"],
            "persistence": ["T1053", "T1547", "T1543"],
            "exfiltration": ["T1041", "T1048", "T1567"],
            "c2": ["T1071", "T1095", "T1573"],
            "discovery": ["T1046", "T1082", "T1083"],
        }
        
        # Benign indicators
        self.benign_indicators = [
            "windows update", "trustedinstaller", "wsus",
            "antivirus", "defender", "msmpe", 
            "backup", "maintenance", "scheduled task",
            "it admin", "administrator", "sccm", "ansible",
            "patch", "update", "security scan"
        ]
    
    def assess(
        self, 
        alert: Dict[str, Any], 
        rag_results: Dict[str, Any] = None,
        logs: Dict[str, Any] = None
    ) -> NoveltyAssessment:
        """
        Assess novelty of an alert.
        
        Args:
            alert: The alert to analyze
            rag_results: Results from RAG queries (if already done)
            logs: Forensic logs associated with alert
            
        Returns:
            NoveltyAssessment with knowledge level and recommendations
        """
        signals = {}
        missing_context = []
        recommendations = []
        
        # 1. Check MITRE technique mapping
        mitre_technique = alert.get("mitre_technique", "")
        signals["has_mitre_mapping"] = bool(mitre_technique)
        if not mitre_technique:
            missing_context.append("No MITRE ATT&CK technique mapped")
        
        # 2. Check if MITRE technique is known to us
        signals["mitre_in_known_patterns"] = self._is_known_mitre(mitre_technique)
        
        # 3. Check RAG results if provided
        if rag_results:
            signals["has_rag_mitre_info"] = rag_results.get("mitre", {}).get("found", False)
            signals["has_historical_match"] = rag_results.get("historical", {}).get("found", False)
            signals["has_business_rules"] = rag_results.get("business_rules", {}).get("found", False)
            signals["has_attack_patterns"] = rag_results.get("attack_patterns", {}).get("found", False)
            
            if not signals["has_historical_match"]:
                missing_context.append("No similar historical alerts found")
            if not signals["has_business_rules"]:
                missing_context.append("No business rules for this context")
        else:
            # No RAG results provided, assume partial context
            signals["has_rag_mitre_info"] = bool(mitre_technique)
            signals["has_historical_match"] = False
            signals["has_business_rules"] = False
            signals["has_attack_patterns"] = False
            missing_context.append("RAG context not available")
        
        # 4. Check logs availability
        if logs:
            log_count = sum(len(v) for v in logs.values() if isinstance(v, list))
            signals["has_forensic_logs"] = log_count > 0
            signals["log_count"] = log_count
            if log_count == 0:
                missing_context.append("No forensic logs available")
        else:
            signals["has_forensic_logs"] = False
            signals["log_count"] = 0
            missing_context.append("No forensic logs queried")
        
        # 5. Check alert name against known patterns
        alert_name = alert.get("alert_name", "").lower()
        signals["matches_known_pattern"] = self._matches_known_pattern(alert_name)
        signals["has_benign_indicators"] = self._has_benign_indicators(alert_name, alert.get("description", ""))
        
        # 6. Check for critical fields
        signals["has_source_ip"] = bool(alert.get("source_ip"))
        signals["has_hostname"] = bool(alert.get("hostname"))
        signals["has_username"] = bool(alert.get("username"))
        
        if not signals["has_hostname"] and not signals["has_username"]:
            missing_context.append("No host or user context")
        
        # Calculate knowledge level
        knowledge_level, confidence_ceiling = self._calculate_knowledge_level(signals)
        
        # Generate recommendations based on level
        recommendations = self._generate_recommendations(knowledge_level, signals, missing_context)
        
        # Generate prompt modifier
        prompt_modifier = self._generate_prompt_modifier(knowledge_level, missing_context)
        
        logger.info(f"[NOVELTY] Alert '{alert.get('alert_name')}' assessed as {knowledge_level.value} "
                   f"(confidence ceiling: {confidence_ceiling:.0%})")
        
        return NoveltyAssessment(
            knowledge_level=knowledge_level,
            confidence_ceiling=confidence_ceiling,
            signals=signals,
            missing_context=missing_context,
            recommendations=recommendations,
            prompt_modifier=prompt_modifier
        )
    
    def _is_known_mitre(self, technique: str) -> bool:
        """Check if MITRE technique is in our known patterns"""
        if not technique:
            return False
        
        for patterns in self.known_patterns.values():
            if technique in patterns or any(technique.startswith(p) for p in patterns):
                return True
        return False
    
    def _matches_known_pattern(self, alert_name: str) -> bool:
        """Check if alert name matches known attack patterns"""
        for pattern in self.known_patterns.keys():
            if pattern in alert_name:
                return True
        return False
    
    def _has_benign_indicators(self, alert_name: str, description: str) -> bool:
        """Check if alert has indicators of benign activity"""
        combined = f"{alert_name} {description}".lower()
        return any(indicator in combined for indicator in self.benign_indicators)
    
    def _calculate_knowledge_level(self, signals: Dict[str, bool]) -> Tuple[KnowledgeLevel, float]:
        """
        Calculate overall knowledge level and confidence ceiling.
        
        Returns:
            (KnowledgeLevel, max_confidence)
        """
        # Count positive signals
        core_signals = [
            signals.get("has_mitre_mapping", False),
            signals.get("mitre_in_known_patterns", False),
            signals.get("has_rag_mitre_info", False),
            signals.get("has_historical_match", False),
            signals.get("has_forensic_logs", False),
            signals.get("matches_known_pattern", False),
        ]
        
        positive_count = sum(1 for s in core_signals if s)
        
        # Check for insufficient data
        if not signals.get("has_forensic_logs") and not signals.get("has_mitre_mapping"):
            return KnowledgeLevel.INSUFFICIENT, 0.40
        
        # Determine level based on signal count
        if positive_count >= 5:
            return KnowledgeLevel.KNOWN, 0.95
        elif positive_count >= 3:
            return KnowledgeLevel.PARTIAL, 0.80
        elif positive_count >= 1:
            return KnowledgeLevel.NOVEL, 0.65
        else:
            return KnowledgeLevel.INSUFFICIENT, 0.40
    
    def _generate_recommendations(
        self, 
        level: KnowledgeLevel, 
        signals: Dict, 
        missing: List[str]
    ) -> List[str]:
        """Generate handling recommendations based on knowledge level"""
        recommendations = []
        
        if level == KnowledgeLevel.KNOWN:
            recommendations.append("AI analysis should be reliable")
            recommendations.append("Auto-close if benign with high confidence")
        
        elif level == KnowledgeLevel.PARTIAL:
            recommendations.append("Review AI reasoning carefully")
            recommendations.append("Consider gathering additional context")
            if not signals.get("has_historical_match"):
                recommendations.append("Add to historical database after resolution")
        
        elif level == KnowledgeLevel.NOVEL:
            recommendations.append("HUMAN REVIEW REQUIRED regardless of verdict")
            recommendations.append("AI analysis is exploratory only")
            recommendations.append("Consider adding to knowledge base after investigation")
            recommendations.append("Do NOT auto-close even if marked benign")
        
        elif level == KnowledgeLevel.INSUFFICIENT:
            recommendations.append("CANNOT RELIABLY ANALYZE - manual triage required")
            recommendations.append("Gather more context before AI analysis")
            if missing:
                recommendations.append(f"Missing: {', '.join(missing[:3])}")
        
        return recommendations
    
    def _generate_prompt_modifier(self, level: KnowledgeLevel, missing: List[str]) -> str:
        """Generate additional prompt text based on knowledge level"""
        
        if level == KnowledgeLevel.KNOWN:
            return """
You have strong context for this alert type from historical data and knowledge base.
Provide a confident analysis grounded in the available evidence.
"""
        
        elif level == KnowledgeLevel.PARTIAL:
            return f"""
PARTIAL CONTEXT AVAILABLE: Some knowledge gaps exist.
Missing: {', '.join(missing[:3]) if missing else 'Some historical context'}

Provide analysis but clearly indicate where you are making inferences
vs. where you have concrete evidence. Be appropriately conservative.
"""
        
        elif level == KnowledgeLevel.NOVEL:
            return f"""
⚠️ NOVEL ALERT TYPE - LIMITED HISTORICAL CONTEXT ⚠️

This alert type has NO historical precedent in my knowledge base.
Missing context: {', '.join(missing[:3]) if missing else 'Historical data for this pattern'}

YOU MUST:
1. Explicitly state this is an EXPLORATORY analysis
2. List what information you WISH you had
3. Explain reasoning from first principles
4. Set confidence NO HIGHER than 0.65
5. Include "knowledge_level": "novel" in response
6. Recommend human review REGARDLESS of verdict

Do NOT be overconfident. It's okay to say "I don't have enough context to be certain."
"""
        
        else:  # INSUFFICIENT
            return """
⚠️ INSUFFICIENT DATA FOR RELIABLE ANALYSIS ⚠️

Critical context is missing. You MUST:
1. Set verdict to "needs_review"
2. Set confidence to 0.40 or below
3. List all missing context
4. Do NOT make a definitive benign/malicious call
5. Recommend manual investigation

This alert cannot be reliably analyzed with available data.
"""


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def assess_alert_novelty(
    alert: Dict[str, Any],
    rag_system=None,
    rag_results: Dict = None,
    logs: Dict = None
) -> NoveltyAssessment:
    """
    Convenience function to assess alert novelty.
    
    Args:
        alert: Alert to assess
        rag_system: Optional RAG system for additional queries
        rag_results: Pre-computed RAG results
        logs: Forensic logs
        
    Returns:
        NoveltyAssessment
    """
    detector = NoveltyDetector(rag_system)
    return detector.assess(alert, rag_results, logs)


# =============================================================================
# TEST
# =============================================================================

if __name__ == "__main__":
    # Test with sample alerts
    print("="*60)
    print("NOVELTY DETECTOR TEST")
    print("="*60)
    
    # Test 1: Known alert
    known_alert = {
        "alert_name": "PowerShell Encoded Command Execution",
        "description": "powershell.exe with -enc parameter",
        "mitre_technique": "T1059.001",
        "hostname": "FINANCE-PC",
        "username": "j.smith",
        "source_ip": "10.0.0.50"
    }
    
    print("\n--- Test 1: Known Alert ---")
    detector = NoveltyDetector()
    result = detector.assess(
        known_alert,
        rag_results={"mitre": {"found": True}, "historical": {"found": True}},
        logs={"process_logs": [{"pid": 1234}]}
    )
    print(f"Level: {result.knowledge_level.value}")
    print(f"Confidence Ceiling: {result.confidence_ceiling:.0%}")
    print(f"Recommendations: {result.recommendations}")
    
    # Test 2: Novel alert
    novel_alert = {
        "alert_name": "CustomApp XYZ Crash",
        "description": "Internal application crashed with memory error",
        "hostname": "ACCT-PC",
        "username": "m.chen"
    }
    
    print("\n--- Test 2: Novel Alert ---")
    result = detector.assess(
        novel_alert,
        rag_results={"mitre": {"found": False}, "historical": {"found": False}},
        logs={}
    )
    print(f"Level: {result.knowledge_level.value}")
    print(f"Confidence Ceiling: {result.confidence_ceiling:.0%}")
    print(f"Missing: {result.missing_context}")
    print(f"Recommendations: {result.recommendations}")
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)

"""
Analyst Feedback System
========================

Tracks AI accuracy over time based on analyst corrections.

WHAT THIS DOES:
1. Stores analyst feedback (correct/wrong) for each verdict
2. Calculates accuracy metrics per alert type, MITRE technique, etc.
3. Identifies patterns where AI consistently fails
4. Provides data for improving prompts and fine-tuning

WHY THIS MATTERS:
- Without feedback, AI operates blind
- We can't improve what we don't measure
- Identifies systematic biases (always says benign, etc.)
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Literal
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

# Try to use database, fall back to file storage
try:
    from backend.storage.database import get_supabase_client
    HAS_SUPABASE = True
except:
    HAS_SUPABASE = False


class FeedbackType(str, Enum):
    CORRECT = "correct"
    WRONG_WAS_MALICIOUS = "wrong_was_malicious"  # AI said benign, was actually malicious
    WRONG_WAS_BENIGN = "wrong_was_benign"        # AI said malicious, was actually benign
    NEEDS_INVESTIGATION = "needs_investigation"   # Can't determine yet
    

@dataclass
class AnalystFeedback:
    """Single feedback entry from an analyst"""
    alert_id: str
    ai_verdict: str
    ai_confidence: float
    feedback_type: str
    correct_verdict: Optional[str]  # What it should have been
    analyst_notes: Optional[str]    # What did AI miss?
    analyst_id: str
    mitre_technique: Optional[str]
    alert_type: Optional[str]
    timestamp: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class FeedbackStore:
    """
    Stores and retrieves analyst feedback.
    Uses Supabase if available, otherwise local JSON file.
    """
    
    def __init__(self):
        self.feedback_file = "logs/analyst_feedback.json"
        self._ensure_storage()
    
    def _ensure_storage(self):
        """Create storage if it doesn't exist"""
        if not HAS_SUPABASE:
            os.makedirs("logs", exist_ok=True)
            if not os.path.exists(self.feedback_file):
                with open(self.feedback_file, 'w') as f:
                    json.dump([], f)
    
    def save_feedback(self, feedback: AnalystFeedback) -> bool:
        """Save feedback to storage"""
        try:
            if HAS_SUPABASE:
                client = get_supabase_client()
                client.table('analyst_feedback').insert(feedback.to_dict()).execute()
            else:
                # Local file storage
                with open(self.feedback_file, 'r') as f:
                    data = json.load(f)
                data.append(feedback.to_dict())
                with open(self.feedback_file, 'w') as f:
                    json.dump(data, f, indent=2)
            
            logger.info(f"[FEEDBACK] Saved: {feedback.alert_id} = {feedback.feedback_type}")
            return True
        except Exception as e:
            logger.error(f"[FEEDBACK] Save failed: {e}")
            return False
    
    def get_all_feedback(self, days: int = 30) -> List[Dict]:
        """Get feedback from last N days"""
        try:
            if HAS_SUPABASE:
                client = get_supabase_client()
                cutoff = (datetime.now() - timedelta(days=days)).isoformat()
                result = client.table('analyst_feedback').select('*').gte('timestamp', cutoff).execute()
                return result.data
            else:
                with open(self.feedback_file, 'r') as f:
                    data = json.load(f)
                # Filter by date
                cutoff = datetime.now() - timedelta(days=days)
                return [
                    f for f in data 
                    if datetime.fromisoformat(f['timestamp']) > cutoff
                ]
        except Exception as e:
            logger.error(f"[FEEDBACK] Load failed: {e}")
            return []


class AccuracyTracker:
    """
    Calculates AI accuracy metrics from analyst feedback.
    
    METRICS TRACKED:
    - Overall accuracy rate
    - Accuracy by verdict type (malicious/benign/suspicious)
    - Accuracy by MITRE technique
    - Accuracy by alert type
    - False positive rate (AI said malicious, was benign)
    - False negative rate (AI said benign, was malicious)
    - Overconfidence detection (high confidence + wrong)
    """
    
    def __init__(self):
        self.store = FeedbackStore()
    
    def calculate_metrics(self, days: int = 30) -> Dict:
        """Calculate all accuracy metrics"""
        feedback = self.store.get_all_feedback(days)
        
        if not feedback:
            return {
                "status": "no_data",
                "message": "No analyst feedback recorded yet",
                "total_feedback": 0
            }
        
        total = len(feedback)
        correct = sum(1 for f in feedback if f['feedback_type'] == 'correct')
        
        # Group by AI verdict
        by_verdict = {}
        for f in feedback:
            verdict = f['ai_verdict']
            if verdict not in by_verdict:
                by_verdict[verdict] = {'correct': 0, 'wrong': 0}
            if f['feedback_type'] == 'correct':
                by_verdict[verdict]['correct'] += 1
            elif f['feedback_type'] != 'needs_investigation':
                by_verdict[verdict]['wrong'] += 1
        
        # Group by MITRE technique
        by_mitre = {}
        for f in feedback:
            tech = f.get('mitre_technique', 'UNKNOWN')
            if tech not in by_mitre:
                by_mitre[tech] = {'correct': 0, 'wrong': 0}
            if f['feedback_type'] == 'correct':
                by_mitre[tech]['correct'] += 1
            elif f['feedback_type'] != 'needs_investigation':
                by_mitre[tech]['wrong'] += 1
        
        # Calculate false positive/negative rates
        false_positives = sum(1 for f in feedback if f['feedback_type'] == 'wrong_was_benign')
        false_negatives = sum(1 for f in feedback if f['feedback_type'] == 'wrong_was_malicious')
        
        # Overconfidence detection
        overconfident = [
            f for f in feedback 
            if f['feedback_type'] != 'correct' 
            and f['feedback_type'] != 'needs_investigation'
            and f['ai_confidence'] > 0.85
        ]
        
        # Find struggling areas
        struggling_mitre = sorted(
            [(tech, data['wrong'] / (data['correct'] + data['wrong']) if data['correct'] + data['wrong'] > 0 else 0)
             for tech, data in by_mitre.items() if data['wrong'] > 2],
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            "period_days": days,
            "total_feedback": total,
            "overall_accuracy": correct / total if total > 0 else 0,
            "correct_count": correct,
            "wrong_count": total - correct - sum(1 for f in feedback if f['feedback_type'] == 'needs_investigation'),
            
            "by_verdict": {
                verdict: {
                    "accuracy": data['correct'] / (data['correct'] + data['wrong']) if (data['correct'] + data['wrong']) > 0 else 0,
                    "correct": data['correct'],
                    "wrong": data['wrong']
                }
                for verdict, data in by_verdict.items()
            },
            
            "false_positive_count": false_positives,
            "false_negative_count": false_negatives,
            "false_positive_rate": false_positives / total if total > 0 else 0,
            "false_negative_rate": false_negatives / total if total > 0 else 0,
            
            "overconfident_wrong_count": len(overconfident),
            "overconfidence_examples": [
                {"alert_id": f['alert_id'], "confidence": f['ai_confidence'], "verdict": f['ai_verdict']}
                for f in overconfident[:5]
            ],
            
            "struggling_mitre_techniques": [
                {"technique": tech, "error_rate": rate}
                for tech, rate in struggling_mitre
            ],
            
            "generated_at": datetime.now().isoformat()
        }
    
    def get_weekly_report(self) -> str:
        """Generate human-readable weekly report"""
        metrics = self.calculate_metrics(days=7)
        
        if metrics.get("status") == "no_data":
            return "No feedback data available for the past week."
        
        report = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WEEKLY AI ACCURACY REPORT
  Generated: {metrics['generated_at'][:10]}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OVERALL PERFORMANCE
  Total Alerts Reviewed:  {metrics['total_feedback']}
  Accuracy Rate:          {metrics['overall_accuracy']*100:.1f}%
  Correct Verdicts:       {metrics['correct_count']}
  Wrong Verdicts:         {metrics['wrong_count']}

ERROR BREAKDOWN
  False Positives:        {metrics['false_positive_count']} (AI said malicious, was benign)
  False Negatives:        {metrics['false_negative_count']} (AI said benign, was malicious)
  Overconfident Errors:   {metrics['overconfident_wrong_count']} (>85% confidence but wrong)

BY VERDICT TYPE:
"""
        for verdict, data in metrics['by_verdict'].items():
            report += f"  {verdict.upper():12} {data['accuracy']*100:5.1f}% ({data['correct']}/{data['correct']+data['wrong']})\n"
        
        if metrics['struggling_mitre_techniques']:
            report += "\nSTRUGGLING MITRE TECHNIQUES:\n"
            for item in metrics['struggling_mitre_techniques']:
                report += f"  {item['technique']:15} {item['error_rate']*100:.1f}% error rate\n"
        
        report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        
        return report


def submit_feedback(
    alert_id: str,
    ai_verdict: str,
    ai_confidence: float,
    feedback_type: str,
    analyst_id: str = "analyst",
    correct_verdict: Optional[str] = None,
    analyst_notes: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    alert_type: Optional[str] = None
) -> Dict:
    """
    API function to submit analyst feedback.
    
    Args:
        alert_id: ID of the alert
        ai_verdict: What the AI said (malicious/benign/suspicious)
        ai_confidence: AI's confidence score
        feedback_type: correct, wrong_was_malicious, wrong_was_benign, needs_investigation
        analyst_id: Who submitted the feedback
        correct_verdict: What it should have been (if wrong)
        analyst_notes: What did the AI miss?
        mitre_technique: MITRE ATT&CK technique ID
        alert_type: Type of alert
    
    Returns:
        {"success": True/False, "message": str}
    """
    try:
        feedback = AnalystFeedback(
            alert_id=alert_id,
            ai_verdict=ai_verdict,
            ai_confidence=ai_confidence,
            feedback_type=feedback_type,
            correct_verdict=correct_verdict,
            analyst_notes=analyst_notes,
            analyst_id=analyst_id,
            mitre_technique=mitre_technique,
            alert_type=alert_type,
            timestamp=datetime.now().isoformat()
        )
        
        store = FeedbackStore()
        success = store.save_feedback(feedback)
        
        if success:
            return {"success": True, "message": "Feedback recorded"}
        else:
            return {"success": False, "message": "Failed to save feedback"}
    
    except Exception as e:
        return {"success": False, "message": str(e)}


def get_accuracy_metrics(days: int = 30) -> Dict:
    """API function to get accuracy metrics"""
    tracker = AccuracyTracker()
    return tracker.calculate_metrics(days)


# Quick test
if __name__ == '__main__':
    print("\n" + "="*60)
    print("ANALYST FEEDBACK SYSTEM - Testing")
    print("="*60)
    
    # Test feedback submission
    print("\n[TEST 1] Submit feedback")
    result = submit_feedback(
        alert_id="TEST-001",
        ai_verdict="benign",
        ai_confidence=0.87,
        feedback_type="wrong_was_malicious",
        analyst_notes="AI missed the C2 beacon pattern",
        mitre_technique="T1071.001"
    )
    print(f"Result: {result}")
    
    # Test metrics
    print("\n[TEST 2] Get metrics")
    metrics = get_accuracy_metrics(days=30)
    print(f"Total feedback: {metrics.get('total_feedback', 0)}")
    
    # Test weekly report
    print("\n[TEST 3] Weekly report")
    tracker = AccuracyTracker()
    print(tracker.get_weekly_report())

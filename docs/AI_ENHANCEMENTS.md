# AI Analysis Enhancements

This document describes the AI analysis framework in the AI-SOC Watchdog system.

---

## 1. Structured System Prompt

**Location:** `backend/ai/api_resilience.py` lines 226-265

The AI uses a 5-step investigation framework:

1. **Establish Baseline** - Check if user/system behavior is normal for their role and time of day
2. **Analyze the 5 W's** - Who, What, Where, When, Why
3. **Evaluate Indicators** - Process chains, network behavior, file activity, MITRE mapping
4. **Cross-Reference** - OSINT data, historical patterns, business context
5. **Make the Call** - Benign, Malicious, or Suspicious

---

## 2. Investigation Questions

**Location:** `backend/ai/rag_system.py` lines 633-680

Each alert prompt includes 7 questions the AI must answer:

| Question | Focus Area |
|----------|------------|
| Q1 | User Analysis - account type, normal behavior |
| Q2 | Process Chain - parent/child relationships |
| Q3 | Network Analysis - IP reputation, ports |
| Q4 | Timing Analysis - business hours, scheduling |
| Q5 | Historical Context - previous verdicts |
| Q6 | Business Justification - asset role, change tickets |
| Q7 | Attack Indicators - MITRE stage, correlations |

---

## 3. Analyst Feedback

**Locations:**
- API Endpoint: `app.py` - `POST /api/alerts/<alert_id>/feedback`
- Storage: `backend/storage/database.py` - `store_analyst_feedback()`
- RAG Integration: `backend/ai/rag_system.py` - Section 8

### What it does:

1. Analyst submits feedback via the dashboard
2. Feedback is stored in the alerts table with:
   - `analyst_verdict`
   - `analyst_notes`
   - `ai_was_correct` (calculated automatically)
3. When analyzing new alerts, the system retrieves past verdicts for similar alerts
4. Past analyst corrections are included in the AI prompt context

**Note:** Feedback is stored and retrieved for context, but the AI model itself is not retrained. The improvement comes from providing relevant historical corrections in the prompt.

### API Usage:

```bash
# Submit feedback
curl -X POST http://localhost:5000/api/alerts/123/feedback \
  -H "Content-Type: application/json" \
  -d '{"analyst_verdict": "benign", "analyst_notes": "Known IT maintenance task"}'

# Get accuracy stats
curl http://localhost:5000/api/feedback/stats
```

---

## 4. Output Schema

The AI returns:

```json
{
  "verdict": "benign|malicious|suspicious",
  "confidence": 0.0-1.0,
  "evidence": ["finding 1", "..."],
  "investigation_answers": {
    "user_analysis": "Q1 answer",
    "process_analysis": "Q2 answer",
    "network_analysis": "Q3 answer",
    "timing_analysis": "Q4 answer",
    "historical_context": "Q5 answer",
    "business_justification": "Q6 answer",
    "attack_indicators": "Q7 answer"
  },
  "chain_of_thought": [
    {"step": 1, "question": "Q1-User", "finding": "...", "interpretation": "..."}
  ],
  "reasoning": "Synthesis of findings",
  "recommendation": "Suggested next steps"
}
```

---

## 5. Confidence Calibration

**Location:** `backend/ai/alert_analyzer_final.py` lines 660-685

Raw AI confidence is adjusted based on evidence quality:

```python
calibrated_confidence = (raw_confidence * 0.7) + (evidence_factor * 0.3)
```

Evidence factors include:
- Log availability (process, network, file, windows)
- OSINT enrichment
- Chain of thought depth
- Evidence count

---

## 6. RAG Context Structure

Context sent to the AI includes:

1. MITRE Technique Information
2. Historical Similar Incidents
3. Business Context and Priorities
4. Attack Patterns and Indicators
5. Detection Rule That Triggered
6. Signature Patterns Matched
7. Asset Context
8. Analyst-Corrected Past Verdicts
9. Current Alert Details
10. Correlated Logs

---

## Implementation Status

| Feature | Status | Location |
|---------|--------|----------|
| Structured System Prompt | Implemented | api_resilience.py |
| 7 Investigation Questions | Implemented | rag_system.py |
| Analyst Feedback API | Implemented | app.py |
| Feedback Storage | Implemented | database.py |
| Past Verdicts in RAG | Implemented | rag_system.py |
| Investigation Answers Output | Implemented | alert_analyzer_final.py |
| Accuracy Stats API | Implemented | app.py |

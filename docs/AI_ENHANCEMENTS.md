# AI Analysis Enhancements

This document describes the structured AI analysis framework implemented in the AI-SOC Watchdog system.

---

## 1. Structured System Prompt (SOC Analyst Framework)

**Location:** `backend/ai/api_resilience.py` lines 226-265

The AI operates as a senior SOC analyst using a **5-Step Investigation Framework**:

### Step 1: Establish Baseline
- Is this user/system known? What is their normal activity pattern?
- Is this behavior expected for this role/department/time of day?
- Have we seen this exact alert before? What was the outcome?

### Step 2: Analyze the 5 W's
- **WHO**: Which user/service account? Privileged or standard?
- **WHAT**: What action was taken? What process/file/command?
- **WHERE**: Source/destination IPs and hosts
- **WHEN**: Time of activity - business hours? Maintenance window?
- **WHY**: Is there a legitimate business reason?

### Step 3: Evaluate Indicators
- Process chain analysis
- Network behavior
- File activity
- Persistence mechanisms
- MITRE mapping

### Step 4: Cross-Reference
- OSINT data
- Historical patterns
- Business context
- Asset criticality

### Step 5: Make the Call
- **BENIGN**: Clear legitimate activity
- **MALICIOUS**: Clear attack indicators
- **SUSPICIOUS**: Genuine uncertainty

---

## 2. Systematic Investigation Questions

**Location:** `backend/ai/rag_system.py` lines 633-680

Every alert prompt includes 7 mandatory questions the AI must answer:

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

## 3. Analyst Feedback Loop

**Locations:**
- API Endpoint: `app.py` → `POST /api/alerts/<alert_id>/feedback`
- Storage: `backend/storage/database.py` → `store_analyst_feedback()`
- RAG Integration: `backend/ai/rag_system.py` → Section 8 (Analyst-Corrected Past Verdicts)

### How It Works:

1. **Analyst submits feedback** via the dashboard
2. **Feedback is stored** in the alerts table with:
   - `analyst_verdict`
   - `analyst_notes`
   - `ai_was_correct` (calculated automatically)
3. **Future alerts query past verdicts** for similar alerts
4. **AI sees analyst corrections** in the context, learning from mistakes

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

## 4. Enhanced Output Schema

The AI now returns a richer response structure:

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
    {"step": 1, "question": "Q1-User", "finding": "...", "interpretation": "..."},
    ...
  ],
  "reasoning": "300+ char synthesis",
  "recommendation": "Actionable steps"
}
```

---

## 5. Confidence Calibration

**Location:** `backend/ai/alert_analyzer_final.py` lines 660-685

Raw AI confidence is blended with evidence quality:

```python
calibrated_confidence = (raw_confidence * 0.7) + (evidence_factor * 0.3)
```

Evidence factors:
- Log availability (process, network, file, windows)
- OSINT enrichment
- Chain of thought depth
- Evidence count

---

## 6. RAG Context Structure

The context sent to AI includes 10 sections:

1. MITRE Technique Information
2. Historical Similar Incidents
3. Business Context & Priorities
4. Attack Patterns & Indicators
5. Detection Rule That Triggered
6. Signature Patterns Matched
7. Asset Context
8. **Analyst-Corrected Past Verdicts** (NEW)
9. Current Alert Details
10. Correlated Logs

Plus:
- Systematic Investigation Questions
- Verdict Decision Criteria
- JSON Response Format Requirements

---

## Summary of Changes

| Feature | Status | Location |
|---------|--------|----------|
| Structured System Prompt | ✅ Implemented | api_resilience.py |
| 7 Investigation Questions | ✅ Implemented | rag_system.py |
| Analyst Feedback API | ✅ Implemented | app.py |
| Feedback Storage | ✅ Implemented | database.py |
| Past Verdicts in RAG | ✅ Implemented | rag_system.py |
| Investigation Answers Output | ✅ Implemented | alert_analyzer_final.py |
| Accuracy Stats API | ✅ Implemented | app.py |

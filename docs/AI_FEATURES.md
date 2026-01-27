# AI Security Features - 26 Features Explained

## Overview

The AI-SOC Watchdog implements **26 security features** organized into **6 phases**. Each feature serves a specific purpose in ensuring secure, reliable, and transparent AI-powered alert analysis.

---

## Phase 1: Security Gates (Features 1-4, 6-8, 14-17)

### Features 1-4: Input Guard (Prompt Injection Protection)
**File:** `backend/ai/security_guard.py` - `InputGuard` class

**Purpose:** Prevent attackers from manipulating AI decisions through malicious input

**Checks Performed:**
- SQL injection patterns (`'; DROP TABLE`, `UNION SELECT`)
- Command injection (`; rm -rf`, `| cat /etc/passwd`)
- XSS attacks (`<script>`, `javascript:`)
- Prompt injection (`ignore previous`, `new instructions`)

**How It Works:**
```python
is_valid, reason, cleaned = input_guard.validate(alert)
if not is_valid:
    return error("Security violation", reason)
```

---

### Feature 6: Pydantic Schema Validation
**File:** `backend/ai/validation.py` - `AlertValidator` class

**Purpose:** Ensure all required fields exist and are in correct format

**Schema Requirements:**
```python
class AlertSchema:
    alert_name: str  # Required
    severity: str    # Required
    description: str # Required
    source_ip: Optional[str]
    dest_ip: Optional[str]
    timestamp: Optional[datetime]
```

---

### Features 7-8: Alert Validation Rules
**File:** `backend/ai/validation.py`

**Purpose:** Business logic validation beyond schema

**Checks:**
- Severity is valid value (low, medium, high, critical)
- IP addresses are valid format
- Timestamp is not in future
- Description is not empty

---

### Features 14-17: Data Protection Guard
**File:** `backend/ai/data_protection.py` - `DataProtectionGuard` class

**Purpose:** Protect sensitive data before sending to AI

**Checks:**
- PII detection (SSN, credit cards, phone numbers)
- Credential patterns (API keys, passwords)
- Internal network exposure
- Compliance requirements (GDPR, HIPAA markers)

---

## Phase 2: Optimization (Features 5, 22)

### Feature 5: Dynamic Budget Tracker
**File:** `backend/ai/dynamic_budget_tracker.py` - `DynamicBudgetTracker` class

**Purpose:** Prevent runaway API costs

**How It Works:**
```python
can_process, cost, reason = budget.can_process_queue('priority', alert_count)
if not can_process:
    return error("Budget exhausted", reason, queued=True)
```

**Features:**
- Daily spending limit ($2.00 default)
- Per-alert cost estimation
- Priority queue gets budget preference
- Alerts queued when budget depleted

---

### Feature 22: Response Caching
**File:** `backend/ai/alert_analyzer_final.py` - `DictCache` class

**Purpose:** Skip redundant API calls for identical alerts

**How It Works:**
```python
if cache.get(alert):
    return cached_response  # Instant return, $0 cost
# Otherwise, call AI
result = analyze_with_ai(alert)
cache.set(alert, result)
```

---

## Phase 3: Context Building (RAG System)

### RAG System - 7 ChromaDB Collections
**File:** `backend/ai/rag_system.py` - `RAGSystem` class

**Purpose:** Provide expert knowledge to AI for better decisions

**Collections:**

| Collection | Documents | Purpose |
|------------|-----------|---------|
| `mitre_severity` | 201 | MITRE ATT&CK technique descriptions |
| `historical_analyses` | ~50 | Past alerts and their verdicts |
| `business_rules` | ~20 | Organizational priorities |
| `attack_patterns` | ~30 | Known attack indicators |
| `detection_rules` | ~25 | SIEM correlation rules |
| `detection_signatures` | ~40 | Regex/behavioral patterns |
| `company_infrastructure` | ~15 | Asset context (tokenized) |

**Query Methods:**
```python
rag.query_mitre_info("T1059.001")
rag.query_historical_alerts(alert_name, mitre_technique)
rag.query_business_rules(department, severity)
rag.query_attack_patterns(mitre_technique)
rag.query_detection_signatures(alert_name)
rag.query_asset_context(username, hostname)
```

---

## Phase 4: AI Analysis (Features 9-13)

### Feature 9: Claude API Client Wrapper
**File:** `backend/ai/api_resilience.py` - `ClaudeAPIClient` class

**Purpose:** Clean interface to Anthropic API

**Configuration:**
```python
model = "claude-3-5-sonnet-20241022"
max_tokens = 4096
temperature = 0.1  # Low for consistent responses
```

---

### Feature 10: Retry Logic with Exponential Backoff
**File:** `backend/ai/api_resilience.py`

**Purpose:** Handle transient API failures

**Strategy:**
```
Attempt 1: Wait 0s
Attempt 2: Wait 2s
Attempt 3: Wait 4s
Attempt 4: Wait 8s (max)
```

---

### Feature 11: Rate Limiting
**File:** `backend/ai/api_resilience.py`

**Purpose:** Respect API rate limits

**Implementation:**
- Track requests per minute
- Queue excess requests
- Automatic throttling

---

### Feature 12: Timeout Handling
**File:** `backend/ai/api_resilience.py`

**Purpose:** Prevent hung requests

**Default Timeout:** 25 seconds

---

### Feature 13: Fallback Response
**File:** `backend/ai/alert_analyzer_final.py` - `_fallback()` method

**Purpose:** Provide verdict even when AI fails

**Logic:**
```python
def _fallback(alert):
    severity = alert.get('severity', '').lower()
    if severity in ['critical', 'high']:
        return {'verdict': 'suspicious', 'confidence': 0.6}
    return {'verdict': 'benign', 'confidence': 0.4}
```

---

## Phase 5: Output Validation (Features 3-4, 7-8)

### Features 3-4: Output Guard
**File:** `backend/ai/security_guard.py` - `OutputGuard` class

**Purpose:** Ensure AI response is safe

**Checks:**
- No shell commands in recommendations
- No SQL injection in output
- Valid JSON structure
- No harmful action suggestions

**How It Works:**
```python
is_safe, issues = output_guard.validate(ai_response)
if not is_safe:
    return fallback_response()
```

---

## Phase 6: Observability (Features 18-21)

### Feature 18: Audit Logger
**File:** `backend/ai/observability.py` - `AuditLogger` class

**Purpose:** Compliance and forensic trail

**Logs:**
- Every AI decision
- Input/output pairs
- Timestamp and alert ID
- Stored in `backend/logs/audit/`

---

### Feature 19: Health Monitor
**File:** `backend/ai/observability.py` - `HealthMonitor` class

**Purpose:** Track system health

**Metrics:**
- API success rate
- Average response time
- Error counts
- Queue depths

---

### Feature 20: Metrics Collector
**File:** `backend/ai/observability.py` - `MetricsCollector` class

**Purpose:** Performance analytics

**Tracks:**
- Processing time per alert
- Cost per analysis
- Cache hit rate
- RAG query latency

---

### Feature 21: Cost Tracker
**File:** `backend/ai/dynamic_budget_tracker.py`

**Purpose:** Financial monitoring

**Calculation:**
```python
input_cost = input_tokens * $0.000003   # $3 per 1M tokens
output_cost = output_tokens * $0.000015 # $15 per 1M tokens
total_cost = input_cost + output_cost
```

---

## AI Analysis Output Format

The AI returns a structured JSON response:

```json
{
  "verdict": "malicious",
  "confidence": 0.95,
  "evidence": [
    "PowerShell spawned from Word process",
    "Base64 encoded command detected",
    "Connection to known malicious IP",
    "MITRE T1059.001 technique match"
  ],
  "chain_of_thought": [
    {
      "step": 1,
      "observation": "powershell.exe spawned by WINWORD.EXE",
      "analysis": "This is a classic macro-enabled document attack pattern",
      "conclusion": "High confidence malicious behavior"
    }
  ],
  "reasoning": "The alert shows a clear attack chain...",
  "recommendation": "1. Isolate the endpoint immediately..."
}
```

---

## Feature Summary Table

| # | Feature | Phase | File |
|---|---------|-------|------|
| 1-4 | Input Guard | 1 | security_guard.py |
| 5 | Budget Tracker | 2 | dynamic_budget_tracker.py |
| 6 | Schema Validation | 1 | validation.py |
| 7-8 | Alert Validation | 1 | validation.py |
| 9 | API Client | 4 | api_resilience.py |
| 10 | Retry Logic | 4 | api_resilience.py |
| 11 | Rate Limiting | 4 | api_resilience.py |
| 12 | Timeout Handling | 4 | api_resilience.py |
| 13 | Fallback Response | 4 | alert_analyzer_final.py |
| 14-17 | Data Protection | 1 | data_protection.py |
| 18 | Audit Logger | 6 | observability.py |
| 19 | Health Monitor | 6 | observability.py |
| 20 | Metrics Collector | 6 | observability.py |
| 21 | Cost Tracker | 6 | dynamic_budget_tracker.py |
| 22 | Response Cache | 2 | alert_analyzer_final.py |
| 23-26 | RAG System | 3 | rag_system.py |

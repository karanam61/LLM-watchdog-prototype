# AI Analysis Pipeline

This document describes how the AI-SOC Watchdog processes security alerts through its analysis pipeline. The system validates input, manages API costs, retrieves relevant context, calls Claude for analysis, validates output, and logs everything for observability.

## Input Validation

Before any alert reaches the AI, it passes through several validation layers in `backend/ai/security_guard.py` and `backend/ai/validation.py`.

The InputGuard class scans for injection attacks including SQL injection patterns, command injection sequences, XSS payloads, and prompt injection attempts. If malicious content is detected, the alert is rejected before consuming API resources.

```python
is_valid, reason, cleaned = input_guard.validate(alert)
if not is_valid:
    return error("Security violation", reason)
```

Schema validation ensures required fields exist and have correct types. Alerts must include an alert name, severity level, and description. Optional fields like source IP, destination IP, and timestamp are validated when present.

The DataProtectionGuard in `backend/ai/data_protection.py` scans for sensitive data that should not be sent to external APIs. This includes PII patterns like SSN and credit card numbers, credential patterns like API keys, and internal network information.

## Budget Tracking

The DynamicBudgetTracker in `backend/ai/dynamic_budget_tracker.py` prevents runaway API costs by enforcing daily spending limits.

Each analysis request checks remaining budget before proceeding. The system estimates costs based on token counts and tracks actual spending. When budget is exhausted, alerts are queued for later processing rather than rejected outright.

```python
can_process, cost, reason = budget.can_process_queue('priority', alert_count)
if not can_process:
    return error("Budget exhausted", reason, queued=True)
```

Priority queues receive budget preference over normal queues. The default daily limit is $2.00.

Cost calculation uses Claude's pricing model:

```python
input_cost = input_tokens * 0.000003   # $3 per 1M tokens
output_cost = output_tokens * 0.000015 # $15 per 1M tokens
```

## RAG System

The RAGSystem class in `backend/ai/rag_system.py` retrieves relevant context from ChromaDB collections before calling the AI. This context helps Claude make better decisions by providing domain knowledge.

The system maintains several collections. The mitre_severity collection contains MITRE ATT&CK technique descriptions. Historical analyses stores past alerts and their verdicts. Business rules contains organizational priorities. Attack patterns describes known attack indicators. Detection rules and signatures provide SIEM correlation context. Company infrastructure stores asset information.

Query methods retrieve relevant documents based on the alert being analyzed:

```python
rag.query_mitre_info("T1059.001")
rag.query_historical_alerts(alert_name, mitre_technique)
rag.query_business_rules(department, severity)
rag.query_attack_patterns(mitre_technique)
rag.query_detection_signatures(alert_name)
rag.query_asset_context(username, hostname)
```

Retrieved context is included in the prompt sent to Claude, giving it access to institutional knowledge without requiring fine-tuning.

## Claude API Calls

The ClaudeAPIClient wrapper in `backend/ai/api_resilience.py` handles communication with the Anthropic API. It uses Claude 3.5 Sonnet with low temperature (0.1) for consistent responses.

The client implements retry logic with exponential backoff. Failed requests wait 2 seconds before the first retry, then 4 seconds, then 8 seconds maximum. Rate limiting tracks requests per minute and queues excess requests. A 25-second timeout prevents hung requests.

When the API fails after all retries, the fallback method in `backend/ai/alert_analyzer_final.py` provides a conservative verdict based on severity:

```python
def _fallback(alert):
    severity = alert.get('severity', '').lower()
    if severity in ['critical', 'high']:
        return {'verdict': 'suspicious', 'confidence': 0.6}
    return {'verdict': 'benign', 'confidence': 0.4}
```

A response cache in DictCache skips redundant API calls when identical alerts are analyzed.

## Output Validation

The OutputGuard class in `backend/ai/security_guard.py` validates AI responses before returning them to users. It checks for shell commands in recommendations, SQL injection patterns, valid JSON structure, and harmful action suggestions.

```python
is_safe, issues = output_guard.validate(ai_response)
if not is_safe:
    return fallback_response()
```

If validation fails, the system returns a fallback response rather than potentially dangerous AI output.

## Logging and Metrics

Observability components in `backend/ai/observability.py` track system behavior for debugging and compliance.

The AuditLogger records every AI decision with input/output pairs, timestamps, and alert IDs. Logs are stored in `backend/logs/audit/` for forensic review.

The HealthMonitor tracks API success rates, average response times, error counts, and queue depths. The MetricsCollector provides performance analytics including processing time per alert, cost per analysis, cache hit rate, and RAG query latency.

## AI Response Format

The AI returns structured JSON with verdict, confidence, evidence, reasoning chain, and recommendations:

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

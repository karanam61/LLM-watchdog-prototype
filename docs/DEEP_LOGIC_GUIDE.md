# Design Rationale

This document explains the reasoning behind key architectural decisions.

## Core Philosophy

- Defense in depth: multiple validation layers, no single points of failure
- Transparency: every AI decision must be explainable
- Compliance first: tokenization and data protection are required
- Cost awareness: AI API calls are expensive
- Fail gracefully: system degrades, doesn't crash

## Why This System Exists

SOC analysts deal with 200-300 alerts/day, 80-90% false positives. Each investigation takes 30-45 minutes. Our approach: AI handles initial triage with reasoning, analyst makes the final call.

## Alert Processing Order

```
SIEM Alert → Parser → Tokenizer → MITRE Mapper → Severity → Risk Calculator → Queue Router
```

Why this order:
1. Parse first - can't process garbage
2. Tokenize second - protect data before any logging
3. MITRE map third - needed for risk calculation
4. Severity fourth - needed for multiplier
5. Risk calculate fifth - needed for queue routing
6. Route last - determines processing priority

## Tokenization

Replaces sensitive data with tokens before AI processing:
- `192.168.1.100` → `IP-a3f9b2c1`
- `FINANCE-DC-01` → `HOST-8d4f6e2a`
- `john.smith` → `USER-7bc3e1f5`

This is required for GDPR/SOC2 compliance but means AI can't do OSINT lookups (VirusTotal, etc.). We accept this trade-off. Future solution: local models with local threat intel.

## Risk Scoring

```
Risk Score = Attack Damage Score × Severity Multiplier
```

Damage scores are based on US breach data (IBM Cost of Data Breach Report):
- Ransomware (T1486): 90 points, avg $4.5M
- Credential Dumping (T1003): 85 points, avg $2.5M
- Port Scanning (T1046): 20 points, avg $50K

Severity multipliers:
- CRITICAL_HIGH: 1.5×
- HIGH: 1.0×
- MEDIUM: 0.7×
- LOW: 0.5×

Alerts with risk >= 75 go to priority queue.

## AI Analysis Phases

1. Security Gates - input validation, prompt injection detection, PII masking
2. Optimization - budget check, deduplication
3. Context Building - RAG queries, log correlation
4. AI Analysis - Claude API call with structured prompt
5. Output Validation - sanitize response, validate schema
6. Observability - audit logging, metrics

## Trade-offs

**Tokenization**: We lose OSINT capability but gain compliance and safer logs.

**Fast mode for dashboards**: Dashboard APIs generate summaries from alert data instead of live ChromaDB queries (which timeout on Railway). Actual analysis still uses real RAG.

**In-memory metrics**: Reset on container restart, but faster access and less database load.

**SIEM severity**: We don't override it. We use it as input to our risk calculation alongside attack damage context.

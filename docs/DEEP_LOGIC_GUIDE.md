# AI-SOC Watchdog - Deep Logic & Design Rationale

## Purpose of This Document

This document explains the **WHY** behind every architectural decision in AI-SOC Watchdog. It's designed for AI assistants (Claude, GPT, etc.) to understand the deep reasoning, trade-offs, and design philosophy that shaped this system.

---

## Table of Contents

1. [Core Philosophy](#core-philosophy)
2. [Alert Processing Pipeline](#alert-processing-pipeline)
3. [Tokenization System](#tokenization-system)
4. [Risk Scoring & Queue Routing](#risk-scoring--queue-routing)
5. [RAG System Design](#rag-system-design)
6. [AI Analysis Pipeline](#ai-analysis-pipeline)
7. [Security Architecture](#security-architecture)
8. [Trade-offs & Limitations](#trade-offs--limitations)

---

## Core Philosophy

### Design Principles

1. **Defense in Depth**: Multiple layers of validation, not single points of failure
2. **Transparency Over Black Box**: Every AI decision must be explainable
3. **Compliance First**: Tokenization and data protection are not optional
4. **Cost Awareness**: AI API calls are expensive; optimize ruthlessly
5. **Fail Gracefully**: System must degrade, not crash

### Why We Built This

SOC analysts face three core problems:

1. **Volume**: 200-300 alerts/day, 80-90% false positives
2. **Time**: 30-45 minutes per alert investigation
3. **Context**: Junior analysts lack organizational knowledge

Our solution: AI handles initial triage, provides reasoning, analyst makes final call.

---

## Alert Processing Pipeline

### The Flow (Before AI)

```
SIEM Alert
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: PARSER (parser.py)                                  │
│ - Normalizes different SIEM formats                         │
│ - Handles Splunk nested structure & flat formats            │
│ - Extracts: alert_name, severity, IPs, hostname, username   │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: TOKENIZER (tokenizer.py) [OPTIONAL BUT RECOMMENDED] │
│ - Replaces real IPs → IP-a3f9b2c1                           │
│ - Replaces hostnames → HOST-finance-dc01                    │
│ - Replaces usernames → USER-8c4fea72                        │
│ - Stores mappings in Supabase for reverse lookup            │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: MITRE MAPPER (mitre_mapping.py)                     │
│ - Keyword matching against alert name + description         │
│ - Maps to MITRE ATT&CK technique IDs                        │
│ - Example: "ransomware" → T1486                             │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 4: SEVERITY CLASSIFIER (Severity.py)                   │
│ - Reads SIEM-provided severity                              │
│ - Maps to internal classes: CRITICAL_HIGH or MEDIUM_LOW     │
│ - Does NOT override SIEM severity                           │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 5: RISK CALCULATOR (attack_damage_data.py)             │
│ - Queries mitre_severity table for damage scores            │
│ - Applies severity multiplier                               │
│ - Formula: risk_score = damage_score × severity_multiplier  │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 6: QUEUE ROUTER (Queue_manager.py)                     │
│ - Risk ≥ 75 → Priority Queue (processed first)              │
│ - Risk < 75 → Standard Queue (processed after)              │
│ - Thread-safe with locks                                    │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
[WAITING FOR AI ANALYSIS...]
```

### Why This Order Matters

1. **Parse first**: Can't analyze garbage data
2. **Tokenize second**: Protect data before any processing/logging
3. **MITRE map third**: Needed for risk calculation
4. **Severity fourth**: Needed for multiplier calculation
5. **Risk calculate fifth**: Needed for queue routing
6. **Route last**: Determines processing priority

---

## Tokenization System

### What Gets Tokenized

| Field | Example Real Value | Tokenized Value |
|-------|-------------------|-----------------|
| IP Address | 192.168.1.100 | IP-a3f9b2c1 |
| Hostname | FINANCE-DC-01 | HOST-8d4f6e2a |
| Username | john.smith | USER-7bc3e1f5 |
| Email | john@company.com | EMAIL-2e66a741 |

### How It Works

```python
# tokenizer.py
class SecureTokenizer:
    def tokenize(self, entity_type, real_value):
        # 1. Check in-memory cache (fast path)
        # 2. Check database for existing token
        # 3. If not found, generate new token: PREFIX-uuid8
        # 4. Store mapping in Supabase token_map table
        # 5. Cache for future lookups
        return token
    
    def detokenize(self, token):
        # Reverse lookup - ONLY for analyst display
        # Never expose real values to AI
        return real_value
```

### Token Format

```
PREFIX-8_char_uuid

Prefixes:
- IP-     → IP addresses
- HOST-   → Hostnames
- USER-   → Usernames
- EMAIL-  → Email addresses
- TOKEN-  → Generic/unknown
```

### Why Tokenization Matters

**Compliance Requirements:**
- GDPR: Data minimization principle
- SOC 2: Access control requirements
- HIPAA: PHI protection (if healthcare)

**Security Benefits:**
- AI never sees real infrastructure
- Logs are safe to share
- Debug data can be exported

**Trade-off: OSINT Limitation**

When alerts are tokenized, the AI **cannot**:
- Look up IPs on VirusTotal
- Check domains on AnyRun
- Query threat intelligence feeds

**Why we accept this trade-off:**
1. Compliance > convenience
2. Local models (Ollama) will solve this eventually
3. Organizations can run their own TI lookups separately
4. For demo purposes, we don't want to expose real infrastructure

### Dual Mode Support

The system supports both modes for testing:

```python
# data_protection.py
def _check_tokenization(self, alert):
    # RELAXED MODE: Allow non-tokenized data (for testing)
    # Logs warning but doesn't reject
    # Production should enforce strict mode
```

---

## Risk Scoring & Queue Routing

### The Problem We're Solving

Not all alerts are equal:
- Ransomware encrypting files > Someone failing a login
- Credential dumping on DC > Port scan from external

SIEM provides severity (critical/high/medium/low), but this doesn't capture **attack damage potential**.

### Our Solution: Risk Score

```
Risk Score = Attack Damage Score × Severity Multiplier
```

### Attack Damage Scores

**Source: US organizational breach data analysis**

Scores are based on:
- Average cost of breach (from IBM Cost of Data Breach Report)
- Recovery time
- Business disruption impact
- Regulatory implications

| MITRE Technique | Attack Type | Damage Score | Avg Cost (USD) |
|-----------------|-------------|--------------|----------------|
| T1486 | Ransomware | 90 | $4,500,000 |
| T1003 | Credential Dumping | 85 | $2,500,000 |
| T1190 | Exploit Public App | 80 | $2,000,000 |
| T1566 | Phishing | 60 | $1,200,000 |
| T1110 | Brute Force | 40 | $500,000 |
| T1046 | Port Scanning | 20 | $50,000 |

**Why US data?**
- Most comprehensive breach reporting
- Regulatory requirements mandate disclosure
- Largest sample size available

### Severity Multipliers

| SIEM Severity | Multiplier | Rationale |
|---------------|------------|-----------|
| CRITICAL_HIGH | 1.5× | Highest priority, max resources |
| HIGH | 1.0× | Standard priority |
| MEDIUM | 0.7× | Reduced priority |
| LOW | 0.5× | Minimum priority |

### Queue Routing Logic

```python
PRIORITY_QUEUE_THRESHOLD = 75

if risk_score >= 75:
    → Priority Queue (processed immediately)
else:
    → Standard Queue (processed after priority)
```

### Example Calculations

```
Ransomware (90) × Critical (1.5) = 135 → PRIORITY
Ransomware (90) × Low (0.5)      = 45  → STANDARD (likely false positive)
Brute Force (40) × Critical (1.5) = 60 → STANDARD
Credential Dump (85) × High (1.0) = 85 → PRIORITY
```

### Why Not Just Use SIEM Severity?

SIEM severity is based on **rule matching**, not **business impact**.

Example: A "critical" port scan from the internet has low actual damage potential. A "medium" credential access attempt on a domain controller has high damage potential.

**We combine both:**
- SIEM severity → Context (how confident is the detection?)
- Attack damage → Impact (how bad if this is real?)

---

## RAG System Design

### The 7 ChromaDB Collections

| Collection | Purpose | Document Count |
|------------|---------|----------------|
| mitre_severity | MITRE ATT&CK technique details | ~200 |
| historical_analyses | Past alerts with analyst decisions | ~50 |
| business_rules | Org-specific policies | ~10 |
| attack_patterns | Known attack indicators | ~40 |
| detection_rules | SIEM correlation rules | ~30 |
| detection_signatures | Behavioral patterns | ~25 |
| company_infrastructure | Asset context (tokenized) | ~20 |

### Why RAG Over Fine-Tuning

| Approach | Pros | Cons |
|----------|------|------|
| Fine-tuning | Faster inference, built-in knowledge | Expensive, hard to update, no transparency |
| RAG | Easy updates, transparent sources, lower cost | Slower, requires vector DB |

**Our choice: RAG**

Reasons:
1. Knowledge changes frequently (new TTPs)
2. Organization-specific context varies
3. Need to show "which sources influenced this decision"
4. No training compute required

### Company Infrastructure in RAG

**What's stored (tokenized):**
```json
{
  "tokenized_name": "USER-8c4fea72",
  "department": "finance",
  "role": "Financial Analyst",
  "access_level": "standard",
  "high_value_target": false,
  "typical_hours": "9am-6pm EST"
}
```

**Why this helps AI:**
- "Is this user expected to run PowerShell?" → Check role
- "Is this after-hours activity?" → Check typical_hours
- "Should this user access server X?" → Check department

**What's NOT stored:**
- Real IP addresses
- Real hostnames
- Real employee names
- Real email addresses

---

## AI Analysis Pipeline

### The 6 Phases

```
Phase 1: Security Gates
├── InputGuard: Prompt injection detection
├── AlertValidator: Pydantic schema validation
└── DataProtectionGuard: PII masking, size limits

Phase 2: Optimization
├── BudgetTracker: Check daily API limit
└── Deduplication: Skip recently analyzed identical alerts

Phase 3: Context Building
├── RAG queries: 7 collections
├── Log queries: 4 tables (process, network, file, windows)
└── OSINT enrichment: (disabled when tokenized)

Phase 4: AI Analysis
├── Build structured prompt
├── Call Claude API with retry logic
└── Parse structured response

Phase 5: Output Validation
├── OutputGuard: Sanitize response
├── Schema validation: Ensure correct format
└── Verdict normalization: lowercase, valid values

Phase 6: Observability
├── Audit logging: Every decision logged
├── Metrics collection: Cost, time, accuracy
└── Live logger: Real-time debug dashboard
```

### Prompt Structure

```
SYSTEM PROMPT:
- Role: Senior SOC analyst
- Task: Analyze security alert
- Output format: JSON with verdict, confidence, evidence, reasoning

CONTEXT (from RAG):
- MITRE technique details
- Historical similar alerts
- Business rules
- Attack patterns

ALERT DATA:
- Tokenized alert fields
- Correlated logs

INSTRUCTIONS:
- Explain reasoning step-by-step
- List specific evidence
- Provide confidence score
- Recommend actions
```

### Verdict Calibration

| Verdict | When to Use | Confidence Range |
|---------|-------------|------------------|
| MALICIOUS | Clear attack indicators | 0.85-1.0 |
| SUSPICIOUS | Needs investigation | 0.50-0.84 |
| BENIGN | Known false positive patterns | 0.80-1.0 |
| ERROR | Analysis failed | N/A |

**Benign Recognition Patterns:**
- Windows Update processes
- IT admin remote sessions (during business hours)
- Developer IDE activity
- Scheduled security scans

---

## Security Architecture

### Input Security

```
┌──────────────────────────────────────────────┐
│ InputGuard                                   │
├──────────────────────────────────────────────┤
│ • Prompt injection detection                 │
│   - "ignore previous instructions"           │
│   - "you are now a..."                       │
│   - Base64/hex encoded payloads              │
│                                              │
│ • Pattern matching: 20+ injection patterns   │
│ • Action: Block and log                      │
└──────────────────────────────────────────────┘
```

### Data Protection

```
┌──────────────────────────────────────────────┐
│ DataProtectionGuard                          │
├──────────────────────────────────────────────┤
│ • Tokenization enforcement                   │
│ • PII detection: 15 patterns                 │
│   - SSN: XXX-XX-XXXX                         │
│   - Credit cards: Visa/MC/Amex/Discover      │
│   - API keys: sk-, AKIA, AIza                │
│   - Passwords in logs                        │
│   - Email addresses                          │
│   - Phone numbers                            │
│                                              │
│ • Size limits:                               │
│   - Input: 10,000 chars                      │
│   - Output: 8,000 chars                      │
│   - Description: 5,000 chars                 │
└──────────────────────────────────────────────┘
```

### Output Security

```
┌──────────────────────────────────────────────┐
│ OutputGuard                                  │
├──────────────────────────────────────────────┤
│ • XSS prevention in AI responses             │
│ • SQL injection pattern removal              │
│ • Markdown sanitization                      │
│ • Code block filtering                       │
│ • Size enforcement                           │
└──────────────────────────────────────────────┘
```

### API Security

| Layer | Protection |
|-------|------------|
| Ingest Endpoint | X-Ingest-Key header required |
| Session Auth | Secure cookies, HttpOnly, SameSite |
| Credentials | Timing-safe comparison (prevents timing attacks) |
| Request Size | 2MB limit |
| CORS | Configurable (wildcard for demo) |

---

## Trade-offs & Limitations

### Tokenization Trade-off

**What we gain:**
- Compliance (GDPR, SOC 2)
- Safe logs and debugging
- AI never sees real infrastructure

**What we lose:**
- OSINT enrichment (VirusTotal, AnyRun, etc.)
- IP reputation lookups
- Domain categorization

**Future solution:**
- Local models via Ollama can access local threat intel
- Separate non-AI OSINT pipeline (pre-tokenization)
- Hybrid approach: OSINT first, then tokenize for AI

### Fast Mode for Dashboards

**What we did:**
- RAG/Transparency APIs generate summaries from alert data
- No live ChromaDB queries (which timeout on Railway)

**Trade-off:**
- Dashboards show representative summary, not actual retrieved documents
- AI verdicts are still 100% real (used real RAG during analysis)

**Why acceptable:**
- Demo needs fast responses
- Railway has memory constraints
- Actual analysis (which matters) uses real RAG

### In-Memory Metrics

**What we did:**
- Metrics stored in memory, not database

**Trade-off:**
- Metrics reset on container restart

**Why acceptable:**
- Faster access for real-time dashboards
- Reduces database load
- Metrics rebuild quickly as alerts process

### Severity: SIEM vs Our Classification

**Important clarification:**

We do **NOT** override SIEM severity. Here's how it works:

1. SIEM provides severity (critical/high/medium/low)
2. We use it as **input** to our risk calculation
3. We **add** attack damage context based on MITRE mapping
4. Final risk score combines both

```
SIEM says: "critical"
We calculate: Damage(85) × Critical(1.5) = 127.5
Result: Priority queue + appropriate AI response
```

The SIEM's severity judgment is respected; we're adding business impact context.

---

## Summary

This system is designed with these priorities:

1. **Compliance first**: Tokenization is not optional
2. **Transparency**: Every AI decision is explainable
3. **Cost-aware**: Optimize API usage
4. **Fail gracefully**: Degrade, don't crash
5. **Speed where it matters**: Cache aggressively

The trade-offs we made are conscious decisions based on:
- Compliance requirements
- Infrastructure constraints
- Demo requirements
- Future extensibility

When running in production with:
- More memory (ChromaDB queries won't timeout)
- Local models (OSINT can work with tokenized data)
- Database metrics (persistence across restarts)

...these trade-offs can be revisited.

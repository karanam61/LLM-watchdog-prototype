# Architecture Decisions Record

Document 02 of 08
Last Updated: January 9, 2026
Status: Backend Architecture 70% Complete

## System Architecture Overview

Alert processing follows this pipeline:

1. Parser - Extract structured fields from raw alerts
2. MITRE Mapper - Classify attack technique
3. Severity Classifier - Calculate risk score
4. Queue Manager - Route to priority or standard queue
5. Budget Tracker - Check budget availability
6. Tokenizer - Protect sensitive data for DB storage
7. AI Analyzer - Claude API analysis
8. RAG - Add historical context
9. Result - Verdict, confidence, and reasoning

### Technology Stack

Backend (implemented): Python 3.13, Flask REST API, threading for background processing. Supports Zeek, Suricata, Sysmon, and Splunk JSON formats.

Database (implemented): Supabase PostgreSQL with Row Level Security and real-time subscriptions. AWS S3 backup via Terraform.

AI/ML (in progress): Claude Sonnet 4.5 via Anthropic API. ChromaDB planned for RAG. Lakera Guard designed but not integrated. Pydantic validation designed but not integrated.

Frontend (basic structure): React with Vite dev server on port 5173.

Infrastructure (implemented): Terraform for AWS S3 backup, secrets in .env files, Docker deployment planned.

## Alert Parser Design

The parser converts raw alerts from Zeek, Suricata, Sysmon, and Splunk into a standardized format.

Input example (Sysmon):
```json
{
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\powershell.exe",
    "CommandLine": "powershell.exe -enc JABhAD0A...",
    "User": "DOMAIN\\john.smith"
}
```

Standardized output:
```json
{
    "alert_id": "ALERT_1704672345_001",
    "alert_name": "Suspicious PowerShell Execution",
    "description": "PowerShell executed with encoded command",
    "source_ip": "192.168.1.100",
    "username": "john.smith@company.com",
    "hostname": "DESKTOP-WIN10-001",
    "timestamp": "2024-01-07T19:45:23.582Z",
    "source_system": "sysmon"
}
```

### Field Mapping Decision

We considered three options: hardcode mapping per source (fast but brittle), AI-based field extraction (flexible but expensive), and configurable mapping rules (middle ground).

Decision: Configurable mapping with sensible defaults. Each source has a field mapping dictionary. Easy to add new sources, testable, mappings in one place.

### Critical Bug Fixed (Day 1)

Parser returned nested structure `{alert: {alert_name: ...}}` but app.py expected flat structure `{alert_name: ...}`. Fixed by flattening parser output.

## MITRE ATT&CK Mapper

Maps alerts to MITRE ATT&CK techniques using pattern matching with keywords and regex.

Example patterns for T1059 (Command and Scripting Interpreter): Keywords like powershell, cmd.exe, wscript, cscript, bash. Regex patterns like `powershell.*-enc`, `cmd.*/c`, `bash -c`. Damage cost: 65 (medium-high).

Attack damage scores come from IBM Cost of Data Breach, Verizon DBIR, and Ponemon Institute research. Scores range 0-100 based on financial impact, recovery time, and prevalence.

### UNKNOWN Technique Handling

Problem: What happens when no pattern matches?

Decision: Use "UNKNOWN" sentinel value with default damage score of 50 (medium). System continues working, we can track classification rate, and novel attacks get flagged for review.

Bug fixed: Initial code crashed when `get_damage_score('UNKNOWN')` returned None. Now returns default 50.

## Severity Classifier

Calculates risk scores 0-200 by combining base severity, MITRE damage, and context multipliers.

Formula: `risk_score = (base_severity + damage_cost) * multiplier`

Context multipliers: External IP (not RFC1918) adds 1.5x. Privileged username (admin, root, system) adds 1.3x. High-risk keywords (ransomware, c2, beacon) adds 1.4x.

Classifications: CRITICAL_HIGH is 150+, HIGH is 100-149, MEDIUM is 50-99, LOW is 0-49.

## Queue Manager Architecture

Two-queue system: priority and standard. Priority queue processed first.

Routing logic: Priority queue gets alerts with risk_score >= 100 OR damage_cost >= 70. Everything else goes to standard queue.

### Decision: Queue-Based vs Tier-Based

Problem: What if all high-priority alerts arrive at once?

Tier-based approach splits budget 50/50. Wastes budget if priority tier is light, can't adapt to volume changes.

Queue-based approach processes priority first, uses entire budget dynamically, reserves 10% for late arrivals. More efficient, adapts to workloads.

Decision: Queue-based with dynamic allocation. Standard queue might starve on heavy priority days, but that's correct behavior (critical threats matter more than noise).

## Dynamic Budget Tracker

Tracks daily AI analysis budget with separate priority and standard spend tracking.

Default budget: $10/day. Priority reserve: 10% ($1) held for late-arriving critical alerts. Reset: Midnight UTC.

Budget checks before each analysis. Records cost after completion. Resets automatically at midnight.

## Tokenization System

Protects sensitive data at rest in the database. Bidirectional mapping between real values and tokens.

`john.smith@company.com` becomes `TOKEN_000001`

Important: Tokenization is for database storage only, not for AI input. AI needs real semantic context to analyze effectively.

## Database Architecture

Supabase PostgreSQL with these tables: alerts (main storage with tokenized PII), token_mappings (value to token relationships), mitre_techniques (attack damage data), audit_logs (activity tracking), feedback (accuracy tracking), metrics (performance tracking).

Row Level Security enabled. Indexes on key fields. Timestamps on all tables.

## Project Structure

```
ai-soc-watchdog/
├── backend/
│   ├── core/           # parser.py, mitre_mapping.py, Severity.py, Queue_manager.py
│   ├── ai/             # alert_analyzer_final.py, rag_system.py, dynamic_budget_tracker.py
│   ├── storage/        # database.py, s3_failover.py
│   ├── security/       # tokenizer.py, security_guard.py
│   └── monitoring/     # system_monitor.py, live_logger.py
├── soc-dashboard/      # React frontend
├── terraform-s3/       # AWS backup
├── docs/
├── tests/
├── app.py              # Flask API
└── README.md
```

### Implementation Status

Implemented: Alert parser (Zeek, Suricata, Sysmon, Splunk), MITRE mapper with attack damage integration, severity classifier, queue manager, dynamic budget tracker, tokenizer (database-level), Supabase schema, Terraform S3 backup, React frontend (basic structure), Flask API.

Designed but not coded: AI Analyzer (architecture complete, code in progress), Pydantic validation, Lakera Guard integration, RAG with ChromaDB.

## Worker Architecture

Background worker processes alerts from queues:

1. Get next alert from queue
2. Check budget availability
3. Analyze with AI
4. Record cost
5. Tokenize before storing
6. Store result

Flask API submits alerts through POST /api/alert, which parses, maps MITRE technique, calculates severity, and routes to queue.

### Python Module Import Fix (Day 3)

Problem: `python backend/worker/worker.py` fails with ModuleNotFoundError because sys.path doesn't include project root.

Solution: Always run as module with `python -m backend.worker.worker` instead of running as script.

## Key Takeaways

What worked well: Modular design (each component testable independently), queue-based processing (dynamic, efficient resource use), risk-based prioritization (threats get attention first), database tokenization (protects sensitive data at rest), iterative debugging (fixed issues as they appeared).

Production improvements needed: Message queue (RabbitMQ/Redis instead of in-memory), distributed workers for scale, Prometheus metrics and Grafana dashboards, circuit breakers for cascade failure prevention, automated health checks.

Critical questions that improved design: "What if priority queue gets all budget?" led to reserve mechanism. "How do we handle UNKNOWN techniques?" led to sentinel value with default damage. "Why tokenize for AI?" led to realizing we shouldn't, only for DB. "What if worker isn't running?" led to need for automated health checks.

Next Document: 03_AI_ANALYZER_DESIGN.md

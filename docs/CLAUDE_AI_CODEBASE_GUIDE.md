# Codebase Guide

## What This System Does

Ingests security alerts from SIEM/EDR tools, analyzes them with Claude AI, and presents verdicts (malicious/benign/suspicious) to analysts. Addresses alert fatigue from thousands of daily alerts (90%+ false positives).

## Architecture

```
[SIEM] → [/ingest API] → [Parser] → [MITRE Mapper] → [Severity] → [Queue Manager]
                                                                         ↓
                                                              [Priority] [Standard]
                                                                         ↓
                                                              [AI Analysis Pipeline]
                                                                         ↓
[Supabase] ↔ [Context Builder] ↔ [ChromaDB RAG]
                    ↓
               [Claude AI]
                    ↓
              [Verdict] → Dashboard
```

## Directory Structure

```
AI Project/
├── app.py                          # Flask entry point
├── backend/
│   ├── ai/
│   │   ├── alert_analyzer_final.py # 6-phase analysis
│   │   ├── rag_system.py           # RAG retrieval
│   │   ├── security_guard.py       # Input/output validation
│   │   ├── osint_lookup.py         # Threat intel lookups
│   │   ├── validation.py           # Pydantic models
│   │   ├── dynamic_budget_tracker.py
│   │   └── api_resilience.py       # Retry logic
│   ├── core/
│   │   ├── parser.py               # Alert normalization
│   │   ├── mitre_mapping.py        # MITRE ATT&CK mapping
│   │   ├── Severity.py             # Risk scoring
│   │   └── Queue_manager.py        # Queue routing
│   ├── storage/
│   │   ├── database.py             # Supabase operations
│   │   └── s3_failover.py          # S3 backup
│   └── monitoring/
│       ├── system_monitor.py
│       ├── live_logger.py
│       └── api.py
├── soc-dashboard/                   # React frontend
│   └── src/pages/
│       ├── AnalystDashboard.jsx
│       ├── TransparencyDashboard.jsx
│       ├── RAGDashboard.jsx
│       └── DebugDashboard.jsx
└── docs/
```

## Key Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| /ingest | POST | Receive alerts from SIEM |
| /queue-status | GET | Queue counts |
| /alerts | GET | Fetch alerts |
| /alerts/<id> | GET | Single alert with analysis |

## AI Analysis Phases

1. VALIDATION - sanitize input, check for injection
2. OPTIMIZATION - check cache, select model
3. CONTEXT - query forensic logs, OSINT, RAG
4. AI ANALYSIS - call Claude API
5. OUTPUT VALIDATION - verify response structure
6. ACTION - store result, auto-close if benign

## RAG Collections (ChromaDB)

| Collection | Content |
|------------|---------|
| mitre_severity | 201 MITRE techniques |
| historical_analyses | Past alert analyses |
| business_rules | Org policies |
| attack_patterns | IOCs, TTPs |
| detection_rules | SIEM detection logic |
| detection_signatures | Regex patterns |
| company_infrastructure | Asset info |

## Environment Variables

```env
ANTHROPIC_API_KEY=sk-ant-...
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=xxx
SUPABASE_SERVICE_KEY=xxx
INGEST_API_KEY=xxx

# Optional
AWS_ACCESS_KEY=xxx
AWS_SECRET_KEY=xxx
VIRUSTOTAL_API_KEY=xxx
ABUSEIPDB_API_KEY=xxx
```

## Database Schema

**alerts table**: id, alert_name, mitre_technique, severity, source_ip, dest_ip, hostname, username, timestamp, description, status, ai_analysis (JSONB), risk_score, created_at

Related log tables: process_logs, network_logs, file_activity_logs, windows_event_logs

## Running Locally

```bash
# Backend
python app.py  # http://localhost:5000

# Frontend
cd soc-dashboard && npm run dev  # http://localhost:5173

# Test ingestion
curl -X POST http://localhost:5000/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-ingest-key-123" \
  -d '{"alert_name": "Test Alert", "severity": "high"}'
```

## Limitations

- Single AI provider (Claude only)
- Frontend polls instead of WebSocket push
- Cold start delay on free hosting
- ~$0.002-0.02 per alert

## Security

- Input validation via security_guard.py
- PII tokenized before logging
- X-API-Key required for /ingest
- Rate limiting: 100 req/min per IP

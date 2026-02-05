# File Structure

```
AI Project/
├── app.py                          # Flask entry point, API endpoints, queue workers
├── requirements.txt                # Python dependencies
├── .env                            # Environment variables (not in git)
│
├── backend/
│   ├── ai/
│   │   ├── alert_analyzer_final.py # 6-phase AI analysis pipeline, calls Claude
│   │   ├── api_resilience.py       # Claude API client with retry/timeout
│   │   ├── rag_system.py           # RAG queries across 7 ChromaDB collections
│   │   ├── security_guard.py       # Input/output validation, blocks injection
│   │   ├── osint_lookup.py         # IP/hash/domain threat intelligence
│   │   ├── validation.py           # Pydantic schemas for alerts/responses
│   │   ├── data_protection.py      # PII detection and redaction
│   │   ├── dynamic_budget_tracker.py # Daily cost limits
│   │   ├── observability.py        # Audit logging, health checks, metrics
│   │   ├── optimization.py         # Response caching, batch processing
│   │   └── flask_security.py       # Rate limiting, auth, CORS
│   │
│   ├── core/
│   │   ├── parser.py               # SIEM alert normalization
│   │   ├── mitre_mapping.py        # Map alerts to ATT&CK techniques
│   │   ├── Severity.py             # Classify CRITICAL_HIGH or MEDIUM_LOW
│   │   ├── Queue_manager.py        # Route alerts by risk score
│   │   ├── attack_damage_data.py   # MITRE technique damage scores
│   │   └── sample_data/            # RAG seed JSON files (mitre, rules, etc.)
│   │
│   ├── storage/
│   │   ├── database.py             # Supabase operations (store/query alerts)
│   │   └── backup.py               # S3 failover storage
│   │
│   ├── monitoring/
│   │   ├── system_monitor.py       # CPU, memory, cost metrics
│   │   ├── live_logger.py          # Real-time debug logging
│   │   ├── ai_tracer.py            # AI operation tracing
│   │   ├── api.py                  # /api/monitoring/* endpoints
│   │   ├── rag_api.py              # /api/rag/* endpoints
│   │   ├── transparency_api.py     # /api/transparency/* endpoints
│   │   └── shared_state.py         # Cross-module state
│   │
│   ├── api/
│   │   └── auth.py                 # JWT authentication
│   │
│   ├── security/
│   │   └── tokenizer.py            # Tokenize sensitive IPs/hostnames
│   │
│   ├── visualizer/
│   │   └── console_flow.py         # Terminal pipeline progress
│   │
│   └── scripts/
│       ├── seed_rag.py             # Populate ChromaDB
│       ├── seed_logs.py            # Generate forensic log data
│       ├── seed_forensics.py       # Link logs to alerts
│       └── health_check.py         # System health verification
│
├── soc-dashboard/                  # React frontend
│   └── src/
│       ├── pages/
│       │   ├── AnalystConsole.jsx  # Main alert review (/)
│       │   ├── AIDashboard.jsx     # AI performance (/ai-dashboard)
│       │   ├── RAGDashboard.jsx    # RAG visualization (/rag)
│       │   └── SystemDebug.jsx     # Debug logs (/debug)
│       ├── components/
│       │   ├── Navbar.jsx          # Navigation header
│       │   ├── AlertCard.jsx       # Alert display
│       │   ├── ChainOfThought.jsx  # AI reasoning steps
│       │   └── EvidencePanel.jsx   # Evidence display
│       └── utils/
│           └── api.js              # API calls
│
├── tests/
│   ├── ai/                         # AI connection, reasoning, live tests
│   ├── backend/                    # API endpoint tests
│   ├── integration/                # E2E tests
│   └── verification/               # Feature verification
│
├── scripts/
│   ├── seed_test_logs.py           # Create alerts with forensic logs
│   └── test_volume_and_benign.py   # Stress/false positive tests
│
├── docs/                           # Documentation
└── terraform-s3/                   # Infrastructure as code
```

## Data Flow

```
SIEM Alert -> app.py (/ingest)
    -> parser.py (normalize)
    -> mitre_mapping.py (ATT&CK)
    -> Severity.py (classify)
    -> Queue_manager.py (route)

Background Worker (app.py)
    -> database.py (fetch logs)
    -> osint_lookup.py (threat intel)
    -> rag_system.py (knowledge)
    -> alert_analyzer_final.py
        -> security_guard.py (validate in)
        -> data_protection.py (filter PII)
        -> api_resilience.py (Claude)
        -> security_guard.py (validate out)
    -> database.py (store result)

Frontend <- monitoring APIs
```

## Database (Supabase)

| Table | Purpose |
|-------|---------|
| alerts | Security alerts with AI verdict |
| process_logs | Sysmon process events |
| network_logs | Zeek network connections |
| file_activity_logs | File system changes |
| windows_event_logs | Windows security events |

## ChromaDB Collections

| Collection | Purpose |
|------------|---------|
| mitre_severity | 201 ATT&CK techniques |
| historical_analyses | Past alert verdicts |
| business_rules | Org policies |
| attack_patterns | Attack indicators |
| detection_rules | SIEM rules |
| detection_signatures | Detection patterns |
| company_infrastructure | Asset context |

# AI-SOC Watchdog

## Commands
- **Backend**: `py app.py` (Flask + SocketIO on port 5000)
- **Frontend**: `cd soc-dashboard && npm run dev` (Vite on port 5173)
- **Install deps**: `pip install -r requirements.txt` and `cd soc-dashboard && npm install`
- **Tests**: `python tests/run_all_tests.py` (all), `--quick` (no API), `--api` (API only), `--ai` (AI components)
- **Alert Tester**: `python scripts/test_alerts_interactive.py` (interactive) or `--test all` (automated)
- **Health check**: `curl http://localhost:5000/api/health`
- **Kill everything**: `stop_everything.bat` (kills all Python + Node processes)

## Authentication
- **Default login**: `analyst` / `watchdog123`
- Configure via `.env`: `AUTH_USERNAME`, `AUTH_PASSWORD`, `SESSION_SECRET`
- Session-based auth with timing-safe credential comparison
- **Auth middleware is currently DISABLED** (commented out in app.py lines 213-224) for demo/hosting
- Frontend hardcodes `user = { username: 'analyst' }` in App.jsx

---

## 1. Project Overview

AI-SOC Watchdog is an AI-powered Security Operations Center automation system that receives security alerts from SIEMs (Splunk, Wazuh), processes them through a 6-phase AI analysis pipeline using Claude API, and presents verdicts with full transparency on a React dashboard. It demonstrates real-world SOC automation with MITRE ATT&CK mapping, RAG-powered context enrichment, hypothesis-based analysis, novelty detection, and analyst feedback loops.

---

## 2. Tech Stack

### Backend
| Technology | Version | Purpose |
|-----------|---------|---------|
| Python | 3.13 | Core language |
| Flask | 3.1.2 | Web framework, REST API |
| Flask-SocketIO | 5.6.0 | WebSocket support (backend-side, not used by frontend currently) |
| Flask-CORS | 6.0.2 | Cross-origin resource sharing |
| Anthropic SDK | 0.75.0 | Claude API client |
| Supabase | 2.27.2 | PostgreSQL database (hosted) |
| ChromaDB | 1.4.1 | Vector database for RAG |
| Boto3 | (installed) | AWS S3 backup/failover |
| Pydantic | 2.x | Schema validation |
| Requests | (installed) | HTTP client for OSINT |
| psutil | (installed) | System monitoring |
| python-dotenv | (installed) | Environment variable loading |

### Frontend
| Technology | Version | Purpose |
|-----------|---------|---------|
| React | 18.2 | UI framework |
| Vite | 5.1 | Build tool, dev server |
| TailwindCSS | 3.4 | Styling (glassmorphism design) |
| Axios | 1.6 | HTTP client |
| Recharts | 2.12 | Charts (Line, Bar, Pie) |
| Framer Motion | 11.0 | Animations |
| Lucide React | 0.344 | Icons |
| React Router DOM | 6.22 | Client-side routing |
| socket.io-client | 4.7 | WebSocket client (installed but NOT used in any component) |

### Infrastructure
| Service | Purpose |
|---------|---------|
| Supabase | PostgreSQL database (alerts, forensic logs) |
| ChromaDB | Local vector DB for RAG (7 collections, stored in `backend/chromadb_data/`) |
| AWS S3 | Backup/failover for alerts (optional, fails gracefully if not configured) |

---

## 3. Folder Structure

```
AI Project/
├── app.py                          # Main Flask app (~2400 lines). Routes, queue workers, alert ingestion, auto-seed
├── requirements.txt                # Python dependencies
├── .env                            # Secrets (API keys, DB credentials) — NEVER commit
├── .env.example                    # Template for .env
├── stop_everything.bat             # Emergency kill script for all Python + Node processes
├── Procfile                        # Railway deployment config
├── railway.json                    # Railway deployment config
│
├── backend/
│   ├── ai/                         # AI analysis pipeline (THE CORE)
│   │   ├── alert_analyzer_final.py # THE MONOLITH — orchestrates all 26 features in 6 phases
│   │   ├── security_guard.py       # InputGuard (prompt injection regex) + OutputGuard (dangerous commands)
│   │   ├── validation.py           # Pydantic schemas: AlertInput, AlertAnalysis
│   │   ├── data_protection.py      # PII detection, size limits, sensitive data filtering
│   │   ├── dynamic_budget_tracker.py # Daily API cost tracking ($2 default limit) — IN RAM, resets on restart
│   │   ├── api_resilience.py       # ClaudeAPIClient with retry, backoff, timeout, model selection by severity
│   │   ├── rag_system.py           # ChromaDB RAG — queries 7 collections for context enrichment
│   │   ├── osint_lookup.py         # Threat intel: IP reputation, hash lookup, domain reputation
│   │   ├── novelty_detector.py     # Determines if alert type is KNOWN/PARTIAL/NOVEL, sets confidence ceiling
│   │   ├── hypothesis_analysis.py  # Forces AI to test both benign + malicious hypotheses before verdict
│   │   ├── structured_output.py    # Parses Claude's JSON response with multiple fallback strategies
│   │   ├── observability.py        # AuditLogger, HealthMonitor, MetricsCollector
│   │   ├── analyst_feedback.py     # Analyst verdict feedback loop (was AI correct?)
│   │   ├── transparency_verifier.py # Verifies AI reasoning quality
│   │   ├── optimization.py         # Caching and optimization utilities
│   │   └── flask_security.py       # Flask security utilities
│   │
│   ├── core/                       # Alert processing fundamentals
│   │   ├── parser.py               # parse_splunk_alert() — normalizes SIEM formats to standard schema
│   │   ├── mitre_mapping.py        # map_to_mitre() — maps alerts to MITRE ATT&CK techniques via RAG
│   │   ├── Severity.py             # classify_severity() — CRITICAL_HIGH or MEDIUM_LOW
│   │   ├── Queue_manager.py        # QueueManager — dual queue (priority/standard), thread-safe, dedup
│   │   ├── attack_damage_data.py   # Risk score calculations, damage potential per attack type
│   │   └── sample_data/            # Sample alert data for testing
│   │
│   ├── storage/                    # Database and persistence
│   │   ├── database.py             # Supabase CRUD: store_alert, update_alert_with_ai_analysis, query_*_logs
│   │   ├── backup.py               # S3 backup for alerts
│   │   ├── s3_failover.py          # S3 failover system (optional)
│   │   ├── schema.sql              # Database schema definition (users table)
│   │   ├── schema_updates.sql      # Schema migration queries
│   │   └── seed_users.sql          # Default user seeding
│   │
│   ├── monitoring/                 # Observability and debugging
│   │   ├── system_monitor.py       # Real-time CPU, memory, API call metrics
│   │   ├── live_logger.py          # Structured logging with _explanation field for Debug Dashboard
│   │   ├── ai_tracer.py            # AI operation tracing
│   │   ├── api.py                  # /api/monitoring/* blueprint (metrics, history, errors)
│   │   ├── rag_api.py              # /api/rag/* blueprint (stats, collections, per-alert usage)
│   │   ├── transparency_api.py     # /api/transparency/* blueprint (proof, summary)
│   │   └── shared_state.py         # Singleton registry to share live_logger across modules
│   │
│   ├── chromadb_data/              # ChromaDB vector database storage (7 collections)
│   └── visualizer/                 # Console flow tracker for debugging
│
├── soc-dashboard/                  # React frontend
│   ├── src/
│   │   ├── App.jsx                 # Router: 5 routes, auth disabled, hardcoded user
│   │   ├── main.jsx                # Entry point with ErrorBoundary
│   │   ├── utils/api.js            # Axios instance: baseURL from VITE_API_URL, 2min timeout
│   │   ├── components/
│   │   │   ├── Sidebar.jsx         # Left nav with 5 links (Operations, Monitoring, AI Insights)
│   │   │   └── ErrorBoundary.jsx   # React error boundary
│   │   └── pages/
│   │       ├── AnalystDashboard.jsx     # Main alert triage console (757 lines)
│   │       ├── PerformanceDashboard.jsx # System metrics, charts, costs
│   │       ├── DebugDashboard.jsx       # Live terminal-style log viewer
│   │       ├── RAGDashboard.jsx         # RAG system visualization
│   │       ├── TransparencyDashboard.jsx # AI decision proof/verification
│   │       └── Login.jsx                # Login form (not routed, auth disabled)
│   └── package.json
│
├── docs/                           # Project documentation
│   ├── AGENTIC_AI_SECURITY.md      # Agentic security concepts + OWASP Top 10 + governance
│   ├── MULTI_AGENT_ARCHITECTURE.md # Multi-agent design plan (next phase)
│   ├── RED_TEAM_14_DAY_PLAN.md     # 30-day red teaming plan (future phase)
│   ├── internal/
│   │   └── WHAT_HAPPENED_13_DOLLARS.md # Post-mortem: $13 credit burn incident
│   └── ...other docs...
│
├── scripts/                        # Utility scripts
├── tests/                          # Test suites
├── terraform-s3/                   # Terraform configs for S3 bucket
└── logs/                           # Application log files
```

---

## 4. What's Built (Complete Features)

### Alert Processing Pipeline
- **Alert ingestion** via `POST /ingest` — accepts Splunk/Wazuh/generic JSON formats
- **SIEM format normalization** — `parse_splunk_alert()` standardizes all formats
- **MITRE ATT&CK mapping** — maps alerts to techniques using RAG search
- **Severity classification** — CRITICAL_HIGH or MEDIUM_LOW based on keywords + risk scoring
- **Dual-queue routing** — priority queue (risk ≥ 75) + standard queue, thread-safe with dedup
- **Auto-seed on startup** — sends 3 hardcoded realistic alerts after server boots

### AI Analysis (26 Features in 6 Phases)
- **Phase 1 — Security Gates:** InputGuard (11 regex patterns for prompt injection), Pydantic schema validation, PII detection/filtering, data size limits
- **Phase 2 — Optimization:** Redis cache check (optional), daily budget tracking ($2 default)
- **Phase 3 — Context Building:** Forensic log retrieval (4 log types from Supabase), OSINT enrichment (IP/hash/domain reputation), RAG context from 7 ChromaDB collections, novelty detection (KNOWN/PARTIAL/NOVEL confidence ceiling)
- **Phase 4 — AI Analysis:** Claude API with retry + exponential backoff + timeout + fallback, hypothesis-based prompting (facts first, both hypotheses, then verdict), model selection by severity (Sonnet for critical, Haiku for low)
- **Phase 5 — Output Validation:** OutputGuard (15 dangerous command patterns, 18 attack keyword contradiction detection)
- **Phase 6 — Observability:** Audit logging, health monitoring, metrics collection, cost tracking, confidence calibration

### Database (Supabase)
- Alert storage with full metadata
- AI verdict storage with 3-tier fallback (all fields → minimal → core only)
- Forensic log tables (process, network, file activity, Windows events)
- Auto-close for benign + high confidence + non-critical alerts

### Frontend (React + Tailwind)
- **Analyst Dashboard** — alert triage with severity badges, AI verdict pills, expandable detail panels, 7 sub-tabs (summary, feedback, 4 log types, notes), pagination, 5s polling
- **Performance Dashboard** — CPU/memory charts, AI cost tracking, verdict distribution, error log
- **Debug Dashboard** — live terminal-style log viewer with category filters, 1s polling
- **RAG Dashboard** — knowledge base visualization, per-alert RAG usage
- **Transparency Dashboard** — AI decision proof, hypothesis comparison, verification scores
- **Glassmorphism design** with dark theme, cyan accents, Framer Motion animations

### Security Features
- Timing-safe credential comparison (`secrets.compare_digest`)
- Request size limits (2MB max)
- Secure cookie settings (HttpOnly, SameSite)
- Sensitive data redaction in logs
- Optional API key protection for `/ingest` endpoint
- InputGuard prompt injection detection (Lakera ML disabled, regex active)
- OutputGuard dangerous command filtering

### Monitoring & Observability
- Real-time system metrics (CPU, memory, queue sizes)
- Live structured logging with `_explanation` field for educational context
- AI operation tracing
- API cost tracking per call
- Heartbeat logger (every 30 seconds)

---

## 5. What's In Progress / Partially Done

| Feature | State | Notes |
|---------|-------|-------|
| Authentication middleware | Built but DISABLED | Commented out in app.py (lines 213-224) for demo |
| Lakera ML prompt injection | Built but DISABLED | `if False:` in security_guard.py — security alerts cause false positives |
| Redis caching | Code exists but not connected | Requires `REDIS_URL` env var, falls back gracefully |
| S3 failover system | Loaded but misconfigured | S3 bucket returns 404, system continues without it |
| WebSocket real-time updates | socket.io-client installed | Not imported or used in any frontend component |
| Rate limiting | Code comments only | Instructions in app.py (lines 132-143) but not implemented |
| Role-based access control | Schema exists | `users` table in schema.sql, but no RBAC logic in app |
| Budget tracker persistence | IN RAM ONLY | Resets to $0 on every server restart — caused $13 incident |

---

## 6. Architecture Decisions

### Why Monolithic Analyzer (Current)?
The `AlertAnalyzer` class in `alert_analyzer_final.py` runs all 26 features in one `analyze_alert()` call. This was chosen for simplicity during initial development. **Planned refactor:** Split into multi-agent architecture (Triage → Investigation → Verdict → Policy Engine) — see `docs/MULTI_AGENT_ARCHITECTURE.md`.

### Why Hypothesis-Based Prompting?
LLMs tend to decide first, then justify. The hypothesis prompt forces: extract facts → test benign hypothesis → test malicious hypothesis → pick winner based on evidence weight. This reduces confirmation bias in verdicts.

### Why Dual Queues?
Risk score = attack damage potential × severity multiplier. Score ≥ 75 goes to priority queue (processed first by better model). Lower scores go to standard queue. Prevents ransomware waiting behind failed login attempts.

### Why Model Selection by Severity?
`api_resilience.py` maps severity to Claude models: CRITICAL_HIGH → claude-sonnet-4 ($3/$15 per 1M tokens), MEDIUM_LOW → claude-3-haiku ($0.25/$1.25 per 1M tokens). Saves ~90% on low-priority alerts.

### Why 3-Tier Database Fallback?
`update_alert_with_ai_analysis()` tries: full data (12+ enhanced fields) → minimal data (core + chain_of_thought) → core only (verdict, confidence, evidence, reasoning, recommendation, status). Ensures `ai_verdict` saves even if Supabase schema is missing enhanced columns. **This was the root cause of the $13 incident** — before the fallback existed, verdicts silently failed to save.

### Why No LangChain/LangGraph?
Deliberate choice. Building agents from scratch ensures understanding of every trust boundary, data flow, and permission scope. Frameworks abstract away the exact concepts this project is meant to demonstrate.

---

## 7. Security Considerations

### Sensitive Areas
- `.env` file contains `ANTHROPIC_API_KEY`, `SUPABASE_URL`, `SUPABASE_KEY`, `SUPABASE_SERVICE_KEY`
- `app.py` line 148: `AUTH_PASSWORD` defaults to `watchdog123` — only use for development
- CORS is set to `*` (allow all origins) — intentional for demo, must restrict in production
- Auth middleware is DISABLED — all API endpoints are publicly accessible

### Known Security Gaps
- **No rate limiting** on any endpoint — `/ingest` can be flooded
- **CORS wildcard** — any website can call the API
- **Budget tracker in RAM** — resets on restart, no persistent spending limit
- **InputGuard non-blocking** — regex matches are logged but alerts are NOT rejected (line 176-182 in security_guard.py: "DON'T block the alert")
- **Lakera ML disabled** — only regex patterns active for prompt injection
- **No input sanitization for XSS** — alert fields render on dashboard without escaping
- **Auto-close logic** runs without human approval for benign + high confidence

### Security Patterns Used
- `secrets.compare_digest()` for all credential comparisons (timing-safe)
- `SENSITIVE_HEADERS` and `SENSITIVE_BODY_FIELDS` sets for log redaction
- Pydantic validation for input schema enforcement
- OutputGuard blocks dangerous commands in AI recommendations
- DynamicBudgetTracker prevents unlimited API spending (when it works)

---

## 8. What NOT to Touch

| File/Area | Why |
|-----------|-----|
| `backend/chromadb_data/` | Pre-populated vector database with MITRE ATT&CK data and security knowledge. Deleting = RAG breaks. |
| `.env` | Contains all secrets. Never commit. Never log contents. |
| `backend/ai/hypothesis_analysis.py` | Core prompt engineering — changes here affect ALL verdicts. Test thoroughly before modifying. |
| `backend/storage/database.py` update_alert_with_ai_analysis() | The 3-tier fallback (lines 351-371) prevents the $13 incident. Do not simplify. |
| `backend/core/Queue_manager.py` mark_done() | Dedup lifecycle fix. Removing this causes infinite re-queuing (see $13 post-mortem). |
| `stop_everything.bat` | Emergency kill switch. Keep it working. |
| The existing `alert_analyzer_final.py` | Even after multi-agent refactor, keep as fallback reference. Do NOT delete. |

---

## 9. Current State

### Working
- Full alert ingestion → AI analysis → dashboard display pipeline
- MITRE ATT&CK mapping via RAG
- Hypothesis-based AI analysis with novelty detection
- 5 frontend dashboards (Analyst, Performance, Debug, RAG, Transparency)
- Supabase storage with 3-tier fallback
- Background queue workers (priority + standard)
- Auto-seed on startup (3 realistic alerts)
- Analyst feedback loop

### Not Working / Disabled
- Authentication (disabled for demo)
- Rate limiting (not implemented)
- Redis caching (not configured)
- S3 failover (bucket 404)
- WebSocket real-time updates (not wired up)
- Lakera ML (disabled, regex only)

### Recent Fixes (from $13 incident)
- `debug=False` in `app.py` (was `debug=True` with `use_reloader=False`)
- Background DB scanner DISABLED (lines 1115-1118 in app.py)
- Smart rehydration: last 24 hours only, max 10 alerts
- Dedup lifecycle: IDs held until processing FINISHES via `mark_done()`
- 3-tier database fallback for verdict storage

---

## 10. Next Steps (Planned Roadmap)

### Phase 1: Multi-Agent Architecture (Next — ~17 days)
Split monolithic `AlertAnalyzer` into separation-of-duty agents:
- **Triage Agent** — extract facts from raw alert (no verdict)
- **Investigation Agent** — gather RAG/logs/OSINT context (no verdict, never sees raw alert)
- **Verdict Agent** — evaluate evidence, give verdict (no action recommendations)
- **Policy Engine** — pure Python, maps verdict to pre-approved actions (no AI)
- **Orchestrator** — coordinates agents in sequence with error handling
- See `docs/MULTI_AGENT_ARCHITECTURE.md` for complete design

### Phase 2: Agentic Security Implementation
Apply security concepts from `docs/AGENTIC_AI_SECURITY.md`:
- Trust boundary enforcement between agents
- Information flow control (taint tracking)
- Adaptive governance (3A's: Decision Authority, Process Autonomy, Accountability)
- Persistent budget tracking (file-based, not RAM)
- Runtime behavioral monitoring

### Phase 3: Red Teaming (30 days)
Systematic security testing — see `docs/RED_TEAM_14_DAY_PLAN.md`:
- Week 1: Foundations & reconnaissance
- Week 2: Application security testing (auth, injection, API)
- Week 3: AI security red teaming (prompt injection, RAG poisoning, resource exhaustion)
- Week 4: Advanced attacks, fixes, final report

---

## Code Style
- Python: snake_case functions/variables, PascalCase classes, type hints encouraged
- Use `live_logger.log()` for structured logging with `_explanation` field
- Use `secrets.compare_digest()` for credential comparisons (timing-safe)
- Return generic error messages to clients; log full errors internally
- Environment vars via `python-dotenv`; secrets in `.env` (never commit)
- API endpoints return JSON; use Flask blueprints for modularity
- Frontend: JSX components in `src/pages/`, API calls via `src/utils/api.js`
- Apply DVFS (Desirable, Viable, Feasible, Sustainable) to all design decisions

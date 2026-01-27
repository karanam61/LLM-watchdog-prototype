# File Structure - AI-SOC Watchdog

## Project Root Structure

```
AI Project/
├── app.py                      # Main Flask application entry point
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (not in git)
├── README.md                   # Project readme
│
├── backend/                    # Backend Python modules
│   ├── ai/                     # AI analysis components
│   ├── api/                    # API utilities
│   ├── core/                   # Core processing logic
│   ├── monitoring/             # Monitoring & observability
│   ├── scripts/                # Utility scripts
│   ├── security/               # Security utilities
│   ├── storage/                # Database interactions
│   └── visualizer/             # Flow visualization
│
├── soc-dashboard/              # React frontend
│   ├── src/
│   │   ├── pages/              # Dashboard pages
│   │   ├── components/         # Reusable components
│   │   └── utils/              # Utilities
│   └── package.json
│
├── docs/                       # Documentation
├── tests/                      # Test suites
├── scripts/                    # Startup scripts
└── terraform-s3/               # Infrastructure as code
```

---

## Detailed File Breakdown

### /backend/ai/ - AI Analysis Components

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `alert_analyzer_final.py` | Main AI orchestrator | `AlertAnalyzer.analyze_alert()` |
| `api_resilience.py` | Claude API client with retry | `ClaudeAPIClient.analyze_with_resilience()` |
| `data_protection.py` | PII/sensitive data guard | `DataProtectionGuard.validate_input()` |
| `dynamic_budget_tracker.py` | Cost control | `DynamicBudgetTracker.can_process_queue()` |
| `observability.py` | Logging & metrics | `AuditLogger`, `HealthMonitor`, `MetricsCollector` |
| `optimization.py` | Performance utilities | Caching helpers |
| `rag_system.py` | RAG knowledge retrieval | `RAGSystem.build_context()` |
| `security_guard.py` | Input/output validation | `InputGuard`, `OutputGuard` |
| `validation.py` | Schema validation | `AlertValidator`, `AlertSchema` |

---

### /backend/core/ - Core Processing

| File | Purpose | Key Functions |
|------|---------|---------------|
| `parser.py` | SIEM format normalization | `parse_splunk_alert()` |
| `mitre_mapping.py` | MITRE ATT&CK mapping | `map_to_mitre()` |
| `Severity.py` | Priority classification | `classify_severity()` |
| `Queue_manager.py` | Alert queue routing | `QueueManager.route_alert()` |
| `attack_damage_data.py` | Attack severity data | Lookup tables |

#### /backend/core/sample_data/ - RAG Seed Data

| File | Content |
|------|---------|
| `mitre_severity.json` | 201 MITRE techniques with severity |
| `historical_alert_analyses.json` | Past alert analysis examples |
| `business_rules.json` | Organizational policies |
| `attack_patterns_2025.json` | Known attack patterns |
| `detection_rules.json` | SIEM correlation rules |
| `detection_signatures.json` | Detection patterns |
| `company_infrastructure.json` | Asset inventory |

---

### /backend/monitoring/ - Monitoring & APIs

| File | Purpose | Key Classes |
|------|---------|-------------|
| `api.py` | Monitoring API endpoints | `monitoring_bp` Blueprint |
| `rag_api.py` | RAG visualization API | `rag_monitoring_bp` Blueprint |
| `transparency_api.py` | AI transparency API | `transparency_bp` Blueprint |
| `system_monitor.py` | System metrics collector | `SystemMonitor` |
| `live_logger.py` | Real-time debug logging | `LiveLogger` |
| `ai_tracer.py` | AI operation tracing | `AIOperationTracer` |
| `shared_state.py` | Cross-module state | State management |

---

### /backend/storage/ - Database Layer

| File | Purpose | Key Functions |
|------|---------|---------------|
| `database.py` | Supabase interactions | `store_alert()`, `query_*_logs()`, `update_alert_with_ai_analysis()` |
| `backup.py` | S3 backup functionality | `backup_to_s3()` |

---

### /backend/scripts/ - Utility Scripts

| Script | Purpose |
|--------|---------|
| `seed_rag.py` | Populate ChromaDB collections |
| `seed_logs.py` | Generate forensic log data |
| `seed_forensics.py` | Link logs to alerts |
| `health_check.py` | System health verification |
| `check_tables.py` | Database schema check |
| `debug_*.py` | Various debugging utilities |

---

### /soc-dashboard/src/pages/ - Frontend Pages

| File | Route | Purpose |
|------|-------|---------|
| `AnalystConsole.jsx` | `/` | Main alert review dashboard |
| `AIDashboard.jsx` | `/ai-dashboard` | AI performance metrics |
| `RAGDashboard.jsx` | `/rag` | RAG system visualization |
| `SystemDebug.jsx` | `/debug` | Real-time debug logs |

---

### /soc-dashboard/src/components/ - Reusable Components

| Component | Used In | Purpose |
|-----------|---------|---------|
| `Navbar.jsx` | All pages | Navigation header |
| `AlertCard.jsx` | AnalystConsole | Alert display card |
| `ChainOfThought.jsx` | AnalystConsole | AI reasoning steps |
| `EvidencePanel.jsx` | AnalystConsole | Evidence display |

---

### /docs/ - Documentation

| File | Content |
|------|---------|
| `PROJECT_OVERVIEW.md` | High-level project overview |
| `API_REFERENCE.md` | All API endpoints |
| `AI_FEATURES.md` | 26 AI features explained |
| `TESTING_GUIDE.md` | How to test each feature |
| `FILE_STRUCTURE.md` | This file |
| `DESIGN.md` | Design decisions |
| `QUICKSTART.md` | Quick start guide |

---

### /tests/ - Test Suites

```
tests/
├── ai/
│   ├── test_ai_connection.py    # API connectivity
│   ├── test_chain_of_thought.py # Reasoning tests
│   └── test_live_analysis.py    # Live alert tests
├── backend/
│   ├── test_backend_api.py      # API endpoint tests
│   ├── test_rag_api.py          # RAG endpoint tests
│   └── test_analyzer_full.py    # Full pipeline tests
├── integration/
│   ├── test_complete_system.py  # E2E tests
│   └── test_dashboard_integration.py
└── verification/
    ├── verify_core_polish.py    # Feature verification
    └── verify_rag_polish.py     # RAG verification
```

---

### /scripts/windows/ - Windows Startup Scripts

| Script | Purpose |
|--------|---------|
| `start_all.bat` | Start backend + frontend |
| `start_backend.bat` | Start Flask server only |
| `start_frontend.bat` | Start React dev server |

---

## Database Tables (Supabase)

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `alerts` | Security alerts | id, alert_name, severity, ai_verdict, ai_confidence |
| `process_logs` | Sysmon process events | alert_id, process_name, command_line |
| `network_logs` | Zeek network connections | alert_id, source_ip, dest_ip, port |
| `file_activity_logs` | File system changes | alert_id, file_path, action |
| `windows_event_logs` | Windows security events | alert_id, event_id, event_type |

---

## ChromaDB Collections (RAG)

| Collection | Documents | Purpose |
|------------|-----------|---------|
| `mitre_severity` | 201 | MITRE ATT&CK techniques |
| `historical_analyses` | ~50 | Past alert verdicts |
| `business_rules` | ~20 | Org policies |
| `attack_patterns` | ~30 | Attack indicators |
| `detection_rules` | ~25 | SIEM rules |
| `detection_signatures` | ~40 | Detection patterns |
| `company_infrastructure` | ~15 | Asset context |

---

## Key Entry Points

| What | Where | How to Run |
|------|-------|------------|
| Backend | `app.py` | `python app.py` |
| Frontend | `soc-dashboard/` | `cd soc-dashboard && npm run dev` |
| Seed RAG | `backend/scripts/seed_rag.py` | `python backend/scripts/seed_rag.py` |
| Seed Logs | `backend/scripts/seed_logs.py` | `python backend/scripts/seed_logs.py` |
| Tests | `tests/` | `python -m pytest tests/ -v` |

# Claude AI - Complete Codebase Understanding Guide

This document provides Claude AI with comprehensive knowledge about the AI-SOC Watchdog codebase to enable effective assistance with development, debugging, and enhancements.

---

## 1. PROJECT OVERVIEW

### What This Project Does

AI-SOC Watchdog is an **AI-powered Security Operations Center (SOC) automation system** that:

1. **Ingests security alerts** from SIEM/EDR tools via webhook
2. **Enriches alerts** with forensic logs, OSINT threat intel, and RAG knowledge
3. **Analyzes alerts** using Claude AI to determine if they're malicious/benign/suspicious
4. **Auto-triages** low-risk benign alerts to reduce analyst workload
5. **Provides transparency** so analysts can verify AI decisions

### The Core Problem It Solves

SOC analysts face **alert fatigue** - thousands of alerts daily, 90%+ are false positives. This system uses AI to:
- Automatically analyze alerts with context
- Provide verdicts with evidence
- Auto-close benign alerts
- Let analysts focus on real threats

---

## 2. ARCHITECTURE OVERVIEW

```
[SIEM/EDR] → [Webhook API] → [Parser] → [MITRE Mapper] → [Severity Classifier]
                                                                    ↓
                                                            [Queue Manager]
                                                            ↓           ↓
                                                    [Priority]    [Standard]
                                                            ↓           ↓
                                                        [AI Analysis Pipeline]
                                                                    ↓
[Supabase DB] ←→ [Context Builder] ←→ [ChromaDB RAG]
[OSINT APIs]  →         ↓
                   [Claude AI]
                        ↓
                   [Verdict]
                   ↓     ↓      ↓
            [Malicious] [Suspicious] [Benign]
                   ↓           ↓         ↓
            [Dashboard]  [Review]  [Auto-Close]
```

---

## 3. DIRECTORY STRUCTURE

```
AI Project/
├── app.py                      # Main Flask application entry point
├── requirements.txt            # Python dependencies
├── Procfile                    # Production deployment config
├── .env                        # Environment variables (not in git)
│
├── backend/
│   ├── ai/                     # AI Analysis Pipeline
│   │   ├── alert_analyzer_final.py  # Main 6-phase analysis orchestrator
│   │   ├── rag_system.py            # RAG knowledge retrieval (ChromaDB)
│   │   ├── security_guard.py        # Input/output validation, PII detection
│   │   ├── osint_lookup.py          # IP/hash/domain threat intel
│   │   ├── validation.py            # Pydantic models for data validation
│   │   ├── data_protection.py       # PII tokenization
│   │   ├── dynamic_budget_tracker.py # Cost tracking and model selection
│   │   ├── api_resilience.py        # Retry logic, circuit breaker
│   │   ├── optimization.py          # Caching, batch processing
│   │   ├── observability.py         # Logging, metrics
│   │   └── flask_security.py        # Rate limiting, API auth
│   │
│   ├── core/                   # Core Processing
│   │   ├── parser.py                # Alert normalization
│   │   ├── mitre_mapping.py         # MITRE ATT&CK technique mapping
│   │   ├── Severity.py              # Risk scoring (0-100)
│   │   ├── Queue_manager.py         # Priority/standard queue routing
│   │   └── attack_damage_data.py    # Attack type damage scores
│   │
│   ├── storage/                # Data Persistence
│   │   ├── database.py              # Supabase operations + S3 failover
│   │   ├── s3_failover.py           # S3 backup and read fallback
│   │   └── backup.py                # Basic S3 backup
│   │
│   ├── monitoring/             # Observability
│   │   ├── system_monitor.py        # CPU, memory, cost tracking
│   │   ├── live_logger.py           # Real-time operation logging
│   │   ├── ai_tracer.py             # AI decision tracing
│   │   ├── api.py                   # Monitoring API endpoints
│   │   ├── rag_api.py               # RAG dashboard API
│   │   ├── transparency_api.py      # AI transparency API
│   │   └── shared_state.py          # Shared state between modules
│   │
│   ├── api/                    # Authentication
│   │   └── auth.py                  # JWT token handling
│   │
│   ├── security/               # Security
│   │   └── tokenizer.py             # PII tokenization
│   │
│   └── visualizer/             # Debug Tools
│       └── console_flow.py          # Console visualization
│
├── soc-dashboard/              # React Frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── AnalystDashboard.jsx      # Main alert triage
│   │   │   ├── TransparencyDashboard.jsx # AI decision verification
│   │   │   ├── RAGDashboard.jsx          # RAG knowledge visualization
│   │   │   ├── PerformanceDashboard.jsx  # System metrics
│   │   │   └── DebugDashboard.jsx        # Live operation logs
│   │   └── components/                    # Reusable UI components
│   └── package.json
│
├── scripts/                    # Utility Scripts
│   ├── seed_test_logs.py            # Generate test data
│   ├── test_volume_and_benign.py    # Volume/false positive testing
│   ├── test_s3_failover.py          # S3 failover testing
│   └── seed_chromadb_knowledge.py   # Populate RAG knowledge base
│
└── docs/                       # Documentation
    ├── MANUAL_TESTING_GUIDE.md
    ├── HOSTING_GUIDE.md
    ├── ARCHITECTURE_DIAGRAM.md
    └── ... other docs
```

---

## 4. KEY FILES IN DETAIL

### 4.1 `app.py` - Main Application

**Purpose**: Flask application entry point that ties everything together.

**Key Endpoints**:
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/ingest` | POST | Receive alerts from SIEM/EDR |
| `/queue-status` | GET | Check queue counts |
| `/alerts` | GET | Fetch alerts from database |
| `/alerts/<id>` | GET | Get single alert with analysis |
| `/alerts/<id>/status` | PUT | Update alert status |
| `/api/failover/status` | GET | Check S3 failover status |
| `/api/failover/sync` | POST | Trigger S3 sync |

**Background Workers**:
- `queue_processor_worker()` - Processes alerts from queue
- `background_s3_sync()` - Syncs data to S3 every 5 minutes

### 4.2 `backend/ai/alert_analyzer_final.py` - AI Pipeline

**Purpose**: Orchestrates the 6-phase AI analysis pipeline.

**The 6 Phases**:
1. **VALIDATION** - Sanitize input, check for injection
2. **OPTIMIZATION** - Check cache, select model (Sonnet vs Haiku)
3. **CONTEXT** - Query forensic logs, OSINT, RAG knowledge
4. **AI ANALYSIS** - Build prompt, call Claude API
5. **OUTPUT VALIDATION** - Verify response structure
6. **ACTION** - Store result, auto-close if benign

**Key Methods**:
```python
class AlertAnalyzer:
    def analyze(self, alert: Dict) -> Dict:
        """Main entry point - runs all 6 phases"""
        
    def _build_context(self, alert, logs, osint) -> str:
        """Build enriched prompt with RAG + logs + OSINT"""
        
    def _call_claude_api(self, context, alert) -> Dict:
        """Call Claude with retry and model fallback"""
        
    def _fallback(self, alert) -> Dict:
        """Rule-based fallback when AI fails"""
```

### 4.3 `backend/ai/rag_system.py` - Knowledge Retrieval

**Purpose**: RAG (Retrieval-Augmented Generation) using ChromaDB.

**7 Knowledge Collections**:
| Collection | Content | Purpose |
|------------|---------|---------|
| `mitre_severity` | 201 MITRE techniques | Attack context |
| `historical_analyses` | Past alert analyses | Learn from history |
| `business_rules` | Organization policies | Business context |
| `attack_patterns` | IOCs, TTPs | Threat patterns |
| `detection_rules` | SIEM detection logic | Rule context |
| `detection_signatures` | Regex patterns | Signature matching |
| `company_infrastructure` | Asset info | Asset context |

**Key Methods**:
```python
class RAGSystem:
    def build_context(self, alert, logs) -> str:
        """Query all collections in parallel, build context"""
        
    def query_mitre_info(self, technique_id) -> Dict:
        """Get MITRE technique details"""
        
    def query_historical_alerts(self, alert_name, ...) -> Dict:
        """Find similar past alerts"""
```

### 4.4 `backend/storage/database.py` - Data Persistence

**Purpose**: Supabase operations with S3 failover.

**Key Functions**:
```python
def store_alert(alert_data) -> Dict:
    """Store alert, sync to S3 if enabled"""
    
def query_process_logs(alert_id) -> List:
    """Get process logs, fallback to S3 if DB down"""
    
def query_network_logs(alert_id) -> List:
    """Get network logs, fallback to S3 if DB down"""
    
def get_failover_status() -> Dict:
    """Check if in failover mode"""
```

### 4.5 `backend/core/Queue_manager.py` - Alert Routing

**Purpose**: Route alerts to priority or standard queue based on risk.

**Logic**:
```python
if risk_score >= 75:  # Critical/High
    priority_queue.put(alert)
else:  # Medium/Low
    standard_queue.put(alert)
```

---

## 5. DATA FLOW

### Alert Ingestion Flow

```
1. SIEM sends POST to /ingest with alert JSON
2. parser.py normalizes the alert
3. mitre_mapping.py enriches with MITRE technique
4. Severity.py calculates risk_score (0-100)
5. Queue_manager routes to priority or standard queue
6. Alert stored in Supabase with status="pending"
```

### AI Analysis Flow

```
1. queue_processor_worker picks alert from queue
2. AlertAnalyzer.analyze() called
3. Phase 1: Input validation (security_guard.py)
4. Phase 2: Cache check, model selection
5. Phase 3: Query logs from Supabase, OSINT, RAG
6. Phase 4: Build prompt, call Claude API
7. Phase 5: Validate JSON response
8. Phase 6: Store analysis, auto-close if benign
```

### Frontend Data Flow

```
1. Dashboard polls /alerts every 5 seconds
2. Analyst clicks alert → fetches /alerts/<id>
3. Transparency view shows analysis proof
4. RAG dashboard shows knowledge usage
5. Performance dashboard shows system metrics
```

---

## 6. ENVIRONMENT VARIABLES

```env
# Required
ANTHROPIC_API_KEY=sk-ant-...          # Claude AI
SUPABASE_URL=https://xxx.supabase.co  # Database
SUPABASE_KEY=xxx                       # Supabase anon key
SUPABASE_SERVICE_KEY=xxx               # Supabase service key

# Optional (for S3 failover)
AWS_ACCESS_KEY=xxx
AWS_SECRET_KEY=xxx
AWS_REGION=us-east-1
S3_BUCKET=your-bucket

# Optional (for OSINT)
VIRUSTOTAL_API_KEY=xxx
ABUSEIPDB_API_KEY=xxx
```

---

## 7. DATABASE SCHEMA (Supabase)

### `alerts` table
```sql
id              UUID PRIMARY KEY
alert_name      TEXT
mitre_technique TEXT
severity        TEXT (critical/high/medium/low)
source_ip       TEXT
dest_ip         TEXT
hostname        TEXT
username        TEXT
timestamp       TIMESTAMPTZ
description     TEXT
status          TEXT (pending/analyzed/closed)
ai_analysis     JSONB  -- The AI verdict + evidence
risk_score      INT
created_at      TIMESTAMPTZ
```

### `process_logs` table
```sql
id              UUID PRIMARY KEY
alert_id        UUID REFERENCES alerts(id)
process_name    TEXT
parent_process  TEXT
command_line    TEXT
username        TEXT
timestamp       TIMESTAMPTZ
```

### `network_logs` table
```sql
id              UUID PRIMARY KEY
alert_id        UUID REFERENCES alerts(id)
source_ip       TEXT
dest_ip         TEXT
dest_port       INT
protocol        TEXT
bytes_sent      INT
bytes_received  INT
timestamp       TIMESTAMPTZ
```

### `file_activity_logs` table
```sql
id              UUID PRIMARY KEY
alert_id        UUID REFERENCES alerts(id)
action          TEXT (create/modify/delete/read)
file_path       TEXT
process_name    TEXT
timestamp       TIMESTAMPTZ
```

### `windows_event_logs` table
```sql
id              UUID PRIMARY KEY
alert_id        UUID REFERENCES alerts(id)
event_id        INT
event_type      TEXT
username        TEXT
description     TEXT
timestamp       TIMESTAMPTZ
```

---

## 8. API RESPONSE FORMATS

### AI Analysis Response
```json
{
  "success": true,
  "verdict": "malicious",
  "confidence": 0.92,
  "evidence": [
    "[PROCESS-1] powershell.exe spawned from WINWORD.EXE",
    "[NETWORK-1] Connection to known C2 IP 185.220.101.45",
    "MITRE T1059.001: Command and Scripting Interpreter"
  ],
  "chain_of_thought": [
    {
      "step": 1,
      "observation": "Word spawned PowerShell",
      "analysis": "Unusual parent-child relationship",
      "conclusion": "Indicates macro-based attack"
    }
  ],
  "reasoning": "The alert shows classic signs of...",
  "recommendation": "1. Isolate host immediately..."
}
```

### Alert Status Update
```json
{
  "status": "closed",
  "resolution": "false_positive",
  "analyst_notes": "Verified as scheduled task"
}
```

---

## 9. COMMON TASKS

### Adding a New API Endpoint

1. Add route in `app.py`:
```python
@app.route('/api/new-endpoint', methods=['GET'])
def new_endpoint():
    return jsonify({"data": "value"})
```

2. Register blueprint if separate module

### Adding a New RAG Collection

1. Add collection in `rag_system.py`:
```python
def seed_new_collection(self):
    collection = self.client.get_or_create_collection("new_collection")
    collection.add(documents=[...], ids=[...], metadatas=[...])
```

2. Add query method and call in `build_context()`

### Modifying AI Prompt

Edit `backend/ai/rag_system.py`:
- `build_context()` method builds the full prompt
- `_format_logs()` formats forensic logs
- Footer section contains JSON structure requirements

### Adding New Log Type

1. Create table in Supabase
2. Add query function in `database.py`
3. Add to `_format_logs()` in `rag_system.py`
4. Update `s3_failover.py` SYNC_TABLES list

---

## 10. TESTING

### Run Backend
```bash
cd "AI Project"
python app.py
# Runs on http://localhost:5000
```

### Run Frontend
```bash
cd "AI Project/soc-dashboard"
npm install
npm run dev
# Runs on http://localhost:5173
```

### Test Alert Ingestion
```bash
curl -X POST http://localhost:5000/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-ingest-key-123" \
  -d '{"alert_name": "Test Alert", "severity": "high"}'
```

### Run Volume Tests
```bash
python scripts/test_volume_and_benign.py
```

---

## 11. KNOWN LIMITATIONS

1. **Single AI Provider**: Only Claude, no OpenAI/Gemini fallback
2. **No Real-time Push**: Frontend polls, no WebSocket
3. **Cold Start**: First request slow on free hosting
4. **RAG Accuracy**: Depends on seeded knowledge quality
5. **Cost**: ~$0.002-0.02 per alert depending on model

---

## 12. DEBUGGING TIPS

### Check AI Analysis
Look at Debug Dashboard or `live_logger` output for phase-by-phase trace.

### Check RAG Context
Print `context` variable before Claude API call in `alert_analyzer_final.py`.

### Check Database
Use Supabase dashboard or:
```python
from backend.storage.database import supabase
result = supabase.table('alerts').select('*').limit(5).execute()
```

### Check S3 Failover
```bash
python scripts/test_s3_failover.py
```

---

## 13. SECURITY CONSIDERATIONS

1. **Input Validation**: All inputs sanitized via `security_guard.py`
2. **PII Protection**: Sensitive data tokenized before logging
3. **API Auth**: Ingest endpoint requires X-API-Key header
4. **Rate Limiting**: 100 req/min per IP via `flask_security.py`
5. **Output Validation**: AI responses checked for dangerous content

---

This document should give Claude AI complete understanding of the codebase to assist with any development, debugging, or enhancement tasks.

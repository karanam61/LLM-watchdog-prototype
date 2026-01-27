# File Reference Guide - AI-SOC Watchdog

Quick reference for all Python files in the project.

---

## Root Directory

| File | Purpose |
|------|---------|
| `app.py` | **Main Flask Application** - Entry point, API endpoints, background workers, queue processing |

---

## Backend - AI Module (`backend/ai/`)

| File | Purpose |
|------|---------|
| `alert_analyzer_final.py` | **6-Phase AI Analysis Pipeline** - Orchestrates all 26 security features, sends alerts to Claude |
| `api_resilience.py` | **Claude API Client** - Timeout handling, retry logic, cost tracking, model selection by severity |
| `rag_system.py` | **RAG Knowledge Retrieval** - Queries 7 ChromaDB collections for context |
| `security_guard.py` | **Input/Output Validation** - Blocks prompt injection, validates AI responses |
| `osint_lookup.py` | **Threat Intelligence** - IP, hash, domain reputation lookups |
| `validation.py` | **Pydantic Schemas** - Validates alert structure and AI response format |
| `data_protection.py` | **PII Detection** - Detects/redacts sensitive data before AI processing |
| `dynamic_budget_tracker.py` | **Cost Control** - Daily budget limits, priority reserve |
| `observability.py` | **Audit/Metrics** - Logging, health checks, metrics collection |
| `optimization.py` | **Caching/Batching** - Response caching, batch processing |
| `flask_security.py` | **API Security** - Rate limiting, authentication, CORS |

---

## Backend - Core Module (`backend/core/`)

| File | Purpose |
|------|---------|
| `parser.py` | **Alert Parser** - Converts SIEM alerts to standard format |
| `mitre_mapping.py` | **MITRE Mapper** - Maps alerts to ATT&CK technique IDs |
| `Severity.py` | **Severity Classifier** - Classifies alerts as CRITICAL_HIGH or MEDIUM_LOW |
| `Queue_manager.py` | **Queue Router** - Routes alerts to priority/standard queues by risk score |
| `attack_damage_data.py` | **Damage Scoring** - Retrieves MITRE technique damage scores |

---

## Backend - Storage Module (`backend/storage/`)

| File | Purpose |
|------|---------|
| `database.py` | **Supabase Client** - All database operations (store alerts, query logs) |
| `backup.py` | **S3 Backup** - Failover storage when database unavailable |

---

## Backend - Monitoring Module (`backend/monitoring/`)

| File | Purpose |
|------|---------|
| `system_monitor.py` | **Metrics Collection** - CPU, memory, costs, processing times |
| `live_logger.py` | **Debug Logger** - Captures every operation for Debug Dashboard |
| `ai_tracer.py` | **AI Operation Tracer** - Human-readable AI activity logging |
| `api.py` | **Monitoring API** - Flask endpoints for Performance Dashboard |
| `rag_api.py` | **RAG API** - Flask endpoints for RAG Dashboard |
| `transparency_api.py` | **Transparency API** - Flask endpoints for AI Transparency Dashboard |
| `shared_state.py` | **Singleton Registry** - Shared instances across modules |

---

## Backend - API Module (`backend/api/`)

| File | Purpose |
|------|---------|
| `auth.py` | **JWT Authentication** - User login, token generation |

---

## Backend - Security Module (`backend/security/`)

| File | Purpose |
|------|---------|
| `tokenizer.py` | **Data Tokenizer** - Replaces sensitive IPs/hostnames with tokens |

---

## Backend - Visualizer Module (`backend/visualizer/`)

| File | Purpose |
|------|---------|
| `console_flow.py` | **Console Visualizer** - Real-time pipeline progress in terminal |

---

## Scripts (`scripts/`)

| File | Purpose |
|------|---------|
| `seed_test_logs.py` | **Test Data Seeder** - Creates alerts with associated forensic logs |
| `test_volume_and_benign.py` | **Volume/False Positive Testing** - Stress tests and benign alert verification |

---

## How the Files Connect (Data Flow)

```
SIEM Alert
    │
    ▼
app.py (/ingest endpoint)
    │
    ├─► parser.py (standardize format)
    │
    ├─► mitre_mapping.py (map to ATT&CK)
    │
    ├─► Severity.py (classify severity)
    │
    ├─► Queue_manager.py (route to queue)
    │
    ▼
Background Worker (app.py)
    │
    ├─► database.py (fetch forensic logs)
    │
    ├─► osint_lookup.py (threat intelligence)
    │
    ├─► rag_system.py (knowledge retrieval)
    │
    ├─► alert_analyzer_final.py
    │       │
    │       ├─► security_guard.py (validate input)
    │       ├─► data_protection.py (filter PII)
    │       ├─► api_resilience.py (call Claude)
    │       ├─► security_guard.py (validate output)
    │       └─► observability.py (audit log)
    │
    ▼
database.py (store AI analysis)
    │
    ▼
Frontend Dashboards
    │
    ├─► api.py (/api/monitoring/*)
    ├─► rag_api.py (/api/rag/*)
    └─► transparency_api.py (/api/transparency/*)
```

---

## Quick Start Commands

```bash
# Start backend
cd "c:\Users\karan\Desktop\AI Project"
python app.py

# Start frontend
cd "c:\Users\karan\Desktop\AI Project\soc-dashboard"
npm run dev

# Seed test data
python scripts/seed_test_logs.py --all

# Run volume test
python scripts/test_volume_and_benign.py --volume 100
```

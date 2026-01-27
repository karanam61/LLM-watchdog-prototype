# AI-SOC Watchdog - Project Overview

## What Is This Project?

AI-SOC Watchdog is an **AI-powered Security Operations Center (SOC) automation system** that:
1. **Ingests security alerts** from SIEMs (Splunk, Wazuh)
2. **Analyzes them using Claude AI** with 26 security features
3. **Provides verdicts** (benign/suspicious/malicious) with evidence
4. **Displays results** on a React dashboard for analysts

---

## Quick Start

### Start Backend (Flask API):
```bash
cd "c:\Users\karan\Desktop\AI Project"
python app.py
```
Backend runs on: `http://localhost:5000`

### Start Frontend (React Dashboard):
```bash
cd "c:\Users\karan\Desktop\AI Project\soc-dashboard"
npm run dev
```
Frontend runs on: `http://localhost:5173`

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI-SOC WATCHDOG                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│  │  SIEM    │───▶│ /ingest  │───▶│  Queue   │───▶│    AI    │      │
│  │ (Splunk) │    │   API    │    │ Manager  │    │ Analyzer │      │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘      │
│                                        │               │            │
│                                        ▼               ▼            │
│                               ┌──────────────┐ ┌──────────────┐    │
│                               │   Supabase   │ │   ChromaDB   │    │
│                               │  (Postgres)  │ │    (RAG)     │    │
│                               └──────────────┘ └──────────────┘    │
│                                        │               │            │
│                                        ▼               ▼            │
│                               ┌─────────────────────────────┐      │
│                               │      React Dashboard         │      │
│                               │  (Analyst Console + Debug)   │      │
│                               └─────────────────────────────┘      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Components

### 1. Backend (`app.py`)
- Flask web server
- API endpoints for alert ingestion, retrieval, updates
- Background queue processor for AI analysis

### 2. AI Analyzer (`backend/ai/alert_analyzer_final.py`)
- 6-phase analysis pipeline
- 26 security features (input guards, budget control, RAG, etc.)
- Claude API integration with resilience

### 3. RAG System (`backend/ai/rag_system.py`)
- 7 ChromaDB collections for knowledge retrieval
- MITRE ATT&CK techniques, historical alerts, business rules

### 4. Frontend (`soc-dashboard/`)
- React + Vite application
- Pages: Analyst Console, AI Dashboard, RAG Visualization, System Debug

### 5. Database (Supabase)
- Tables: alerts, process_logs, network_logs, file_activity_logs, windows_event_logs

---

## Data Flow

1. **Alert Ingestion** (`POST /ingest`)
   - SIEM sends alert JSON
   - Parser normalizes format
   - MITRE technique mapped
   - Severity classified
   - Stored in database
   - Routed to queue

2. **Background Processing**
   - Queue processor dequeues alert
   - AI Analyzer runs 6-phase pipeline
   - Claude API called with RAG context
   - Verdict saved to database

3. **Analyst Review**
   - Dashboard displays alerts with verdicts
   - Analyst reviews AI reasoning
   - Closes/escalates as needed

---

## Environment Variables (`.env`)

```env
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_anon_key
SUPABASE_SERVICE_KEY=your_service_key
ANTHROPIC_API_KEY=your_claude_api_key
INGEST_API_KEY=secure-ingest-key-123
```

---

## Documentation Index

| Document | Description |
|----------|-------------|
| [API_REFERENCE.md](./API_REFERENCE.md) | All API endpoints with examples |
| [AI_FEATURES.md](./AI_FEATURES.md) | The 26 AI security features |
| [TESTING_GUIDE.md](./TESTING_GUIDE.md) | How to test each functionality |
| [FILE_STRUCTURE.md](./FILE_STRUCTURE.md) | Organized file listing |
| [DESIGN.md](./DESIGN.md) | Design decisions |

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.13, Flask, Flask-CORS |
| AI | Anthropic Claude 3.5 Sonnet |
| Vector DB | ChromaDB (RAG) |
| Database | Supabase (PostgreSQL) |
| Frontend | React 18, Vite, Tailwind CSS, Recharts |
| Infrastructure | Terraform (S3 backup) |

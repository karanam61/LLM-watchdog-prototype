# AI-SOC Watchdog

A security alert automation system. It ingests alerts from SIEMs, analyzes them with Claude AI, and shows results on a dashboard for analysts to review.

## Quick Start

```bash
# Backend
python app.py
# Runs on http://localhost:5000

# Frontend
cd soc-dashboard
npm run dev
# Runs on http://localhost:5173
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      AI-SOC WATCHDOG                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  SIEM    │───▶│ /ingest  │───▶│  Queue   │───▶│    AI    │  │
│  │ (Splunk) │    │   API    │    │ Manager  │    │ Analyzer │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                        │               │        │
│                                        ▼               ▼        │
│                               ┌──────────────┐ ┌──────────────┐│
│                               │   Supabase   │ │   ChromaDB   ││
│                               │  (Postgres)  │ │    (RAG)     ││
│                               └──────────────┘ └──────────────┘│
│                                        │               │        │
│                                        ▼               ▼        │
│                               ┌─────────────────────────────┐  │
│                               │      React Dashboard        │  │
│                               └─────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Components

**app.py** - Flask backend with REST API and SocketIO. Handles alert ingestion, serves data to the frontend, runs background queue processing.

**backend/ai/alert_analyzer_final.py** - AI analysis pipeline using Claude. Takes alerts through multiple analysis phases and returns verdicts (benign/suspicious/malicious) with reasoning.

**backend/ai/rag_system.py** - RAG system using ChromaDB. Stores MITRE ATT&CK techniques, historical alerts, and business rules for context during analysis.

**backend/core/queue_manager.py** - Manages the processing queue. Alerts go in, get analyzed by AI, results come out.

**backend/storage/database.py** - Supabase (PostgreSQL) interface. Stores alerts, logs, and analysis results.

**soc-dashboard/** - React frontend built with Vite. Shows alerts, AI analysis results, and system status.

## Data Flow

1. SIEM sends alert to `/ingest` endpoint
2. Alert gets parsed, MITRE-mapped, and queued
3. Queue processor sends alert to AI analyzer
4. AI analyzer queries RAG for context, calls Claude
5. Verdict saved to database
6. Dashboard displays results for analyst review

## Environment Variables

Create a `.env` file with:

```
SUPABASE_URL=...
SUPABASE_KEY=...
ANTHROPIC_API_KEY=...
INGEST_API_KEY=...
```

## Other Docs

- [API_REFERENCE.md](./API_REFERENCE.md) - API endpoints
- [AI_FEATURES.md](./AI_FEATURES.md) - AI security features
- [TESTING_GUIDE.md](./TESTING_GUIDE.md) - Testing guide

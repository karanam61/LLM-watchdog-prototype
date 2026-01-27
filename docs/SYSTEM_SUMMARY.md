# AI-SOC Watchdog - Complete System Summary

## What This System Does (One Paragraph)

AI-SOC Watchdog is an automated security alert triage system that receives alerts from SIEMs (like Splunk), enriches them with knowledge from a RAG database (MITRE ATT&CK, historical patterns, business rules), analyzes them using Claude AI with 26 security features, and returns verdicts (malicious/suspicious/benign) with evidence and recommendations. Analysts review these AI-generated verdicts on a React dashboard.

---

## The Alert Journey (Step by Step)

```
1. SIEM sends alert → POST /ingest
2. Parser normalizes format → parse_splunk_alert()
3. MITRE technique mapped → map_to_mitre()
4. Severity classified → classify_severity()
5. Stored in Supabase → store_alert()
6. Routed to queue → QueueManager.route_alert()
7. Background worker picks up → background_queue_processor()
8. AI Analyzer runs 6 phases → AlertAnalyzer.analyze_alert()
   - Phase 1: Security gates (block malicious input)
   - Phase 2: Check cache/budget
   - Phase 3: Query RAG + forensic logs
   - Phase 4: Call Claude AI
   - Phase 5: Validate AI output
   - Phase 6: Log metrics/audit
9. Verdict saved → update_alert_with_ai_analysis()
10. Analyst sees in dashboard → GET /alerts
```

---

## Key Files You Need to Understand

### Backend Entry Point: `app.py`
- Flask server on port 5000
- Registers blueprints: monitoring, RAG, transparency
- Runs background queue processor thread
- Main endpoints: /ingest, /alerts, /api/logs

### AI Brain: `backend/ai/alert_analyzer_final.py`
- `AlertAnalyzer` class orchestrates 26 features
- `analyze_alert(alert)` is the main function
- Returns: verdict, confidence, evidence, chain_of_thought, reasoning

### Knowledge Base: `backend/ai/rag_system.py`
- `RAGSystem` queries 7 ChromaDB collections
- `build_context(alert, logs)` creates enriched prompt for AI
- Combines MITRE data, historical alerts, business rules

### Database: `backend/storage/database.py`
- Supabase PostgreSQL interactions
- `store_alert()`, `query_*_logs()`, `update_alert_with_ai_analysis()`

---

## The 26 Security Features (Grouped)

**Security (Features 1-4, 6-8, 14-17):**
- Input validation against prompt injection
- Schema validation with Pydantic
- PII/credential protection
- Output sanitization

**Optimization (Features 5, 22):**
- Daily budget tracking ($2/day limit)
- Response caching to avoid duplicate calls

**AI Analysis (Features 9-13):**
- Claude API client with retry logic
- Rate limiting and timeout handling
- Fallback responses when AI fails

**Observability (Features 18-21):**
- Audit logging for compliance
- Health monitoring
- Metrics collection
- Cost tracking

**RAG (Features 23-26):**
- 7 ChromaDB collections
- Semantic search for relevant context
- MITRE, historical, business rule retrieval

---

## API Endpoints Quick Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | /ingest | Receive alerts from SIEM |
| GET | /alerts | Fetch alerts for dashboard |
| PATCH | /api/alerts/{id} | Update alert status |
| GET | /api/logs | Get forensic logs |
| GET | /queue-status | Queue sizes |
| GET | /api/rag/usage/{id} | RAG data for alert |
| GET | /api/rag/stats | RAG statistics |
| GET | /api/rag/collections/status | RAG health check |
| GET | /api/monitoring/metrics/dashboard | System metrics |
| GET | /api/monitoring/logs/recent | Debug logs |

---

## Frontend Pages

| Route | Page | Shows |
|-------|------|-------|
| / | Analyst Console | Alert list, AI verdicts, evidence |
| /ai-dashboard | AI Dashboard | AI metrics, processing stats |
| /rag | RAG Visualization | Knowledge base queries |
| /debug | System Debug | Real-time operation logs |

---

## How to Test

```bash
# 1. Start backend
python app.py

# 2. Start frontend (new terminal)
cd soc-dashboard && npm run dev

# 3. Send test alert
curl -X POST http://localhost:5000/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-ingest-key-123" \
  -d '{"alert_name":"Test Alert","severity":"high","description":"Test"}'

# 4. Check alerts
curl http://localhost:5000/alerts

# 5. Wait 30s for AI analysis, then check dashboard
```

---

## Environment Variables Required

```env
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=eyJxxx
SUPABASE_SERVICE_KEY=eyJxxx
ANTHROPIC_API_KEY=sk-ant-xxx
INGEST_API_KEY=secure-ingest-key-123
```

---

## Database Schema (Supabase)

### alerts table
```sql
id UUID PRIMARY KEY
alert_name TEXT
severity TEXT
source_ip TEXT
dest_ip TEXT
timestamp TIMESTAMP
description TEXT
mitre_technique TEXT
severity_class TEXT
ai_verdict TEXT
ai_confidence FLOAT
ai_evidence JSONB
ai_reasoning TEXT
ai_recommendation TEXT
ai_chain_of_thought JSONB
status TEXT DEFAULT 'open'
created_at TIMESTAMP DEFAULT NOW()
```

### Log tables (process_logs, network_logs, etc.)
```sql
id UUID PRIMARY KEY
alert_id UUID REFERENCES alerts(id)
timestamp TIMESTAMP
-- type-specific fields
```

---

## RAG Collections (ChromaDB)

| Collection | Data Source | Query Method |
|------------|-------------|--------------|
| mitre_severity | MITRE ATT&CK | query_mitre_info(technique_id) |
| historical_analyses | Past alerts | query_historical_alerts(name, mitre) |
| business_rules | Org policies | query_business_rules(dept, severity) |
| attack_patterns | Attack IOCs | query_attack_patterns(mitre) |
| detection_rules | SIEM rules | query_detection_rules(alert_name) |
| detection_signatures | Patterns | query_detection_signatures(alert_name) |
| company_infrastructure | Assets | query_asset_context(user, host) |

---

## AI Response Format

```json
{
  "verdict": "malicious",
  "confidence": 0.95,
  "evidence": ["PowerShell from Word", "Encoded command", "Known malicious IP"],
  "chain_of_thought": [
    {"step": 1, "observation": "...", "analysis": "...", "conclusion": "..."},
    {"step": 2, "observation": "...", "analysis": "...", "conclusion": "..."}
  ],
  "reasoning": "Complete analysis explaining how evidence connects...",
  "recommendation": "1. Isolate endpoint 2. Block IP 3. Investigate user"
}
```

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Backend won't start | Check .env variables |
| AI not analyzing | Check ANTHROPIC_API_KEY |
| RAG returns empty | Run seed_rag.py |
| Logs not found | Run seed_logs.py for test data |
| Budget exhausted | Run reset_budget.py |
| Frontend can't connect | Ensure backend on port 5000 |

---

## Project Statistics

- **Backend Files:** ~50 Python files
- **Frontend Files:** ~15 React files
- **API Endpoints:** 12+
- **AI Features:** 26
- **RAG Collections:** 7
- **Database Tables:** 5
- **Test Files:** 20+

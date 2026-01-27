# API Reference - AI-SOC Watchdog

## Base URL
```
http://localhost:5000
```

---

## Authentication

### Ingestion Endpoint
Requires `X-API-Key` header:
```
X-API-Key: secure-ingest-key-123
```

---

## Core Endpoints (app.py)

### 1. POST /ingest
**Purpose:** Main entry point for all security alerts from SIEMs

**Headers:**
```
Content-Type: application/json
X-API-Key: secure-ingest-key-123
```

**Request Body:**
```json
{
  "alert_name": "PowerShell Download Cradle",
  "severity": "critical",
  "source_ip": "10.20.1.45",
  "dest_ip": "185.220.101.45",
  "timestamp": "2026-01-27T14:30:00Z",
  "description": "PowerShell spawned from Word with encoded command",
  "hostname": "WORKSTATION-001",
  "username": "john.doe"
}
```

**Response:**
```json
{
  "status": "processed",
  "alert_id": "uuid-here",
  "mitre_technique": "T1059.001",
  "severity": "CRITICAL_HIGH",
  "ai_analysis": {}
}
```

**Functions Called:**
1. `parse_splunk_alert(data)` - Normalize SIEM format
2. `map_to_mitre(parsed)` - Map to MITRE ATT&CK
3. `classify_severity(parsed)` - Determine priority
4. `store_alert(parsed, mitre, severity)` - Save to database
5. `qm.route_alert(parsed, severity)` - Add to queue

---

### 2. GET /alerts
**Purpose:** Fetch recent alerts for Analyst Console

**Response:**
```json
{
  "alerts": [
    {
      "id": "uuid",
      "alert_name": "PowerShell Download Cradle",
      "severity": "critical",
      "ai_verdict": "malicious",
      "ai_confidence": 0.95,
      "ai_reasoning": "...",
      "status": "analyzed",
      "created_at": "2026-01-27T14:30:00Z"
    }
  ],
  "count": 50
}
```

**Functions Called:**
- `supabase.table('alerts').select('*').order('created_at').limit(50)`

---

### 3. PATCH /api/alerts/{alert_id}
**Purpose:** Update alert status (close/investigate)

**Request Body:**
```json
{
  "status": "closed"
}
```

**Valid Statuses:** `open`, `investigating`, `closed`, `false_positive`

**Functions Called:**
- `supabase.table('alerts').update({'status': status}).eq('id', alert_id)`

---

### 4. GET /api/logs
**Purpose:** Fetch forensic logs for investigation

**Query Parameters:**
- `type` - Log type: `process`, `network`, `file`, `windows`
- `alert_id` - UUID of the alert

**Example:**
```
GET /api/logs?type=process&alert_id=uuid-here
```

**Functions Called:**
- `query_process_logs(alert_id)`
- `query_network_logs(alert_id)`
- `query_file_activity_logs(alert_id)`
- `query_windows_event_logs(alert_id)`

---

### 5. GET /queue-status
**Purpose:** Get current queue sizes

**Response:**
```json
{
  "priority_count": 2,
  "standard_count": 5
}
```

---

## RAG Monitoring Endpoints (backend/monitoring/rag_api.py)

### 6. GET /api/rag/usage/{alert_id}
**Purpose:** Get RAG knowledge used for a specific alert analysis

**Response:**
```json
{
  "alert_id": "uuid",
  "alert_name": "PowerShell Download Cradle",
  "sources_queried": ["MITRE Techniques", "Historical Alerts", "Business Rules"],
  "total_documents_retrieved": 8,
  "total_query_time": 0.234,
  "retrieved_by_source": {
    "MITRE Techniques": [{"text": "...", "score": 0.95}],
    "Historical Alerts": [{"text": "...", "score": 0.85}]
  }
}
```

**Functions Called:**
- `RAGSystem.query_mitre_info(technique_id)`
- `RAGSystem.query_historical_alerts(alert_name, mitre)`
- `RAGSystem.query_business_rules(department, severity)`
- `RAGSystem.query_attack_patterns(mitre_technique)`
- `RAGSystem.query_detection_signatures(alert_name)`
- `RAGSystem.query_asset_context(username, hostname)`

---

### 7. GET /api/rag/stats
**Purpose:** Get overall RAG system statistics

**Response:**
```json
{
  "total_queries": 150,
  "avg_query_time": 0.05,
  "avg_docs_retrieved": 3.5,
  "cache_hit_rate": 0.15,
  "query_distribution": {"mitre": 25, "historical": 30},
  "total_alerts": 50
}
```

---

### 8. GET /api/rag/collections/status
**Purpose:** Health check for RAG knowledge base

**Response:**
```json
{
  "collections": [
    {"name": "mitre_severity", "status": "active", "document_count": 201},
    {"name": "historical_analyses", "status": "active", "document_count": 50}
  ],
  "total_collections": 7,
  "active_collections": 7
}
```

---

## Monitoring Endpoints (backend/monitoring/api.py)

### 9. GET /api/monitoring/metrics/dashboard
**Purpose:** Get real-time system metrics (CPU, Memory, Budget)

**Response:**
```json
{
  "cpu_usage": 45.2,
  "memory_usage": 62.1,
  "budget_remaining": 1.85,
  "alerts_processed_today": 25
}
```

---

### 10. GET /api/monitoring/logs/recent
**Purpose:** Get recent operation logs for Debug Dashboard

**Query Parameters:**
- `limit` - Number of logs (default: 100)
- `category` - Filter by: `API`, `WORKER`, `AI`, `RAG`, `DATABASE`, `QUEUE`

**Response:**
```json
{
  "operations": [
    {
      "timestamp": "2026-01-27T14:30:00Z",
      "category": "AI",
      "operation": "analyze_alert()",
      "details": {"verdict": "malicious"}
    }
  ],
  "count": 50
}
```

---

### 11. GET /api/monitoring/logs/stream
**Purpose:** Server-Sent Events stream for real-time logs

**Response:** SSE stream with JSON events

---

## Transparency Endpoints (backend/monitoring/transparency_api.py)

### 12. GET /api/transparency/alert/{alert_id}
**Purpose:** Get detailed AI decision explanation

**Response:**
```json
{
  "alert_id": "uuid",
  "verdict": "malicious",
  "confidence": 0.95,
  "chain_of_thought": [
    {"step": 1, "observation": "...", "analysis": "...", "conclusion": "..."}
  ],
  "evidence": ["finding 1", "finding 2"],
  "rag_sources_used": ["MITRE T1059.001", "Historical Alert Pattern"]
}
```

---

## Error Responses

All endpoints return errors in this format:
```json
{
  "error": "Error message here"
}
```

**HTTP Status Codes:**
- `200` - Success
- `400` - Bad Request (missing parameters)
- `401` - Unauthorized (invalid API key)
- `404` - Not Found
- `500` - Server Error

---

## Testing with cURL

### Ingest an Alert:
```bash
curl -X POST http://localhost:5000/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-ingest-key-123" \
  -d '{"alert_name": "Test Alert", "severity": "high", "description": "Test"}'
```

### Get Alerts:
```bash
curl http://localhost:5000/alerts
```

### Get RAG Stats:
```bash
curl http://localhost:5000/api/rag/stats
```

### Update Alert Status:
```bash
curl -X PATCH http://localhost:5000/api/alerts/uuid-here \
  -H "Content-Type: application/json" \
  -d '{"status": "closed"}'
```

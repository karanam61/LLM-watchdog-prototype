# API Reference

Base URL: `http://localhost:5000`

## Authentication

The `/ingest` endpoint requires an API key header:

```
X-API-Key: secure-ingest-key-123
```

## Endpoints

### POST /ingest

Receives security alerts from SIEMs.

**Headers:**

| Header | Value |
|--------|-------|
| Content-Type | application/json |
| X-API-Key | your-api-key |

**Request:**

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

### GET /alerts

Returns recent alerts (up to 50).

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

### PATCH /api/alerts/{alert_id}

Updates alert status.

**Request:**

```json
{
  "status": "closed"
}
```

**Valid statuses:** `open`, `investigating`, `closed`, `false_positive`

### GET /api/logs

Returns forensic logs for an alert.

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| type | Log type: `process`, `network`, `file`, `windows` |
| alert_id | UUID of the alert |

**Example:**

```
GET /api/logs?type=process&alert_id=uuid-here
```

### GET /queue-status

Returns current queue sizes.

**Response:**

```json
{
  "priority_count": 2,
  "standard_count": 5
}
```

## RAG Endpoints

### GET /api/rag/usage/{alert_id}

Returns RAG knowledge used for a specific alert analysis.

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

### GET /api/rag/stats

Returns RAG system statistics.

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

### GET /api/rag/collections/status

Returns health status of RAG collections.

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

## Monitoring Endpoints

### GET /api/monitoring/metrics/dashboard

Returns system metrics.

**Response:**

```json
{
  "cpu_usage": 45.2,
  "memory_usage": 62.1,
  "budget_remaining": 1.85,
  "alerts_processed_today": 25
}
```

### GET /api/monitoring/logs/recent

Returns recent operation logs.

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| limit | Number of logs (default: 100) |
| category | Filter: `API`, `WORKER`, `AI`, `RAG`, `DATABASE`, `QUEUE` |

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

### GET /api/monitoring/logs/stream

Server-Sent Events stream for real-time logs.

### GET /api/transparency/alert/{alert_id}

Returns AI decision explanation for an alert.

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

## Error Responses

```json
{
  "error": "Error message here"
}
```

| Status Code | Meaning |
|-------------|---------|
| 200 | Success |
| 400 | Bad request |
| 401 | Invalid API key |
| 404 | Not found |
| 500 | Server error |

## Examples

**Ingest an alert:**

```bash
curl -X POST http://localhost:5000/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-ingest-key-123" \
  -d '{"alert_name": "Test Alert", "severity": "high", "description": "Test"}'
```

**Get alerts:**

```bash
curl http://localhost:5000/alerts
```

**Get RAG stats:**

```bash
curl http://localhost:5000/api/rag/stats
```

**Update alert status:**

```bash
curl -X PATCH http://localhost:5000/api/alerts/uuid-here \
  -H "Content-Type: application/json" \
  -d '{"status": "closed"}'
```

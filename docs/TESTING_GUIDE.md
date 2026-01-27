# Testing Guide - AI-SOC Watchdog

## Prerequisites

Before testing, ensure:
1. Backend is running: `python app.py`
2. Frontend is running: `cd soc-dashboard && npm run dev`
3. Environment variables are set in `.env`
4. Supabase database is accessible
5. ChromaDB RAG data is seeded

---

## 1. Testing Alert Ingestion

### Manual Test via cURL
```bash
curl -X POST http://localhost:5000/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-ingest-key-123" \
  -d '{
    "alert_name": "PowerShell Download Cradle - Possible Malware",
    "severity": "critical",
    "source_ip": "10.20.1.45",
    "dest_ip": "185.220.101.45",
    "timestamp": "2026-01-27T14:30:00Z",
    "description": "PowerShell spawned from Word with encoded command",
    "hostname": "FINANCE-WS-001",
    "username": "john.doe"
  }'
```

### Expected Response:
```json
{
  "status": "processed",
  "alert_id": "uuid-returned-here",
  "mitre_technique": "T1059.001",
  "severity": "CRITICAL_HIGH"
}
```

### Verification:
1. Check backend console for processing logs
2. Verify alert appears in Analyst Console
3. Wait ~30 seconds for AI analysis to complete
4. Refresh dashboard to see AI verdict

---

## 2. Testing API Key Security

### Test Without API Key (Should Fail):
```bash
curl -X POST http://localhost:5000/ingest \
  -H "Content-Type: application/json" \
  -d '{"alert_name": "Test", "severity": "high"}'
```

### Expected Response:
```json
{"error": "Unauthorized: Invalid API Key"}
```
**Status Code:** 401

---

## 3. Testing Alert Retrieval

### Get All Alerts:
```bash
curl http://localhost:5000/alerts
```

### Verify:
- Returns array of alerts
- Each alert has: id, alert_name, severity, ai_verdict, status
- Ordered by created_at descending

---

## 4. Testing Alert Status Update

### Update Alert to Closed:
```bash
curl -X PATCH http://localhost:5000/api/alerts/{ALERT_ID} \
  -H "Content-Type: application/json" \
  -d '{"status": "closed"}'
```

### Verification:
1. Refresh Analyst Console
2. Alert status should show "closed"

---

## 5. Testing RAG System

### Check RAG Collections Status:
```bash
curl http://localhost:5000/api/rag/collections/status
```

### Expected Response (7 Collections):
```json
{
  "collections": [
    {"name": "mitre_severity", "status": "active", "document_count": 201},
    {"name": "historical_analyses", "status": "active", "document_count": 50},
    {"name": "business_rules", "status": "active", "document_count": 20},
    {"name": "attack_patterns", "status": "active", "document_count": 30},
    {"name": "detection_rules", "status": "active", "document_count": 25},
    {"name": "detection_signatures", "status": "active", "document_count": 40},
    {"name": "company_infrastructure", "status": "active", "document_count": 15}
  ],
  "total_collections": 7,
  "active_collections": 7
}
```

### Test RAG Usage for Alert:
```bash
curl http://localhost:5000/api/rag/usage/{ALERT_ID}
```

---

## 6. Testing Forensic Logs

### Query Process Logs:
```bash
curl "http://localhost:5000/api/logs?type=process&alert_id={ALERT_ID}"
```

### Query Network Logs:
```bash
curl "http://localhost:5000/api/logs?type=network&alert_id={ALERT_ID}"
```

### Query File Activity Logs:
```bash
curl "http://localhost:5000/api/logs?type=file&alert_id={ALERT_ID}"
```

### Query Windows Event Logs:
```bash
curl "http://localhost:5000/api/logs?type=windows&alert_id={ALERT_ID}"
```

---

## 7. Testing Queue System

### Check Queue Status:
```bash
curl http://localhost:5000/queue-status
```

### Expected Response:
```json
{
  "priority_count": 0,
  "standard_count": 0
}
```

### Test Priority Routing:
1. Send alert with `"severity": "critical"` → Goes to priority queue
2. Send alert with `"severity": "low"` → Goes to standard queue
3. Check queue-status to verify

---

## 8. Testing Monitoring Endpoints

### Get System Metrics:
```bash
curl http://localhost:5000/api/monitoring/metrics/dashboard
```

### Get Recent Debug Logs:
```bash
curl http://localhost:5000/api/monitoring/logs/recent?limit=20
```

### Get Log Categories:
```bash
curl http://localhost:5000/api/monitoring/logs/categories
```

---

## 9. Frontend Testing

### Analyst Console (http://localhost:5173/)
1. **Verify alert list loads** - Should show recent alerts
2. **Click an alert** - Should show details panel
3. **Check AI verdict display** - Should show malicious/benign/suspicious
4. **Check evidence list** - Should show AI findings
5. **Test status change** - Click close/investigate buttons

### AI Dashboard (http://localhost:5173/ai-dashboard)
1. **Verify metrics cards load** - Alerts processed, budget, costs
2. **Check AI usage chart** - Should show processing timeline
3. **Verify recent analyses list** - Should show latest AI verdicts

### RAG Visualization (http://localhost:5173/rag)
1. **Verify collection status** - All 7 should be green/active
2. **Select an alert** - Click from left panel
3. **Check RAG sources** - Should show retrieved documents
4. **Expand source details** - Should show document text and metadata

### System Debug (http://localhost:5173/debug)
1. **Verify logs stream** - Should show recent operations
2. **Filter by category** - Test API, AI, RAG, DATABASE filters
3. **Check metrics charts** - CPU, memory, cost tracking

---

## 10. End-to-End Test Script

Create and run this test script:

```python
# tests/e2e_test.py
import requests
import time

BASE_URL = "http://localhost:5000"
API_KEY = "secure-ingest-key-123"

def test_full_flow():
    # 1. Ingest Alert
    print("1. Ingesting alert...")
    response = requests.post(
        f"{BASE_URL}/ingest",
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
        json={
            "alert_name": "E2E Test Alert",
            "severity": "high",
            "description": "End-to-end test alert",
            "source_ip": "10.0.0.1",
            "dest_ip": "8.8.8.8"
        }
    )
    assert response.status_code == 200
    alert_id = response.json().get("alert_id")
    print(f"   Alert ID: {alert_id}")
    
    # 2. Wait for AI Analysis
    print("2. Waiting for AI analysis (30s)...")
    time.sleep(30)
    
    # 3. Verify Alert in List
    print("3. Fetching alerts...")
    response = requests.get(f"{BASE_URL}/alerts")
    assert response.status_code == 200
    alerts = response.json().get("alerts", [])
    found = any(a.get("id") == alert_id for a in alerts)
    assert found, "Alert not found in list"
    print("   Alert found in list")
    
    # 4. Check AI Verdict
    alert = next(a for a in alerts if a.get("id") == alert_id)
    print(f"   AI Verdict: {alert.get('ai_verdict')}")
    print(f"   Confidence: {alert.get('ai_confidence')}")
    
    # 5. Test RAG Usage
    print("4. Testing RAG...")
    response = requests.get(f"{BASE_URL}/api/rag/usage/{alert_id}")
    if response.status_code == 200:
        rag_data = response.json()
        print(f"   Sources queried: {len(rag_data.get('sources_queried', []))}")
    
    # 6. Update Status
    print("5. Updating status to closed...")
    response = requests.patch(
        f"{BASE_URL}/api/alerts/{alert_id}",
        json={"status": "closed"}
    )
    assert response.status_code == 200
    print("   Status updated")
    
    print("\n✓ All tests passed!")

if __name__ == "__main__":
    test_full_flow()
```

Run with: `python tests/e2e_test.py`

---

## 11. Automated Test Suites

### Run Backend Tests:
```bash
cd "c:\Users\karan\Desktop\AI Project"
python -m pytest tests/backend/ -v
```

### Run AI Tests:
```bash
python -m pytest tests/ai/ -v
```

### Run Integration Tests:
```bash
python -m pytest tests/integration/ -v
```

---

## 12. Troubleshooting

### Backend won't start:
- Check `.env` file has all required variables
- Verify Supabase URL/keys are correct
- Run `python -c "from backend.storage.database import test_connection; test_connection()"`

### AI analysis not running:
- Check ANTHROPIC_API_KEY in .env
- Check budget tracker hasn't exhausted daily limit
- Run `python reset_budget.py` to reset

### RAG returns empty:
- Run `python backend/scripts/seed_rag.py` to populate ChromaDB
- Check `backend/chromadb_data/` exists with data

### Frontend can't connect:
- Ensure backend is on port 5000
- Check CORS is enabled (it is by default)
- Check browser console for errors

---

## Quick Test Commands Summary

```bash
# Health Check
curl http://localhost:5000/queue-status

# Ingest Alert
curl -X POST http://localhost:5000/ingest -H "Content-Type: application/json" -H "X-API-Key: secure-ingest-key-123" -d '{"alert_name":"Test","severity":"high","description":"Test alert"}'

# Get Alerts
curl http://localhost:5000/alerts

# RAG Status
curl http://localhost:5000/api/rag/collections/status

# System Metrics
curl http://localhost:5000/api/monitoring/metrics/dashboard
```

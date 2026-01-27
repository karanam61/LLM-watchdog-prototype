# Manual Testing Guide - AI-SOC Watchdog

## How to Verify Every Feature We Built

This guide walks you through testing each feature manually so you can prove it works.

---

## Prerequisites

### 1. Start the Backend
```bash
cd "c:\Users\karan\Desktop\AI Project"
python app.py
```
Wait until you see: `Running on http://127.0.0.1:5000`

### 2. Start the Frontend
```bash
cd "c:\Users\karan\Desktop\AI Project\soc-dashboard"
npm run dev
```
Wait until you see: `Local: http://localhost:5173`

### 3. Open Browser
Go to `http://localhost:5173`

---

## Feature 1: Create Case / Close Case Buttons

### What We Fixed
The buttons were calling the wrong API endpoint (`/alerts/` instead of `/api/alerts/`).

### How to Test
1. Go to **Analyst Dashboard** (My Operations tab)
2. Click on any alert to expand it
3. Click **"Create Case"** button
4. **Expected**: Alert moves to "Investigation Channel" tab
5. Switch to "Investigation Channel" tab
6. Click on the alert, then click **"Close Alert"**
7. **Expected**: Alert moves to "History Channel" tab

### How to Verify in Code
```
File: soc-dashboard/src/pages/AnalystDashboard.jsx
Lines 49-70: handleCloseAlert and handleCreateCase functions
The URL changed from `/alerts/${id}` to `/api/alerts/${id}`
```

---

## Feature 2: Analyst Notes Tab

### What We Added
A new "Notes" tab where analysts can write investigation notes for each alert.

### How to Test
1. Go to **Analyst Dashboard**
2. Click on any alert to expand it
3. Click the **"Notes"** tab (next to Process Logs, Network Logs, File Logs)
4. Type some notes in the text area
5. Click **"Save Notes"**
6. Refresh the page
7. Go back to the same alert and check Notes tab
8. **Expected**: Your notes are still there

### How to Verify in Database
```sql
-- In Supabase SQL Editor:
SELECT id, alert_name, analyst_notes FROM alerts WHERE analyst_notes IS NOT NULL;
```

---

## Feature 3: Auto-Close Benign Low/Medium Alerts

### What We Added
When AI determines an alert is BENIGN with >70% confidence AND it's not CRITICAL_HIGH severity, the system automatically closes it.

### How to Test
1. Run the benign test cases:
```bash
python scripts/seed_test_logs.py --benign
```
2. Wait 30-60 seconds for AI to process
3. Go to **Analyst Dashboard** → **History Channel**
4. **Expected**: Low/medium benign alerts appear here with status "closed"

### How to Verify in Database
```sql
SELECT alert_name, ai_verdict, ai_confidence, status, auto_closed, auto_close_reason 
FROM alerts 
WHERE auto_closed = true;
```

### How to Verify in Code
```
File: app.py
Lines ~550-580: Auto-close logic in background_queue_processor
Condition: verdict == 'benign' AND confidence >= 0.7 AND severity_class != 'CRITICAL_HIGH'
```

---

## Feature 4: Cost Reduction (Model Selection by Severity)

### What We Added
- CRITICAL/HIGH alerts use Claude Sonnet ($3/$15 per 1M tokens)
- LOW/MEDIUM alerts use Claude Haiku ($0.25/$1.25 per 1M tokens) - **90% cheaper**

### How to Test
1. Check the terminal where backend is running
2. Send a LOW severity alert:
```bash
curl -X POST http://localhost:5000/ingest \
  -H "X-API-Key: secure-ingest-key-123" \
  -H "Content-Type: application/json" \
  -d '{"alert_name": "Test Low", "severity": "low", "description": "Test"}'
```
3. Watch terminal output - should show: `[Model Selection] Severity 'low' -> Model 'claude-3-haiku-...'`
4. Send a CRITICAL alert:
```bash
curl -X POST http://localhost:5000/ingest \
  -H "X-API-Key: secure-ingest-key-123" \
  -H "Content-Type: application/json" \
  -d '{"alert_name": "Test Critical", "severity": "critical", "description": "Ransomware"}'
```
5. **Expected**: Shows `Model 'claude-sonnet-...'`

### How to Verify in Code
```
File: backend/ai/api_resilience.py
Lines 40-52: SEVERITY_MODEL_MAP dictionary
Lines 175-185: get_model_for_severity() method
```

---

## Feature 5: OSINT Integration (IP/Hash/Domain Lookups)

### What We Added
The AI now checks IPs, hashes, and domains against threat intelligence before making a verdict.

### How to Test
1. Send an alert with a known bad IP:
```bash
curl -X POST http://localhost:5000/ingest \
  -H "X-API-Key: secure-ingest-key-123" \
  -H "Content-Type: application/json" \
  -d '{"alert_name": "Test OSINT", "severity": "high", "description": "Connection detected", "dest_ip": "185.220.101.45"}'
```
2. Watch the backend terminal
3. **Expected**: You'll see `[OSINT Enrichment]` logs showing IP lookup results
4. The AI context will include: `OSINT THREAT INTELLIGENCE: Source IP (185.220.101.45): malicious - Tor Exit Node Range`

### How to Verify in Code
```
File: backend/ai/osint_lookup.py (entire file - new)
File: backend/ai/alert_analyzer_final.py
Lines ~395-420: OSINT enrichment in Phase 3
Lines ~795-830: _build_context() includes OSINT data
```

---

## Feature 6: System Metrics Dashboard

### How to Test
1. Go to **Performance** page in the dashboard
2. **Expected to see**:
   - CPU Usage (%)
   - Memory Usage (GB and %)
   - AI Cost (total $ spent)
   - Uptime (hours and minutes)
   - Alerts Processed (count)
   - System Resource Usage chart (24h)
   - Alert Processing Volume chart
   - AI Verdict Distribution pie chart
   - AI Performance Stats (avg response time, tokens, cost per alert)
   - Recent Errors list

### How to Verify It's Real-Time
1. Open the Performance page
2. Send some test alerts
3. Watch the "Alerts Processed" counter increase
4. **The page updates every 5 seconds automatically**

---

## Feature 7: RAG Dashboard (Real-Time)

### How to Test
1. Go to **RAG Visualization** page
2. **Expected to see**:
   - Total Queries count
   - Avg Query Time
   - Avg Docs Retrieved
   - Cache Hit Rate
   - Knowledge Base Collections bar chart
   - Query Distribution pie chart
   - Knowledge Base Status (7 collections with green checkmarks)

3. Click on an analyzed alert in the left panel
4. **Expected**: RAG Knowledge Retrieval section shows:
   - Sources Queried count
   - Docs Retrieved count
   - Query Time
   - Retrieved documents from each source

### How to Verify It's Real-Time
1. Keep the page open
2. Send new alerts
3. **The page updates every 10 seconds**
4. New analyzed alerts appear in the list

---

## Feature 8: AI Transparency Dashboard

### How to Test
1. Go to **AI Transparency** page
2. **Expected to see**:
   - Deep Analysis count
   - Shallow Analysis count
   - Avg Evidence Items
   - Verdict Distribution

3. Click on an analyzed alert
4. **Expected**:
   - Verification Score (0-100%)
   - Facts Found list
   - Missing Facts (if any)
   - RAG Knowledge Utilized
   - Original Alert Data (expandable)
   - AI Analysis Output (verdict, confidence, evidence, chain of thought)
   - Correlated Logs (expandable)

---

## Feature 9: False Positive Testing (Benign Alerts)

### How to Test
1. Seed benign alerts with realistic logs:
```bash
python scripts/seed_test_logs.py --benign
```
2. Wait 1-2 minutes for AI analysis
3. Go to **Analyst Dashboard**
4. Check the verdicts of these alerts:
   - "Windows Update Service Started" → Should be **BENIGN**
   - "Scheduled Backup Job Completed" → Should be **BENIGN**
   - "IT Admin RDP Session" → Should be **BENIGN**
   - "Chrome Auto-Update" → Should be **BENIGN**
   - "Antivirus Scan Completed" → Should be **BENIGN**

### Why This Works
The AI sees the forensic logs showing:
- Signed Microsoft/Veeam/Google processes
- Internal IP addresses only
- Legitimate file paths (Windows, Program Files)
- Normal Windows event IDs

---

## Feature 10: Volume Testing (100 Alerts)

### How to Test
```bash
python scripts/test_volume_and_benign.py --volume 100
```

### What to Observe
1. All 100 alerts should be accepted (no failures)
2. Alerts queue up and process over time
3. Check queue status:
```bash
curl http://localhost:5000/queue-status
```
4. **Expected**: Queue processes alerts without crashing

### Performance Expectations
- Ingestion rate: ~20-50 alerts/second
- AI analysis rate: ~1 alert per 5-15 seconds (API dependent)
- System should remain stable throughout

---

## Quick Verification Commands

### Check Backend is Running
```bash
curl http://localhost:5000/queue-status
```

### Check Alert Count
```bash
curl http://localhost:5000/alerts | python -c "import sys,json; print(json.load(sys.stdin)['count'])"
```

### Check RAG Collections
```bash
curl http://localhost:5000/api/rag/collections/status
```

### Check System Metrics
```bash
curl http://localhost:5000/api/monitoring/metrics/dashboard
```

---

## Troubleshooting

### "Backend not running"
- Make sure you ran `python app.py` in the project root
- Check for port 5000 conflicts

### "Alerts not being analyzed"
- Check the backend terminal for errors
- Verify ANTHROPIC_API_KEY is set in `.env`

### "RAG data stuck loading"
- Check if the alert has been analyzed (ai_verdict not null)
- The RAG usage endpoint only works for analyzed alerts

### "OSINT not showing"
- OSINT data is included in the AI context, not displayed separately
- Check backend logs for `[OSINT Enrichment]` messages

---

## Feature 11: S3 Failover System (Database Resilience)

### What We Added
The database is no longer a single point of failure. When Supabase goes down:
1. System automatically detects failure (after 3 consecutive failures)
2. Switches to S3 as data source
3. Frontend and AI continue working using S3 data
4. When Supabase recovers, automatically switches back

### Prerequisites
Add these to your `.env` file:
```
AWS_ACCESS_KEY=your_aws_access_key
AWS_SECRET_KEY=your_aws_secret_key
AWS_REGION=us-east-1
S3_BUCKET=your-bucket-name
```

### How to Test

#### Test 1: Check Failover Status
```bash
curl http://localhost:5000/api/failover/status
```
**Expected**: Returns status showing S3 availability and failover mode

#### Test 2: Manually Trigger S3 Sync
```bash
curl -X POST http://localhost:5000/api/failover/sync
```
**Expected**: All tables sync to S3 (alerts, process_logs, network_logs, etc.)

#### Test 3: Run Failover Test
```bash
curl -X POST http://localhost:5000/api/failover/test
```
**Expected**: Tests read capability from S3 for all tables

#### Test 4: Run Complete Test Script
```bash
python scripts/test_s3_failover.py
```
**Expected**: All 7 tests pass

### Verify in AWS Console
1. Log into AWS Console
2. Go to S3 -> Your Bucket
3. You should see folders:
   - `alerts/latest.json`
   - `process_logs/latest.json`
   - `network_logs/latest.json`
   - `file_activity_logs/latest.json`
   - `windows_event_logs/latest.json`

### How It Works
1. **Background Sync**: Every 5 minutes, all tables sync to S3
2. **Auto-Detect Failure**: After 3 failed DB operations, enters failover mode
3. **S3 Read**: All query functions automatically fallback to S3
4. **Auto-Recovery**: When Supabase works again, exits failover mode

### Verify in Code
```
File: backend/storage/s3_failover.py (entire file - new)
File: backend/storage/database.py
  - Lines 60-90: Failover imports and tracking
  - Lines 95-140: _handle_db_success/failure functions
  - Lines 145-270: Query functions with S3 fallback
File: app.py
  - Lines 780-840: S3 sync background worker
  - Lines 1470-1580: Failover API endpoints
```

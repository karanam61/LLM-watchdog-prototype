# Testing Guide

## Setup

Start backend:
```bash
python app.py
```

Start frontend:
```bash
cd soc-dashboard
npm run dev
```

Open http://localhost:5173

---

## Test Scripts

### Run All Tests
```bash
python tests/run_all_tests.py
```

Options:
- `--quick` - Skip API tests
- `--api` - API tests only
- `--ai` - AI component tests only

### AI Analysis Tests (Blind)
```bash
python scripts/test_comprehensive_blind.py --all
python scripts/test_comprehensive_blind.py --check   # Check results after 2-3 min
python scripts/test_comprehensive_blind.py --volume 100   # Stress test
```

### Blind Tests with Logs
```bash
python scripts/test_blind_with_logs.py --all
python scripts/test_blind_with_logs.py --check
```

### Benign Alert Tests
```bash
python scripts/seed_test_logs.py --benign
```

### Volume Test
```bash
python scripts/test_volume_and_benign.py --volume 100
```

### S3 Failover Test
```bash
python scripts/test_s3_failover.py
```

---

## Quick Verification

```bash
# Health check
curl http://localhost:5000/api/health

# Queue status
curl http://localhost:5000/queue-status

# RAG collections
curl http://localhost:5000/api/rag/collections/status

# System metrics
curl http://localhost:5000/api/monitoring/metrics/dashboard

# Failover status
curl http://localhost:5000/api/failover/status
```

---

## Manual Feature Tests

### Create/Close Case
1. Analyst Dashboard > click alert > Create Case
2. Alert moves to Investigation Channel
3. Click Close Alert
4. Alert moves to History Channel

### Analyst Notes
1. Click alert > Notes tab
2. Type notes > Save Notes
3. Refresh page, verify notes persist

### Auto-Close Benign
1. Run `python scripts/seed_test_logs.py --benign`
2. Wait 30-60 seconds
3. Check History Channel for auto-closed low/medium benign alerts

### Model Selection by Severity
Watch backend logs when sending alerts:
- LOW/MEDIUM: Uses claude-3-haiku
- CRITICAL/HIGH: Uses claude-sonnet

### OSINT Lookups
Send alert with IP, watch for `[OSINT Enrichment]` in backend logs.

### Dashboard Pages
- Performance: CPU, memory, AI cost, uptime, charts (updates every 5s)
- RAG Visualization: Query stats, collections, retrieved docs (updates every 10s)
- AI Transparency: Verdict distribution, evidence items, chain of thought

---

## Expected AI Results

Benign scenarios should get BENIGN verdict (90%+ confidence):
- Windows Update, Chrome Update, IT Admin RDP, Antivirus Scan, Backup Job

Malicious scenarios should get MALICIOUS verdict (80%+ confidence):
- PowerShell download cradle, LSASS dump, Data exfiltration, Ransomware, Lateral movement

Edge cases should get SUSPICIOUS verdict:
- Admin using PsExec, Encoded PowerShell from CI/CD

---

## Troubleshooting

**Alerts stuck in Analyzing**: Check API key, backend logs, budget

**All same verdict**: Check log insertion, RAG system, AI prompt

**Backend not running**: Check port 5000 conflicts

**RAG data stuck loading**: Alert may not be analyzed yet (ai_verdict null)

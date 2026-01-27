# 🛡️ AI-SOC Watchdog - Quick Start Guide

## ✅ All Issues Fixed

### What Was Fixed:
1. ✅ **Authentication Removed** - Direct access enabled, no login required
2. ✅ **AI Analysis Bug** - Fixed `_build_context` parameter mismatch
3. ✅ **Log Display** - Verified alert_id foreign keys work correctly
4. ✅ **Frontend Cleanup** - Removed all auth components (Login, ProtectedRoute, AuthContext)
5. ✅ **Data Generation** - Created reliable test data script

---

## 🚀 Start the System (3 Commands)

### Option 1: Automated (Recommended)
```bash
python start.py
```

### Option 2: Manual
```bash
# Terminal 1 - Backend
python app.py

# Terminal 2 - Frontend
cd soc-dashboard
npm run dev
```

---

## 📊 Generate Test Data

Run this **after** starting the backend:

```bash
python scripts/data/generate_test_data.py
```

This creates:
- 3 realistic security alerts
- 10 correlated forensic logs
- All data has proper alert_id foreign keys

---

## 🎯 How to Use

1. **Open Browser**: http://localhost:5173
2. **Main Dashboard**: See alerts automatically (no login!)
3. **Click Alert**: Expands to show Investigation panel
4. **View Logs**: Click tabs: Summary, Process, Network, File
5. **Wait for AI**: ~10 seconds for AI verdict to appear

---

## 🔍 What Each Tab Shows

### Summary Tab
- Alert description
- AI verdict (MALICIOUS/BENIGN/SUSPICIOUS)
- AI confidence score
- Evidence chain
- AI reasoning

### Process Logs Tab
- Process name (e.g., powershell.exe)
- Command line
- Parent process
- Username & hostname
- Timestamp

### Network Logs Tab
- Source IP → Destination IP
- Port & Protocol
- Bytes sent/received
- Connection state

### File Logs Tab
- File action (Create/Delete/Modify)
- File path
- Process responsible
- Username

---

## 🤖 AI Analysis

The system uses **Claude Sonnet 4** to analyze alerts automatically.

### How It Works:
1. Alert arrives → Stored in database
2. Background thread picks it up
3. Fetches related forensic logs
4. Sends to AI with context
5. AI returns verdict + reasoning
6. Updates database
7. Frontend shows verdict pill

### If AI Analysis Doesn't Appear:
- Check backend terminal for errors
- Verify ANTHROPIC_API_KEY is set in `.env`
- Check budget limits (default $2/day in `alert_analyzer_final.py`)
- Look for "🤖 Analyzing Alert ID..." in backend logs

---

## 📁 Project Structure

```
AI Project/
├── app.py                          # Backend API server (Flask)
├── start.py                        # One-click launcher
├── scripts/
│   └── data/
│       └── generate_test_data.py   # Test data generator
├── .env                            # API keys (ALREADY CONFIGURED)
├── backend/
│   ├── core/
│   │   ├── parser.py              # SIEM alert parser
│   │   ├── mitre_mapping.py       # MITRE ATT&CK mapping
│   │   ├── Severity.py            # Severity classifier
│   │   └── Queue_manager.py       # Priority queue
│   ├── ai/
│   │   ├── alert_analyzer_final.py # AI brain (26 features)
│   │   ├── api_resilience.py      # Claude API client
│   │   └── rag_system.py          # Context enrichment
│   ├── storage/
│   │   └── database.py            # Supabase queries
│   └── security/
│       └── tokenizer.py           # PII tokenization (disabled)
└── soc-dashboard/
    ├── src/
    │   ├── App.jsx                # Main router
    │   ├── pages/
    │   │   └── AnalystDashboard.jsx # Main dashboard
    │   └── utils/
    │       └── api.js             # Backend API wrapper
    └── package.json
```

---

## 🔧 API Endpoints

### GET /alerts
Fetches all alerts for dashboard
```json
{
  "alerts": [...],
  "count": 5
}
```

### GET /api/logs?type=network&alert_id=xxx
Fetches forensic logs for an alert
- Types: `process`, `network`, `file`, `windows`

### PATCH /api/alerts/:id
Updates alert status
```json
{
  "status": "closed" | "investigating" | "open"
}
```

### POST /ingest
Receives alerts from SIEM (requires X-API-Key header)

---

## 🗄️ Database Schema

### alerts
- `id` (UUID, primary key)
- `alert_name`, `description`
- `source_ip`, `dest_ip`, `hostname`, `username`
- `mitre_technique`, `severity`, `severity_class`
- `ai_verdict`, `ai_confidence`, `ai_evidence`, `ai_reasoning`
- `status` ('open', 'investigating', 'closed', 'analyzed')

### process_logs
- `alert_id` (foreign key → alerts.id)
- `process_name`, `command_line`, `parent_process`
- `username`, `hostname`, `timestamp`

### network_logs
- `alert_id` (foreign key → alerts.id)
- `source_ip`, `dest_ip`, `dest_port`, `protocol`
- `bytes_sent`, `bytes_received`, `service`

### file_activity_logs
- `alert_id` (foreign key → alerts.id)
- `action`, `file_path`, `file_name`
- `process_name`, `username`, `timestamp`

---

## 🐛 Troubleshooting

### Frontend shows "ESTABLISHING UPLINK..."
- Backend isn't running
- Run: `python app.py`

### Alerts appear but no logs
- Run: `python scripts/data/generate_test_data.py` (creates data with proper alert_ids)
- Check backend terminal: Should see `[INNER TRACE] DB Query (Network): AlertID=xxx -> Found X logs`

### AI verdict stays "Analyzing..."
- Check backend terminal for errors
- Verify `.env` has `ANTHROPIC_API_KEY=sk-ant-...`
- Look for "🤖 Analyzing Alert ID..." messages
- Check budget: Line 95 in `alert_analyzer_final.py`

### Port already in use
```bash
# Windows
netstat -ano | findstr "5000"
taskkill /PID <PID> /F

netstat -ano | findstr "5173"
taskkill /PID <PID> /F
```

---

## 📝 Environment Variables

Your `.env` file is already configured with:
```
ANTHROPIC_API_KEY=sk-ant-...
SUPABASE_URL=https://...
SUPABASE_KEY=...
SUPABASE_SERVICE_KEY=...
```

---

## 🎨 Features Implemented

✅ Real-time alert feed with auto-refresh  
✅ AI-powered threat analysis (Claude Sonnet 4)  
✅ Forensic log correlation  
✅ MITRE ATT&CK technique mapping  
✅ Priority queue (critical alerts first)  
✅ Background AI processing  
✅ Investigation panel with tabbed logs  
✅ Status management (open/investigating/closed)  
✅ Modern glass-morphism UI  
✅ Responsive design  
✅ Error handling & retry logic  
✅ Cost tracking & budget limits  

---

## 📚 Additional Scripts

### Check Database
```bash
python backend/scripts/db_inspector.py
```

### Test AI Connection
```bash
python tests/ai/test_ai_connection.py
```

### Health Check
```bash
curl http://localhost:5000/queue-status
```

---

## 🚨 Important Notes

1. **Authentication is REMOVED** - Anyone with access to localhost:5173 can view alerts
2. **Tokenization is DISABLED** - Raw IPs/usernames are stored (was for privacy compliance)
3. **AI costs money** - Default budget is $2/day (configurable in `alert_analyzer_final.py`)
4. **Background processing** - AI analysis happens in a separate thread
5. **Poll-based updates** - Frontend checks every 5 seconds for new AI verdicts

---

## ✨ You're All Set!

Everything is fixed and ready to run. Just:
1. `python scripts/data/generate_test_data.py` (creates alerts)
2. `python start.py` (starts servers)
3. Open http://localhost:5173
4. Click alerts to see logs & AI analysis

**Enjoy your AI-powered SOC dashboard!** 🎉

# Development Decisions Log

## AI-SOC Watchdog - Architecture & Implementation Decisions

This document chronicles all major decisions, fixes, and architectural changes made during development.

---

## Table of Contents

1. [Project Setup](#1-project-setup)
2. [Validation & Schema Fixes](#2-validation--schema-fixes)
3. [Queue System Architecture](#3-queue-system-architecture)
4. [Authentication System](#4-authentication-system)
5. [Security Hardening](#5-security-hardening)
6. [Frontend Implementation](#6-frontend-implementation)
7. [AI Analysis Improvements](#7-ai-analysis-improvements)
8. [Testing Strategy](#8-testing-strategy)
9. [Deployment Configuration](#9-deployment-configuration)
10. [Decisions Against (What We Didn't Do)](#10-decisions-against-what-we-didnt-do)

---

## 1. Project Setup

### AGENTS.md Creation
**Decision:** Created `AGENTS.md` file with build commands, architecture info, and code style guidelines.

**Rationale:** Provides context for AI assistants and new developers to understand the project quickly.

**Content includes:**
- Build/run commands for backend and frontend
- Default login credentials
- Architecture overview
- Code style conventions

---

## 2. Validation & Schema Fixes

### Fix: Optional Timestamp Field
**Problem:** `timestamp Input should be a valid string [type=string_type, input_value=None, input_type=NoneType]`

**Solution:** Made `timestamp` optional in `AlertInput` Pydantic schema.

```python
# Before
timestamp: str = Field(..., description="ISO timestamp")

# After
timestamp: Optional[str] = Field(default=None, description="ISO timestamp")
```

**Location:** `backend/ai/validation.py`

### Fix: Sensible Defaults for Non-Critical Fields
**Problem:** Alerts failing validation due to missing optional fields.

**Solution:** Added defaults for non-critical fields:
- `hostname` → `"unknown-host"`
- `username` → `"unknown-user"`
- `mitre_technique` → `None`

**Rationale:** Better to analyze with partial data than to reject the alert entirely.

---

## 3. Queue System Architecture

### Decision: Dual Queue Workers (Parallel Processing)

**Before:** Single `background_queue_processor` handling both queues sequentially.

**After:** Two dedicated workers running in parallel:
- `priority_queue_worker` - Processes CRITICAL_HIGH alerts immediately
- `standard_queue_worker` - Processes MEDIUM_LOW alerts

**Rationale:** Critical security alerts shouldn't wait behind a backlog of low-priority alerts.

### Fix: Correct Queue Data Structure Access
**Problem:** Using `pop(0)` on `deque` objects.

**Solution:** Changed to `popleft()` for proper deque handling.

```python
# Before (wrong)
alert = qm.priority_queue.pop(0)

# After (correct)
alert = qm.priority_queue.popleft()
```

### Decision: Automatic Alert Queuing from Database
**Problem:** Alerts inserted directly to DB (not via `/ingest`) weren't being processed.

**Solution:** Added `background_db_scanner` thread that periodically:
1. Queries for alerts where `status='open'` AND `ai_verdict IS NULL`
2. Automatically queues them for processing

**Rationale:** Ensures no alerts are orphaned, regardless of how they entered the system.

---

## 4. Authentication System

### Decision: Session-Based Authentication

**Approach:** Flask session cookies (not JWT).

**Rationale:**
- Simpler to implement for single-domain deployment
- Built-in Flask support
- Secure with proper cookie settings

### Endpoints Added
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/auth/login` | POST | Authenticate user |
| `/api/auth/logout` | POST | Clear session |
| `/api/auth/check` | GET | Verify authentication status |

### Default Credentials
```
Username: analyst
Password: watchdog123
```

Configurable via `.env`:
```
AUTH_USERNAME=your-username
AUTH_PASSWORD=your-password
```

### Decision: Authentication Disabled for Demo
**Rationale:** Easier for evaluators/demos to access. Can be re-enabled by uncommenting `require_auth` middleware.

---

## 5. Security Hardening

### CORS Restriction
**Before:** `CORS(app)` - Open to all origins.

**After:** 
```python
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5173').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)
```

### Timing-Safe Credential Comparison
**Before:** `if password == stored_password`

**After:** `if secrets.compare_digest(password, stored_password)`

**Rationale:** Prevents timing attacks that could reveal password length/characters.

### Error Message Sanitization
**Before:** `return jsonify({"error": str(e)}), 500`

**After:** 
```python
print(f"[ERROR] {e}")  # Internal logging
return jsonify({"error": "An internal error occurred"}), 500  # Generic to client
```

### Audit Trail for Analyst Actions
**Addition:** Log username, timestamp, and changes when analysts update alerts.

```python
live_logger.log('AUDIT', 'Analyst Action', {
    'analyst': session.get('username'),
    'alert_id': alert_id,
    'changes': update_payload,
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ')
})
```

---

## 6. Frontend Implementation

### Re-Analyze Button for ERROR Verdicts
**Problem:** Alerts that failed AI analysis (ERROR verdict) had no recovery path.

**Solution:** Added "Re-analyze" button that:
1. Clears AI analysis fields
2. Resets status to 'open'
3. Re-queues for processing

**Backend:** `POST /api/alerts/<alert_id>/reanalyze`

### Pagination for Alert List
**Problem:** All alerts loaded at once, causing performance issues with large datasets.

**Solution:** 
- Backend: Paginated `/alerts?page=1&per_page=20` endpoint
- Frontend: Pagination bar with Previous/Next buttons

**Response format:**
```json
{
  "alerts": [...],
  "page": 1,
  "total_pages": 5,
  "has_next": true,
  "has_prev": false,
  "total": 100
}
```

### Login Page
**Addition:** New `Login.jsx` component with:
- Username/password form
- Error handling
- Session persistence check

### Sidebar Updates
- Display logged-in username
- Logout button
- Visual indicator of auth status

---

## 7. AI Analysis Improvements

### Verdict Calibration
**Problem:** AI defaulting to "50% suspicious" too often, not clearly identifying benign activity.

**Solution:** Added explicit decision criteria to prompts:

#### BENIGN Criteria
- Administrative PowerShell/CMD by IT staff
- Scheduled tasks, Windows Update, maintenance
- Internal vulnerability scans (Nessus, Qualys)
- Known automation tools (Ansible, SCCM, Jenkins)
- Backup operations, antivirus scans

#### MALICIOUS Criteria
- Known malware signatures/hashes
- C2 server connections
- Data exfiltration patterns
- Credential dumping (mimikatz, lsass)
- Ransomware indicators

#### SUSPICIOUS Criteria
- Genuinely ambiguous activity
- First-time behavior deviating from baseline
- Needs human investigation

### Confidence Calibration
| Range | Meaning |
|-------|---------|
| 90-100% | Clear evidence, high certainty |
| 70-89% | Strong indicators, some ambiguity |
| 50-69% | Mixed signals, needs human review |
| <50% | Should not be used (default to suspicious) |

### False Positive Recognition
Added explicit list of typically benign activities:
- Windows/Microsoft Update processes
- Legitimate admin PowerShell commands
- IT support tools (TeamViewer, Bomgar)
- Developer tools (VS Code, Docker, npm)
- Cloud sync clients (OneDrive, Dropbox)

### Instruction for Benign Explanations
AI now instructed to say:
- "This is normal administrative activity because..."
- "This is a false positive - the behavior matches routine maintenance..."

---

## 8. Testing Strategy

### Decision: Blind Testing
**Problem:** AI might be biased by alert names containing words like "attack" or "malicious".

**Solution:** Created blind test scripts that:
1. Don't reveal expected verdict in alert name
2. Provide realistic log data
3. Let AI determine verdict purely from evidence

### Test Scripts
| Script | Purpose |
|--------|---------|
| `test_blind_with_logs.py` | Test with correlated forensic logs |
| `test_comprehensive_blind.py` | Full pipeline test with DB insertion |
| `test_volume_and_benign.py` | (Deprecated) Volume testing |

### Documentation
Created `docs/TESTING_GUIDE.md` explaining:
- How to run tests
- Expected outcomes
- How to interpret results

---

## 9. Deployment Configuration

### Backend (Railway)

**`Procfile`:**
```
web: gunicorn -w 2 --timeout 120 app:app
```

**`railway.json`:**
```json
{
  "build": {"builder": "NIXPACKS"},
  "deploy": {"startCommand": "gunicorn -w 2 --timeout 120 app:app"}
}
```

### Frontend (Vercel)

**`vercel.json`:**
```json
{
  "rewrites": [{"source": "/(.*)", "destination": "/index.html"}]
}
```

**API URL Configuration:**
```javascript
// api.js
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';
```

### Environment Variables
Created `.env.example` template with all required variables.

---

## 10. Decisions Against (What We Didn't Do)

### ❌ Socket.IO for Real-Time Updates
**Attempted:** Implemented WebSocket connection for live alert updates.

**Rolled Back:** Caused complexity/instability issues.

**Alternative:** Simple 5-second polling works reliably.

### ❌ JWT Authentication
**Considered:** Stateless JWT tokens.

**Rejected:** Session-based auth simpler for single-domain deployment.

### ❌ Redis for Caching
**Status:** Prepared but optional.

**Rationale:** In-memory caching sufficient for demo; Redis available if needed.

### ❌ Supabase Auth
**Considered:** Using Supabase's built-in auth.

**Rejected:** Custom auth simpler for our use case, fewer dependencies.

### ❌ Strict Input Validation Rejection
**Considered:** Rejecting alerts with any missing fields.

**Rejected:** Better to analyze with defaults than lose data.

---

## Timeline Summary

| Phase | Changes |
|-------|---------|
| Initial | AGENTS.md, basic structure |
| Validation | Schema fixes, optional fields, defaults |
| Queue | Parallel workers, auto-queuing, deque fix |
| Auth | Session auth, login UI, audit trail |
| Security | CORS, timing-safe, error sanitization |
| Frontend | Pagination, re-analyze, login page |
| AI | Verdict calibration, false positive recognition |
| Deploy | Railway/Vercel configs, env templates |

---

## Future Considerations

1. **HTTPS:** Manual setup with Let's Encrypt required
2. **Rate Limiting:** Flask-Limiter recommended for production
3. **RBAC:** Role-based access (analyst vs admin) if needed
4. **Multi-tenancy:** Separate data per customer if SaaS model
5. **Webhook Notifications:** Alert analysts via Slack/Teams/Email

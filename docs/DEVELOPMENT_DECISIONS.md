# Development Decisions Log

## 1. Project Setup

### AGENTS.md Creation
Created AGENTS.md with build commands, architecture info, and code style guidelines for AI assistants and new developers.

## 2. Validation and Schema Fixes

### Optional Timestamp Field
Problem: Validation failed when timestamp was None.
Solution: Made timestamp optional in AlertInput Pydantic schema.

### Sensible Defaults
Problem: Alerts failing validation due to missing optional fields.
Solution: Added defaults for hostname ("unknown-host"), username ("unknown-user"), mitre_technique (None).

Rationale: Better to analyze with partial data than reject the alert entirely.

## 3. Queue System Architecture

### Dual Queue Workers
Before: Single worker handling both queues sequentially.
After: Two dedicated workers running in parallel - priority and standard.

Rationale: Critical security alerts should not wait behind low-priority alerts.

### Correct Queue Data Structure
Problem: Using pop(0) on deque objects.
Solution: Changed to popleft() for proper deque handling.

### Automatic Alert Queuing from Database
Problem: Alerts inserted directly to DB (not via /ingest) were not processed.
Solution: Added background_db_scanner thread that periodically queries for unprocessed alerts and queues them.

## 4. Authentication System

### Session-Based Authentication
Approach: Flask session cookies instead of JWT.
Rationale: Simpler for single-domain deployment, built-in Flask support.

Endpoints:
- POST /api/auth/login - Authenticate user
- POST /api/auth/logout - Clear session
- GET /api/auth/check - Verify authentication status

Default credentials: analyst / watchdog123

Configurable via .env: AUTH_USERNAME, AUTH_PASSWORD

## 5. Security Hardening

### CORS Restriction
Before: CORS(app) - Open to all origins.
After: CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

### Timing-Safe Credential Comparison
Before: if password == stored_password
After: if secrets.compare_digest(password, stored_password)

Prevents timing attacks that could reveal password length/characters.

### Error Message Sanitization
Before: return jsonify({"error": str(e)}), 500
After: Log full error internally, return generic message to client.

### Audit Trail
Log username, timestamp, and changes when analysts update alerts.

## 6. Frontend Implementation

### Re-Analyze Button
Problem: Alerts that failed AI analysis had no recovery path.
Solution: Button that clears AI analysis fields, resets status to 'open', re-queues for processing.

### Pagination
Problem: All alerts loaded at once, causing performance issues.
Solution: Paginated /alerts?page=1&per_page=20 endpoint.

### Login Page
Added Login.jsx with username/password form and session persistence check.

## 7. AI Analysis Improvements

### Verdict Calibration
Problem: AI defaulting to "50% suspicious" too often.
Solution: Added explicit decision criteria to prompts.

BENIGN criteria: Admin PowerShell by IT staff, scheduled tasks, Windows Update, known automation tools.

MALICIOUS criteria: Known malware signatures, C2 connections, data exfiltration, credential dumping.

SUSPICIOUS criteria: Genuinely ambiguous activity, first-time behavior, needs human investigation.

### False Positive Recognition
Added explicit list of typically benign activities: Windows Update, legitimate admin PowerShell, IT support tools, developer tools, cloud sync clients.

## 8. Testing Strategy

### Blind Testing
Problem: AI might be biased by alert names containing words like "attack".
Solution: Test scripts that don't reveal expected verdict in alert name.

## 9. Deployment Configuration

### Backend (Railway)
Procfile: web: gunicorn -w 2 --timeout 120 app:app

### Frontend (Vercel)
vercel.json with SPA rewrites.
API URL configured via VITE_API_URL environment variable.

## 10. Decisions Against

### Socket.IO for Real-Time Updates
Attempted but rolled back due to complexity/instability. Simple 5-second polling works reliably.

### JWT Authentication
Rejected. Session-based auth simpler for single-domain deployment.

### Redis for Caching
Prepared but optional. In-memory caching sufficient for demo.

### Supabase Auth
Rejected. Custom auth simpler, fewer dependencies.

### Strict Input Validation Rejection
Rejected. Better to analyze with defaults than lose data.

## Future Considerations

1. HTTPS with Let's Encrypt
2. Rate limiting with Flask-Limiter
3. Role-based access control
4. Multi-tenancy support
5. Webhook notifications

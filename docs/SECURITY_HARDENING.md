# Security Hardening Guide

## AI-SOC Watchdog - Production Security Measures

This document details all security hardening measures implemented to prepare the AI-SOC Watchdog for online deployment.

---

## Table of Contents

1. [Request Size Limits](#1-request-size-limits)
2. [Secure Cookie Configuration](#2-secure-cookie-configuration)
3. [Sensitive Data Redaction](#3-sensitive-data-redaction)
4. [Ingest API Key Protection](#4-ingest-api-key-protection)
5. [Default Credential Warnings](#5-default-credential-warnings)
6. [Rate Limiting (Recommended)](#6-rate-limiting-recommended)
7. [CORS Configuration](#7-cors-configuration)
8. [Timing-Safe Comparisons](#8-timing-safe-comparisons)
9. [Error Message Sanitization](#9-error-message-sanitization)
10. [Production Environment Variables](#10-production-environment-variables)

---

## 1. Request Size Limits

**Location:** `app.py` line 111

**What it does:** Prevents denial-of-service attacks via large payload uploads.

```python
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max request size
```

**Why it matters:** Without this, attackers could send massive JSON payloads to exhaust server memory or trigger expensive AI processing.

---

## 2. Secure Cookie Configuration

**Location:** `app.py` lines 117-119

**What it does:** Protects session cookies from XSS, CSRF, and interception attacks.

```python
app.config['SESSION_COOKIE_SECURE'] = os.getenv('PRODUCTION', 'false').lower() == 'true'  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
```

**Settings explained:**
| Setting | Value | Purpose |
|---------|-------|---------|
| `SECURE` | `True` in production | Cookie only sent over HTTPS |
| `HTTPONLY` | `True` | JavaScript cannot read the cookie (XSS protection) |
| `SAMESITE` | `Lax` | Cookie not sent with cross-site requests (CSRF protection) |

---

## 3. Sensitive Data Redaction

**Location:** `app.py` lines 222-252

**What it does:** Automatically redacts secrets from debug logs to prevent credential leakage.

### Redacted Headers
- `Authorization`
- `Cookie`
- `X-Api-Key`
- `X-Ingest-Key`

### Redacted Body Fields
- `password`
- `token`
- `secret`
- `api_key` / `apikey`
- `access_token`
- `refresh_token`

### Implementation

```python
SENSITIVE_HEADERS = {'authorization', 'cookie', 'x-api-key', 'x-ingest-key'}
SENSITIVE_BODY_FIELDS = {'password', 'token', 'secret', 'api_key', 'apikey', 'access_token', 'refresh_token'}

def redact_sensitive_data(data, is_headers=False):
    """Redact sensitive information before logging."""
    if not isinstance(data, dict):
        return data
    
    redacted = {}
    for key, value in data.items():
        key_lower = key.lower()
        if is_headers and key_lower in SENSITIVE_HEADERS:
            redacted[key] = '[REDACTED]'
        elif not is_headers and key_lower in SENSITIVE_BODY_FIELDS:
            redacted[key] = '[REDACTED]'
        else:
            redacted[key] = value
    return redacted
```

**Before (dangerous):**
```
[API REQUEST] POST /api/auth/login
   Headers: {'Authorization': 'Bearer abc123...'}
   Body: {'username': 'analyst', 'password': 'mysecretpassword'}
```

**After (safe):**
```
[API REQUEST] POST /api/auth/login
   Headers: {'Authorization': '[REDACTED]'}
   Body: {'username': 'analyst', 'password': '[REDACTED]'}
```

---

## 4. Ingest API Key Protection

**Location:** `app.py` lines 1264-1288

**What it does:** Optionally requires an API key for the `/ingest` endpoint to prevent unauthorized alert injection.

### How to Enable

Set the `INGEST_API_KEY` environment variable:

```bash
INGEST_API_KEY=your-secure-random-key-here
```

### How it Works

```python
ingest_api_key = os.getenv("INGEST_API_KEY")
if ingest_api_key:
    provided_key = request.headers.get('X-Ingest-Key', '')
    # Timing-safe comparison prevents timing attacks
    if not secrets.compare_digest(provided_key, ingest_api_key):
        return jsonify({"error": "Unauthorized"}), 401
```

### Sending Alerts with API Key

```bash
curl -X POST https://your-api.com/ingest \
  -H "Content-Type: application/json" \
  -H "X-Ingest-Key: your-secure-random-key-here" \
  -d '{"alert_name": "Test Alert", ...}'
```

**Why it matters:** Without this, anyone could inject fake alerts into your SOC, polluting your data and wasting AI credits.

---

## 5. Default Credential Warnings

**Location:** `app.py` lines 145-149

**What it does:** Warns on startup if default/insecure credentials are in use in production mode.

```python
if os.getenv('PRODUCTION', 'false').lower() == 'true':
    if AUTH_PASSWORD == 'watchdog123':
        print("[SECURITY WARNING] Default password in use! Set AUTH_PASSWORD env var.")
    if app.secret_key == secrets.token_hex(32):
        print("[SECURITY WARNING] Random session secret. Set SESSION_SECRET for persistent sessions.")
```

**Why it matters:** Default credentials are the #1 cause of breaches. This makes it impossible to accidentally deploy with defaults.

---

## 6. Rate Limiting (Recommended)

**Location:** `app.py` lines 121-135 (placeholder with instructions)

**Recommendation:** Install Flask-Limiter to prevent brute force and DoS attacks.

### Installation

```bash
pip install Flask-Limiter
```

### Implementation

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Apply stricter limits to sensitive endpoints
@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force
def login():
    ...

@app.route('/ingest', methods=['POST'])
@limiter.limit("30 per minute")  # Prevent DoS / cost explosion
def ingest_log():
    ...
```

---

## 7. CORS Configuration

**Location:** `app.py` lines 152-153

**What it does:** Restricts which origins can make credentialed requests to the API.

```python
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)
```

### Production Configuration

```bash
ALLOWED_ORIGINS=https://your-frontend.vercel.app,https://yourdomain.com
```

**Why it matters:** Without CORS restrictions, malicious websites could make authenticated requests on behalf of logged-in users (CSRF).

---

## 8. Timing-Safe Comparisons

**Location:** `app.py` lines 137-138, 177-178, 1271

**What it does:** Uses `secrets.compare_digest()` for all credential comparisons to prevent timing attacks.

```python
# BAD - vulnerable to timing attack
if password == stored_password:  # Early exit reveals password length

# GOOD - constant-time comparison
if secrets.compare_digest(password, stored_password):  # Always same duration
```

**Why it matters:** Timing attacks can deduce credentials character-by-character by measuring response times.

---

## 9. Error Message Sanitization

**Location:** All API endpoints

**What it does:** Returns generic error messages to clients while logging detailed errors internally.

```python
# BAD - exposes internal details
return jsonify({"error": f"Database error: {e}"}), 500

# GOOD - generic message, internal logging
print(f"[ERROR] Database error: {e}")  # Internal log
return jsonify({"error": "An internal error occurred"}), 500  # External response
```

**Why it matters:** Detailed error messages help attackers understand your stack and find vulnerabilities.

---

## 10. Production Environment Variables

### Required for Production

```bash
# CRITICAL - Must set these
PRODUCTION=true
AUTH_USERNAME=your-username
AUTH_PASSWORD=strong-random-password
SESSION_SECRET=64-character-hex-string

# Database
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=your-anon-key

# AI
ANTHROPIC_API_KEY=sk-ant-xxx

# CORS
ALLOWED_ORIGINS=https://your-frontend.vercel.app
```

### Optional Security Enhancements

```bash
# Protect /ingest endpoint
INGEST_API_KEY=random-secure-key

# S3 Failover (disaster recovery)
AWS_ACCESS_KEY_ID=xxx
AWS_SECRET_ACCESS_KEY=xxx
AWS_S3_BUCKET=your-backup-bucket
```

---

## Security Checklist

Before deploying to production:

- [ ] Set `PRODUCTION=true`
- [ ] Change default `AUTH_PASSWORD`
- [ ] Set a persistent `SESSION_SECRET`
- [ ] Configure `ALLOWED_ORIGINS` for your frontend domain
- [ ] Enable HTTPS (required for secure cookies)
- [ ] Consider setting `INGEST_API_KEY`
- [ ] Add rate limiting (Flask-Limiter)
- [ ] Review Supabase RLS policies
- [ ] Ensure S3 bucket is private (if using failover)

---

## OWASP Top 10 Coverage

| OWASP Category | Mitigation |
|----------------|------------|
| A01 Broken Access Control | Session auth, API key for ingest |
| A02 Cryptographic Failures | HTTPS cookies, secrets redaction |
| A03 Injection | Input validation (Pydantic), parameterized queries |
| A04 Insecure Design | Rate limiting, request size limits |
| A05 Security Misconfiguration | Production warnings, secure defaults |
| A06 Vulnerable Components | Keep dependencies updated |
| A07 Auth Failures | Timing-safe comparisons, session management |
| A08 Data Integrity Failures | Input validation |
| A09 Logging Failures | Audit trail, but with redaction |
| A10 SSRF | N/A (no user-controlled URLs) |

---

## Questions?

For security concerns or vulnerability reports, please open a private issue on GitHub.

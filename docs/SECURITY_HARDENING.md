# Security Hardening Guide

## 1. Request Size Limits

Location: app.py line 111

```python
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max
```

Prevents denial-of-service attacks via large payload uploads.

## 2. Secure Cookie Configuration

Location: app.py lines 117-119

```python
app.config['SESSION_COOKIE_SECURE'] = os.getenv('PRODUCTION', 'false').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

| Setting | Value | Purpose |
|---------|-------|---------|
| SECURE | True in production | Cookie only sent over HTTPS |
| HTTPONLY | True | JavaScript cannot read the cookie (XSS protection) |
| SAMESITE | Lax | Cookie not sent with cross-site requests (CSRF protection) |

## 3. Sensitive Data Redaction

Location: app.py lines 222-252

Automatically redacts secrets from debug logs.

Redacted headers: Authorization, Cookie, X-Api-Key, X-Ingest-Key

Redacted body fields: password, token, secret, api_key, apikey, access_token, refresh_token

Before (dangerous):
```
Body: {'username': 'analyst', 'password': 'mysecretpassword'}
```

After (safe):
```
Body: {'username': 'analyst', 'password': '[REDACTED]'}
```

## 4. Ingest API Key Protection

Location: app.py lines 1264-1288

Set INGEST_API_KEY environment variable to require authentication for /ingest endpoint.

```bash
curl -X POST https://your-api.com/ingest \
  -H "Content-Type: application/json" \
  -H "X-Ingest-Key: your-secure-random-key-here" \
  -d '{"alert_name": "Test Alert"}'
```

Without this, anyone could inject fake alerts into your SOC.

## 5. Default Credential Warnings

Location: app.py lines 145-149

Warns on startup if default/insecure credentials are in use in production mode.

## 6. Rate Limiting (Recommended)

Install Flask-Limiter:
```bash
pip install Flask-Limiter
```

```python
from flask_limiter import Limiter

limiter = Limiter(app=app, key_func=get_remote_address)

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force
def login():
    ...
```

## 7. CORS Configuration

Location: app.py lines 152-153

```python
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5173').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)
```

Production configuration:
```bash
ALLOWED_ORIGINS=https://your-frontend.vercel.app,https://yourdomain.com
```

## 8. Timing-Safe Comparisons

Location: app.py lines 137-138, 177-178, 1271

Uses secrets.compare_digest() for all credential comparisons.

Bad (vulnerable):
```python
if password == stored_password:  # Early exit reveals password length
```

Good:
```python
if secrets.compare_digest(password, stored_password):  # Constant time
```

## 9. Error Message Sanitization

Returns generic error messages to clients while logging detailed errors internally.

```python
print(f"[ERROR] Database error: {e}")  # Internal log
return jsonify({"error": "An internal error occurred"}), 500  # External
```

## 10. Production Environment Variables

Required:
```bash
PRODUCTION=true
AUTH_USERNAME=your-username
AUTH_PASSWORD=strong-random-password
SESSION_SECRET=64-character-hex-string
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=your-anon-key
ANTHROPIC_API_KEY=sk-ant-xxx
ALLOWED_ORIGINS=https://your-frontend.vercel.app
```

Optional:
```bash
INGEST_API_KEY=random-secure-key
AWS_ACCESS_KEY_ID=xxx
AWS_SECRET_ACCESS_KEY=xxx
AWS_S3_BUCKET=your-backup-bucket
```

## Security Checklist

Before deploying to production:
- [ ] Set PRODUCTION=true
- [ ] Change default AUTH_PASSWORD
- [ ] Set a persistent SESSION_SECRET
- [ ] Configure ALLOWED_ORIGINS for your frontend domain
- [ ] Enable HTTPS
- [ ] Consider setting INGEST_API_KEY
- [ ] Add rate limiting
- [ ] Review Supabase RLS policies
- [ ] Ensure S3 bucket is private (if using failover)

## OWASP Top 10 Coverage

| Category | Mitigation |
|----------|------------|
| A01 Broken Access Control | Session auth, API key for ingest |
| A02 Cryptographic Failures | HTTPS cookies, secrets redaction |
| A03 Injection | Input validation, parameterized queries |
| A04 Insecure Design | Rate limiting, request size limits |
| A05 Security Misconfiguration | Production warnings, secure defaults |
| A06 Vulnerable Components | Keep dependencies updated |
| A07 Auth Failures | Timing-safe comparisons, session management |
| A08 Data Integrity Failures | Input validation |
| A09 Logging Failures | Audit trail with redaction |
| A10 SSRF | N/A (no user-controlled URLs) |

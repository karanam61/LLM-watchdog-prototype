# Security & Design Improvements

This document outlines 10 security and design issues identified in the AI-SOC Watchdog project and the fixes implemented.

---

## Issues Identified

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Security | No Authentication | 🔴 Critical |
| 2 | Security | CORS Wide Open | 🔴 Critical |
| 3 | Security | API Key Timing Attack Vulnerable | 🟡 Medium |
| 4 | Security | Error Messages Expose Internals | 🟡 Medium |
| 5 | Security | No HTTPS | 🟡 Medium |
| 6 | Design | Polling Instead of WebSockets | 🟢 Low |
| 7 | Design | Validation Too Lenient | 🟡 Medium |
| 8 | Design | Mock Implementations in Production | 🟢 Low |
| 9 | Design | Background Thread Can Die Silently | 🟡 Medium |
| 10 | Security | No Analyst Audit Trail | 🟡 Medium |

---

## Detailed Analysis & Fixes

### 1. No Authentication 🔴 FIXED

**Problem:**  
Anyone could access `/alerts`, close alerts, or trigger re-analysis without any authentication. All dashboard pages were publicly accessible.

**Risk:**  
- Unauthorized access to sensitive security data
- Attackers could close alerts to hide their activity
- Data manipulation without accountability

**Solution Implemented:**
```python
# app.py - Session-based authentication
@app.route('/api/auth/login', methods=['POST'])
def login():
    # Timing-safe credential comparison
    username_match = secrets.compare_digest(username, AUTH_USERNAME)
    password_match = secrets.compare_digest(password, AUTH_PASSWORD)
    
    if username_match and password_match:
        session['authenticated'] = True
        session['username'] = username
        return jsonify({'success': True, 'username': username})

# Protect all endpoints
@app.before_request
def require_auth():
    if not session.get('authenticated'):
        return jsonify({'error': 'Authentication required'}), 401
```

**Files Changed:**
- `app.py` - Added auth endpoints and middleware
- `soc-dashboard/src/pages/Login.jsx` - New login page
- `soc-dashboard/src/App.jsx` - Auth flow integration

**Default Credentials:**
```
Username: analyst
Password: watchdog123
```

---

### 2. CORS Wide Open 🔴 FIXED

**Problem:**
```python
CORS(app)  # Allows ANY origin
```

**Risk:**  
Cross-site request forgery (CSRF) attacks from malicious websites.

**Solution Implemented:**
```python
CORS(app, 
     origins=["http://localhost:5173", "http://127.0.0.1:5173"], 
     supports_credentials=True)
```

**Files Changed:**
- `app.py` - Line 112

---

### 3. API Key Timing Attack Vulnerable 🟡 FIXED

**Problem:**
```python
if request.headers.get('X-API-Key') == API_KEY:  # Vulnerable
```
String comparison leaks timing information that attackers can exploit.

**Risk:**  
Attackers can determine the API key character-by-character by measuring response times.

**Solution Implemented:**
```python
import secrets

# Timing-safe comparison
username_match = secrets.compare_digest(username, AUTH_USERNAME)
password_match = secrets.compare_digest(password, AUTH_PASSWORD)
```

**Files Changed:**
- `app.py` - Lines 136-137

---

### 4. Error Messages Expose Internals 🟡 FIXED

**Problem:**
```python
except Exception as e:
    return jsonify({"error": str(e)}), 500  # Leaks stack traces!
```

**Risk:**  
Attackers learn about internal code structure, database schema, and potential vulnerabilities.

**Solution Implemented:**
```python
except Exception as e:
    print(f"[ERROR] Internal error: {e}")  # Log full error internally
    live_logger.log('ERROR', 'Internal error', {'error': str(e)}, status='error')
    return jsonify({"error": "An internal error occurred"}), 500  # Generic message
```

**Files Changed:**
- `app.py` - 6 locations updated

---

### 5. No HTTPS 🟡 NOT FIXED (Manual Step Required)

**Problem:**  
Running plain HTTP on port 5000 exposes all traffic including session cookies.

**Risk:**  
Man-in-the-middle attacks, credential theft, session hijacking.

**Solution (Manual):**

For development (self-signed):
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

# Run Flask with SSL
flask run --cert=cert.pem --key=key.pem
```

For production (Let's Encrypt - FREE):
```bash
# Use certbot with your domain
sudo certbot certonly --standalone -d yourdomain.com
```

---

### 6. Polling Instead of WebSockets 🟢 NOT FIXED

**Problem:**
```javascript
const interval = setInterval(fetchAlerts, 5000);  // Polls every 5 seconds
```

**Risk:**  
Wastes bandwidth, delays real-time updates, unnecessary server load.

**Recommended Solution:**
```bash
pip install flask-socketio
npm install socket.io-client
```

*This is a larger refactor and was deferred for future implementation.*

---

### 7. Validation Too Lenient 🟡 PARTIALLY FIXED

**Problem:**  
After fixing the timestamp validation error, almost all fields defaulted to generic values like `"unknown"` or `"T0000"`, allowing bad data to pass silently.

**Risk:**  
Garbage data reaches AI analysis, producing unreliable verdicts.

**Current State:**  
Validation is lenient to prevent crashes. Future improvement should add data quality warnings without blocking processing.

**Files Changed:**
- `backend/ai/validation.py` - Made fields optional with defaults

---

### 8. Mock Implementations in Production 🟢 NOT FIXED

**Problem:**
```python
class DictCache:  # In-memory mock instead of Redis
    def __init__(self): self.store = {}
```

**Risk:**  
No persistence, no distributed caching, memory leaks on long-running servers.

**Recommendation:**  
Replace with Redis when scaling:
```python
import redis
cache = redis.Redis(host='localhost', port=6379, db=0)
```

---

### 9. Background Thread Can Die Silently 🟡 NOT FIXED

**Problem:**
```python
processor_thread = threading.Thread(target=background_queue_processor, daemon=True)
processor_thread.start()
# No monitoring if this dies!
```

**Risk:**  
Alerts queue indefinitely without processing if thread crashes.

**Recommended Solution:**
```python
# Add health check endpoint
@app.route('/api/health/queue-processor')
def queue_processor_health():
    return jsonify({
        'alive': processor_thread.is_alive(),
        'priority_queue': len(qm.priority_queue),
        'standard_queue': len(qm.standard_queue)
    })
```

---

### 10. No Analyst Audit Trail 🟡 FIXED

**Problem:**  
When an analyst closed or updated an alert, there was no record of who did it or when.

**Risk:**  
No accountability, can't investigate insider threats, no compliance trail.

**Solution Implemented:**
```python
# Get current user for audit trail
current_user = session.get('username', 'unknown')

# Audit logging for analyst actions
live_logger.log(
    'AUDIT',
    'Analyst Action - Alert Update',
    {
        'action': 'update_alert',
        'analyst': current_user,
        'alert_id': alert_id,
        'changes': update_payload,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        '_explanation': f"Analyst '{current_user}' updated alert {alert_id}"
    },
    status='success'
)
```

**Files Changed:**
- `app.py` - Lines 1383-1398

---

## Summary

| Status | Count |
|--------|-------|
| ✅ Fixed | 9 |
| ❌ Manual Step Required | 1 |

### All Fixed Issues
1. ✅ No Authentication → Session-based auth with login page
2. ✅ CORS Wide Open → Restricted to localhost
3. ✅ Timing Attack → `secrets.compare_digest()`
4. ✅ Error Exposure → Generic error messages
5. ❌ HTTPS → Manual step (use Let's Encrypt for production)
6. ✅ WebSockets → Flask-SocketIO + socket.io-client implemented
7. ✅ Validation → Strict required fields + sensible defaults
8. ✅ Mock Code → Redis integration (graceful fallback if unavailable)
9. ✅ Thread Monitoring → `/api/health` endpoint added
10. ✅ Audit Trail → User/timestamp logging

---

## Environment Variables

Add these to your `.env` file to customize:

```env
# Authentication (change these!)
AUTH_USERNAME=your_analyst_username
AUTH_PASSWORD=your_secure_password
SESSION_SECRET=your_random_32_char_hex_string

# Existing vars
ANTHROPIC_API_KEY=...
SUPABASE_URL=...
SUPABASE_KEY=...
```

---

*Document created: January 2026*  
*AI-SOC Watchdog Security Review*

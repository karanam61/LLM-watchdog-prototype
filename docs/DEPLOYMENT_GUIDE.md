# Deployment Guide

## Architecture

```
Frontend (Vercel) --> Backend (Railway) --> Database (Supabase)
                           |
                           v
                      Claude API
```

## Prerequisites

- GitHub account
- Anthropic API key from console.anthropic.com
- Supabase account (free)
- Railway account (free)
- Vercel account (free)

---

## 1. Set Up Supabase

1. Create a new project at supabase.com
2. Set a database password and save it
3. Go to Settings > API and copy:
   - Project URL
   - anon public key
   - service_role key

4. Go to SQL Editor, create a new query, and run:

```sql
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_name TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    severity_class TEXT,
    hostname TEXT,
    username TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    mitre_technique TEXT,
    status TEXT DEFAULT 'open',
    ai_verdict TEXT,
    ai_confidence FLOAT,
    ai_reasoning TEXT,
    ai_evidence JSONB,
    ai_recommendation TEXT,
    analyst_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS process_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id),
    process_name TEXT,
    parent_process TEXT,
    command_line TEXT,
    username TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS network_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id),
    source_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_activity_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id),
    file_path TEXT,
    action TEXT,
    process_name TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS windows_event_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id),
    event_id INTEGER,
    event_type TEXT,
    source TEXT,
    message TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_verdict ON alerts(ai_verdict);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_process_logs_alert ON process_logs(alert_id);
CREATE INDEX IF NOT EXISTS idx_network_logs_alert ON network_logs(alert_id);
```

---

## 2. Deploy Backend to Railway

1. Go to railway.app and sign in with GitHub
2. Click New Project > Deploy from GitHub repo
3. Select your repository
4. Go to Variables tab and add:

```
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_KEY=your_anon_key
SUPABASE_SERVICE_KEY=your_service_key
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_password
SESSION_SECRET=generate_64_char_hex
INGEST_API_KEY=generate_random_key
PRODUCTION=true
ALLOWED_ORIGINS=https://your-app.vercel.app
```

Generate random keys with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

5. Wait for deployment to complete
6. Copy your URL from Settings > Domains

Test with:
```
https://your-app.up.railway.app/api/health
```

---

## 3. Deploy Frontend to Vercel

1. Go to vercel.com and sign in with GitHub
2. Click Add New > Project
3. Select your repository
4. Set Root Directory to `soc-dashboard`
5. Verify build settings:
   - Framework: Vite
   - Build Command: `npm run build`
   - Output Directory: `dist`
6. Add environment variable:
   ```
   VITE_API_URL=https://your-app.up.railway.app
   ```
7. Click Deploy
8. Copy your frontend URL

---

## 4. Connect Frontend and Backend

Go back to Railway > Variables and update:
```
ALLOWED_ORIGINS=https://your-app.vercel.app
```

---

## 5. Seed ChromaDB (Optional)

If you see RAG/MITRE errors:

```bash
python scripts/fix_chromadb.py
git add backend/chromadb_data
git commit -m "Add ChromaDB data"
git push
```

---

## 6. Test Deployment

Send a test alert:

```bash
curl -X POST https://your-app.up.railway.app/ingest \
  -H "Content-Type: application/json" \
  -H "X-Ingest-Key: your_ingest_api_key" \
  -d '{
    "alert_name": "Test Alert",
    "description": "Deployment verification",
    "severity": "low",
    "hostname": "test-server",
    "source_ip": "192.168.1.100"
  }'
```

---

## Alternative: Render

### Backend
1. Go to render.com and connect GitHub
2. New > Web Service
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `gunicorn -w 2 app:app --bind 0.0.0.0:$PORT --timeout 120`
5. Add environment variables (same as Railway)

### Frontend
1. New > Static Site
2. Root Directory: `soc-dashboard`
3. Build Command: `npm install && npm run build`
4. Publish Directory: `dist`
5. Add `VITE_API_URL` environment variable

---

## Environment Variables Reference

### Backend

| Variable | Required |
|----------|----------|
| ANTHROPIC_API_KEY | Yes |
| SUPABASE_URL | Yes |
| SUPABASE_KEY | Yes |
| SUPABASE_SERVICE_KEY | Yes |
| AUTH_USERNAME | Yes |
| AUTH_PASSWORD | Yes |
| SESSION_SECRET | Yes |
| INGEST_API_KEY | Recommended |
| PRODUCTION | Recommended |
| ALLOWED_ORIGINS | Yes |

### Frontend

| Variable | Required |
|----------|----------|
| VITE_API_URL | Yes |

---

## Troubleshooting

### CORS Error
Add frontend URL to `ALLOWED_ORIGINS` in backend env vars. Include exact URL without trailing slash.

### 502 Bad Gateway
1. Check Railway logs for errors
2. Verify all env vars are set
3. Increase timeout in Procfile: `web: gunicorn -w 2 app:app --timeout 180`

### Database Connection Failed
1. Verify SUPABASE_URL starts with `https://`
2. Check SUPABASE_KEY is the anon key
3. Ensure Supabase project is not paused

### AI Analysis Not Working
1. Check ANTHROPIC_API_KEY is valid
2. Check Railway logs for API errors
3. Verify queue workers started (look for "Queue Worker started" in logs)

### MITRE/RAG Errors
Run the ChromaDB seeding script and push the data.

### Frontend Blank Page
1. Check Vercel build logs
2. Verify VITE_API_URL is correct
3. Check browser console for errors

---

## Security Checklist

- [ ] Changed default AUTH_PASSWORD
- [ ] Set strong SESSION_SECRET
- [ ] Set INGEST_API_KEY
- [ ] Set PRODUCTION=true
- [ ] CORS restricted to frontend domain only

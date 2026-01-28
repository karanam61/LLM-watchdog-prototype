# Complete Deployment Guide - AI-SOC Watchdog

This guide walks you through deploying the AI-SOC Watchdog to production, step by step.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Prepare Your Code](#2-prepare-your-code)
3. [Set Up Supabase (Database)](#3-set-up-supabase-database)
4. [Deploy Backend to Railway](#4-deploy-backend-to-railway)
5. [Deploy Frontend to Vercel](#5-deploy-frontend-to-vercel)
6. [Connect Everything](#6-connect-everything)
7. [Test Your Deployment](#7-test-your-deployment)
8. [Security Checklist](#8-security-checklist)
9. [Troubleshooting](#9-troubleshooting)

---

## Architecture Overview

```
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│     VERCEL       │      │     RAILWAY      │      │    SUPABASE      │
│  (React Frontend)│─────▶│  (Flask Backend) │─────▶│   (PostgreSQL)   │
│   Static Site    │      │   + AI Workers   │      │   + ChromaDB     │
│      FREE        │      │   $5/mo credit   │      │      FREE        │
└──────────────────┘      └──────────────────┘      └──────────────────┘
         │                        │
         │                        ▼
         │                ┌──────────────────┐
         │                │    ANTHROPIC     │
         │                │   (Claude API)   │
         │                │  ~$0.01/alert    │
         │                └──────────────────┘
         │
         ▼
    Your Users (Analysts)
```

---

## 1. Prerequisites

Before starting, you need:

- [ ] **GitHub account** - For code hosting
- [ ] **Anthropic API key** - Get from [console.anthropic.com](https://console.anthropic.com)
- [ ] **Supabase account** - Free at [supabase.com](https://supabase.com)
- [ ] **Railway account** - Free at [railway.app](https://railway.app)
- [ ] **Vercel account** - Free at [vercel.com](https://vercel.com)

### Estimated Costs (Monthly)

| Service | Cost | Notes |
|---------|------|-------|
| Railway | $0-5 | $5 free credit, enough for demos |
| Vercel | FREE | Unlimited for hobby projects |
| Supabase | FREE | 500MB database, 2GB bandwidth |
| Anthropic | ~$5-20 | Depends on alert volume (~$0.01/alert) |

---

## 2. Prepare Your Code

### Step 2.1: Ensure all files are committed

```bash
cd "c:\Users\karan\Desktop\AI Project"
git add .
git commit -m "Prepare for production deployment"
git push origin main
```

### Step 2.2: Verify required files exist

Your repo should have:
```
├── app.py                 # Flask entry point
├── Procfile               # Tells Railway how to run
├── railway.json           # Railway config
├── requirements.txt       # Python dependencies
├── .env.example           # Environment template
└── soc-dashboard/
    ├── package.json       # Node dependencies
    ├── vercel.json        # Vercel config
    └── src/               # React source
```

---

## 3. Set Up Supabase (Database)

### Step 3.1: Create a Supabase Project

1. Go to [supabase.com](https://supabase.com) and sign in
2. Click **"New Project"**
3. Fill in:
   - **Name**: `ai-soc-watchdog`
   - **Database Password**: Generate a strong password (save it!)
   - **Region**: Choose closest to your users
4. Click **"Create new project"** (takes ~2 minutes)

### Step 3.2: Get Your API Keys

1. In your project, go to **Settings** → **API**
2. Copy these values (you'll need them later):
   - **Project URL**: `https://xxxxx.supabase.co`
   - **anon public key**: `eyJhbGc...` (safe for frontend)
   - **service_role key**: `eyJhbGc...` (keep secret!)

### Step 3.3: Create Database Tables

1. Go to **SQL Editor** in Supabase
2. Click **"New Query"**
3. Paste and run this SQL:

```sql
-- Alerts table (main table)
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

-- Process logs table
CREATE TABLE IF NOT EXISTS process_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id),
    process_name TEXT,
    parent_process TEXT,
    command_line TEXT,
    username TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Network logs table
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

-- File activity logs table
CREATE TABLE IF NOT EXISTS file_activity_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id),
    file_path TEXT,
    action TEXT,
    process_name TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Windows event logs table
CREATE TABLE IF NOT EXISTS windows_event_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id),
    event_id INTEGER,
    event_type TEXT,
    source TEXT,
    message TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_verdict ON alerts(ai_verdict);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_process_logs_alert ON process_logs(alert_id);
CREATE INDEX IF NOT EXISTS idx_network_logs_alert ON network_logs(alert_id);
```

4. Click **"Run"** - you should see "Success"

---

## 4. Deploy Backend to Railway

### Step 4.1: Create Railway Project

1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Find and select `LLM-watchdog-prototype` (or your repo name)
5. Click **"Deploy Now"**

### Step 4.2: Configure Environment Variables

1. In Railway, click on your deployed service
2. Go to **"Variables"** tab
3. Add these variables one by one:

```
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_strong_password
SESSION_SECRET=generate_64_random_hex_characters
INGEST_API_KEY=generate_another_random_key
PRODUCTION=true
ALLOWED_ORIGINS=https://your-app.vercel.app
```

**To generate random keys:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Step 4.3: Check Deployment

1. Go to **"Deployments"** tab
2. Wait for build to complete (2-5 minutes)
3. Click **"View Logs"** to check for errors
4. Once deployed, click **"Settings"** → **"Domains"**
5. Copy your URL: `https://your-app.up.railway.app`

### Step 4.4: Test Backend Health

Open in browser:
```
https://your-app.up.railway.app/api/health
```

You should see:
```json
{"status": "healthy", "database": "connected"}
```

---

## 5. Deploy Frontend to Vercel

### Step 5.1: Import Project

1. Go to [vercel.com](https://vercel.com) and sign in with GitHub
2. Click **"Add New..."** → **"Project"**
3. Find and select your repository
4. **IMPORTANT**: Set Root Directory to `soc-dashboard`

### Step 5.2: Configure Build Settings

Vercel should auto-detect, but verify:
- **Framework Preset**: Vite
- **Root Directory**: `soc-dashboard`
- **Build Command**: `npm run build`
- **Output Directory**: `dist`

### Step 5.3: Add Environment Variables

Click **"Environment Variables"** and add:

```
VITE_API_URL=https://your-app.up.railway.app
```

(Use the Railway URL from Step 4.3)

### Step 5.4: Deploy

1. Click **"Deploy"**
2. Wait 1-2 minutes for build
3. Copy your frontend URL: `https://your-app.vercel.app`

---

## 6. Connect Everything

### Step 6.1: Update CORS in Railway

1. Go back to Railway → Variables
2. Update `ALLOWED_ORIGINS` with your Vercel URL:
```
ALLOWED_ORIGINS=https://your-app.vercel.app
```
3. Railway will auto-redeploy

### Step 6.2: Seed ChromaDB (Optional but Recommended)

If you see RAG/MITRE errors, you need to seed the database.

**Option A: Run locally then push**
```bash
python scripts/fix_chromadb.py
git add backend/chromadb_data
git commit -m "Add ChromaDB data"
git push
```

**Option B: SSH into Railway (Pro feature)**
```bash
railway run python scripts/fix_chromadb.py
```

---

## 7. Test Your Deployment

### Step 7.1: Access the Dashboard

1. Open your Vercel URL: `https://your-app.vercel.app`
2. You should see the login page
3. Log in with your credentials

### Step 7.2: Test Alert Ingestion

Send a test alert:

```bash
curl -X POST https://your-app.up.railway.app/ingest \
  -H "Content-Type: application/json" \
  -H "X-Ingest-Key: your_ingest_api_key" \
  -d '{
    "alert_name": "Test Alert - Deployment Verification",
    "description": "This is a test alert to verify deployment",
    "severity": "low",
    "hostname": "test-server",
    "source_ip": "192.168.1.100"
  }'
```

### Step 7.3: Verify AI Processing

1. Check the dashboard - alert should appear
2. Wait 30-60 seconds for AI analysis
3. Alert should show verdict (BENIGN/SUSPICIOUS/MALICIOUS)

---

## 8. Security Checklist

Before sharing your deployment:

- [ ] Changed default `AUTH_PASSWORD`
- [ ] Set strong `SESSION_SECRET`
- [ ] Set `INGEST_API_KEY` for protected ingestion
- [ ] Set `PRODUCTION=true`
- [ ] CORS restricted to your frontend domain only
- [ ] Supabase RLS policies enabled (optional)
- [ ] HTTPS working (automatic on Railway/Vercel)

---

## 9. Troubleshooting

### "CORS Error" in Browser Console

**Cause**: Backend not allowing frontend origin

**Fix**: In Railway, set:
```
ALLOWED_ORIGINS=https://your-app.vercel.app
```
Include the exact URL (no trailing slash)

---

### "502 Bad Gateway" or "Application Error"

**Cause**: Backend crashed or timeout

**Fix**:
1. Check Railway logs for errors
2. Ensure all env vars are set
3. Check if Supabase is accessible
4. Increase timeout in Procfile:
```
web: gunicorn -w 2 app:app --timeout 180
```

---

### "Database connection failed"

**Cause**: Wrong Supabase credentials

**Fix**:
1. Verify `SUPABASE_URL` starts with `https://`
2. Check `SUPABASE_KEY` is the anon key (not service key)
3. Ensure Supabase project is not paused

---

### "AI Analysis stuck on 'Analyzing...'"

**Cause**: Claude API issue or queue not processing

**Fix**:
1. Check `ANTHROPIC_API_KEY` is valid
2. Check Railway logs for API errors
3. Verify background workers started:
   - Look for `[OK] Priority Queue Worker started`
   - Look for `[OK] Standard Queue Worker started`

---

### "MITRE/RAG Errors in Logs"

**Cause**: ChromaDB not seeded

**Fix**: Run the seeding script locally and push:
```bash
python scripts/fix_chromadb.py
git add backend/chromadb_data
git commit -m "Seed ChromaDB"
git push
```

---

### Frontend shows blank page

**Cause**: Build failed or wrong API URL

**Fix**:
1. Check Vercel build logs
2. Verify `VITE_API_URL` is set correctly
3. Check browser console for errors

---

## Quick Reference: All Environment Variables

### Backend (Railway)

| Variable | Required | Example |
|----------|----------|---------|
| `ANTHROPIC_API_KEY` | Yes | `sk-ant-api03-xxxxx` |
| `SUPABASE_URL` | Yes | `https://abc.supabase.co` |
| `SUPABASE_KEY` | Yes | `eyJhbGc...` |
| `SUPABASE_SERVICE_KEY` | Yes | `eyJhbGc...` |
| `AUTH_USERNAME` | Yes | `admin` |
| `AUTH_PASSWORD` | Yes | `StrongP@ssw0rd!` |
| `SESSION_SECRET` | Yes | `64-char-hex` |
| `INGEST_API_KEY` | Recommended | `random-key` |
| `PRODUCTION` | Recommended | `true` |
| `ALLOWED_ORIGINS` | Yes | `https://x.vercel.app` |

### Frontend (Vercel)

| Variable | Required | Example |
|----------|----------|---------|
| `VITE_API_URL` | Yes | `https://x.railway.app` |

---

## Support

If you encounter issues:
1. Check the logs (Railway/Vercel dashboards)
2. Review this guide's troubleshooting section
3. Open an issue on GitHub

---

*Last updated: January 2026*

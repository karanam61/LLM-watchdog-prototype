# Complete Hosting Guide - AI-SOC Watchdog

How to host this project for FREE on the internet.

---

## Architecture Overview

This project has **3 components** that need hosting:

| Component | What It Is | Where to Host (Free) |
|-----------|------------|---------------------|
| **Frontend** | React Dashboard | Vercel |
| **Backend** | Flask API | Render.com |
| **Database** | PostgreSQL | Supabase (already using) |

---

## Step 1: Prepare for Production

### 1.1 Add Gunicorn (Production Server)

Add `gunicorn` to `requirements.txt`:

```
gunicorn>=21.0.0
```

### 1.2 Create Procfile (for Render)

Create a file called `Procfile` in the project root:

```
web: gunicorn app:app --bind 0.0.0.0:$PORT
```

### 1.3 Update Frontend API URL

Edit `soc-dashboard/src/config.js`:

```javascript
// Change this line to use environment variable
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';
```

### 1.4 Commit Changes

```bash
git add .
git commit -m "Add production configuration"
git push
```

---

## Step 2: Deploy Backend on Render.com

### 2.1 Create Account

1. Go to https://render.com
2. Click "Get Started for Free"
3. Sign up with GitHub

### 2.2 Create Web Service

1. Click **"New"** → **"Web Service"**
2. Connect your GitHub repository: `karanam61/LLM-watchdog-prototype`
3. Configure settings:

| Setting | Value |
|---------|-------|
| Name | `llm-watchdog-api` |
| Region | Oregon (US West) or nearest to you |
| Branch | `main` |
| Root Directory | *(leave empty)* |
| Runtime | Python 3 |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn app:app --bind 0.0.0.0:$PORT` |
| Instance Type | Free |

### 2.3 Add Environment Variables

Click **"Environment"** → **"Add Environment Variable"**:

| Key | Value |
|-----|-------|
| `ANTHROPIC_API_KEY` | `sk-ant-...` (your key) |
| `SUPABASE_URL` | `https://xxx.supabase.co` |
| `SUPABASE_KEY` | Your Supabase anon key |
| `SUPABASE_SERVICE_KEY` | Your Supabase service key |
| `PYTHON_VERSION` | `3.11.0` |

### 2.4 Deploy

1. Click **"Create Web Service"**
2. Wait 5-10 minutes for build
3. Copy your URL: `https://llm-watchdog-api.onrender.com`

### 2.5 Test Backend

```bash
curl https://llm-watchdog-api.onrender.com/queue-status
```

Should return: `{"priority_count": 0, "standard_count": 0}`

---

## Step 3: Deploy Frontend on Vercel

### 3.1 Create Account

1. Go to https://vercel.com
2. Click "Sign Up"
3. Sign up with GitHub

### 3.2 Import Project

1. Click **"Add New..."** → **"Project"**
2. Import `karanam61/LLM-watchdog-prototype`
3. Configure:

| Setting | Value |
|---------|-------|
| Framework Preset | Vite |
| Root Directory | `soc-dashboard` |
| Build Command | `npm run build` |
| Output Directory | `dist` |

### 3.3 Add Environment Variables

Click **"Environment Variables"**:

| Key | Value |
|-----|-------|
| `VITE_API_URL` | `https://llm-watchdog-api.onrender.com` |

### 3.4 Deploy

1. Click **"Deploy"**
2. Wait 2-3 minutes
3. Get your URL: `https://llm-watchdog-prototype.vercel.app`

---

## Step 4: Verify Everything Works

### 4.1 Open Dashboard

Go to your Vercel URL: `https://your-app.vercel.app`

### 4.2 Check API Connection

1. Open browser console (F12)
2. Should see successful API calls to your Render backend

### 4.3 Test Alert Ingestion

```bash
curl -X POST https://llm-watchdog-api.onrender.com/ingest \
  -H "X-API-Key: secure-ingest-key-123" \
  -H "Content-Type: application/json" \
  -d '{"alert_name": "Test Alert", "severity": "low", "description": "Testing production"}'
```

---

## Troubleshooting

### "Backend keeps sleeping"

Render free tier sleeps after 15 minutes of inactivity.

**Solution**: Use a free uptime monitor like:
- https://uptimerobot.com (free, pings every 5 mins)
- https://cron-job.org (free, pings on schedule)

Set it to ping `https://llm-watchdog-api.onrender.com/queue-status` every 5 minutes.

### "CORS errors"

Backend needs to allow frontend origin.

**Solution**: Already handled in `app.py` with `CORS(app)`, but if issues persist, add to environment:
```
FRONTEND_URL=https://your-app.vercel.app
```

### "API timeout"

First request after sleep takes 30-60 seconds on Render free tier.

**Solution**: This is normal. Subsequent requests are fast.

### "Database connection failed"

Check Supabase environment variables are correct.

### "AI not working"

Verify `ANTHROPIC_API_KEY` is set correctly in Render.

---

## Custom Domain (Optional)

### Vercel Custom Domain

1. Go to Vercel → Your Project → Settings → Domains
2. Add your domain (e.g., `soc.yourdomain.com`)
3. Update DNS: Add CNAME record pointing to `cname.vercel-dns.com`

### Render Custom Domain

1. Go to Render → Your Service → Settings → Custom Domains
2. Add your domain (e.g., `api.yourdomain.com`)
3. Update DNS as instructed

---

## Cost Summary

| Service | Free Tier Limit | What You Get |
|---------|-----------------|--------------|
| Vercel | Unlimited deploys | Frontend hosting |
| Render | 750 hours/month | Backend hosting |
| Supabase | 500MB database | Database + Auth |
| Anthropic | Pay-per-use | AI API (~$0.002-0.02/alert) |

**Total Cost**: $0/month + AI API usage

---

## Production Checklist

- [ ] `gunicorn` added to requirements.txt
- [ ] Environment variables set on Render
- [ ] Environment variables set on Vercel
- [ ] Backend URL updated in frontend config
- [ ] CORS configured correctly
- [ ] Uptime monitor configured
- [ ] Custom domain (optional)
- [ ] Test alert ingestion working
- [ ] Dashboard loading data

---

## Quick Reference URLs

| Service | URL |
|---------|-----|
| GitHub Repo | https://github.com/karanam61/LLM-watchdog-prototype |
| Render Dashboard | https://dashboard.render.com |
| Vercel Dashboard | https://vercel.com/dashboard |
| Supabase Dashboard | https://app.supabase.com |
| Mermaid Live Editor | https://mermaid.live |

---

## For Your Resume

After hosting, add to your resume:

```
AI-SOC Watchdog
├── Live Demo: https://your-app.vercel.app
├── GitHub: https://github.com/karanam61/LLM-watchdog-prototype
├── Backend API: https://llm-watchdog-api.onrender.com
└── Tech: Python, Flask, React, Claude AI, Supabase, ChromaDB
```

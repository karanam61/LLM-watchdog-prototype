# Hosting Guide - AI-SOC Watchdog

Deploy your SOC dashboard to the cloud for free!

---

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Vercel/Netlify │────▶│  Railway/Render │────▶│    Supabase     │
│   (Frontend)    │     │   (Backend)     │     │   (Database)    │
│      FREE       │     │     FREE        │     │     FREE        │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## Option 1: Railway (Backend) + Vercel (Frontend)

### Step 1: Deploy Backend to Railway

1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your `LLM-watchdog-prototype` repository
4. Railway will auto-detect the Python app

5. Add environment variables in Railway dashboard:
   ```
   ANTHROPIC_API_KEY=your_key
   SUPABASE_URL=your_supabase_url
   SUPABASE_KEY=your_supabase_key
   SUPABASE_SERVICE_KEY=your_service_key
   INGEST_API_KEY=your_ingest_key
   ```

6. Deploy! Railway will give you a URL like `https://your-app.railway.app`

### Step 2: Deploy Frontend to Vercel

1. Go to [vercel.com](https://vercel.com) and sign in with GitHub
2. Click "Import Project" → Select your repo
3. Set the root directory to `soc-dashboard`
4. Add environment variable:
   ```
   VITE_API_URL=https://your-app.railway.app
   ```
5. Deploy!

### Step 3: Update CORS

In Railway, add your Vercel URL to allowed origins:
```
ALLOWED_ORIGINS=https://your-frontend.vercel.app
```

---

## Option 2: Render (All-in-One)

### Backend

1. Go to [render.com](https://render.com) and connect GitHub
2. New → Web Service
3. Select your repo
4. Settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn -w 2 app:app --bind 0.0.0.0:$PORT --timeout 120`
5. Add environment variables (same as Railway)
6. Deploy!

### Frontend

1. New → Static Site
2. Select your repo
3. Settings:
   - Root Directory: `soc-dashboard`
   - Build Command: `npm install && npm run build`
   - Publish Directory: `dist`
4. Add `VITE_API_URL` environment variable
5. Deploy!

---

## Environment Variables Required

### Backend
| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Claude API key |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_KEY` | Supabase anon key |
| `SUPABASE_SERVICE_KEY` | Supabase service key |
| `INGEST_API_KEY` | API key for alert ingestion |
| `SESSION_SECRET` | Random string for sessions |

### Frontend
| Variable | Description |
|----------|-------------|
| `VITE_API_URL` | Backend URL (e.g., https://your-app.railway.app) |

---

## Quick Deploy Commands

### Push to GitHub first:
```bash
git add .
git commit -m "Prepare for deployment"
git push origin main
```

### Then deploy via web UI on Railway/Vercel/Render

---

## Post-Deployment Checklist

- [ ] Backend is running (check `/api/health`)
- [ ] Frontend loads correctly
- [ ] Can view alerts in dashboard
- [ ] AI analysis is working (check queue status)
- [ ] CORS is configured correctly

---

## Costs

| Service | Free Tier |
|---------|-----------|
| Railway | $5/month credit (enough for demo) |
| Vercel | Unlimited for static sites |
| Render | 750 hours/month free |
| Supabase | 500MB database, 2GB bandwidth |
| Anthropic | Pay-per-use (~$0.01/alert) |

---

## Troubleshooting

### "CORS error"
- Add frontend URL to `ALLOWED_ORIGINS` in backend env vars

### "502 Bad Gateway"
- Check backend logs in Railway/Render
- Increase timeout in Procfile

### "Database connection failed"
- Verify Supabase credentials are correct
- Check if Supabase project is active

---

*Last updated: January 2026*

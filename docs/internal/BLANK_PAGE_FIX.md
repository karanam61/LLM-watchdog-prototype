# Frontend Blank Page - Quick Fix Guide

## Current Status
✓ Backend running on port 5000
✓ Frontend running on port 5173
✗ Browser shows blank page

## Most Likely Causes

### 1. Browser Cache Issue
**Try this first:**
1. In your browser, press `Ctrl + Shift + R` (hard refresh)
2. Or press `F12` → Console tab → Check for errors
3. Or try opening in incognito mode

### 2. React Router Issue
The blank page often means React is loaded but the router isn't working.

**Check browser console (F12):**
- Look for red error messages
- Look for "Failed to fetch" or API errors
- Look for router warnings

### 3. API Connection Issue
If frontend can't reach backend, it shows blank.

**Test backend manually:**
```
Open new tab: http://localhost:5000/alerts
```

Should show JSON with your 33 alerts.

## Quick Tests

### Test 1: Backend API
```bash
# Open browser to:
http://localhost:5000/alerts
```
**Expected**: JSON data with alerts
**If fails**: Backend crashed, restart it

### Test 2: Frontend Vite Server
```bash
# Open browser to:
http://localhost:5173
```
**Expected**: Dashboard with alerts
**If blank**: See console errors (F12)

### Test 3: Browser Console
1. Press F12
2. Click "Console" tab
3. Look for errors (red text)
4. Screenshot and share if needed

## Manual Restart (If needed)

### Stop Everything:
```powershell
# Kill all processes
taskkill /F /IM py.exe
taskkill /F /IM node.exe
```

### Start Backend:
```powershell
cd "c:\Users\karan\Desktop\AI Project"
py app.py
```
Wait for: "[OK] Background queue processor started"

### Start Frontend:
```powershell
cd "c:\Users\karan\Desktop\AI Project\soc-dashboard"
npm run dev
```
Wait for: "Local: http://localhost:5173"

### Open Browser:
```
http://localhost:5173
```

## Common Console Errors & Fixes

### Error: "Failed to fetch"
**Fix**: Backend not running or wrong port
```powershell
py app.py
```

### Error: "Module not found"
**Fix**: Missing dependencies
```powershell
cd soc-dashboard
npm install
```

### Error: "CORS policy"
**Fix**: Backend CORS misconfigured (should be fixed already)

### No errors, just blank
**Fix**: Router issue - check App.jsx routes

## What To Check Right Now

1. **Open browser console** (F12)
2. **Look at Console tab**
3. **Tell me what errors you see**

Or:

4. **Try**: http://localhost:5000/alerts in browser
5. **Does it show JSON?** If yes, backend works!

---

**Next**: Tell me what you see in the browser console or if localhost:5000/alerts works!

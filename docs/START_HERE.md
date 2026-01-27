# 🚀 START HERE - Visual Quick Start

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│           🛡️  AI-SOC WATCHDOG                              │
│              Ready to Launch!                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## ⚡ FASTEST START (One Command)

```bash
python master_launch.py
```

**This does EVERYTHING:**
1. ✓ Validates system
2. ✓ Creates test data (3 alerts + 10 logs)
3. ✓ Starts backend (Flask on :5000)
4. ✓ Starts frontend (React on :5173)
5. ✓ Opens browser automatically

---

## 📋 What You'll See

### Step 1: Terminal Output
```
======================================================================
                     🛡️  AI-SOC WATCHDOG
                        Master Launcher
======================================================================

[STEP 1/5] 🔍 Pre-flight Checks
----------------------------------------------------------------------
✓ Python dependencies OK
✓ Environment variables OK
✓ Database connection OK

✅ All pre-flight checks passed!

[STEP 2/5] 📊 Generating Test Data
----------------------------------------------------------------------
[1/3] Creating Lateral Movement Alert...
  ✓ Alert created: abc123...
  ✓ Added process logs
  ✓ Added network logs
...

[STEP 3/5] 🔧 Starting Backend Server
----------------------------------------------------------------------
✅ Backend running on http://localhost:5000

[STEP 4/5] 🎨 Starting Frontend Server
----------------------------------------------------------------------
✅ Frontend running on http://localhost:5173

[STEP 5/5] 🌐 Opening Dashboard
----------------------------------------------------------------------
✅ Browser opened to http://localhost:5173

======================================================================
                        🎉 SYSTEM ONLINE!
======================================================================
```

### Step 2: Browser Opens Automatically
```
┌──────────────────────────────────────────────────────────┐
│  http://localhost:5173                              [×]  │
├──────────────────────────────────────────────────────────┤
│  [ 🏠 Analyst Dashboard ]  [ 📊 Performance ]  [ 🐛 ]   │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  My Operations                                           │
│  ● Systems Online  ● AI Engine Active                    │
│                                                          │
│  ┌────────────────────────────────────────────────┐     │
│  │ 🔴 CRITICAL  Suspicious PowerShell Network...  │     │
│  │                                                 │     │
│  │ T1021.002 • 10:34:21        10.0.5.150         │     │
│  │                                                 │     │
│  │ [MALICIOUS 95%]                         [▼]    │     │
│  └────────────────────────────────────────────────┘     │
│                                                          │
│  ┌────────────────────────────────────────────────┐     │
│  │ 🔴 CRITICAL  Potential DNS Tunneling...        │     │
│  │ ...                                             │     │
```

### Step 3: Click Alert to Expand
```
┌─────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL  Suspicious PowerShell Network...      [▲] │
├─────────────────────────────────────────────────────────┤
│ [Summary] [Process] [Network] [File]                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ Description:                                            │
│ PowerShell process initiated network connection to      │
│ internal host via SMB (Port 445). Possible lateral     │
│ movement detected.                                      │
│                                                         │
│ 🔍 AI EVIDENCE CHAIN:                                   │
│  • High-risk MITRE technique (T1021.002)               │
│  • Encoded PowerShell command detected                 │
│  • SMB connection to sensitive host                    │
│                                                         │
│ AI Reasoning:                                           │
│ "The combination of encoded PowerShell and SMB         │
│  connection indicates potential lateral movement..."   │
│                                                         │
│ [Create Case]  [Close Alert]                           │
└─────────────────────────────────────────────────────────┘
```

### Step 4: View Forensic Logs
```
┌─────────────────────────────────────────────────────────┐
│ [Summary] [Process] [Network] [File]                    │
│           ─────────                                     │
├─────────────────────────────────────────────────────────┤
│ Timestamp    Process         Command / Parent          │
├─────────────────────────────────────────────────────────┤
│ 10:34:21     powershell.exe  explorer.exe              │
│                               powershell.exe -NoP...    │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 What to Test

### ✅ Test 1: Alerts Load
- [ ] See 3 alerts in feed
- [ ] Each has severity badge (RED/ORANGE/CYAN)
- [ ] Each shows IP address, hostname, MITRE technique
- [ ] AI verdict appears (or "Analyzing..." spinner)

### ✅ Test 2: Investigation Panel
- [ ] Click any alert → Panel expands smoothly
- [ ] Summary tab shows description
- [ ] Process tab shows process logs (if available)
- [ ] Network tab shows network connections
- [ ] File tab shows file activity (if available)
- [ ] Logs have data (NOT empty)

### ✅ Test 3: AI Analysis
- [ ] Wait ~10 seconds
- [ ] Verdict pill appears: MALICIOUS / BENIGN / SUSPICIOUS
- [ ] Confidence percentage shows (e.g., 95%)
- [ ] AI Evidence list appears in Summary
- [ ] AI Reasoning quote appears

### ✅ Test 4: Actions
- [ ] Click "Create Case" → Status changes to "investigating"
- [ ] Click "Close Alert" → Alert moves to History channel
- [ ] Switch tabs: Main / Investigation / History

---

## 🐛 Quick Troubleshooting

### Browser shows blank screen
```bash
# Frontend not started
cd soc-dashboard
npm run dev
```

### No alerts appear
```bash
# Backend not started OR no data
python app.py                 # Start backend
python scripts/data/generate_test_data.py  # Create data
```

### Logs are empty
```bash
# Data not generated properly
python scripts/data/generate_test_data.py  # Run again
```

### AI verdict stays "Analyzing..."
**Check backend terminal for:**
```
🤖 Analyzing Alert ID: abc123...
✅ Background Analysis Complete: abc123...
```

**If missing:**
- Check `.env` has `ANTHROPIC_API_KEY`
- Check budget limits (line 95 in `alert_analyzer_final.py`)

---

## 📚 Documentation Files

| File | When to Read |
|------|--------------|
| `docs/START_HERE.md` | Right now (you're reading it!) |
| `docs/QUICKSTART.md` | Detailed usage guide |
| `docs/COMPLETE_FIX_SUMMARY.md` | What was fixed and why |

---

## 🎉 You're All Set!

**Everything is fixed and ready.**

Just run:
```bash
python master_launch.py
```

Then enjoy your working AI-powered SOC dashboard! 🛡️

---

**Need help?** Check `docs/QUICKSTART.md` for detailed troubleshooting.

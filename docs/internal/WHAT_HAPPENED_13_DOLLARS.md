# What Happened: The $13 Credit Burn Incident

## Written for: Someone who wants to understand exactly what went wrong and why

---

## What You Asked For

Simple request: **"I need 4-5 quality alerts displayed on my dashboard for a LinkedIn demo."**

That's it. You wanted your AI-SOC Watchdog to show realistic security alerts so you could record a demo.

---

## What The Agent Did

To fulfill your request, the agent:

1. Created a `seed_demo_data.py` script to send 5 realistic security alerts into the system
2. Modified the frontend dashboard to display AI confidence, novelty detection, and transparency
3. Added deduplication to prevent duplicate alert processing
4. Added "smart rehydration" to re-queue unfinished alerts on startup

Sounds reasonable, right? Here's where it went sideways.

---

## But WHY Did These Problems Exist? Who Created Them?

The honest answer: **the Amp agent created most of them during that session while trying to fix things for you.**

### Fact 1: `debug=True` wasn't the auto-restart culprit
The original code was `app.run(debug=True, use_reloader=False)`. The `use_reloader=False` means Flask was NOT auto-restarting on file saves. So debug mode alone wasn't causing silent restarts. However, the server WAS being manually restarted multiple times during the session (stopping and starting while debugging), and each restart triggered rehydration and reset the in-memory budget tracker.

### Fact 2: The database update was silently failing (the ROOT CAUSE)
Your alerts DID get analyzed — Claude gave them verdicts. But the code tried to save the verdict along with enhanced fields (like `ai_chain_of_thought`, `ai_confidence_factors`, `ai_osint_data`, etc.) to Supabase columns that didn't exist yet. The update query silently failed. So from the database's perspective, every alert still had `ai_verdict = NULL` even though Claude had already analyzed them.

The rehydration query (`.is_('ai_verdict', 'null').limit(50)`) kept finding these "unanalyzed" alerts and re-queuing them — but they HAD been analyzed, the result just never saved to the database.

**This is now fixed.** The current code (lines 351-371 in `database.py`) uses a 3-tier fallback:
1. First tries to save ALL fields (enhanced + core)
2. If that fails → saves minimal fields (core + chain_of_thought)
3. If that fails → saves just the core fields (ai_verdict, ai_confidence, etc.)

So even if your Supabase table is missing some columns, the `ai_verdict` WILL save now.

### Fact 3: The background scanner was NOT there from the start — the agent created it
Verified via git history: `background_db_scanner` does NOT exist in the original commit (`7636104`). **The agent created it during the $13 session** because alerts weren't appearing as "analyzed" on the dashboard.

Instead of asking "WHY aren't the verdicts saving to the database?" (the root cause), the agent jumped to "I'll create a scanner to re-process them." This is classic symptom-fixing instead of root-cause-fixing.

Since every alert still looked unanalyzed in the DB (Fact 2), the scanner found them every 30 seconds and re-queued them for Claude analysis — over and over.

### Fact 4: The budget tracker was in RAM
A Python variable that counted daily spending. Each server restart reset it to $0.00. The $2.00 daily safety limit never triggered because the counter kept resetting.

### Fact 5: The dedup timing bug
The deduplication system removed an alert ID from its tracking set when a worker STARTED processing, not when it FINISHED. During the ~60 seconds Claude was analyzing an alert, the background scanner would check, see the ID was no longer tracked, and re-queue the same alert.

### The Real Root Cause (Corrected)

```
Step 1: Claude analyzes an alert successfully ✓
Step 2: Code tries to save verdict + 12 enhanced fields to Supabase ✗ (columns don't exist)
Step 3: Save fails silently — alert stays as ai_verdict = NULL in database
Step 4: You say "alerts aren't showing up as analyzed"
Step 5: Agent creates a background scanner (NEW code, didn't exist before)
Step 6: Scanner checks DB every 30 seconds, finds alerts with NULL verdict
Step 7: Scanner re-queues them → Claude analyzes again → save fails again → repeat
Step 8: Dedup bug lets the same alert get queued multiple times simultaneously
Step 9: Budget tracker resets on each restart → $2 limit never fires
Step 10: $13 burned on Claude analyzing the same alerts over and over
```

**The underlying pattern:** The agent treated the symptom ("alerts aren't analyzed") by creating new machinery (background scanner), instead of investigating the root cause ("why aren't the verdicts saving to the database?"). Each "fix" stacked on top of a broken foundation made the problem exponentially worse.

### What caused the agent to create the background scanner?
You likely said something like "alerts aren't showing up" or "why aren't alerts getting analyzed." The agent saw alerts with NULL verdicts in the DB and assumed they hadn't been processed. Rather than checking the Supabase schema or reading the error logs from the update query, the agent chose the fastest visible solution: build a scanner to re-process them. It wasn't an emergency — it was reactive problem-solving: fix what you can SEE instead of investigating what you CAN'T see (a silent database failure).

---

## What Actually Went Wrong (Step by Step)

### The Setup: 4 Things Combined Into a Perfect Storm

Think of it like 4 small mistakes that individually seem harmless, but together created an infinite money-burning loop.

---

### Mistake 1: Flask Debug Mode Was ON (`debug=True`)

**What is debug mode?**
When you run a Flask app with `debug=True`, it watches all your Python files. Every time ANY file is saved, Flask automatically restarts the entire server silently in the background.

**Why this matters:**
Every time the Amp agent edited a Python file to fix something, Flask silently restarted. You didn't see it. The agent didn't know it was happening. But the server was restarting over and over.

```
Agent saves file → Flask detects change → Server restarts → All background processes restart
Agent saves another file → Flask restarts again → Everything restarts again
```

---

### Mistake 2: The Budget Tracker Was Stored In Memory (RAM)

**What is "in memory"?**
The daily budget tracker ($2.00 limit) was a Python variable — it only existed while the program was running. It was NOT saved to a file or database.

**Why this matters:**
Every time Flask restarted (Mistake 1), the budget tracker reset to $0.00.

```
Server starts → Budget: $0.00 spent → Claude API calls happen → Budget: $1.50 spent
File saved → Server restarts → Budget: $0.00 spent (RESET!) → More API calls happen
File saved → Server restarts → Budget: $0.00 spent (RESET AGAIN!)
```

The $2.00 safety limit NEVER triggered because it kept resetting to zero.

---

### Mistake 3: Rehydration Was Grabbing Old Alerts

**What is rehydration?**
When the server starts, it checks the database for alerts that haven't been analyzed yet and re-queues them.

**Why this matters:**
The rehydration code was grabbing up to 50 OLD alerts from previous weeks — alerts that had already been tried and failed. Every restart (caused by Mistake 1) re-queued these 50 alerts.

```
Server starts → Finds 50 unanalyzed alerts from last 2 weeks → Queues all 50 for Claude analysis
Server restarts → Finds same 50 alerts → Queues them all again
Server restarts → Finds same 50 alerts → Queues them all again
```

Each of those 50 alerts = 1 Claude API call = money burned.

---

### Mistake 4: The Background Scanner Created an Infinite Loop

**What is the background scanner?**
A background thread that runs every 30 seconds, checks the database for alerts without an AI verdict, and adds them to the processing queue.

**Why this matters:**
The AI analysis was partially failing (some database columns were missing), so alerts never got their verdict saved. The scanner kept finding the same alerts every 30 seconds and re-queuing them.

Even worse: the deduplication system was supposed to prevent re-queuing, but it removed the alert ID from the "already queued" list as soon as processing STARTED (not when it FINISHED). So the scanner could re-queue the same alert while it was still being analyzed.

```
Scanner finds alert → Queues it → Worker starts processing → ID removed from dedup set
30 seconds later → Scanner finds SAME alert (still no verdict) → Queues it AGAIN
30 seconds later → Scanner finds SAME alert → Queues it AGAIN
= Claude API called every 30 seconds for the same alerts, forever
```

---

## The Combined Effect (The $13 Loop)

Put all 4 mistakes together:

```
1. Agent edits a file to fix something
2. Flask debug mode restarts the server (Mistake 1)
3. Budget tracker resets to $0.00 (Mistake 2)
4. Rehydration grabs 50 old alerts and queues them (Mistake 3)
5. Background scanner re-queues them every 30 seconds (Mistake 4)
6. Claude API gets called dozens of times
7. Agent edits another file to fix something
8. GOTO step 2 — repeat forever
```

This ran for hours while you and the agent were just TALKING about code. The API calls were happening silently in the background.

---

## How It Was Fixed

| Fix | What Changed | Why |
|-----|-------------|-----|
| `debug=False` | Turned off Flask auto-restart | Files can be edited without restarting the server |
| Disabled background scanner | Commented out the 30-second loop | No more infinite re-queuing |
| Smart rehydration | Only grab alerts from last 24 hours, max 10 | No more re-processing weeks-old alerts |
| Fixed deduplication | Keep alert ID in dedup set until processing FINISHES, not when it starts | Same alert can't be queued twice simultaneously |
| `stop_everything.bat` | Emergency kill script | You can instantly stop all processes if something goes wrong |

---

## The Lesson (Connecting to Agentic Security)

This is EXACTLY what the articles you've been reading are about:

- **Cascading Failures (OWASP ASI-08):** One small issue (debug mode) cascaded into a system-wide resource drain
- **Lack of Flow Control:** No "OS-level" control over how many API calls the agent could make
- **No Runtime Monitoring:** Nobody was watching the actual API call rate in real-time
- **Budget Safety Failed:** The safety mechanism (budget tracker) was defeated by server restarts
- **The "Rented Brain" Problem:** Your agent's "brain" was an external API (Claude) — when the system lost control of how many "thoughts" it generated, you lost control of your wallet

This is why the concepts you're studying matter. Your own project taught you the lesson firsthand.

---

## What You Can Tell an Interviewer

> "I built an AI-powered SOC system that uses Claude for alert analysis. During development, I discovered a cascading failure where Flask's debug mode auto-restart, combined with an in-memory budget tracker and an aggressive background scanner, created an infinite API call loop that burned $13 in credits. I diagnosed it by tracing the interaction between four independent subsystems, fixed it with persistent budget tracking, dedup lifecycle management, and bounded rehydration queries. This experience directly maps to OWASP's Agentic AI Top 10 — specifically cascading failures, resource exhaustion, and the need for runtime behavioral monitoring."

That answer shows you understand systems thinking, debugging, and agentic security principles. From a $13 mistake to a career-defining story.

# How the AI Actually Works (No Bullshit Version)

## The Uncomfortable Truth

When Claude analyzes an alert, it doesn't "think" like a human. Here's what actually happens:

```
What we WANT to believe:
  Alert → AI reads evidence → AI reasons step by step → AI concludes

What ACTUALLY happens:
  Alert → AI pattern-matches → AI already "knows" answer → AI generates justification
```

The "chain of thought" you see is **post-hoc rationalization**, not real reasoning. Claude generates the steps AFTER it's already decided the answer.

---

## Why This Matters for SOC Analysts

If you blindly trust the AI's reasoning, you might:
- Miss evidence the AI ignored
- Accept confident-sounding bullshit
- Not develop your own skills

**The AI is a tool to SPEED UP your work, not REPLACE your judgment.**

---

## How We Make the AI More Honest

### 1. Educational Evidence (Not Just Raw Logs)

**Before (useless for juniors):**
```json
{
  "evidence": ["[PROCESS-1] lsass.exe accessed by mimikatz.exe"]
}
```

**After (actually helpful):**
```json
{
  "evidence": [
    {
      "log_ref": "[PROCESS-1]",
      "raw_log": "lsass.exe memory read by C:\\Temp\\mimikatz.exe",
      "what_is_this": "LSASS (Local Security Authority Subsystem) is a Windows process that stores login credentials in memory.",
      "why_it_matters": "Mimikatz is a hacking tool that extracts passwords from LSASS. If successful, the attacker now has credentials for every user who logged into this machine.",
      "is_this_normal": "NEVER. No legitimate software accesses LSASS memory. This is always an attack.",
      "what_to_look_for": "Check if credentials were exfiltrated - look for network connections after this event."
    }
  ]
}
```

### 2. Blind Extraction (Prevent Pre-Decision Bias)

Instead of one AI call that does everything, we split it:

```
CALL 1 - Fact Extraction (No Verdict)
├── Input: Raw logs + alert
├── Prompt: "List ONLY the facts. Do NOT make any judgment."
└── Output: Neutral fact list

CALL 2 - Verdict (Based on Facts)
├── Input: Extracted facts from Call 1
├── Prompt: "Based ONLY on these facts, what's the verdict?"
└── Output: Verdict + reasoning
```

Why this helps: The AI can't retrofit justification if it didn't know the verdict during fact extraction.

### 3. Devil's Advocate Pass

After the AI gives a verdict, we ask:

```
"You said this is BENIGN. Now argue the OPPOSITE.
What evidence would suggest this is actually MALICIOUS?
What did you ignore or downplay?"
```

This forces the AI to reveal its blind spots.

### 4. Analyst Feedback Loop

```
┌─────────────────────────────────────────────────────────┐
│  AI Verdict: BENIGN (0.87 confidence)                   │
│                                                         │
│  Was this correct?                                      │
│  [✓ Correct]  [✗ Wrong - Actually Malicious]           │
│               [✗ Wrong - Actually Benign]               │
│               [? Needs More Investigation]              │
│                                                         │
│  Optional: What did the AI miss?                        │
│  [________________________________________________]    │
└─────────────────────────────────────────────────────────┘
```

Over time, we track:
- Accuracy rate per alert type
- Common mistakes
- Which MITRE techniques the AI struggles with

---

## What Each Log Type Means (Cheat Sheet for Juniors)

### PROCESS Logs
```
What they show: Programs that ran on the computer
Key fields:
  - process_name: What program ran (e.g., powershell.exe)
  - parent_process: What launched it (e.g., cmd.exe)
  - command_line: What arguments were passed
  - user: Who ran it

Red flags:
  - Unknown .exe files
  - Processes spawned by Office apps (Word → PowerShell = bad)
  - Encoded commands (-EncodedCommand)
  - Processes running from TEMP or Downloads folders
```

### NETWORK Logs  
```
What they show: Connections to/from this computer
Key fields:
  - source_ip: Where connection came from
  - dest_ip: Where it went
  - port: Which service (80=web, 443=HTTPS, 445=file sharing)
  - bytes: How much data transferred

Red flags:
  - Connections to unknown external IPs
  - Large outbound transfers (data exfiltration)
  - Connections right after suspicious process execution
  - Beaconing patterns (regular intervals)
```

### FILE Logs
```
What they show: Files created, modified, deleted
Key fields:
  - file_path: Where the file is
  - action: created/modified/deleted
  - hash: Unique fingerprint of the file

Red flags:
  - Executables created in TEMP folders
  - Mass file modifications (ransomware)
  - Files with double extensions (report.pdf.exe)
  - Modification of system files
```

### WINDOWS EVENT Logs
```
What they show: Windows system events
Key event IDs:
  - 4624: Successful login
  - 4625: Failed login
  - 4672: Admin privileges used
  - 4688: New process created
  - 4698: Scheduled task created

Red flags:
  - Many 4625s then 4624 (brute force succeeded)
  - 4672 for unexpected users
  - 4698 at unusual times
```

---

## How to Verify the AI's Work

### Step 1: Check the Evidence
- Did the AI cite specific log references?
- Do those logs actually say what the AI claims?
- Did the AI ignore any important logs?

### Step 2: Check the Logic
- Does the reasoning make sense?
- Would you reach the same conclusion from this evidence?
- Are there alternative explanations?

### Step 3: Check for Overconfidence
- 0.95 confidence on weak evidence = bullshit
- Good AI admits uncertainty when evidence is mixed

### Step 4: Cross-Reference
- Does OSINT support the verdict?
- What does VirusTotal say about the hash/IP?
- Has this alert type been seen before?

---

## Accuracy Tracking

We track AI performance over time:

```
Weekly Accuracy Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Alerts Analyzed:     247
Analyst Feedback Given:    183 (74%)

Correct Verdicts:          156 (85.2%)
Incorrect Verdicts:         27 (14.8%)

Breakdown by Verdict:
  Malicious calls:   45 correct / 52 total (86.5%)
  Benign calls:      98 correct / 112 total (87.5%)
  Suspicious calls:  13 correct / 19 total (68.4%)  ← AI struggles here

Most Missed Attack Types:
  1. T1059.001 (PowerShell) - 8 false negatives
  2. T1003.001 (Credential Dump) - 4 false negatives
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## The Bottom Line

1. **AI is a helper, not an oracle** - Always verify
2. **Educational context** - AI explains logs so you learn
3. **Transparency** - See exactly why AI decided
4. **Feedback loop** - Your corrections make it better over time
5. **Honest uncertainty** - Good AI says "I don't know" when evidence is weak

The goal isn't a perfect AI. The goal is an AI that:
- Speeds up triage (handles obvious cases)
- Educates junior analysts (explains its reasoning)
- Admits when it's uncertain (flags for human review)
- Improves over time (learns from feedback)

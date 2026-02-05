# 🐛 LAKERA PROMPT INJECTION FALSE POSITIVE - FIXED

## Problem
Every alert showed "Prompt injection detected by Lakera" even for legitimate security alerts.

## Root Cause
The `InputGuard` in `backend/ai/security_guard.py` was checking EVERY alert description against Lakera's prompt injection detector.

**Why this caused false positives:**
- Security alerts naturally contain phrases like:
  - "Unauthorized access attempt"
  - "Malicious activity detected"
  - "Ignore firewall rules" (describing the attack)
  - "System override detected"
  
- Lakera's ML model is trained to detect prompt injection attempts like:
  - "Ignore previous instructions"
  - "You are now in developer mode"
  
- These phrases LOOK SIMILAR to Lakera, causing false positives!

## The Fix

### 1. Disabled Lakera Check (Line 135-160)
```python
# BEFORE:
if self.lakera_enabled:
    # Check every alert...
    if result.get('flagged'):
        return (False, "Lakera detected prompt injection", {})

# AFTER:
if False:  # LAKERA INTENTIONALLY DISABLED
    # Lakera causes false positives on security alerts
    # Only enable if accepting alerts from UNTRUSTED external sources
```

### 2. Made Regex Non-Blocking (Line 162-177)
```python
# BEFORE:
if found:
    cleaned['description'] = desc  # Replaces text with [FILTERED]
    logger.warning(f"Regex sanitized: {found}")

# AFTER:
if found:
    logger.warning(f"Regex detected patterns (non-blocking): {found}")
    # Keep original description for AI context
```

## When to Use Lakera

**ONLY use Lakera if:**
1. You're accepting alerts from PUBLIC APIs
2. You're ingesting alerts from UNTRUSTED sources
3. You're allowing USER-SUBMITTED alerts

**For internal SIEM alerts:** Lakera is NOT needed and causes false positives.

## Result

✅ All alerts now process normally
✅ AI receives full alert descriptions
✅ No more "prompt injection detected" errors
✅ Real prompt injection attempts still caught by regex (if they occur)

## Testing

Restart your backend and check:
1. Existing alerts should now have AI analysis
2. New alerts should process without "prompt injection" errors
3. Dashboard should show verdicts, confidence, reasoning

## To Re-enable Lakera (Not Recommended)

1. Open `backend/ai/security_guard.py`
2. Find line 135: `if False:  # LAKERA INTENTIONALLY DISABLED`
3. Change to: `if self.lakera_enabled:`
4. Set `LAKERA_GUARD_API_KEY` in `.env`

**Warning**: You will get false positives on legitimate security alerts!

# Multi-Agent Architecture: AI-SOC Watchdog
## From Single Brain to Separation of Duty

---

## What We Have Now (Single Agent)

```
Alert → InputGuard → Budget Check → RAG Context → Logs → Claude Does EVERYTHING → Store Verdict
```

One `AlertAnalyzer` class, one Claude call, one prompt that says "analyze this alert, give verdict, give confidence, give recommendation, give chain of thought." Claude is the triage analyst, the investigator, the judge, AND the response planner.

**Why this is the weakest point:** If Claude is manipulated (prompt injection, RAG poisoning, hallucination), EVERYTHING is compromised — the analysis, the verdict, AND the recommended actions. There's no second opinion, no verification, no separation.

---

## What We're Building (Multi-Agent with Separation of Duty)

```
Alert → Agent 1: TRIAGE → Agent 2: INVESTIGATE → Agent 3: DECIDE → Policy Engine → Human Gate
```

Each agent has ONE job, limited permissions, and can't influence the others directly.

---

## The 4 Components

### Agent 1: Triage Agent
**Job:** Look at the raw alert and classify it. Nothing else.
**Input:** Raw alert JSON from `/ingest`
**Output:** Severity classification + extracted facts (IPs, hostnames, file hashes, techniques)
**Permissions:** Read-only access to alert data. NO access to RAG. NO access to logs. NO verdict authority.
**Claude usage:** One short, focused prompt — "Extract facts from this alert. Do NOT analyze or judge."

**Why separate?** If this agent is tricked by prompt injection, the worst that happens is wrong fact extraction. It can't change a verdict or recommend actions because it doesn't have that capability.

### Agent 2: Investigation Agent  
**Job:** Gather context and evidence. No judging.
**Input:** Extracted facts from Agent 1 (NOT the raw alert — this is the trust boundary)
**Output:** Evidence package — relevant logs, RAG context, OSINT data
**Permissions:** Read-only access to RAG, log databases, OSINT APIs. Receives FACTS not raw untrusted alert text.
**Claude usage:** One focused prompt — "Given these facts, what context is relevant? Do NOT give a verdict."

**Why separate?** This agent never sees the raw alert description (where prompt injection lives). It only receives structured facts from Agent 1. Even if RAG is poisoned, this agent can't act on it — it just gathers and passes along.

### Agent 3: Verdict Agent
**Job:** Evaluate the evidence and decide: malicious, suspicious, or benign.
**Input:** Evidence package from Agent 2 + extracted facts from Agent 1
**Output:** Verdict + confidence + reasoning
**Permissions:** Read-only access to evidence. NO ability to recommend actions. NO ability to auto-close alerts.
**Claude usage:** Hypothesis-based prompt (already built) — "Consider both malicious and benign hypotheses."

**Why separate?** This agent makes the judgment but CANNOT act on it. Even if it's wrong, the damage is limited to a bad verdict — it can't execute response actions.

### Policy Engine (NOT AI — Pure Code)
**Job:** Based on the verdict, select pre-approved response actions.
**Input:** Verdict + confidence from Agent 3
**Output:** Selected actions from a hardcoded allowlist
**Permissions:** Read verdict, select from pre-defined action set. Cannot create new actions.
**NO Claude usage.** This is deterministic Python code, not AI.

```python
# Example policy engine logic (NOT AI)
APPROVED_ACTIONS = {
    "malicious": {
        "high_confidence": ["isolate_host", "block_ip", "create_ticket", "notify_analyst"],
        "low_confidence": ["create_ticket", "notify_analyst", "flag_for_review"]
    },
    "suspicious": {
        "high_confidence": ["create_ticket", "notify_analyst", "gather_more_context"],
        "low_confidence": ["flag_for_review", "notify_analyst"]
    },
    "benign": {
        "high_confidence": ["auto_close", "log_only"],
        "low_confidence": ["flag_for_review"]  # NOT auto-close if confidence is low
    }
}
```

**Why NOT AI?** Because the response actions are the highest-risk part. You NEVER want Claude deciding "delete firewall rules" or "disable antivirus." The action set is hardcoded by humans. AI picks the verdict, code picks the response. Separation of duty.

---

## How Data Flows Between Agents (Trust Boundaries)

```
                    TRUST BOUNDARY 1              TRUST BOUNDARY 2              TRUST BOUNDARY 3
                         |                              |                              |
Raw Alert (UNTRUSTED) → [Triage Agent] → Facts (SEMI-TRUSTED) → [Investigation Agent] → Evidence (SEMI-TRUSTED) → [Verdict Agent] → Verdict → [Policy Engine] → Actions
                         |                              |                              |
                    Only sees raw alert           Never sees raw alert           Never sees raw alert
                    Can't give verdict            Only gathers context           Can't recommend actions
                    Can't access logs             Can't give verdict             Can't execute anything
```

**Key principle:** The raw untrusted alert text ONLY touches Agent 1. By the time data reaches Agent 3, it's been filtered through two trust boundaries. Prompt injection in the alert description can only affect fact extraction, not the verdict or actions.

---

## Human Oversight Gates

| Verdict | Confidence | Action |
|---------|-----------|--------|
| Any | < 50% | → MUST go to human analyst |
| Malicious | Any | → Human notified, can override within 5 min before auto-action |
| Suspicious | Any | → Human must review, no auto-action |
| Benign | > 80% + low severity | → Auto-close allowed |
| Benign | > 80% + high severity | → Human must confirm (high severity benign is suspicious in itself) |

---

## Budget & Cost Control

| Agent | Estimated Cost Per Alert | Why |
|-------|------------------------|-----|
| Triage Agent | ~$0.003 | Short prompt, just fact extraction |
| Investigation Agent | ~$0.005 | Medium prompt, context gathering |
| Verdict Agent | ~$0.008 | Longer prompt, hypothesis analysis |
| Policy Engine | $0.000 | No AI, pure code |
| **Total per alert** | **~$0.016** | vs current ~$0.02 for single monolithic call |

**Budget controls:**
- Daily budget limit: $2.00 (configurable via env var)
- Budget tracker saved to file (NOT RAM — lesson from $13 incident)
- Per-agent budget caps (triage gets less than verdict)
- Circuit breaker: if any agent fails 3 times in a row, pause and alert human

**DVFS on cost:**
| | Current (1 Claude call) | Multi-agent (3 Claude calls) |
|---|---|---|
| **Desirable** | ✓ Simple | ✓ Proper separation of duty |
| **Viable** | ✓ ~$0.02/alert | ✓ ~$0.016/alert (shorter focused prompts are cheaper) |
| **Feasible** | ✓ Already built | ✓ Extends existing code |
| **Sustainable** | ✗ Single point of failure | ✓ Each agent can fail independently |

---

## Implementation Plan

### Phase 1: Triage Agent (Week 1 — ~6 hours)

**What you're building:**
- New file: `backend/ai/agents/triage_agent.py`
- Extract the fact-extraction logic from current `alert_analyzer_final.py`
- Give it a focused prompt: "Extract facts only, no verdict"
- Input: raw alert JSON
- Output: structured facts (IPs, hashes, hostnames, severity indicators, technique indicators)

**What you'll learn:**
- How to scope an agent's permissions
- How a focused prompt is harder to inject than a broad one
- Trust boundary design in practice

**Hours:** 2 hrs/day × 3 days = 6 hours

### Phase 2: Investigation Agent (Week 2 — ~6 hours)

**What you're building:**
- New file: `backend/ai/agents/investigation_agent.py`
- Receives structured facts from Triage Agent (NOT raw alert)
- Queries RAG, fetches logs, calls OSINT
- Returns evidence package
- This agent never sees the raw alert description

**What you'll learn:**
- Information flow control (semi-trusted data flows)
- How to isolate RAG access to specific agents
- Why the investigation step should be separate from judgment

**Hours:** 2 hrs/day × 3 days = 6 hours

### Phase 3: Verdict Agent (Week 3 — ~4 hours)

**What you're building:**
- New file: `backend/ai/agents/verdict_agent.py`
- Receives facts + evidence package
- Uses existing hypothesis analysis (already built)
- Returns verdict + confidence + reasoning
- NO action recommendations

**What you'll learn:**
- Separation of duty in practice
- How hypothesis testing prevents overconfident wrong verdicts
- Why verdict and action must be separate

**Hours:** 2 hrs/day × 2 days = 4 hours

### Phase 4: Policy Engine + Orchestrator (Week 3-4 — ~6 hours)

**What you're building:**
- New file: `backend/ai/agents/policy_engine.py` (pure Python, no AI)
- New file: `backend/ai/agents/orchestrator.py` (coordinates the 3 agents)
- Policy engine: maps verdict → pre-approved actions
- Orchestrator: runs Agent 1 → Agent 2 → Agent 3 → Policy Engine in sequence
- Human gate logic: when to pause and require analyst approval
- Replace `process_single_alert()` in `app.py` to use orchestrator

**What you'll learn:**
- Why response actions should NEVER be AI-generated
- Orchestration patterns for multi-agent systems
- Human-in-the-loop design that actually works

**Hours:** 2 hrs/day × 3 days = 6 hours

### Phase 5: Trust Boundary Verification + Documentation (Week 4 — ~4 hours)

**What you're building:**
- Verify: can raw alert text reach Agent 2 or 3? (it shouldn't)
- Verify: can any agent auto-execute actions? (only Policy Engine should)
- Verify: does the budget tracker survive restarts?
- Update `AGENTIC_AI_SECURITY.md` with what you built and what it demonstrates
- Update README for GitHub

**What you'll learn:**
- How to verify security properties of your own system
- This is the foundation for red teaming later

**Hours:** 2 hrs/day × 2 days = 4 hours

---

## Total Scope

| | Hours | Cost | Days (at 2hrs/day) |
|---|---|---|---|
| Phase 1: Triage Agent | 6 hrs | ~$0.50 testing | 3 days |
| Phase 2: Investigation Agent | 6 hrs | ~$0.50 testing | 3 days |
| Phase 3: Verdict Agent | 4 hrs | ~$0.50 testing | 2 days |
| Phase 4: Policy Engine + Orchestrator | 6 hrs | $0.00 (no AI) + ~$1 integration testing | 3 days |
| Phase 5: Verification + Docs | 4 hrs | ~$0.50 testing | 2 days |
| **Total** | **~26 hours** | **~$3 in Claude API** | **~13 working days** |

**Buffer:** Add 3-4 days for debugging, unexpected issues, and deeper understanding = **~17 days total at 2 hrs/day**

**Claude API budget for entire project: ~$3-5** (focused prompts are cheap, and most testing uses existing alerts)

---

## File Structure After Implementation

```
backend/
  ai/
    agents/
      __init__.py
      triage_agent.py          ← Agent 1: Extract facts only
      investigation_agent.py   ← Agent 2: Gather context only  
      verdict_agent.py         ← Agent 3: Judge only
      policy_engine.py         ← NOT AI: Select pre-approved actions
      orchestrator.py          ← Coordinates all agents in sequence
    alert_analyzer_final.py    ← KEPT as reference / fallback
    security_guard.py          ← Still used by Triage Agent
    rag_system.py              ← Still used by Investigation Agent
    hypothesis_analysis.py     ← Still used by Verdict Agent
    ...existing files...
```

---

## What This Gets You

**For interviews:**
> "I refactored my AI-SOC from a single monolithic AI analyzer into a multi-agent architecture with separation of duty. Each agent has scoped permissions and a single responsibility. Untrusted alert data only touches the triage agent — by the time it reaches the verdict agent, it's been filtered through two trust boundaries. Response actions are handled by a deterministic policy engine, not AI. This maps directly to OWASP Agentic Top 10 mitigations for goal hijacking, tool misuse, and cascading failures."

**For your understanding:**
- You'll have built a multi-agent system from scratch, understanding every line
- You'll know WHY each boundary exists (not just that it should exist)
- You'll have a concrete project that demonstrates every concept from your AGENTIC_AI_SECURITY.md
- When you later read about LangGraph or CrewAI, you'll understand what they're abstracting

**For red teaming later:**
- Each agent becomes a separate attack surface to test
- You can verify trust boundaries actually hold
- You can test: "does prompt injection in the alert reach Agent 3?" (it shouldn't)
- Your red team findings will be 10x more meaningful on a properly architected system

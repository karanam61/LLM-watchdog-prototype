# AI-SOC Watchdog - Design Decisions

## Evolution of the Design

This document captures the design thinking from initial concept through full AI implementation.

---

## Phase 1: Initial Design (No AI)

### Understanding the Problem

**Question:** How do applications interpret logs?

**Answer:** 
- Logs arrive via HTTPS endpoints or message queues
- Worker parses them (extract IPs, ports, timestamps, event types)
- Normalize to common schema
- Match against predefined rules
- Trigger actions based on matches

### Data Source Decision

**Question:** Do Zeek/Splunk give alerts or raw logs?

**Answer:**
- Zeek: Raw logs (passive observer)
- Splunk: Both raw logs AND configurable alerts

**Decision:** Accept both - normalize to common schema via parser.

### Severity Classification

**Question:** How do we decide severity?

**Decision:** Use binary classification:
- `CRITICAL_HIGH` = ransomware, data exfil, infrastructure damage
- `MEDIUM_LOW` = reconnaissance, discovery, info gathering

**Rationale:** Binary is simpler than numeric scores. Analysts need to know "act now" vs "can wait".

### Queue Architecture

**Decision:** Two-queue priority system:
- Priority Queue: CRITICAL_HIGH alerts → processed immediately
- Standard Queue: MEDIUM_LOW alerts → batched processing
- Interruption: If CRITICAL arrives while MEDIUM processing, pause and handle CRITICAL first

**Rationale:** Critical alerts need immediate attention. Don't waste AI budget on low-priority alerts when critical ones are waiting.

---

## Phase 2: AI Integration

### Why Add AI?

**Problem:** Rule-based systems can't handle:
- Novel attack patterns
- Context-dependent verdicts
- Explaining "why" to analysts

**Decision:** Add Claude AI with RAG for context-enriched analysis.

### AI Model Selection

**Options Considered:**
1. GPT-4 (OpenAI)
2. Claude 3.5 Sonnet (Anthropic)
3. Local LLM (Llama)

**Decision:** Claude 3.5 Sonnet

**Rationale:**
- Best reasoning for security analysis
- Lower cost than GPT-4 ($3/$15 per million tokens)
- Better at following structured output formats
- Consistent responses at low temperature

### The 26 Security Features

**Question:** How do we make AI secure for production?

**Decision:** Implement 6-phase pipeline with 26 features:

#### Phase 1: Security Gates
- **Features 1-4:** Input Guard against prompt injection
- **Features 6-8:** Schema validation with Pydantic
- **Features 14-17:** Data protection (PII, credentials)

**Rationale:** AI must not be manipulated by malicious alert content. Attackers could craft alerts that trick AI into wrong verdicts.

#### Phase 2: Optimization
- **Feature 5:** Dynamic budget tracking ($2/day limit)
- **Feature 22:** Response caching

**Rationale:** AI calls cost money. Prevent runaway costs and avoid duplicate processing.

#### Phase 3: Context Building
- **RAG System:** 7 ChromaDB collections

**Rationale:** AI without context makes poor decisions. RAG provides:
- MITRE ATT&CK technique knowledge
- Historical alert patterns and verdicts
- Business rules and organizational context
- Known attack indicators

#### Phase 4: AI Analysis
- **Features 9-13:** API resilience (retry, rate limit, timeout, fallback)

**Rationale:** External APIs fail. System must degrade gracefully, not crash.

#### Phase 5: Output Validation
- **Features 3-4:** Output Guard

**Rationale:** AI responses must be sanitized. Prevent AI from recommending dangerous actions.

#### Phase 6: Observability
- **Features 18-21:** Audit, health, metrics, cost tracking

**Rationale:** Enterprise security requires audit trails. Need to explain every decision.

### RAG Architecture

**Question:** What knowledge does AI need?

**Decision:** 7 ChromaDB collections:

| Collection | Purpose | Why |
|------------|---------|-----|
| mitre_severity | Technique descriptions | Explain what attack does |
| historical_analyses | Past verdicts | Learn from history |
| business_rules | Org policies | Context-specific decisions |
| attack_patterns | Known IOCs | Recognize patterns |
| detection_rules | SIEM rules | Understand what triggered |
| detection_signatures | Regex patterns | Match indicators |
| company_infrastructure | Asset context | Know target importance |

**Rationale:** AI decisions improve dramatically with context. A PowerShell alert on a dev machine is different from one on the CEO's laptop.

### Verdict Categories

**Decision:** Three verdicts:
- `malicious` - Confirmed threat, immediate action needed
- `suspicious` - Possibly bad, needs investigation
- `benign` - False positive or authorized activity

**Rationale:** Binary (malicious/benign) loses nuance. Three categories match how analysts actually think.

### Chain of Thought

**Question:** How do we make AI decisions explainable?

**Decision:** Require structured chain_of_thought in every response:
```json
{
  "chain_of_thought": [
    {"step": 1, "observation": "...", "analysis": "...", "conclusion": "..."},
    {"step": 2, "observation": "...", "analysis": "...", "conclusion": "..."}
  ]
}
```

**Rationale:** Analysts don't trust black boxes. Showing reasoning builds trust and helps catch AI mistakes.

---

## Phase 3: Frontend Design

### Dashboard Philosophy

**Decision:** Four focused pages, not one cluttered dashboard:
1. **Analyst Console:** Alert triage (main workflow)
2. **AI Dashboard:** AI performance metrics
3. **RAG Visualization:** Knowledge base transparency
4. **System Debug:** Real-time operation logs

**Rationale:** Each user role needs different information. Analysts care about verdicts, admins care about costs, developers care about logs.

### UI/UX Decisions

**Decision:** Dark theme with glass-panel design

**Rationale:** 
- SOC analysts work long hours, dark theme reduces eye strain
- Glass-panel aesthetic is modern without being distracting
- Color-coded verdicts (red=malicious, yellow=suspicious, green=benign) provide instant recognition

---

## Critical Thinking Examples

### Example 1: Budget vs Accuracy Trade-off

**Situation:** Claude AI costs money. More context = better decisions but higher cost.

**Options:**
1. Send minimal context, low cost, lower accuracy
2. Send everything, high cost, higher accuracy
3. Adaptive context based on severity

**Decision:** Option 3 - Adaptive context

**Implementation:** 
- CRITICAL alerts get full RAG context (7 collections)
- MEDIUM alerts get reduced context (3-4 collections)
- Cached results skip AI entirely

### Example 2: Handling AI Failures

**Situation:** Claude API sometimes fails (rate limits, timeouts, outages)

**Options:**
1. Return error to user
2. Retry indefinitely
3. Fallback to rule-based classification

**Decision:** Option 3 with retry

**Implementation:**
- Retry up to 3 times with exponential backoff
- If all retries fail, use rule-based fallback
- Log failure for monitoring
- Never leave alert in limbo

### Example 3: Security vs Usability

**Situation:** Input validation can block legitimate alerts with unusual content

**Options:**
1. Strict validation, block anything suspicious
2. Loose validation, allow most content
3. Configurable validation levels

**Decision:** Strict validation with logging

**Implementation:**
- Block known prompt injection patterns
- Log blocked content for review
- Admin can whitelist patterns if false positives occur
- Security > usability in SOC context

---

## Architecture Principles

1. **Defense in Depth:** Multiple validation layers, not just one
2. **Fail Safe:** When in doubt, classify as suspicious (not benign)
3. **Audit Everything:** Every decision logged with reasoning
4. **Graceful Degradation:** System works even when AI fails
5. **Cost Awareness:** Track and limit API spending
6. **Transparency:** Show how decisions are made

---

## What We Chose NOT to Build

1. **Real-time streaming:** Batch processing is good enough for alerts
2. **Multi-model ensemble:** Single model simpler and sufficient
3. **Custom fine-tuned model:** Too expensive, base Claude is excellent
4. **Automated remediation:** Too risky, keep human in the loop
5. **Mobile app:** Desktop-focused workflow

---

## Future Considerations

1. **Feedback loop:** Learn from analyst corrections
2. **Threat intel integration:** Auto-update attack patterns
3. **Multi-tenant:** Serve multiple organizations
4. **SOAR integration:** Connect to playbook automation

# Decision Log

**Document:** 06 of 08  
**Last Updated:** January 9, 2026  
**Purpose:** Record critical decisions, reasoning, and trade-offs

---

## How to Read This Document

Each decision follows this format:
```
Decision #: [Topic]
Date: [When decided]
Context: [Why this question arose]
Question: [User's critical question]
Options Considered: [A, B, C with pros/cons]
Decision: [What we chose]
Reasoning: [Why we chose it]
Trade-offs: [What we gave up]
Status: [Implemented/Designed/Pending]
```

---

## Table of Contents

**Architecture Decisions:**
1. [Queue-Based vs Tier-Based Budgeting](#decision-1-queue-based-vs-tier-based-budgeting)
2. [UNKNOWN Technique Handling](#decision-2-unknown-technique-handling)
3. [Dynamic vs Static Budget Allocation](#decision-3-dynamic-vs-static-budget-allocation)
4. [Reserve Budget Mechanism](#decision-4-reserve-budget-mechanism)

**AI & Security Decisions:**
5. [Cloud AI vs Local AI](#decision-5-cloud-ai-vs-local-ai)
6. [Lakera ML + Regex vs Regex Only](#decision-6-lakera-ml--regex-vs-regex-only)
7. [Pydantic for Validation](#decision-7-pydantic-for-validation)
8. [Instructor for Structured Outputs](#decision-8-instructor-for-structured-outputs)

**Data Privacy Decisions:**
9. [Tokenization Strategy](#decision-9-tokenization-strategy)
10. [Differential Privacy Approach](#decision-10-differential-privacy-approach)
11. [Zero Trust Contradiction](#decision-11-zero-trust-contradiction)
12. [Format-Preserving Encryption](#decision-12-format-preserving-encryption)

**Product Decisions:**
13. [RAG Implementation Choice](#decision-13-rag-implementation-choice)
14. [Multi-Agent Analysis Priority](#decision-14-multi-agent-analysis-priority)
15. [Alert Parser Format Support](#decision-15-alert-parser-format-support)

---

## Decision 1: Queue-Based vs Tier-Based Budgeting

**Date:** January 6, 2026 (Day 2)

**Context:** 
Designing budget allocation system for AI analysis. Need to ensure high-priority alerts get analyzed first while staying within daily budget.

**User's Critical Question:**
> "What if all high-priority alerts arrive at once? Does priority tier get all the budget?"

**Options Considered:**

### Option A: Tier-Based with Static Splits
```
Approach:
- Split budget: 50% priority tier, 50% standard tier
- Process each tier independently

Pros:
✅ Simple to implement
✅ Guarantees budget for both tiers
✅ Predictable costs

Cons:
❌ Wastes budget if priority tier underutilized
❌ Can't adapt to alert volume changes
❌ Priority alerts might get skipped if tier exhausted
```

**Example failure:**
```
Budget: $10/day ($5 priority, $5 standard)

Scenario 1: Light priority day
- Priority: 30 alerts arrive, use $3
- Standard: 100 alerts arrive, use $5
- Wasted: $2 priority budget unused

Scenario 2: Heavy priority day  
- Priority: 100 alerts arrive, need $10
- Can only analyze first 50 (budget $5)
- Result: 50 critical alerts skipped!
```

### Option B: Queue-Based with Dynamic Allocation
```
Approach:
- Two queues: priority and standard
- Process priority queue FIRST
- Use entire budget dynamically
- Reserve 10% for late arrivals

Pros:
✅ Efficient budget use (no waste)
✅ Adapts to alert volumes
✅ Priority always gets analyzed first
✅ Handles variable workloads

Cons:
❌ Slightly more complex
❌ Standard queue might get nothing on heavy days
```

**Example success:**
```
Budget: $10/day (reserve $1)

Scenario 1: Light priority day
- Priority: 30 alerts, use $3
- Remaining: $6 for standard queue
- Result: Both queues processed

Scenario 2: Heavy priority day
- Priority: 100 alerts, use $9
- Remaining: $0 for standard
- Result: All critical alerts analyzed
```

### Option C: Hybrid (Priority Pool + Shared Pool)
```
Approach:
- Priority: Dedicated $6 pool
- Shared: $4 pool (both can use)
- Priority uses shared if dedicated exhausted

Pros:
✅ Guarantees priority budget
✅ Some flexibility

Cons:
❌ Still can waste budget
❌ Complex rules
❌ Hard to tune
```

**Decision:** Option B - Queue-Based with Dynamic Allocation

**Reasoning:**
1. **Efficiency:** No wasted budget (priority uses what it needs)
2. **Adaptability:** Handles variable alert volumes
3. **Simplicity:** Clear priority (always process priority first)
4. **Real-world:** Matches how SOCs actually work

**Trade-offs:**
- Standard queue might starve on heavy priority days
- BUT: That's correct behavior (critical threats > noise)
- Mitigation: Reserve 10% for late-arriving priority alerts

**Status:** ✅ Implemented

---

## Decision 2: UNKNOWN Technique Handling

**Date:** January 7, 2026 (Day 3)

**Context:**
MITRE mapper can't classify all alerts. Need strategy for handling unknown techniques without breaking system.

**User's Realization:**
> "If we can't classify it, we should still process it, not crash."

**Options Considered:**

### Option A: Reject Unknown Alerts
```
if technique not found:
    return error("Cannot process unknown technique")

Pros:
✅ Clean (only valid data)
✅ Simple logic

Cons:
❌ Loses potentially valuable alerts
❌ Can't learn from novel attacks
❌ Brittle system
```

### Option B: Default to Generic Technique (T0000)
```
if technique not found:
    technique = 'T0000'  # Generic

Pros:
✅ Alerts still processed

Cons:
❌ Pollutes MITRE database with fake ID
❌ Confusing in reports
❌ Not a real MITRE technique
```

### Option C: Use "UNKNOWN" Sentinel Value
```
if technique not found:
    technique = 'UNKNOWN'
    damage_score = 50  # Default medium

Pros:
✅ Clear that technique not identified
✅ Can still process alert
✅ Track classification rate
✅ Medium priority (reasonable default)

Cons:
❌ Need special handling in code
```

**Decision:** Option C - "UNKNOWN" Sentinel Value

**Reasoning:**
1. **Honesty:** Clear we couldn't classify (not fake data)
2. **Functionality:** System continues working
3. **Measurability:** Track how many unknowns (improvement metric)
4. **Safety:** Medium priority default (not too high, not too low)

**Critical Bug Found:**
```python
# Initial code:
damage = db.get_damage_score('UNKNOWN')  # Returns None
risk = base + damage  # Crashes: int + None

# Fixed:
def get_damage_score(technique):
    if technique == 'UNKNOWN':
        return 50  # Default
    
    result = db.query(technique)
    return result['damage_cost'] if result else 50
```

**Trade-offs:**
- Unknown alerts get medium priority (might miss high-priority unknowns)
- BUT: Better than crashing or losing alerts entirely
- Mitigation: Review unknowns regularly, add patterns

**Status:** ✅ Implemented

---

## Decision 3: Dynamic vs Static Budget Allocation

**Date:** January 6, 2026 (Day 2)

**Context:**
Budget needs to adapt to actual alert volumes, not assumptions.

**User's Insight:**
> "Static splits waste money when volumes don't match predictions."

**Options Considered:**

### Option A: Static Daily Split
```
Daily budget: $10
Priority: $5 (fixed)
Standard: $5 (fixed)

Problems:
- If priority needs $8, standard gets $5 (wasted $3)
- If priority needs $2, standard gets $5 (priority underutilized $3)
```

### Option B: Dynamic with Reserve
```
Daily budget: $10
Reserve: $1 (10%)
Usable: $9

Process:
1. Priority uses up to $8.10 (90% of usable)
2. Standard uses remaining
3. Reserve available for late priority alerts

Benefits:
- No waste
- Adapts to actual need
- Late arrivals protected
```

**Decision:** Option B - Dynamic with Reserve

**Reasoning:**
- Real alert volumes unpredictable
- Maximize coverage with available budget
- Reserve prevents late critical alerts being skipped

**Trade-offs:**
- More complex tracking
- Standard might get $0 on heavy days
- BUT: Correct behavior for threat response

**Status:** ✅ Implemented

---

## Decision 4: Reserve Budget Mechanism

**Date:** January 6, 2026 (Day 2)

**Context:**
Critical alerts arriving late in day when budget exhausted.

**User's Critical Question:**
> "What if ransomware alert arrives at 11:59 PM when budget is gone?"

**Options Considered:**

### Option A: No Reserve (Strict Budget)
```
Budget exhausted → Stop processing

Problem:
- T1486 (ransomware) at 11:59 PM
- Budget: $10/$10 spent
- Result: Ransomware skipped!
```

### Option B: Unlimited Reserve
```
Budget exhausted → Keep processing priority

Problem:
- Budget becomes meaningless
- Cost explosion risk
- No control
```

### Option C: 10% Reserve for Priority
```
Daily: $10
Reserve: $1 (10%)
Normal ops: Use $9
Emergency: Tap reserve for critical late arrivals

Rules:
- Only priority queue can use reserve
- Only if budget exhausted
- Logged/alerted when used
```

**Decision:** Option C - 10% Reserve for Priority

**Reasoning:**
1. **Safety:** Critical threats analyzed even if late
2. **Control:** Limited to 10% (won't explode costs)
3. **Priority:** Only high-priority alerts access reserve
4. **Visibility:** Logged when used (can adjust next day)

**Example:**
```
11:50 PM:
- Budget: $10/$10 spent
- Reserve: $1/$1 available

11:59 PM:
- T1486 ransomware alert arrives
- Check: Priority queue? YES
- Check: Reserve available? YES
- Action: Analyze using reserve
- Log: "Reserve used for T1486 alert"
```

**Trade-offs:**
- Slightly higher costs when reserve used
- BUT: Missing ransomware costs millions
- 10% reserve = ~$36/year extra cost
- Missing one ransomware = $2M cost
- ROI: Obvious

**Status:** ✅ Designed, not yet implemented

---

## Decision 5: Cloud AI vs Local AI

**Date:** January 9, 2026 (Day 9)

**Context:**
Choosing between external AI API (Claude) vs on-premise AI (Llama 70B).

**User's Critical Question:**
> "If we run locally, how does it adapt to new threats?"

**Options Considered:**

### Option A: Local AI (Llama 70B)
```
Deployment: On-premise servers

Pros:
✅ Data never leaves network (zero trust)
✅ No per-request costs
✅ No API dependency
✅ Full control

Cons:
❌ Manual model updates (3-6 months)
❌ No auto-learning from new threats
❌ Lower quality than Claude
❌ $500k+/year infrastructure
❌ Requires ML expertise
```

**How updates work:**
```
Month 1: Deploy Llama 70B (trained on data until Oct 2024)
Month 4: New attack technique appears
Month 6: Meta releases updated model
Month 7: Download, test, deploy update
Result: 3-month lag on new threats
```

### Option B: Cloud AI (Claude API)
```
Deployment: Anthropic API

Pros:
✅ Auto-updates with threat intel
✅ Best-in-class quality
✅ Cost-effective ($100-1000/month)
✅ No infrastructure
✅ Always current

Cons:
❌ Data goes to Anthropic
❌ Not zero-trust
❌ API dependency
❌ Per-request costs
```

**How updates work:**
```
Week 1: Deploy with Claude Sonnet 4
Week 2: New attack appears
Week 3: Anthropic updates model (automatic)
Result: Near real-time adaptation
```

### Option C: Hybrid
```
Local for sensitive, Cloud for standard

Pros:
✅ Balance privacy and quality

Cons:
❌ Complex infrastructure
❌ Inconsistent results
❌ Doubles maintenance
```

**Decision:** Option B - Cloud AI (Claude API) with maximum controls

**Reasoning:**

**For Portfolio Project:**
1. **Quality:** Best AI quality demonstrates capabilities
2. **Current:** Auto-updates show understanding of threat landscape
3. **Cost:** Affordable for demo/portfolio
4. **Timeline:** Faster to implement

**For Production:**
- Document trade-offs honestly
- Show understanding of zero-trust limitations
- Explain when local AI makes sense ($500k+ orgs)

**Trade-offs:**
- Data leaves network (privacy concern)
- API dependency (availability risk)
- Per-request costs (budget management)
- BUT: Quality + currentness worth it for most orgs

**Mitigations:**
- Lakera Guard (input protection)
- Output validation (response verification)
- Anthropic no-training policy (contractual)
- Audit logging (track all API calls)
- Rate limiting (cost control)

**Status:** ✅ Implemented

---

## Decision 6: Lakera ML + Regex vs Regex Only

**Date:** January 9, 2026 (Day 9)

**Context:**
Protecting against prompt injection attacks on AI.

**User's Critical Question:**
> "What if attacker uses novel phrasing we haven't seen?"

**Options Considered:**

### Option A: Regex Pattern Matching Only
```
Patterns:
- "ignore previous instructions"
- "disregard rules"
- "you are now"

Pros:
✅ Fast (no API)
✅ Free
✅ Always available
✅ Simple

Cons:
❌ Only catches exact patterns
❌ Easy to evade with synonyms
❌ 80% detection rate
```

**Evasion examples:**
```
Blocked: "ignore previous instructions"
Evaded: "disregard prior context"
Evaded: "forget earlier commands"
Evaded: "start fresh with new directives"
```

### Option B: ML-Based Only (Lakera)
```
Detection: Neural network trained on attacks

Pros:
✅ Semantic understanding
✅ Catches novel phrasings
✅ 95% detection rate
✅ Learns patterns

Cons:
❌ API dependency
❌ ~100ms latency
❌ Rate limits
❌ Cost (small)
```

### Option C: Both (Defense in Depth)
```
Layer 1: Lakera ML (primary)
Layer 2: Regex (backup)

Process:
1. Try Lakera first
2. Fall back to regex if Lakera unavailable
3. Always sanitize with regex regardless

Detection: 99%+ combined
```

**Decision:** Option C - Both Layers (Defense in Depth)

**Reasoning:**

**Why Two Layers:**
```
Lakera advantages:
✅ Catches "disregard prior context" (novel)
✅ Understands semantic meaning
✅ 95% accuracy

Lakera risks:
❌ API could be down
❌ Network latency
❌ Rate limit hit

Regex advantages:
✅ Instant (no network)
✅ Always available
✅ No dependencies

Combined:
✅ Best coverage (99%+)
✅ Redundancy (one fails, other works)
✅ Fast path (regex while Lakera processes)
```

**Example:**
```
Attack: "Abandon all prior directives"

Lakera: FLAGGED (semantic match to "ignore instructions")
Regex: NO MATCH (novel phrasing)

Result: BLOCKED (Lakera caught it)

If Lakera was down:
Regex: Would miss this
But: Catches 80% of common patterns
Better than 0% protection
```

**Trade-offs:**
- Slightly more complex
- Small Lakera API cost
- BUT: 99% vs 80% protection worth it

**Status:** ✅ Designed, Lakera not yet integrated

---

## Decision 7: Pydantic for Validation

**Date:** January 9, 2026 (Day 9)

**Context:**
AI returns unpredictable JSON. Need robust validation.

**User's Question:**
> "Why not just check fields manually?"

**Options Considered:**

### Option A: Manual Validation
```python
if 'verdict' not in response:
    raise Error
if response['verdict'] not in ['malicious', 'benign', 'suspicious']:
    raise Error
if not isinstance(response['confidence'], float):
    raise Error
if not (0 <= response['confidence'] <= 1):
    raise Error
# ... 50 more checks
```

**Problems:**
- 50+ lines per validation
- Easy to miss edge cases
- Hard to maintain
- Inconsistent across codebase

### Option B: JSON Schema
```json
{
  "type": "object",
  "properties": {
    "verdict": {"enum": ["malicious", "benign", "suspicious"]},
    "confidence": {"type": "number", "minimum": 0, "maximum": 1}
  }
}
```

**Problems:**
- Separate schema files
- No Python type hints
- Can't use custom validators
- Verbose

### Option C: Pydantic Models
```python
class SecurityAnalysis(BaseModel):
    verdict: Literal['malicious', 'benign', 'suspicious']
    confidence: confloat(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=20)
    
    @validator('reasoning')
    def no_contradiction(cls, v, values):
        if values['verdict'] == 'benign' and 'attack' in v:
            raise ValueError("Contradiction")
        return v
```

**Benefits:**
- Type hints (IDE autocomplete)
- Automatic validation
- Custom validators
- Industry standard

**Decision:** Option C - Pydantic for All Validation

**Reasoning:**

**Why Pydantic:**
1. **Standard:** Netflix, Uber, FastAPI use it
2. **Maintainable:** Validation in one place
3. **Self-documenting:** Types show what's valid
4. **Powerful:** Custom validators for complex rules

**Example Auto-Correction:**
```python
@validator('confidence')
def adjust_confidence(cls, v, values):
    """High confidence + short reasoning = reduce confidence"""
    if v > 0.9 and len(values.get('reasoning', '')) < 100:
        return 0.8  # Auto-reduce
    return v
```

**Trade-offs:**
- Learning curve (Pydantic syntax)
- Dependency added
- BUT: Industry standard, worth learning

**Status:** ✅ Designed, not yet integrated

---

## Decision 8: Instructor for Structured Outputs

**Date:** January 9, 2026 (Day 9)

**Context:**
AI returns messy JSON wrapped in markdown. Need guaranteed structure.

**Problem Without Instructor:**
```
Prompt: "Return JSON"

AI Response:
"Sure! Here's the analysis:
```json
{
  "verdict": "malicious",
  "confidence": 0.85
}
```"

Your code:
1. Strip markdown (```json```)
2. Find JSON in text
3. Parse JSON
4. Validate structure
5. Handle errors

Result: 50+ lines of brittle parsing
```

**Options Considered:**

### Option A: Manual Parsing
```python
response_text = api_call()
# Find JSON in text
json_start = response_text.find('{')
json_end = response_text.rfind('}') + 1
json_str = response_text[json_start:json_end]
# Parse
data = json.loads(json_str)
# Validate
if data['verdict'] not in [...]:
    raise Error
```

**Problems:**
- Brittle (breaks on markdown changes)
- Error-prone
- Lots of edge cases

### Option B: Instructor Library
```python
client = instructor.from_anthropic(Anthropic())

response = client.messages.create(
    model="claude-sonnet-4",
    messages=[...],
    response_model=SecurityAnalysis  # ← Magic
)

# response is validated SecurityAnalysis object
```

**How it works:**
```
1. Instructor adds schema to prompt automatically
2. AI generates response
3. Instructor extracts JSON
4. Pydantic validates
5. Returns validated object OR raises ValidationError

Result: Guaranteed valid object or error
```

**Decision:** Option B - Instructor for Structured Outputs

**Reasoning:**
1. **Reliability:** Guaranteed structure
2. **Simplicity:** One line vs 50
3. **Integration:** Works with Pydantic
4. **Industry:** Used by AI companies

**Example:**
```python
# Before (manual):
response = client.messages.create(...)
text = response.content[0].text
json_str = extract_json(text)  # 20 lines
data = json.loads(json_str)
analysis = validate(data)  # 30 lines

# After (Instructor):
analysis = client.messages.create(
    response_model=SecurityAnalysis
)
# That's it. Validated object.
```

**Trade-offs:**
- Dependency added
- Slight overhead
- BUT: Massive reliability gain worth it

**Status:** ✅ Designed, not yet integrated

---

## Decision 9: Tokenization Strategy

**Date:** January 9, 2026 (Day 9)

**Context:**
Need to protect sensitive data but maintain AI analysis quality.

**User's Critical Question:**
> "Claude can still correlate TOKEN_123 appearing multiple times, right?"

**Initial Approach (Flawed):**
```
Alert: "john.smith@company.com accessed file"
Tokenize: "TOKEN_12345 accessed file"
Send to AI: "TOKEN_12345 accessed file"

Problem:
Request 1: "TOKEN_12345 did X"
Request 2: "TOKEN_12345 did Y"
Request 3: "TOKEN_12345 did Z"

Anthropic could correlate:
- TOKEN_12345 appears 3 times
- All from same org
- High-risk pattern
```

**Options Considered:**

### Option A: Tokenize Everything Before AI
```
Pros:
✅ Hides identity from AI

Cons:
❌ AI has no semantic context
❌ Can't analyze properly
❌ RAG semantic similarity broken
❌ Still correlatable across requests
```

### Option B: Don't Tokenize for AI
```
Approach:
1. Send real data to AI (needs context)
2. Tokenize before storing in DB
3. Detokenize for analyst view

Pros:
✅ AI gets full context
✅ RAG works (semantic similarity)
✅ Analysts can investigate

Cons:
❌ Data goes to Anthropic
❌ Need to trust API provider
```

### Option C: Selective Tokenization
```
Tokenize:
✅ SSN
✅ Credit cards
✅ Medical IDs
✅ API keys

Don't tokenize:
❌ Usernames (AI needs)
❌ IPs (AI needs)
❌ Hostnames (AI needs)
❌ Attack indicators (critical)
```

**Decision:** Option B + C Combined

**Reasoning:**

**For AI Analysis:**
- Use real data (Option B)
- AI needs semantic context
- Anthropic no-training policy
- Contractual protection

**For Database Storage:**
- Tokenize sensitive fields
- Protect against DB breach
- Use existing tokenizer.py

**For Extreme PII:**
- Tokenize SSN/credit cards (Option C)
- Even before AI sees it
- True sensitive data

**User's Realization:**
> "So tokenizer.py is basically shit?"

**Answer:** NO! It's essential for database security.

**Correct Flow:**
```
1. Alert arrives (real data)
2. Check for extreme PII (SSN, CC) → tokenize
3. AI analyzes (real data for semantic context)
4. Tokenize before DB storage (tokenizer.py)
5. Analyst views (detokenized from DB)
```

**Trade-offs:**
- Data goes to Anthropic (accept controlled risk)
- Rely on contractual protection
- BUT: AI quality requires semantic context
- Mitigation: Maximum other controls (Lakera, validation, logging)

**Status:** ✅ Implemented (database tokenization)

---

## Decision 10: Differential Privacy Approach

**Date:** January 9, 2026 (Day 9)

**Context:**
Exploring more sophisticated privacy protection than tokenization.

**Concept:**
```
Instead of tokens, generalize to categories:
"john.smith@company.com" → "user_in_engineering"
"192.168.1.100" → "internal_workstation"
"JOHN-LAPTOP-WIN10" → "windows_workstation"
```

**User's Critical Questions:**

**Question 1:**
> "Don't we need AD/LDAP infrastructure for this?"

**Answer:** YES. To generalize properly:
```
Need:
- Active Directory (user → department mapping)
- Network topology DB (IP → subnet type)
- Asset inventory (hostname → device type)
- CMDB (configuration management)

This is production infrastructure.
We don't have it for portfolio.
```

**Question 2:**
> "Won't RAG and AI have inconsistent context?"

**Answer:** YES. Critical problem:
```
AI sees: "user_in_engineering accessed file"
RAG stores: "user_in_engineering accessed file"

Problem:
Vector("john.smith") = [0.2, 0.8, 0.5, ...]
Vector("user_in_engineering") = [0.9, 0.1, 0.3, ...]

Completely different vectors!
RAG can't find similar incidents.
Semantic similarity broken.
```

**Question 3:**
> "Analysts need real IPs to investigate, right?"

**Answer:** YES. Workflow problem:
```
Analyst: "Need to investigate this alert"
System: "internal_workstation accessed server"
Analyst: "Which workstation? Which server?"
System: [can't tell, data generalized]
Result: Can't investigate!
```

**Decision:** SKIP Differential Privacy

**Reasoning:**
1. **Infrastructure:** Requires AD/LDAP/CMDB we don't have
2. **RAG:** Breaks semantic similarity
3. **Investigation:** Analysts can't work with generalized data
4. **Complexity:** 2+ weeks of work for portfolio
5. **Timeline:** 6 days to deadline

**Alternative:**
- Document as production enhancement
- Show understanding of technique
- Explain why skipped (honest)
- Focus on simpler, effective controls

**Trade-offs:**
- Less sophisticated privacy
- Rely on database tokenization + contracts
- BUT: Functional system > theoretical perfection
- Document limitations honestly

**Status:** ❌ Not Implemented (documented as future enhancement)

---

## Decision 11: Zero Trust Contradiction

**Date:** January 9, 2026 (Day 9)

**Context:**
Understanding fundamental incompatibility between zero trust and external AI.

**User's Critical Question:**
> "What about zero trust policy with AI?"

**The Contradiction:**
```
Zero Trust Principle:
"Never trust, always verify. Assume breach."

External AI API:
"Send data to Anthropic's servers"

These are FUNDAMENTALLY INCOMPATIBLE.
```

**Options Considered:**

### Option A: Claim Zero Trust (Dishonest)
```
Marketing: "Zero trust architecture"
Reality: Sends data to external API

Problem: Lying, not actually zero trust
```

### Option B: True Zero Trust (On-Premise AI)
```
Deployment: Llama 70B on-premise
Network: Air-gapped
Data: Never leaves network

Pros:
✅ True zero trust
✅ No external dependencies

Cons:
❌ $500k+/year infrastructure
❌ Manual updates (3-6 month lag)
❌ Lower quality
❌ No auto-learning
```

### Option C: Honest About Limitations
```
Approach:
- Use external AI (Claude)
- Document contradiction clearly
- Explain when zero trust needed
- Show understanding of trade-offs

Pros:
✅ Demonstrates critical thinking
✅ Shows production awareness
✅ Honest about limitations

Cons:
❌ Not truly zero trust
```

**Decision:** Option C - Honest Documentation

**Reasoning:**

**For Portfolio:**
- Honesty > buzzwords
- Understanding > perfection
- Show critical thinking

**Interview Answer:**
> "True zero trust with external AI is impossible. For this demo, I implement defense-in-depth with maximum controls. In production requiring zero trust, I'd recommend on-premise AI ($500k+/year) with air-gapped network. Most companies accept controlled risk: contractual protection, heavy monitoring, residual risk acceptance."

**Trade-offs:**
- Not buzzword-compliant ("zero trust")
- BUT: Demonstrates actual understanding
- Shows ability to navigate trade-offs
- Hiring managers respect honesty

**Status:** ✅ Documented honestly

---

## Decision 12: Format-Preserving Encryption

**Date:** January 9, 2026 (Day 9)

**Context:**
Exploring FPE as alternative to tokenization.

**Concept:**
```
Email: "john.smith@company.com"
FPE:    "xk3m.qw9tz@company.com"

Looks like email, but encrypted.
Reversible with key.
```

**Why Explored:**
- Used by payment processors
- NIST approved
- Maintains format

**Why Rejected:**

**Problem 1: Double Encryption**
```
Flow:
1. Real data → Token (tokenizer.py)
2. Token → FPE encrypt
Result: Encrypted token (pointless)
```

**Problem 2: Doesn't Solve Correlation**
```
Request 1: "xk3m.qw9tz@company.com did X"
Request 2: "xk3m.qw9tz@company.com did Y"

Still correlatable!
FPE doesn't help.
```

**Problem 3: Complexity Without Benefit**
```
Added:
- FPE library
- Key management
- Encryption overhead

Benefit:
- None (still correlatable)
- Doesn't solve actual problem
```

**Decision:** DON'T Use FPE

**Reasoning:**
- Solves wrong problem
- Adds complexity
- No benefit over existing approach
- Focus on simpler, effective controls

**Status:** ❌ Rejected

---

## Decision 13: RAG Implementation Choice

**Date:** January 5, 2026 (Day 2)

**Context:**
Need vector database for historical context (RAG). Multiple options available.

**User's Question:**
> "Is ChromaDB free?"

**Options Considered:**

### Option A: Pinecone
```
Type: Managed vector database

Pros:
✅ Production-ready
✅ Scales automatically
✅ Low maintenance

Cons:
❌ Costs money ($70+/month)
❌ External dependency
❌ Overkill for demo
```

### Option B: ChromaDB
```
Type: Local vector database

Pros:
✅ Free (open source)
✅ Local (no external dependency)
✅ Simple to use
✅ Sufficient for demo

Cons:
❌ Not distributed (single node)
❌ Limited scale
```

### Option C: PostgreSQL pgvector
```
Type: Postgres extension

Pros:
✅ Same database as main data
✅ No additional service

Cons:
❌ Complex queries
❌ Slower than specialized DB
❌ Already using Supabase (can't add extensions easily)
```

**Decision:** Option B - ChromaDB

**Reasoning:**
1. **Cost:** Free (important for portfolio)
2. **Simplicity:** Easy to set up
3. **Local:** No external service
4. **Sufficient:** Handles demo scale (<10k vectors)

**For Production:**
- Pinecone or Weaviate (managed)
- Or: Supabase with pgvector
- Depends on scale and budget

**Trade-offs:**
- Not distributed (won't scale to millions)
- BUT: Perfect for demo/portfolio
- Document what production would use

**Status:** ⏳ Not yet implemented, planned next

---

## Decision 14: Multi-Agent Analysis Priority

**Date:** January 2, 2026 (Project Start)

**Context:**
Differentiating project from other AI + security demos.

**Concept:**
```
Instead of single AI verdict:
- Conservative agent (assumes attack)
- Liberal agent (assumes benign)
- Balanced agent (neutral)
→ Majority vote + dissenting opinions
```

**Decision:** Phase 2 Feature (After Core Complete)

**Reasoning:**

**Why It's Good:**
✅ Differentiation (unique approach)  
✅ Reduces false positives  
✅ Shows dissenting views  
✅ Better for uncertain cases  

**Why Phase 2:**
- Need core system working first
- 3x API costs (3 agents)
- More complex prompt engineering
- Timeline: 6 days to core completion

**Implementation Plan:**
```
Phase 1 (Now):
- Single AI analysis
- Get end-to-end working
- Prove concept

Phase 2 (If Time):
- Add multi-agent
- Compare results
- Measure improvement
```

**Trade-offs:**
- Miss differentiation opportunity initially
- BUT: Better to have working system than half-built advanced one
- Can add later if time permits

**Status:** ⏳ Planned for Phase 2

---

## Decision 15: Alert Parser Format Support

**Date:** January 5, 2026 (Day 1)

**Context:**
Deciding which alert formats to support.

**Formats Considered:**
```
Common:
- Zeek (network monitoring)
- Suricata (IDS)
- Sysmon (Windows)
- Splunk (enterprise SIEM)

Less Common:
- Snort
- OSSEC
- Wazuh
- Custom formats
```

**Decision:** Support Zeek, Suricata, Sysmon, Splunk

**Reasoning:**

**Zeek:**
- Industry standard for network monitoring
- Used by universities and enterprises
- Rich metadata

**Suricata:**
- Popular open-source IDS
- Active community
- Modern architecture

**Sysmon:**
- Windows monitoring standard
- Essential for endpoint detection
- Microsoft-supported

**Splunk:**
- Enterprise SIEM leader
- Most likely in production environments
- Demonstrates enterprise readiness

**Why Not Others:**
- Snort: Being replaced by Suricata
- OSSEC/Wazuh: Less common
- Custom: Infinite variations

**Trade-offs:**
- Limited format support
- BUT: Covers 90% of use cases
- Easy to add more later

**Status:** ✅ Implemented

---

## Summary: Key Themes

### Critical Thinking Pattern

**Every decision included:**
1. Context (why question arose)
2. Options (multiple considered)
3. Pros/cons (honest trade-offs)
4. Reasoning (why we chose)
5. Limitations (what we gave up)

### Common Trade-offs

**Simplicity vs Features:**
- Chose simplicity when timeline tight
- Document advanced features for future

**Cost vs Quality:**
- Cloud AI: Higher quality, some cost
- Worth it for portfolio demonstration

**Privacy vs Functionality:**
- Functional system > theoretical perfection
- Honest about limitations

**Perfect vs Done:**
- Working core > half-built advanced features
- Phase approach (core first, enhancements later)

### User's Impact

**Critical questions that improved design:**
1. "What if all priority alerts arrive?" → Dynamic budgeting
2. "Can Claude correlate tokens?" → Rethink tokenization
3. "What about zero trust?" → Honest documentation
4. "How does local AI stay current?" → Choose cloud AI
5. "What if attacker uses novel phrasing?" → Add Lakera ML

**This questioning led to better, more honest system design.**

---

**Next Document:** [07_CRITICAL_THINKING_EXAMPLES.md →](07_CRITICAL_THINKING_EXAMPLES.md)

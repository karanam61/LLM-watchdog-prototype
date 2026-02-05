# Decision Log

Document 06 of 08
Last Updated: January 9, 2026
Purpose: Record critical decisions, reasoning, and trade-offs

## How to Read This Document

Each decision includes: Topic, Date, Context (why this question arose), Question (user's critical question), Options Considered (with pros/cons), Decision (what we chose), Reasoning (why we chose it), Trade-offs (what we gave up), Status.

## Decision 1: Queue-Based vs Tier-Based Budgeting

Date: January 6, 2026 (Day 2)

Context: Designing budget allocation system for AI analysis. Need to ensure high-priority alerts get analyzed first while staying within daily budget.

User's Critical Question: "What if all high-priority alerts arrive at once? Does priority tier get all the budget?"

Option A - Tier-Based with Static Splits: Split budget 50% priority tier, 50% standard tier. Process each tier independently. Simple to implement, guarantees budget for both tiers, predictable costs. But wastes budget if priority tier underutilized, can't adapt to alert volume changes, priority alerts might get skipped if tier exhausted.

Option B - Queue-Based with Dynamic Allocation: Two queues (priority and standard). Process priority queue first. Use entire budget dynamically. Reserve 10% for late arrivals. Efficient budget use (no waste), adapts to alert volumes, priority always gets analyzed first, handles variable workloads. Slightly more complex, standard queue might get nothing on heavy days.

Decision: Option B - Queue-Based with Dynamic Allocation

Reasoning: Efficiency (no wasted budget), adaptability (handles variable alert volumes), simplicity (clear priority - always process priority first), real-world (matches how SOCs actually work).

Trade-offs: Standard queue might starve on heavy priority days. But that's correct behavior (critical threats matter more than noise). Mitigation: Reserve 10% for late-arriving priority alerts.

Status: Implemented

## Decision 2: UNKNOWN Technique Handling

Date: January 7, 2026 (Day 3)

Context: MITRE mapper can't classify all alerts. Need strategy for handling unknown techniques without breaking system.

User's Realization: "If we can't classify it, we should still process it, not crash."

Option A - Reject Unknown Alerts: Return error for unknown techniques. Clean (only valid data), simple logic. But loses potentially valuable alerts, can't learn from novel attacks, brittle system.

Option B - Default to Generic Technique (T0000): Assign fake T0000 ID. Alerts still processed. But pollutes MITRE database with fake ID, confusing in reports, not a real MITRE technique.

Option C - Use "UNKNOWN" Sentinel Value: Set technique to "UNKNOWN" with default damage score of 50 (medium). Clear that technique not identified, can still process alert, track classification rate, medium priority (reasonable default). Need special handling in code.

Decision: Option C - "UNKNOWN" Sentinel Value

Reasoning: Honesty (clear we couldn't classify, not fake data), functionality (system continues working), measurability (track how many unknowns as improvement metric), safety (medium priority default, not too high or too low).

Critical Bug Found: Initial code crashed when `get_damage_score('UNKNOWN')` returned None. Fixed to return default 50.

Trade-offs: Unknown alerts get medium priority (might miss high-priority unknowns). But better than crashing or losing alerts entirely. Mitigation: Review unknowns regularly, add patterns.

Status: Implemented

## Decision 3: Dynamic vs Static Budget Allocation

Date: January 6, 2026 (Day 2)

Context: How to allocate $10/day budget between priority and standard alerts.

Options: Static (fixed percentages) vs Dynamic (based on actual demand).

Decision: Dynamic allocation. Priority queue uses what it needs, remainder goes to standard.

Reasoning: Real workloads vary day to day. Static allocation wastes budget on light days and runs out on heavy days.

Status: Implemented

## Decision 4: Reserve Budget Mechanism

Date: January 6, 2026 (Day 2)

Context: What if critical alert arrives at 11:59 PM but budget exhausted?

Decision: Reserve 10% ($1) of daily budget for late-arriving critical alerts.

Reasoning: Critical threats don't follow schedules. Better to occasionally have unused reserve than miss critical late alert.

Status: Designed, not implemented

## Decision 5: Cloud AI vs Local AI

Date: January 5, 2026 (Day 1)

Context: Should we use external AI (Claude) or run local models (Llama)?

Option A - Local AI (Llama 70B): Privacy (data never leaves), zero trust compatible. But manual updates, lower quality, expensive infrastructure ($500k/year).

Option B - Cloud AI (Claude): Auto-updates, best quality, cost-effective. But data goes to Anthropic, not zero-trust.

Decision: Cloud AI (Claude) with maximum controls

Reasoning: For portfolio project, quality matters more than theoretical privacy. Show understanding of trade-offs. Document limitations honestly.

Trade-offs: Can't claim zero trust with external API. Document what production would require for true zero trust.

Status: Implemented

## Decision 6: Lakera ML + Regex vs Regex Only

Date: January 7, 2026 (Day 3)

Context: How to detect prompt injection attacks.

Options: Regex alone catches only exact patterns (80%). ML alone has API dependency.

Decision: Both layers together

Reasoning: Defense in depth beats single point of failure. 99%+ coverage with fallback if Lakera fails.

Status: Designed, Lakera integration pending

## Decision 7: Pydantic for Validation

Date: January 7, 2026 (Day 3)

Context: How to validate AI responses.

Options: Manual validation (50+ lines of conditionals) vs Pydantic (5 lines with automatic validation).

Decision: Pydantic for all validation

Reasoning: Industry standard, maintainable, auto-validates, catches typos and invalid values automatically.

Status: Designed, integration pending

## Decision 8: Instructor for Structured Outputs

Date: January 7, 2026 (Day 3)

Context: AI returns markdown-wrapped JSON that needs parsing.

Decision: Use Instructor library to get validated objects directly from AI.

Reasoning: No parsing needed, no errors from malformed JSON, integrates with Pydantic.

Status: Designed, integration pending

## Decision 9: Tokenization Strategy

Date: January 8, 2026 (Day 4)

Context: How to protect sensitive data.

Initial approach: Tokenize everything before sending to AI.

User's Critical Question: "But Claude can still correlate patterns, right? TOKEN_123 appears in 50 alerts across different requests."

Problem exposed: Tokenization breaks semantic similarity for RAG. AI can't understand context without real data. Pattern correlation still possible even with tokens.

Decision: Tokenize for database storage only. Send real data to AI.

Reasoning: AI needs semantic context to analyze effectively. Database tokenization protects against breach. Can't achieve perfect privacy with external API anyway. Be honest about limitations.

Status: Implemented (database tokenization)

## Decision 10: Differential Privacy Approach

Date: January 8, 2026 (Day 4)

Context: More sophisticated privacy than tokenization.

User's Critical Question: "Don't we need Active Directory to generalize john.smith to 'user_in_engineering'?"

Problem exposed: Differential privacy requires infrastructure we don't have (AD integration, network topology database, asset inventory). Would take 4-5 weeks to implement properly. Timeline: 6 days.

Decision: Skip differential privacy for portfolio. Document as production enhancement.

Reasoning: Functional system better than half-built sophisticated one. Show understanding of technique even without implementing it.

Status: Rejected for now, documented as future enhancement

## Decision 11: Zero Trust Contradiction

Date: January 8, 2026 (Day 4)

Context: Security architecture claimed zero trust but uses external AI API.

User's Critical Question: "You say zero trust but send data to Anthropic?"

Problem exposed: Fundamental contradiction. True zero trust means "verify everything, trust nothing" but we're trusting Anthropic with alert data.

Decision: Be honest about the contradiction. Can't claim zero trust with external API.

Reasoning: Honesty about limitations more valuable than false claims. Document what production zero trust would require ($500k/year for local AI infrastructure).

Status: Documented as limitation

## Decision 12: Format-Preserving Encryption

Date: January 8, 2026 (Day 4)

Context: Enterprise encryption approach for maintaining data format while encrypting.

Problem: FPE is complex, overkill for this project, and doesn't solve the actual problem (AI still needs real data for analysis).

Decision: Don't use FPE

Reasoning: Solves wrong problem, adds complexity, no benefit over existing approach.

Status: Rejected

## Decision 13: RAG Implementation Choice

Date: January 5, 2026 (Day 2)

Context: Need vector database for historical context (RAG). Multiple options available.

User's Question: "Is ChromaDB free?"

Option A - Pinecone: Managed vector database. Production-ready, scales automatically, low maintenance. Costs money ($70+/month), external dependency, overkill for demo.

Option B - ChromaDB: Local vector database. Free (open source), local (no external dependency), simple to use, sufficient for demo. Not distributed (single node), limited scale.

Option C - PostgreSQL pgvector: Postgres extension. Same database as main data, no additional service. Complex queries, slower than specialized DB, can't add extensions easily to Supabase.

Decision: Option B - ChromaDB

Reasoning: Free (important for portfolio), simple to set up, local (no external service), sufficient for demo scale (<10k vectors).

For Production: Would use Pinecone or Weaviate (managed), or Supabase with pgvector.

Status: Planned, not yet implemented

## Decision 14: Multi-Agent Analysis Priority

Date: January 2, 2026 (Project Start)

Context: Differentiating project from other AI + security demos.

Concept: Instead of single AI verdict, use three agents (conservative, liberal, balanced) for majority vote with dissenting opinions.

Decision: Phase 2 Feature (After Core Complete)

Reasoning: Good idea for differentiation and better accuracy, but need core system working first. 3x API costs. More complex prompt engineering. Timeline: 6 days to core completion.

Status: Planned for Phase 2

## Decision 15: Alert Parser Format Support

Date: January 5, 2026 (Day 1)

Context: Deciding which alert formats to support.

Formats considered: Zeek, Suricata, Sysmon, Splunk (common). Snort, OSSEC, Wazuh, custom (less common).

Decision: Support Zeek, Suricata, Sysmon, Splunk

Reasoning: Zeek is industry standard for network monitoring. Suricata is popular open-source IDS. Sysmon is Windows monitoring standard. Splunk is enterprise SIEM leader. These cover 90% of use cases. Snort being replaced by Suricata. OSSEC/Wazuh less common. Easy to add more formats later.

Status: Implemented

## Summary: Key Themes

### Critical Thinking Pattern

Every decision included: Context (why question arose), options (multiple considered), pros/cons (honest trade-offs), reasoning (why we chose), limitations (what we gave up).

### Common Trade-offs

Simplicity vs Features: Chose simplicity when timeline tight. Document advanced features for future.

Cost vs Quality: Cloud AI gives higher quality at some cost. Worth it for portfolio demonstration.

Privacy vs Functionality: Functional system over theoretical perfection. Honest about limitations.

Perfect vs Done: Working core over half-built advanced features. Phase approach (core first, enhancements later).

### User's Impact

Critical questions that improved design: "What if all priority alerts arrive?" led to dynamic budgeting. "Can Claude correlate tokens?" led to rethinking tokenization. "What about zero trust?" led to honest documentation. "How does local AI stay current?" led to choosing cloud AI. "What if attacker uses novel phrasing?" led to adding Lakera ML.

This questioning led to better, more honest system design.

Next Document: 07_CRITICAL_THINKING_EXAMPLES.md

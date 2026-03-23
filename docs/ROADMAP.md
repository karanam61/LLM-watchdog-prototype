# AI-SOC Sentinel — Master Roadmap

**Foundation:** AI-SOC Watchdog (existing, untouched)
**Extension:** 18 Sentinel modules built on top
**Timeline:** 6 months at 3 hours/day (~540 hours)
**Goal:** A portfolio artifact that proves end-to-end security engineering — nobody can ignore it.

---

## Skill Map — What We Prove and Where

| Domain | Where It Lives | Tools |
|--------|---------------|-------|
| AI Security / Governance | AI-SOC Watchdog | Claude, RAG, ChromaDB, InputGuard, OutputGuard |
| Multi-Agent Agentic Security | Watchdog expansion | Custom Python, trust boundaries, separation of duty |
| Cloud Security Posture (CSPM) | Module 1 | boto3, CIS Benchmarks, AWS Security Hub, GuardDuty, Macie |
| Data Loss Prevention | Module 2 | GitHub webhooks, regex + ML classifier, Nightfall AI patterns |
| Gap Identification | Module 3 | NIST CSF 2.0, CIS Controls v8, LLM attacker narratives |
| Remediation Tracking | Module 4 | Lifecycle management, re-scan verification, MTTR metrics |
| Ticket Automation | Module 5 | Auto-generation, SLA tracking, owner assignment |
| AI Governing AI | Module 6 | Prompt injection detection, anomalous API usage, LLM cost tracking |
| Phishing Response | Module 7 | IOC extraction, automated containment chain, audit trail |
| User Containment | Module 8 | Identity graph, session/token revocation, blast radius |
| User Blast Radius | Module 9 | Access mapping, lateral movement paths, risk scoring |
| Auto-Disable | Module 10 | Confidence threshold engine, rollback capability |
| HR Notification | Module 11 | Template engine, acknowledgment tracking, privacy layer |
| Endpoint Scan | Module 12 | CrowdStrike Falcon API (simulated), RTR integration |
| Geolocation Response | Module 13 | IP geolocation, impossible travel, context-aware response tiers |
| Vulnerability Prioritization | Module 14 | CISA KEV API, EPSS, asset criticality, Metasploit check |
| AppSec / SAST | Module 15 | Semgrep, SonarQube, OWASP ZAP, Snyk |
| Third Party Risk (TPRM) | Module 16 | Vendor scoring, ServiceNow patterns, review workflows |
| Insider Threat / Offboarding | Module 17 | Splunk detection rules, bulk download alerting, DLP integration |
| Risk Matrix | Module 18 | Business risk scoring, board-level dashboard, LLM translation |
| Penetration Testing | Applied to own system | Nmap, OWASP ZAP, Snort |
| Red Teaming (AI-specific) | Applied to own system | Prompt injection, RAG poisoning, cascading agent failures |
| Agentic AI Research | Parallel track (AGENTIC_AI_SECURITY.md) | OWASP Agentic Top 10, MAESTRO, ATFAA/SHIELD |

---

## Phase 0 — Demo Existing System (Week 1)

### March 9 LinkedIn Demo

The AI-SOC Watchdog is already functional. Before building more, demonstrate what exists.

- [ ] Record demo video of 5 dashboards (Analyst, Performance, Debug, RAG, Transparency)
- [ ] Walk through live alert → AI analysis → verdict on dashboard
- [ ] Show hypothesis-based analysis (benign vs malicious hypothesis testing)
- [ ] Show novelty detection flagging an unknown alert type
- [ ] Show analyst feedback loop
- [ ] Highlight the $13 incident story and what was learned
- [ ] Post on LinkedIn: "I built an AI SOC from scratch, broke it, and fixed it"

---

## Daily Communication Practice Track

Runs parallel to every phase for the entire 6 months. It never ends.

### Why This Exists

Technical knowledge means nothing if you go blank when someone asks you to explain it. Communication is not a soft skill — it is the delivery mechanism for every hard skill you have. This track runs every single day alongside everything else. No exceptions.

### The Five Pillars (AI Era Hiring)

| Pillar | What It Means In Practice |
|--------|--------------------------|
| **Basic Computer Foundations** | Explain any technical concept clearly to a non-technical person without losing accuracy |
| **Computational Thinking** | Break any problem into components, identify patterns, explain your reasoning step by step |
| **First Principles Thinking** | Explain why something works, not just what it does. Trace back to fundamentals. |
| **Interpersonal Skills** | Listen before responding. Ask clarifying questions. Hold your position under pressure with evidence not emotion. |
| **Business Requirement Elicitation** | Translate between technical reality and business need. What problem does this solve? What does it cost if we don't solve it? |

### Daily Practice Protocol

Every single day. 15 minutes maximum. Before building anything else.

**Step 1** — Pick one concept from that day's learning
**Step 2** — Explain it out loud or in writing. No notes. Your own words. Two minutes.
**Step 3** — Answer one follow-up question. The hardest question someone could ask about what you just explained.

Document in LEARNING.md:
- Date
- Concept explained
- What came out well
- Where you went blank or vague
- The follow-up question you answered
- One thing to improve tomorrow

### Weekly Escalation

Every Sunday — one full mock interview question. Not a concept explanation. A full question.

Examples:
- "Walk me through how you would secure a multi-agent AI system from prompt injection"
- "A CISO asks you why OS-level enforcement matters when you already have Casbin. What do you say?"
- "Explain the difference between logging and observability to someone who has never heard of OpenLLMetry"
- "Your agent made a wrong verdict on alert 847. Walk me through how you would investigate it"

Time yourself. Two minutes maximum per answer. Record it if possible. Review it. Document what you would change.

### Business Context Practice

Once per week — translate one technical thing you built into business language.

The format:
- What I built (technical, one sentence)
- What problem it solves (business, one sentence)
- What happens if this problem goes unsolved (cost, risk, consequence — one sentence)
- Who cares about this in a company (CISO, CTO, compliance team, board)

Example:
- What I built: Phantom token proxy that keeps API keys out of agent memory
- Problem it solves: Compromised agents cannot exfiltrate credentials
- If unsolved: One prompt injection attack exposes every API key in the system
- Who cares: CISO, compliance, anyone liable for a breach

### Milestone Gates

These are not optional. Before moving to the next phase, pass the gate.

**Before Phase 1:**
Explain the 4-agent pipeline (Triage → Investigation → Verdict → Policy Engine) clearly in under 2 minutes. No notes. Record yourself. Watch it back. If you would hire yourself based on that explanation — proceed.

**Before Phase 2:**
Explain why separation of duty matters in a multi-agent system to a non-technical hiring manager. Under 2 minutes.

**Before Phase 3:**
Explain what the phantom token pattern is and why it is stronger than environment variables. Under 2 minutes.

**Before Phase 4:**
Explain what you would do if a CISO asked you to red team your own AI system. Under 3 minutes. No notes.

**Before Phase 5:**
Full mock interview. 30 minutes. Record it. Every question about Sentinel. If you would hire yourself — you're ready to apply seriously.

### The Core Rule

You already have the thinking. Today proved that. The gap is not knowledge. The gap is converting knowledge into spoken and written words under pressure in real time. That gap closes with daily reps only. Not with more roadmap items. Not with more courses. Reps. Every day. Starting today.

---

## Phase 1 — Multi-Agent MVP + Cloud-First Deployment (4 Weeks)

### Goal: Split monolithic AlertAnalyzer into separation-of-duty agents with inline security validation, containerized from day 1, deployed to AWS by Week 4

**Time budget**: 3 hrs/day building = 21 hrs/week = 84 hrs total
**Constraint**: 9 hrs/day split across building (3hrs), agentic AI security research (3hrs), job applications from Mar 16 (3hrs)
**Budget constraint**: $50/month maximum AWS spend. Free tier first, justify every paid service.

The existing `alert_analyzer_final.py` stays as fallback throughout.

### Cloud-First Rule (NON-NEGOTIABLE)
No agent gets built without a corresponding container definition. Every component built locally gets its cloud equivalent in the same week. The system is deployed incrementally — not "build everything then figure out cloud."

### Local → Cloud Migration Map

| Local Component | Cloud Equivalent | When | Free Tier? | Est. Monthly Cost |
|----------------|-----------------|------|-----------|-------------------|
| Python process (Flask) | ECS Fargate task (0.25 vCPU, 0.5GB) | Week 3 | No | ~$3-5 |
| `Queue_manager.py` (in-memory) | Amazon SQS | Week 3 | Yes (1M requests free) | $0 |
| `.env` file | AWS Secrets Manager | Week 3 | No (4 secrets) | ~$1.60 |
| `docker-compose up` | ECS Fargate cluster | Week 3 | No | Included above |
| `observability.py` (hand-rolled) | CloudWatch Logs + Metrics | Week 4 | Partial (5GB free) | ~$0-2 |
| `ai_tracer.py` (hand-rolled) | AWS X-Ray | Week 4 | Yes (100K traces free) | $0 |
| N/A | CloudTrail (agent audit) | Week 4 | Yes (1 trail free) | $0 |
| GitHub push | GitHub Actions → ECR → ECS | Week 3 | ECR: 500MB free | ~$0-1 |
| ChromaDB (local, no ACL) | pgvector on RDS (row-level security) | Phase 1.5 | Partial (db.t3.micro free 12mo) | ~$0-15 |
| Open network | VPC + private subnets | Phase 1.5 | Yes | $0 |
| Single IAM user | IAM role per agent | Phase 1.5 | Yes | $0 |
| N/A | GuardDuty | Phase 1.5 | Yes (30-day trial) | ~$0-5 |
| N/A | Security Hub | Phase 1.5 | Yes (30-day trial) | ~$0-2 |

### Weekly Cost Estimates

| Week | New AWS Services | Estimated Monthly Cost | Cumulative |
|------|-----------------|----------------------|------------|
| Week 1-2 | None (Docker local only) | $0 | $0 |
| Week 3 | ECS Fargate, SQS, Secrets Manager, ECR, GitHub Actions | ~$6-8 | ~$6-8 |
| Week 4 | CloudWatch, X-Ray, CloudTrail | ~$0-2 | ~$8-10 |
| Phase 1.5 | RDS pgvector, VPC, GuardDuty, Security Hub | ~$15-25 | ~$25-35 |
| **Worst-case total** | | | **~$35-45/month** |

*All estimates assume minimal usage (dev/portfolio workload, not production traffic). Uses us-east-1 pricing. Fargate tasks sized at 0.25 vCPU / 0.5GB minimum. Tasks scaled to zero when not processing alerts.*

### DevSecOps Pipeline (NON-NEGOTIABLE from Day 1)

Active from the first commit of Phase 1. Not optional. Not "later."

- [ ] **Gitleaks** on every commit — no secrets in code ever
- [ ] **Semgrep** SAST on every PR — catches insecure patterns in Python
- [ ] **Trivy** scanning every container image before push to ECR
- [ ] **Failed gate BLOCKS merge** — not a warning, a hard stop

### Agents

**Triage Agent**
- Input: Raw alert
- Job: Extract facts only — source IP, event type, timestamp, affected systems
- Cannot: See RAG context, give verdicts, recommend actions
- Why: If raw alert contains prompt injection, Triage only extracts facts — can't influence verdict

**Investigation Agent**
- Input: Fact sheet from Triage (NEVER the raw alert)
- Job: Gather context — query RAG, pull forensic logs, run OSINT
- Cannot: See raw alert, give verdicts, recommend actions
- Why: Never sees potentially poisoned raw input

**Verdict Agent**
- Input: Evidence package from Investigation
- Job: Evaluate evidence, apply hypothesis analysis, determine verdict + confidence
- Cannot: See raw alert, access tools, recommend actions
- Why: Verdict based purely on evidence, isolated from raw input and action capabilities

**Policy Engine**
- Input: Verdict from Verdict Agent
- Job: Map verdict to pre-approved response actions
- Implementation: Pure Python — NO AI. If/else logic against policy table
- Why: Response actions are deterministic. Compromised AI cannot invent new actions

### Evals Framework — Baseline Scoring (BEFORE LangGraph Refactor)

**Constraint: Do not start LangGraph refactor until baseline eval score is recorded.**

- [ ] Build a scoring rubric for the existing single-agent `alert_analyzer_final.py`
  - Verdict correctness (does the AI get the right answer?)
  - Confidence threshold (is confidence calibrated — high on obvious, lower on ambiguous?)
  - Evidence quality (are evidence items specific, verifiable, and relevant?)
  - Recommendation actionability (can an analyst act on the recommendation without guessing?)
- [ ] Create 20 golden test cases covering each alert type in the existing system
- [ ] Run baseline eval against the monolith — record aggregate score in SENTINEL_STATUS.md
- [ ] **Learn before build:** What is an eval? What is a rubric? What makes a good golden test case?

---

### LangGraph MVP — Definition of Done

The state machine is "done" when:
- 4 nodes: Triage → Investigation → Verdict → Policy Engine (linear flow)
- Pydantic schema enforced at every node boundary
- State object passes between nodes (not raw dicts)
- Existing `alert_analyzer_final.py` stays as fallback if any node fails
- Graph processes one alert end-to-end and produces the same verdict quality as the monolith

### LangGraph Refactor — Explicit Constraints

- [ ] Start with exactly two agents: one orchestrator, one worker. No more.
- [ ] Orchestrator decides what to do. Worker does it. That is the entire architecture at start.
- [ ] Add a third agent only when you can name the specific bottleneck that requires it.
- [ ] Mutex handling is required on all shared state — queue access, ChromaDB writes, Supabase updates.

**NOT in scope for Phase 1:** Branching, parallel execution, replay, serialization, conditional routing, sub-graphs.

---

### Week 1 — Triage Agent + Foundation (Mar 16–22)

**Building (21 hrs):**
- [ ] Triage Agent as standalone class with Pydantic input/output schemas
- [ ] Instructor + Pydantic on Claude calls
- [ ] Unit tests: Triage produces correct fact sheets from sample alerts

**Containerization:**
- [ ] Dockerfile for Flask app (multi-stage build, non-root user, read-only root filesystem)
- [ ] Docker Compose v1: Flask + ChromaDB
- [ ] Trivy scan on built image — zero high/critical CVEs

**DevSecOps:**
- [ ] GitHub Actions workflow: Gitleaks + Semgrep + Trivy on every PR
- [ ] Failed gate blocks merge

**Attack Tests:**
- [ ] Prompt injection in raw alert description → verify injection text does NOT appear in Triage output
- [ ] Oversized/malformed alert → verify Triage rejects gracefully

**✅ Deliverable:** Triage Agent processes 5 sample alerts correctly. Injection test passes. System runs via `docker-compose up`. CI pipeline blocking PRs with secrets or vulnerabilities.

---

### Week 2 — Investigation + Verdict Agents (Mar 23–29)

**Building (21 hrs):**
- [ ] Investigation Agent: receives Triage fact sheet, queries RAG + OSINT, produces evidence package
- [ ] Verdict Agent: receives evidence package, runs hypothesis analysis, produces verdict + confidence
- [ ] Pydantic schemas at both boundaries
- [ ] Trust boundary enforcement: Investigation cannot access raw alert, Verdict cannot access tools

**Containerization:**
- [ ] Dockerfile per agent if running as separate services
- [ ] Docker Compose v2: full pipeline runs locally with one command
- [ ] Drop all Linux capabilities, add back only what's needed per container

**Attack Tests:**
- [ ] Feed Investigation a fact sheet that references the raw alert → verify it cannot retrieve it
- [ ] Craft evidence package designed to hijack Verdict into wrong conclusion
- [ ] Data trust labeling test: UNTRUSTED data cannot pass to TRUSTED context without transformation

**✅ Deliverable:** 3-agent chain processes alerts end-to-end via Docker Compose. All 3 attack tests pass.

---

### Week 3 — Policy Engine + Cloud Foundation (Mar 30–Apr 5)

**Building (21 hrs):**
- [ ] Policy Engine: pure Python, maps verdict to response actions via policy table
- [ ] LangGraph state machine wiring all 4 agents
- [ ] Fallback to existing monolith if any node fails
- [ ] Cross-boundary logging on every data transfer between nodes
- [ ] Casbin on `/ingest` endpoint

**Cloud Foundation:**
- [ ] ECS Fargate cluster created (us-east-1)
- [ ] ECR repository — push container images from GitHub Actions
- [ ] SQS queue replaces in-memory Queue_manager.py
- [ ] Secrets Manager: migrate .env secrets
- [ ] GitHub Actions pipeline: on merge to main → build → push to ECR → deploy to ECS
- [ ] OIDC federation between GitHub Actions and AWS

**Attack Tests:**
- [ ] Policy Engine receives fabricated verdict → verify it cannot execute actions outside the policy table
- [ ] Full chain injection: poisoned raw alert → trace through all 4 agents
- [ ] Casbin test: unauthenticated POST to `/ingest` → verify rejection

**✅ Deliverable:** Full LangGraph pipeline on ECS Fargate. SQS replaces in-memory queue. Secrets in Secrets Manager.

---

### Week 4 — Agents on Cloud + Observability (Apr 6–12)

**Building (21 hrs):**
- [ ] OpenLLMetry instrumentation on all Claude calls
- [ ] Budget tracker moved to persistent storage
- [ ] Integration tests: pipeline handles 20 alerts without failure
- [ ] Performance comparison: monolith vs LangGraph pipeline

**Cloud Observability:**
- [ ] CloudWatch Logs: all agent output streams to log groups
- [ ] CloudWatch Metrics: custom metrics for alert throughput, verdict latency, API cost
- [ ] CloudTrail enabled — every AWS API call logged
- [ ] X-Ray tracing: trace single alert through all 4 agents end-to-end
- [ ] CloudWatch Alarms: budget threshold at $40/month, API error rate > 5%

**Attack Tests:**
- [ ] Resource exhaustion: flood queue with 50 alerts → verify circuit breaker activates
- [ ] Full red team pass: all previous attack tests re-run against cloud-deployed pipeline

**✅ Deliverable:** All 4 agents on ECS Fargate. CloudWatch + X-Ray replacing hand-rolled observability. All attack tests passing.

---

### What You Learn (Phase 1)
- Python classes, inheritance, composition
- Thread safety, queue management
- Pydantic validation
- Trust boundaries as a design pattern
- LangGraph state machines and agent orchestration
- OpenTelemetry-based LLM observability
- Policy-as-code with Casbin
- Docker containerization and multi-stage builds
- AWS ECS Fargate, SQS, Secrets Manager, ECR
- GitHub Actions CI/CD with security gates
- CloudWatch, X-Ray, CloudTrail observability stack
- OIDC federation

---

## Phase 1.5 — Harden Cloud Infrastructure (After Phase 1 Proven)

**Cloud Hardening (2-3 weeks):**
- [ ] **pgvector on RDS** — Replace ChromaDB with pgvector on RDS PostgreSQL. Row-level security per agent.
- [ ] **VPC with private subnets** — Agents never on public internet.
- [ ] **IAM role per agent** — Least privilege enforced structurally, not by prompt.
- [ ] **GuardDuty enabled** — Detects anomalous agent behavior patterns.
- [ ] **Security Hub** — Aggregates findings from GuardDuty, Trivy, and custom checks.

**Frameworks (2-3 weeks):**
- [ ] **DSPy for hypothesis testing** — Replace hand-written hypothesis prompt with DSPy module.
- [ ] **Arize Phoenix** — LLM drift detection.
- [ ] **LlamaIndex provenance** — RAG integrity. Source metadata and integrity hashes on every retrieved document.
- [ ] **Prefect workflows** — Pipeline orchestration with retries, timeouts, audit trail.

**Later — After Cloud Hardening Working:**
- [ ] **OPA (Open Policy Agent)** — Full policy-as-code engine for complex multi-agent policies.

### OS Security Layer — runs alongside cloud hardening

- [ ] **TCB Documentation** (Day 1, no code)
  Document every component Sentinel currently trusts. One entry per component: what it is, what breaks if compromised, whether it can be minimized. No code. Pure analysis. One hour. This is the reference point for every future security decision.

- [ ] **Fail-Secure Audit** (Week 1)
  Review every exception handler and security control in Sentinel. For each one: if this fails, does the system deny or permit? Fix every fail-open case. Document the failure mode of every control explicitly before implementing any new ones.

- [ ] **Phantom Token Proxy** (Week 2)
  Replace .env API key pattern. Python HTTP proxy intercepts outbound Claude API calls. Fake 256-bit token given to agent process. Real key held only in proxy, never in agent memory. Implement memory zeroing on proxy shutdown.

- [ ] **Landlock Filesystem Isolation** (Week 3)
  Agent process gets explicit filesystem boundaries via Python ctypes calling Landlock kernel API. Read from ./alerts only. Write to ./outputs only. Everything else denied at kernel level. Learn Landlock documentation before writing a single line of code.

- [ ] **seccomp Static Filter** (Week 4)
  Install BPF filter at agent process startup. Document every syscall the agent legitimately needs. Block everything else with SECCOMP_RET_ERRNO. Test against all existing alert processing scenarios before enabling in any deployed environment.

---

## Phase 2 — Core Platform + First Modules (Month 2-3)

### Planner vs Swarm — Explicit Decision Required

| Architecture | How It Works | Good For | Risk |
|-------------|-------------|----------|------|
| **Planner** | One orchestrator reasons and delegates to specialized sub-agents | Complex multi-step alerts | Single point of failure |
| **Swarm** | Identical agents pick from shared queue in parallel | High volume, simple tasks | No coordination, race conditions |
| **Hybrid** | Planner for complex, swarm for bulk | Both profiles | Implementation complexity |

**Sentinel's workload profile:** Complex multi-step analysis, moderate volume, requires specialized skills.
**Recommendation:** Planner with mutex-protected shared state.

---

### Tool Layer — Custom MCP Tools

- [ ] Audit all existing tool functions: osint_lookup.py, rag_system.py, alert_analyzer_final.py, mitre_mapping.py
- [ ] Define a standard tool schema for each: name, description, input parameters, output schema, error cases
- [ ] Expose each tool as a proper callable function
- [ ] MCP layer comes after tools are formalized — not before

### Ticketing Engine (Module 5)
- [ ] Auto-generate structured ticket on any detection event
- [ ] Fields: finding type, severity, asset, owner, recommended action, SLA, MITRE tag, evidence
- [ ] Owner assignment based on ownership mapping
- [ ] SLA breach alerting

### AI Governing AI (Module 6)
- [ ] Instrument ALL LLM calls: log prompt, response, latency, tokens, model, cost
- [ ] Extend InputGuard into real-time injection detection dashboard
- [ ] Anomalous API usage detection
- [ ] Dashboard panel: AI health, injection attempts, anomalous events, token spend

### Vulnerability Prioritization (Module 14)
- [ ] Ingest scan output (Nessus XML, Trivy JSON, Snyk)
- [ ] Per-finding enrichment: CISA KEV API, EPSS score, asset criticality, exploit availability
- [ ] Final score: CVSS + KEV + EPSS + asset criticality + exploit availability
- [ ] Auto-assign to repo/asset owner

### CSPM (Module 1)
- [ ] Connect to AWS via boto3 (read-only IAM role)
- [ ] Run checks against CIS AWS Benchmark controls
- [ ] Score environment against 85%+ posture target
- [ ] Auto-generate remediation runbooks per finding

---

## Phase 3 — Identity & Response Cluster (Month 3-4)

### Phishing Response (Module 7)
- [ ] Ingest phishing report (simulated email headers + body)
- [ ] LLM extracts IOCs, classifies confidence, identifies impersonated brand
- [ ] Automated chain: disable sessions → block sender → trigger scan → create ticket → notify HR

### User Containment (Module 8)
- [ ] User identity graph: sessions, OAuth tokens, service accounts, SaaS connections, groups
- [ ] One-click full containment: revoke sessions, invalidate tokens, disable account

### Auto-Disable (Module 10)
- [ ] Confidence threshold engine: above threshold → auto-disable without human
- [ ] Below threshold → alert + one-click disable
- [ ] Rollback capability with audit log

### HR Notification (Module 11)
- [ ] Template engine: incident type determines template
- [ ] Acknowledgment tracking with SLA
- [ ] Privacy layer: PII handled per data classification

### DLP (Module 2)
- [ ] GitHub scanning: secrets, API keys, credentials, PII via webhook on push
- [ ] Slack simulation: classify messages with credit cards, SSNs, API keys
- [ ] Cleartext credential detection with pre-commit hook

---

## Phase 4 — Red Teaming + AppSec + Pen Testing (Month 4-5)

### Red Teaming Your Own System

**Tooling:**
- [ ] Microsoft PyRIT: automated prompt injection and jailbreak campaigns
- [ ] AgentDojo: benchmark multi-agent pipeline against attack scenarios
- [ ] Publish results: red team report mapped to OWASP Agentic Top 10

**Prompt Injection:**
- [ ] Direct injection in alert description field
- [ ] Indirect injection via RAG document poisoning
- [ ] Multi-turn injection (salami slicing)
- [ ] Injection through OSINT data

**Agent Manipulation:**
- [ ] Goal hijacking
- [ ] Tool misuse
- [ ] Privilege escalation
- [ ] Cascading failure

**Data Attacks:**
- [ ] RAG poisoning
- [ ] Memory manipulation
- [ ] Data exfiltration

**Resource Exhaustion:**
- [ ] Flood queue to exhaust API budget
- [ ] Test circuit breaker under load

### AppSec — OWASP Top 10 Applied To Sentinel

Every vulnerability class tested systematically against Sentinel's actual attack surface. Not generic testing — every test case written specifically for how Sentinel works.

**Core Pipeline (existing):**
- [ ] Semgrep SAST engine in GitHub Actions
- [ ] Snyk dependency vulnerability scanning
- [ ] OWASP ZAP dynamic testing against API endpoints
- [ ] Block PR merge on critical findings

#### A01 — Broken Access Control

Sentinel specific attack surface:
- [ ] Can an unauthenticated caller POST to /ingest and inject alerts?
- [ ] Can Triage Agent access Investigation Agent's data directly?
- [ ] Can a low-privilege role read Verdict Agent outputs it should not see?
- [ ] Can the Policy Engine be called directly bypassing Verdict Agent?
- [ ] Horizontal escalation: can one analyst account access another's cases?
- [ ] Test Casbin policy exhaustively — every role against every resource against every action. Document what is permitted and what is denied.
- Tool: Burp Suite for manual access control testing, custom scripts for agent boundary testing

#### A02 — Cryptographic Failures

Sentinel specific attack surface:
- [ ] Are API keys ever written to logs in plaintext — search all log outputs
- [ ] Is data at rest encrypted in RDS, S3, and Secrets Manager?
- [ ] Are TLS certificates valid and properly configured on all endpoints?
- [ ] Are weak cipher suites enabled on any endpoint?
- [ ] Is sensitive alert data (PII, credentials found in alerts) masked in logs and traces?
- [ ] Does OpenLLMetry accidentally log the full prompt including sensitive alert content?
- Tool: testssl.sh for TLS audit, manual log review, AWS Config rules

#### A03 — Injection

Sentinel specific attack surface:
- [ ] SQL injection: every database query in Sentinel — are parameters sanitized?
- [ ] Prompt injection direct: malicious content in alert description field
- [ ] Prompt injection indirect: poisoned RAG document that changes agent behavior
- [ ] Command injection: any subprocess calls in Sentinel codebase?
- [ ] OSINT injection: craft malicious IP reputation API response that injects instructions into Investigation Agent
- [ ] Log injection: can an attacker write to your logs via alert content?
- Tool: Semgrep for static detection, PyRIT for prompt injection, manual testing for SQL and command

#### A04 — Insecure Design

Sentinel specific attack surface:
- [ ] Threat model review: is the 4-agent separation of duty actually enforced at the code level or just intended?
- [ ] Can the Verdict Agent be instantiated without going through Triage first?
- [ ] Is there a way to submit a pre-built evidence package directly to Policy Engine?
- [ ] Are there any design assumptions that are not enforced by code?
- [ ] Document every trust assumption in the architecture and verify each one is structurally enforced not just hoped for
- Tool: Architecture review, code audit, threat modeling session using STRIDE

#### A05 — Security Misconfiguration

Sentinel specific attack surface:
- [ ] Are default credentials changed everywhere — RDS, any admin interfaces?
- [ ] Are unnecessary ports open on ECS tasks or security groups?
- [ ] Are debug endpoints or stack traces exposed in production responses?
- [ ] Are S3 buckets private by default?
- [ ] Is CloudTrail logging all regions not just us-east-1?
- [ ] Are container images running as non-root with read-only root filesystem?
- [ ] Are unnecessary Linux capabilities dropped from all containers?
- Tool: ScoutSuite, Prowler, AWS Config, Docker Bench Security

#### A06 — Vulnerable and Outdated Components

- [ ] Snyk scan on requirements.txt — zero high/critical unpatched CVEs
- [ ] Trivy scan on all container images — zero high/critical unpatched CVEs
- [ ] Dependabot or Renovate enabled for automated dependency updates
- [ ] Python version current and supported
- [ ] All base container images on current supported versions
- Tool: Snyk, Trivy, GitHub Dependabot

#### A07 — Identification and Authentication Failures

Sentinel specific attack surface:
- [ ] Are JWT tokens validated properly on every protected endpoint?
- [ ] Is there session fixation risk on any authenticated endpoint?
- [ ] Are failed authentication attempts logged and rate limited?
- [ ] Can the /ingest endpoint be brute forced — is there rate limiting?
- [ ] Are Casbin policy decisions logged with enough detail to detect credential stuffing attempts?
- [ ] Does the phantom token proxy validate the fake token with constant time comparison?
- Tool: Burp Suite, custom rate limit testing scripts

#### A08 — Software and Data Integrity Failures

Sentinel specific attack surface:
- [ ] Are GitHub Actions workflows pinned to specific commit SHAs not just tags?
- [ ] Is the CI/CD pipeline protected against supply chain attacks — can a malicious PR modify the pipeline itself?
- [ ] Are container images signed and verified before deployment to ECS?
- [ ] Are AGENTS.md and instruction files verified before agent ingestion? (Supply chain attestation — Phase 4 OS security track)
- [ ] Can a compromised dependency modify agent behavior at runtime?
- Tool: GitHub Actions security audit, Sigstore for image signing, nono attestation concepts applied

#### A09 — Security Logging and Monitoring Failures

Sentinel specific attack surface:
- [ ] Is every authentication decision logged?
- [ ] Is every Casbin policy decision logged with timestamp, subject, resource, action, and outcome?
- [ ] Is every agent-to-agent data transfer logged with both sender and receiver?
- [ ] Are logs tamper-evident — can an attacker modify logs to cover tracks?
- [ ] Is there an alert on repeated Casbin denials — potential attack indicator?
- [ ] Does CloudTrail cover every sensitive AWS API call?
- [ ] Can you reconstruct a complete attack timeline from logs alone?
- Tool: CloudTrail, CloudWatch, OpenLLMetry traces, manual log audit

#### A10 — Server Side Request Forgery (SSRF)

Most critical OWASP finding for Sentinel. Your agent makes outbound HTTP calls. Prompt injection can control those calls.

Sentinel specific attack surface:
- [ ] Attempt via prompt injection: make Sentinel's agent call 169.254.169.254 (AWS metadata service) and return IAM credentials in the response
- [ ] Attempt via prompt injection: make agent call internal VPC services it should not reach
- [ ] Attempt via OSINT tool: craft OSINT API endpoint that redirects to internal service
- [ ] Verify phantom token proxy blocks all non-allowlisted destinations
- [ ] Verify IMDSv2 enforced on all ECS tasks — token required, not just IP hop limit
- [ ] Verify network allowlist proxy structurally prevents calls to RFC 1918 addresses, link-local, and cloud metadata endpoints
- Tool: Custom prompt injection payloads, Burp Suite, manual verification of proxy allowlist enforcement

#### OWASP Top 10 — Completion Gate

Before Phase 5 begins:
- [ ] All 10 categories tested against Sentinel specifically
- [ ] Every finding documented with: vulnerability class, evidence, reproduction steps, fix implemented, retest confirmed
- [ ] OWASP Top 10 mapping added to GRC_MAPPING.md
- [ ] Summary published as portfolio artifact — "I ran OWASP Top 10 against my own AI SOC and here is what I found"

### Penetration Testing
- [ ] Reconnaissance: Nmap scan of own deployment
- [ ] Scanning: OWASP ZAP active scan against all endpoints
- [ ] Exploitation: attempt real attacks
- [ ] Detection: write Snort rules that detect attack patterns
- [ ] Reporting: full pen test report

### Penetration Testing — PTES Methodology

Real pen testers follow a structured process. Every test you run against Sentinel follows this methodology. Not just tools — a mental model for how real attackers think.

#### PTES — Penetration Testing Execution Standard

**Stage 1 — Pre-Engagement**
- [ ] Define scope: what is in scope, what is out of scope, what cannot be touched
- [ ] Define success criteria: what does a successful attack look like
- [ ] Document rules of engagement before touching anything
- [ ] Threat profile: who would attack Sentinel in production? Nation state? Insider? Opportunistic attacker? Define the adversary.

**Stage 2 — Intelligence Gathering**
- [ ] Passive recon: what is publicly visible about your deployment without touching it
- [ ] Active recon: Nmap scan of your own ECS deployment, enumerate open ports, services, versions
- [ ] Cloud recon: what AWS resources are publicly discoverable via AWS APIs
- [ ] Dependency mapping: what does Sentinel call outbound, what does it expose inbound
- [ ] Document everything found before attempting any exploitation

**Stage 3 — Threat Modeling**
- [ ] Attack surface map: every input point, every outbound call, every trust boundary
- [ ] STRIDE applied to Sentinel:
  - Spoofing: can an attacker impersonate a trusted agent or data source?
  - Tampering: can alert data be modified in transit or at rest?
  - Repudiation: can an agent deny actions it took — is the audit trail complete?
  - Information Disclosure: what sensitive data could leak and through what path?
  - Denial of Service: how do you exhaust the system — queue flood, token burn?
  - Elevation of Privilege: can Triage Agent acquire Verdict Agent capabilities?
- [ ] Document threat model before exploitation

**Stage 4 — Vulnerability Analysis**
- [ ] Automated scanning: OWASP ZAP against all API endpoints
- [ ] Manual analysis: review every finding from automated scan for false positives
- [ ] OWASP Top 10 manual check against every input surface
- [ ] Cloud misconfiguration audit: ScoutSuite or Prowler against AWS account
- [ ] Container audit: Trivy against all images, docker bench security

**Stage 5 — Exploitation**
- [ ] Attempt real exploitation of every finding from Stage 4
- [ ] Chain vulnerabilities: can you combine two low findings into one critical?
- [ ] Document: what worked, what didn't, why each succeeded or failed
- [ ] Stop at proof of concept — do not destroy data or infrastructure

**Stage 6 — Post Exploitation**
- [ ] If exploitation succeeded: how far can you move from that foothold?
- [ ] Lateral movement: can you reach other agents from a compromised agent?
- [ ] Persistence: could an attacker maintain access after the initial vector is closed?
- [ ] Data access: what data is reachable from the compromised position?
- [ ] Document blast radius of each successful exploitation

**Stage 7 — Reporting**
- [ ] Executive summary: what was found, what is the business risk, what is the priority order for fixing
- [ ] Technical findings: vulnerability, evidence, reproduction steps, CVSS score, remediation
- [ ] OWASP Agentic Top 10 mapping for every AI-specific finding
- [ ] Retest confirmation: every fix verified with a second test pass
- [ ] Publish as portfolio artifact

### Network Level Attacks

- [ ] Man in the middle: attempt TLS interception on agent-to-Claude API calls
- [ ] TLS misconfiguration: test for weak cipher suites, certificate validation, certificate pinning gaps
- [ ] DNS attacks: DNS rebinding against your proxy — can an attacker bypass the allowlist via DNS manipulation?
- [ ] Traffic analysis: what can be inferred from encrypted traffic patterns — timing, size, frequency of API calls

### Cloud Specific Attacks

- [ ] IAM privilege escalation: map every IAM role in Sentinel, identify escalation paths using Cloudsplaining or Parliament
- [ ] Metadata service SSRF: attempt to make Sentinel's agent call 169.254.169.254 via prompt injection — verify phantom token proxy blocks it — verify IMDSv2 is enforced on all ECS tasks
- [ ] S3 misconfiguration: audit every S3 bucket for public access, ACL issues, versioning, logging
- [ ] Container escape: attempt to break out of ECS task container boundary — verify read-only root filesystem holds
- [ ] Lateral movement in ECS: if one task is compromised, can it reach other tasks in the cluster via task role credentials?
- [ ] CloudTrail gaps: are there any actions an attacker could take that would NOT appear in CloudTrail?
- [ ] Secrets Manager: verify no secrets accessible without explicit IAM permission — attempt access from agent role that should not have it

### Tools For Pen Testing Track

| Tool | Purpose | When Used |
|------|---------|-----------|
| Nmap | Network reconnaissance, port scanning | Stage 2 |
| OWASP ZAP | Dynamic application security testing | Stage 4 |
| Burp Suite Community | Manual HTTP interception and testing | Stage 4-5 |
| Metasploit | Exploitation framework | Stage 5 |
| Snort | Write and test detection rules | Stage 6 |
| ScoutSuite | AWS cloud security auditing | Stage 4 |
| Cloudsplaining | IAM privilege escalation analysis | Stage 4 |
| Prowler | AWS security best practices audit | Stage 4 |
| Trivy | Container and dependency scanning | Stage 4 |
| Docker Bench | Container runtime security audit | Stage 4 |
| Wireshark | Network traffic analysis | Stage 4-5 |

---

## Phase 5 — Remaining Modules + Polish (Month 5-6)

### Insider Threat / Offboarding (Module 17)
- [ ] Detection rules: bulk downloads, after-hours access, cloud sync to personal accounts
- [ ] Privileged access logging

### Geolocation Response (Module 13)
- [ ] Risk scoring: impossible travel, new country, off-hours, new device
- [ ] Response tiers: 0-40 log only, 40-70 MFA challenge, 70-85 analyst alert, 85+ auto-contain

### User Blast Radius (Module 9)
- [ ] Access map per user: systems, data classifications, privilege level, lateral movement paths
- [ ] LLM narrative: "If this account is compromised, here is the attack path"

### Endpoint Scan (Module 12)
- [ ] CrowdStrike Falcon API integration (simulated)
- [ ] On compromise: identify device → initiate scan → poll results → parse detections

### Gap Engine (Module 3)
- [ ] Ingest security tool inventory
- [ ] Map against NIST CSF 2.0 and CIS Controls v8
- [ ] LLM: attacker narrative from gaps

### Remediation Tracking (Module 4)
- [ ] Finding lifecycle: Open → In Progress → Remediated → Verified
- [ ] Verified requires re-scan (not manual close)
- [ ] MTTR dashboard by severity

### TPRM (Module 16)
- [ ] Vendor registry with risk scoring
- [ ] LLM questionnaire generator based on vendor type
- [ ] Revocation simulation on failed review

### Risk Matrix (Module 18)
- [ ] Business asset registry: criticality, data classification, regulatory scope
- [ ] Board-level dashboard: business language, not CVE IDs
- [ ] LLM: technical finding → business impact statement

---

## Parallel Track — Agentic AI Security Research

Runs throughout. Theory from AGENTIC_AI_SECURITY.md, practice applied to the multi-agent system.

| Topic | When It's Applied |
|-------|------------------|
| OWASP Agentic Top 10 | Phase 1 + Phase 4 |
| MAESTRO Framework | Phase 1 (threat model) |
| Trust Boundaries | Phase 1 (agent isolation) |
| Memory Poisoning | Phase 4 (red team RAG) |
| Cascading Failures | Phase 4 (red team agent chain) |
| Shadow AI | Phase 2 (Module 6) |
| Embeddings | Phase 1 — before RAG refactor |
| Context Engineering | Phase 1 — prompt consistency |
| Post-Quantum Crypto | Research only |
| OS Security Primitives — nono + OpenShell | Phase 1 (TCB + fail-secure + phantom token) → Phase 1.5 (Landlock + seccomp static) → Phase 2 (seccomp-notify + capability refactor) → Phase 4 (attestation + threat model) |
| GRC & Compliance Mapping | Runs throughout all phases. One entry added per module as it is built. Produces GRC_MAPPING.md by end of Phase 5. |

### OS Security Primitives Track

Runs parallel to all phases. Each concept is learned when the architecture is ready to implement it. Implementation is purpose-built for Sentinel — not wrapping existing tools but understanding the primitives deeply enough to build equivalent controls from scratch.

**Phase 1 — Architecture Independent (implement now)**

- [ ] TCB Documentation
  Document every component Sentinel currently trusts. One entry per component: what it is, what breaks if compromised, whether it can be minimized. No code. Pure analysis. One hour. This is the reference point for every future security decision.

- [ ] Fail-Secure Audit
  Review every exception handler and security control in Sentinel. For each one: if this fails, does the system deny or permit? Fix every fail-open case. Document the failure mode of every control explicitly before implementing any new ones.

- [ ] Phantom Token Proxy
  Replace .env API key pattern. Python HTTP proxy intercepts outbound Claude API calls. Fake 256-bit token given to agent process. Real key held only in proxy, never in agent memory. Implement memory zeroing on shutdown.

**Phase 1.5 — After Multi-Agent Architecture Stable**

- [ ] Landlock Filesystem Isolation
  Agent process gets explicit filesystem boundaries via Python ctypes calling Landlock kernel API directly. Read from ./alerts only. Write to ./outputs only. Everything else denied at kernel level. Learn Landlock documentation before writing a single line of code.

- [ ] seccomp Static Filter
  Install BPF filter at agent process startup. Document every syscall the agent legitimately needs. Block everything else with SECCOMP_RET_ERRNO. Test against all existing alert processing scenarios before enabling in any deployed environment.

**Phase 2 — After LangGraph Stable**

- [ ] seccomp Notify Mode
  Upgrade static filter to SECCOMP_RET_USER_NOTIF on file operations. Implement supervisor process that intercepts, evaluates policy, injects fd or returns EACCES. Agent unaware.

- [ ] Capability-Based Authorization Refactor
  Refactor agent authorization from identity-based (Casbin roles) to capability-based. Agents receive explicit tokens for specific resources. Nothing else reachable by identity inheritance.

- [ ] Network Allowlist Proxy
  All Sentinel outbound calls through local proxy. Only api.anthropic.com permitted. Cloud metadata endpoints hardcoded denied. Everything else structurally blocked.

**Phase 4 — After Red Team Track Begins**

- [ ] Supply Chain Attestation
  Sign AGENTS.md, SENTINEL_STATUS.md, all instruction files. Verify signatures at agent startup. Reject unsigned or tampered instructions. Implement using Sigstore.

- [ ] Full TCB Minimization Pass
  Revisit TCB documentation from Phase 1. Every component added since then justified or removed. Smallest possible trusted base.

- [ ] TOCTOU Audit
  Audit all RAG retrieval and file operations. Implement check-then-verify pattern. Document every place check and use are separated by time or async operations.

### GRC Credibility Track

Goal: Enough GRC knowledge to be credible in conversations with CISOs, compliance teams, and auditors. Not a GRC specialist track. A translation layer between what you build and the language regulators speak.

#### The Frameworks You Need To Know

| Framework | What It Covers | When You Reference It |
|-----------|---------------|----------------------|
| NIST AI RMF | Govern, Map, Measure, Manage — AI risk lifecycle | Every AI decision in Sentinel |
| EU AI Act | Risk tiers, obligations for high-risk AI | SOC AI qualifies as high-risk |
| NIST CSF 2.0 | Identify, Protect, Detect, Respond, Recover | Cybersecurity baseline |
| SOC 2 Type II | Security, availability, confidentiality | Enterprise customer requirement |
| ISO 27001 | Information security management | International enterprise standard |
| OWASP Agentic Top 10 | AI agent specific risks | Already in roadmap |

Study method: one framework per week, one hour only. Read the executive summary not the full document. Map it to Sentinel immediately after reading.

#### The Five CISO Questions

Answer these about Sentinel before Phase 2:

1. Does it reduce workload or just restate what the SIEM already told you?
2. Does it work across your entire stack?
3. Can it explain its reasoning with an evidence chain an auditor can review?
4. What happens when it is wrong?
5. What data does it actually see?

Deliverable: One paragraph answer per question written in SENTINEL_STATUS.md before Phase 2 begins. Updated after each phase.

#### GRC_MAPPING.md — Built Incrementally

Create GRC_MAPPING.md in repo root. One entry added every time a module or security control is completed.

Entry format:
- What was built
- NIST AI RMF function it satisfies
- NIST CSF category it satisfies
- EU AI Act article it addresses
- SOC 2 trust criteria it satisfies
- Evidence produced

Example entry:
- What: OpenLLMetry on all Claude calls
- NIST AI RMF: Measure 2.5 — AI system outputs monitored for performance
- NIST CSF: DE.CM-7 — monitoring for unauthorized activity
- EU AI Act: Article 9 — risk management system logging
- SOC 2: CC7.2 — system monitoring
- Evidence: Traces in CloudWatch, retained 90 days

#### GRC Translation Practice

Once per week as part of daily practice. Take one technical thing you built and translate it into a sentence a board member understands.

Format:
- Technical: what it is
- Risk it mitigates: what goes wrong without it
- Regulatory relevance: which framework requires it
- Business consequence: cost if audited without it

---

## Dashboard — What the Frontend Shows

- [ ] Real-time posture score (AWS CIS Benchmark %)
- [ ] Live incident feed with severity coloring
- [ ] MTTR by severity tier (chart)
- [ ] Findings opened vs closed this week (chart)
- [ ] User risk leaderboard (top 10 highest blast radius)
- [ ] AI monitoring panel (injection attempts, anomalous API calls, token spend)
- [ ] KEV findings currently open
- [ ] DLP events detected this week
- [ ] Phishing response timeline

---

## What This Gets You

By end of 6 months:
- A multi-agent AI SOC with separation-of-duty security architecture
- Cloud-native deployment on AWS (ECS Fargate, SQS, RDS, CloudWatch, X-Ray, CloudTrail)
- DevSecOps pipeline from day 1 (Gitleaks, Semgrep, Trivy — merge-blocking gates)
- 18 working security modules covering cloud, identity, AppSec, DLP, CSPM, TPRM
- OS-level security controls implemented from first principles — Landlock, seccomp, phantom token, supply chain attestation
- Red team findings mapped to OWASP Agentic Top 10
- Pen test report of your own system
- SAST pipeline scanning your own codebase
- IAM role per agent with least-privilege AWS permissions
- Every module produces a measurable metric
- Daily communication practice documented in LEARNING.md
- Portfolio evidence for every claim

**You're not saying "I know about security." You're showing "I built it, broke it, secured it at the OS level, deployed it to cloud, measured it, and here are the numbers."**

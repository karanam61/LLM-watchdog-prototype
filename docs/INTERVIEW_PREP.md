# AI-SOC Watchdog — Interview Preparation Guide

---

## PART 1: DEPLOYMENT CHANGES (What Changed from Dev → Production)

### Infrastructure Setup
- **Backend:** Deployed to Railway using Gunicorn (reduced from 2 workers to 1 to fit free-tier memory limits)
- **Frontend:** Deployed to Vercel with SPA rewrites (`vercel.json`)
- **Database:** Supabase Cloud (PostgreSQL), already cloud-hosted
- **Vector DB:** ChromaDB persisted in `backend/chromadb_data/` — removed from `.gitignore` so it deploys with the container

### Configuration Files Added
- **Procfile:** `web: gunicorn -w 1 -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker -b 0.0.0.0:$PORT app:app`
- **railway.json:** NIXPACKS builder, health check on `/health`, restart on failure (max 5 retries), 180s timeout
- **soc-dashboard/vercel.json:** SPA rewrites so React Router works on Vercel

### Code Changes for Production

**1. CORS "Nuclear Fix"**
- Problem: Vercel generates random preview URLs, couldn't whitelist them all
- Fix: Set `Access-Control-Allow-Origin: *` on all responses via `@app.after_request`
- Trade-off: Had to set `withCredentials: false` in frontend `api.js` (browsers block credentials with wildcard CORS)

**2. Health Check Endpoint**
- Added `/health` returning `{"status": "ok"}` for Railway's deployment checks
- Full `/api/health` checks DB connectivity and background thread status

**3. Memory/OOM Fixes**
- Railway free tier kept killing the container (SIGKILL)
- Created "Fast Mode" for RAG and Transparency APIs — generates summaries from existing alert data instead of live ChromaDB queries
- Added in-memory LRU caching (5-min TTL) to `rag_api.py` and `transparency_api.py`

**4. Pydantic Validation Fix**
- Production DB had `None` values in optional fields
- Pydantic 2.x strict mode rejected them with 422 errors
- Changed `hostname`, `username`, `mitre_technique` etc. to `Optional[str]` with defaults

**5. JSON Parsing Robustness**
- Claude occasionally returned control characters (0x00-0x1F) that broke `json.loads()`
- Added sanitization: `re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', json_str)`

**6. Graceful Shutdown**
- Background worker threads caused "Fatal Python error" during Railway redeploys
- Added `shutdown_event = threading.Event()` + `atexit.register(graceful_shutdown)`

**7. Frontend Null-Safety**
- Dashboard crashed when production DB was empty
- Added null-safe checks: `res.data?.alerts || []` across all dashboard components

**8. Security Hardening**
- 2MB request size limit
- Secure cookies: `SESSION_COOKIE_SECURE=True`, `HTTPONLY=True`, `SAMESITE='Lax'`
- Sensitive header redaction in logging middleware (Authorization, Cookie, API keys)
- `secrets.compare_digest()` for ingest API key validation (timing-safe)

**9. Database Scanner**
- In-memory queue lost on Railway restarts
- Added background scanner that queries Supabase for `status='open'` AND `ai_verdict IS NULL` alerts and re-queues them

**10. Parallel Queue Workers**
- Split single queue processor into two threads: `priority_queue_worker` and `standard_queue_worker`
- Critical alerts no longer blocked behind a backlog of medium alerts

---

## PART 2: PROJECT MASTERY — EVERYTHING YOU NEED TO KNOW

### The One-Liner
"I built an AI-powered Security Operations Center tool that takes security alerts, enriches them with forensic evidence and threat intelligence, uses Claude AI with RAG to analyze them, and gives SOC analysts a verdict with full reasoning they can verify and override."

### What Problem Does This Solve?
SOC analysts get 500-1000+ alerts per day. 70-90% are false positives. They spend hours clicking through repetitive alerts. Alert fatigue causes real threats to get missed. This tool triages the noise so analysts can focus on real threats.

### How It Works (For Non-Technical People)
"Imagine you're a security guard watching 1000 security camera feeds. Most show nothing — a cat walking by, a tree branch moving. But buried in there, one camera shows someone picking a lock. My tool is like a smart assistant that watches all 1000 feeds, tells you 'these 900 are just cats and branches, but camera 47 — that's someone picking a lock, here's why I think so, and here's the footage.' The guard still makes the final call, but now they only review 100 feeds instead of 1000."

### Architecture (Know This Cold)

**Data Flow:**
```
SIEM Alert → /ingest API → Parser → MITRE Mapper → Severity Classifier → Queue Manager
→ AlertAnalyzer (6 phases) → Verdict + Evidence → Supabase → React Dashboard → Analyst
```

**6 Phases of AlertAnalyzer:**
1. Security Gates — InputGuard blocks prompt injection, validates schema, redacts PII
2. Optimization — Budget check (daily $2 limit), cache check (skip duplicates)
3. Context Building — RAG (7 ChromaDB collections in parallel), forensic logs from Supabase, OSINT lookups
4. AI Analysis — Claude API call with retry/backoff, model selection by severity
5. Output Validation — OutputGuard checks verdict validity, confidence range, dangerous commands
6. Observability — Metrics, audit logging, cost tracking

**RAG Pipeline Details:**
- Vector DB: ChromaDB with PersistentClient
- Embedding: `all-MiniLM-L6-v2` (ChromaDB default, 384-dim)
- No explicit chunking — each seed document is a single flattened string
- 7 collections queried in parallel via ThreadPoolExecutor
- Collections: mitre_severity (201 techniques), historical_analyses, business_rules, attack_patterns, detection_rules, detection_signatures, company_infrastructure

**Prompt Engineering:**
- 10-section context: MITRE info, historical incidents, business rules, attack patterns, detection rules, signatures, asset context, analyst-corrected verdicts, current alert, correlated logs
- 7 systematic investigation questions (user, process, network, timing, history, business, attack)
- 2 few-shot examples (benign IT admin + malicious credential theft)
- Hypothesis testing mode: forces Claude to argue BOTH benign and malicious before deciding
- Strict JSON output schema with chain-of-thought

**Cost Optimization:**
- Critical/High → Claude Sonnet ($0.02/alert)
- Medium → Claude Haiku 3.5 (80% cheaper)
- Low → Claude Haiku (90% cheaper)
- Response caching avoids duplicate API calls
- Daily budget tracker with hard limit

**Security Features (26 total):**
- Input: Prompt injection detection (regex + patterns), SQL/XSS/command injection blocking
- Data: PII detection and redaction (SSN, credit cards, emails)
- Output: Verdict validation, confidence range check, dangerous command scanning
- Auth: Session-based login, timing-safe credential comparison
- API: Retry with exponential backoff, timeout protection, rate limiting

**Frontend (React + Vite + TailwindCSS):**
- 4 pages: Analyst Console, AI Dashboard, RAG Visualizer, System Debug
- Real-time updates via Socket.IO
- Analyst feedback loop: agree/disagree with AI, add notes
- Dark theme for SOC analyst eye comfort

### Tech Stack
Backend: Python, Flask, Flask-SocketIO, Gunicorn
Frontend: React 18, Vite, TailwindCSS, Recharts, Socket.IO client
AI: Anthropic Claude (Sonnet + Haiku), structured JSON outputs
Vector DB: ChromaDB (all-MiniLM-L6-v2 embeddings)
Database: Supabase (PostgreSQL)
Cloud: Railway (backend), Vercel (frontend), AWS S3 (failover)
Security: Pydantic validation, PII redaction, prompt injection guards

---

## PART 3: STAR FORMAT INTERVIEW ANSWERS

### Q1: "Tell me about a challenging project you've worked on."

**Situation:** SOC analysts at organizations are overwhelmed with 500-1000+ security alerts daily, and 70-90% are false positives. This leads to alert fatigue where real threats get missed because analysts are burned out from clicking through noise.

**Task:** I set out to build an AI-powered triage system that could analyze security alerts with full forensic context, give explainable verdicts, and reduce the manual workload — while ensuring the AI itself couldn't be manipulated by attackers.

**Action:** I built a full-stack system with a Flask backend and React frontend. The core innovation was the RAG pipeline — I created 7 ChromaDB knowledge collections (MITRE ATT&CK techniques, historical alerts, business rules, attack patterns, detection rules, signatures, and infrastructure context) and queried all 7 in parallel to give Claude AI comprehensive context for each alert. I also built a 6-phase security pipeline with input guards for prompt injection, PII redaction, output validation, and cost optimization that routes alerts to cheaper AI models based on severity. I deployed the backend to Railway and frontend to Vercel, solving production issues like OOM crashes, CORS, and graceful shutdown.

**Result:** The system processes alerts end-to-end with full chain-of-thought reasoning, references specific log entries, and gives analysts a verdict they can verify and override. The cost optimization reduces API spending by routing 70% of low-severity alerts to cheaper models. Analysts can focus on the 10-30% of alerts that actually matter. I also documented 10 honest limitations including no ground truth dataset, no continuous learning, and LLM hallucination risks.

---

### Q2: "Tell me about a time you had to make a difficult technical decision."

**Situation:** When building the AI analysis pipeline, I had to decide how to handle the AI's tendency to default to "suspicious" for everything. If everything is suspicious, nothing is — analysts still have to review everything.

**Task:** I needed the AI to make definitive calls (benign or malicious) when evidence was clear, and only use "suspicious" when genuinely uncertain.

**Action:** I implemented a hypothesis testing system. Instead of just asking "is this malicious?", the prompt forces Claude to build two competing hypotheses — one arguing the alert is benign, one arguing it's malicious — with evidence for each. Only after arguing both sides does it make a final verdict. I also added few-shot examples showing what a confident "benign" call looks like (IT admin running PowerShell during business hours) and what a confident "malicious" call looks like (Mimikatz at 2 AM with C2 beaconing). I added 7 systematic investigation questions the AI must answer before deciding.

**Result:** The hypothesis testing mode produces more nuanced, defensible verdicts. When the AI says "benign," it can explain why the malicious hypothesis failed. When it says "malicious," it acknowledges what opposing evidence exists. This builds analyst trust because they can see the AI considered alternatives.

---

### Q3: "Tell me about a time you dealt with a production issue."

**Situation:** After deploying to Railway's free tier, the application kept getting SIGKILL'd — the container was running out of memory and being killed by the OS.

**Task:** I needed to keep the app running within Railway's memory constraints without losing core functionality.

**Action:** I diagnosed the issue: the RAG and Transparency dashboard APIs were performing live ChromaDB queries on every request, loading the entire vector database into memory. I created "Fast Mode" versions of these APIs that generate summaries from existing alert metadata stored in Supabase instead of querying ChromaDB live. I added in-memory LRU caching with 5-minute TTL so repeated dashboard refreshes don't trigger new queries. I also reduced Gunicorn workers from 2 to 1 and increased the timeout to 180 seconds.

**Result:** The OOM kills stopped. The dashboard loads in seconds instead of timing out at 40+ seconds. The trade-off is that "Fast Mode" RAG stats are approximated from alert metadata rather than live collection queries, but for a demo dashboard this is acceptable. I documented this limitation honestly.

---

### Q4: "How do you handle security in your applications?"

**Situation:** This project processes untrusted data (security alerts from external SIEMs) and sends it to an LLM. An attacker could craft an alert description containing prompt injection to manipulate the AI's verdict — making a real attack look benign.

**Task:** I needed defense-in-depth security that protects the AI from manipulation at every layer.

**Action:** I built a 6-layer security pipeline. Layer 1: InputGuard scans for prompt injection patterns, SQL injection, XSS, and command injection before the AI sees the data. Layer 2: Pydantic schema validation ensures data structure is correct. Layer 3: DataProtectionGuard detects and redacts PII (SSNs, credit cards) before sending to Claude's API. Layer 4: OutputGuard validates the AI's response — checks verdict is valid, confidence is in range, recommendations don't contain dangerous commands. Layer 5: Timing-safe credential comparison using `secrets.compare_digest()` for authentication. Layer 6: All secrets redacted from logs, secure cookie settings, 2MB request limits.

**Result:** The system has multiple independent protection layers. Even if an attacker bypasses input scanning, the output guard catches suspicious AI responses. I also wrote a document (AGENTIC_AI_SECURITY.md) analyzing what real AI agent security looks like versus surface-level content safety, identifying 10 areas where the project could improve — including trust boundary mapping, adversarial red teaming, and separation of duty.

---

### Q5: "How do you optimize costs/performance?"

**Situation:** Running every security alert through Claude Sonnet costs $0.02-0.05 per alert. At 1000 alerts/day, that's $600-1500/month — unsustainable for most organizations.

**Task:** Reduce AI costs without sacrificing analysis quality on critical alerts.

**Action:** I implemented three strategies. First, severity-based model routing: critical and high alerts use Claude Sonnet (best reasoning), medium alerts use Haiku 3.5 (80% cheaper), low alerts use Haiku (90% cheaper). Second, response caching: duplicate or near-identical alerts get cached results instead of new API calls. Third, a daily budget tracker with a hard limit ($2/day default) that prevents runaway spending. I also parallelized RAG queries using ThreadPoolExecutor with 7 workers — one per ChromaDB collection — so context building doesn't add sequential latency.

**Result:** The weighted average cost drops to ~$0.005/alert (75% reduction from naive approach). The daily budget cap ensures costs are predictable. Parallel RAG queries reduced context building time significantly. Critical alerts still get full Sonnet analysis — we only compromise on cost for low-priority alerts where cheaper models are sufficient.

---

### Q6: "What would you do differently? / What are the limitations?"

**Situation:** I built this as a portfolio prototype. I was honest about what's missing.

**Task:** Identify real limitations rather than overselling the project.

**Action:** I documented everything in TECHNICAL_DIFFERENTIATORS_AND_LIMITATIONS.md. Key gaps:
1. **No ground truth dataset** — I can't formally measure precision/recall/F1 because I don't have 1000+ labeled alerts with known verdicts
2. **No continuous learning** — analyst feedback is stored but doesn't automatically retrain or improve the AI
3. **No explicit chunking in RAG** — works now because seed documents are short, but would break with longer documents
4. **Embedding model is default** — `all-MiniLM-L6-v2` is general-purpose, a security-domain-specific embedding model would improve retrieval
5. **LLM hallucination risk** — chain-of-thought helps but doesn't eliminate it
6. **Single API dependency** — if Anthropic is down, analysis stops (no multi-provider failover)
7. **No active response** — analyze-only, doesn't auto-isolate hosts or block IPs (by design — too risky)
8. **English-only** — alerts in other languages may not be analyzed correctly
9. **"95% accuracy" and "70% reduction" are design targets, not measured results**

**Result:** Interviewers respect honesty about limitations more than overblown claims. I can articulate exactly what's needed for production (labeled dataset, feedback loop, fine-tuned model, multi-provider failover, RBAC) and why each matters.

---

## PART 4: EXPLAINING TO NON-TECHNICAL AUDIENCES

### The Security Guard Analogy
"Think of a company's cybersecurity team like security guards watching 1000 surveillance cameras. Every time a door opens, a shadow moves, or a car drives by, an alarm goes off. 90% of these are false alarms — it's just employees coming to work. But buried in those 1000 alarms, maybe 5 are someone actually breaking in. My tool is like giving each security guard a smart assistant that reviews each alarm, checks the employee badge database, looks at past incidents, checks if the door is supposed to be open at that time, and says: 'This one's fine — it's the janitor's regular shift. But THIS one — someone used a stolen badge at 3 AM and the camera shows them going to the server room.' The guard still makes the final call, but now they only need to look at 100 alarms instead of 1000."

### The Doctor's Second Opinion Analogy
"It's like having a doctor's assistant who, before the doctor sees a patient, reviews their medical history, checks similar past cases, looks up the latest research, and prepares a summary: 'Here are the symptoms, here's what it's probably NOT based on their history, here's what it MIGHT be based on similar cases, and here's the evidence for each option.' The doctor still diagnoses and treats — the assistant just does the research legwork."

### Explaining RAG to Non-Technical People
"When you ask someone a question, they answer better if they can look things up first. If I ask you 'is this PowerShell command suspicious?' you'd say 'I don't know.' But if I first show you a reference book of known attack techniques, examples of what normal IT activity looks like, and your company's specific rules — now you can give a much better answer. That's what RAG does for the AI. Before the AI analyzes each alert, I give it access to 7 reference books."

### Explaining Prompt Injection to Non-Technical People
"Imagine someone writes a fake parking ticket and leaves it on a car, but hidden in the fine print it says 'Also, release all prisoners from jail.' If a clerk just processes the ticket without reading carefully, they might accidentally follow those hidden instructions. Attackers do the same thing with AI — they hide instructions inside security alerts hoping the AI follows them instead of analyzing the alert. My system scans for these hidden instructions before the AI ever sees them."

### Explaining Cost Optimization to Non-Technical People
"It's like having two doctors on staff — a specialist who charges $500/visit and a general practitioner who charges $50/visit. You don't send every sniffle to the specialist. My system sends critical alerts to the expensive, more capable AI model, and routine low-risk alerts to the cheaper, faster model. Same quality where it matters, 90% savings where it doesn't."

---

## PART 5: LIKELY INTERVIEW QUESTIONS & SHORT ANSWERS

**Q: Why Claude and not GPT-4?**
A: Better structured output compliance, better security reasoning in my testing, lower cost per token, and more consistent at low temperature settings.

**Q: How do you handle API failures?**
A: Retry with exponential backoff (1s→2s→4s→8s), 30s timeout, max 3 retries, then fallback to rule-based classification. Queue holds alerts so nothing is lost.

**Q: What's your false positive rate?**
A: I don't have a formal measurement because I lack a labeled ground truth dataset. That's honestly what's needed for production — 1000+ alerts with known verdicts to measure precision, recall, and F1.

**Q: How does the feedback loop work?**
A: Analysts can agree/disagree with AI verdicts and add notes. This gets stored in Supabase. Past analyst-corrected verdicts are fed into the RAG context for future alerts (section 8 of the prompt). But there's no automated retraining — it's manual context injection, not model improvement.

**Q: What if an attacker poisons the RAG?**
A: Valid concern I documented in AGENTIC_AI_SECURITY.md. Currently, RAG documents are trusted equally. Production needs trust boundary mapping — untrusted data shouldn't directly influence verdicts without verification. This is a known gap.

**Q: How does this scale?**
A: At 1000 alerts/day with cost optimization, ~$150/month. At 100K/day, ~$8,400/month. Scaling requires multi-provider failover, local LLM fallback, and multi-tenant architecture. Current design is single-tenant prototype.

**Q: What's the latency per alert?**
A: RAG context building is parallelized (~1-2s for 7 collections). Claude API call is 3-15s depending on model and context length. Total: 5-20 seconds per alert. Auto-triage closes low-confidence benign alerts without analyst review.

**Q: Why not fine-tune a model instead of RAG?**
A: Fine-tuning is expensive ($1000+), needs large labeled datasets I don't have, and bakes knowledge into the model permanently. RAG lets me update knowledge (new attack patterns, business rules) by just adding documents — no retraining. For a prototype, RAG is more practical.

**Q: What's the most interesting technical challenge you solved?**
A: Getting the AI to make definitive calls instead of defaulting to "suspicious." The hypothesis testing system — forcing Claude to argue both benign AND malicious before deciding — was the breakthrough. Combined with few-shot examples and 7 systematic investigation questions, it produces much more defensible verdicts.

**Q: What would you add with more time?**
A: A labeled dataset for formal accuracy measurement, continuous learning from analyst feedback, a security-domain embedding model instead of the generic default, explicit chunking for RAG documents, multi-provider AI failover, adversarial red teaming test suite, and RBAC for multi-user access control.

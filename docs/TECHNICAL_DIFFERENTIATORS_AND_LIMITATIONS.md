# Technical Differentiators and Honest Limitations

This document is for security engineers and architects who want to understand what makes this project different from other AI security solutions, and what its limitations are.

## Part 1: What We Did Differently

### Evidence-Based Analysis

Most AI security tools take alert metadata, compare it against rules or ML models, and return a score. We take a different approach.

For each alert, we gather all associated forensic evidence: process execution chains showing parent-child relationships, network connections with source, destination, ports and bytes transferred, file system activity including creates, modifies, and deletes, and Windows security events. We then query threat intelligence for IOCs, retrieve contextually relevant knowledge from MITRE, historical alerts, and business rules, and send this comprehensive context to an LLM for reasoning.

This matters because an alert saying "PowerShell executed encoded command" is suspicious on its own. But when you see that the parent process was `services.exe` rather than `WINWORD.EXE`, the destination IP is Microsoft's update server, the file was created in `C:\Windows\SoftwareDistribution\`, and Windows events show it was the Windows Update service, you can confidently determine it's benign. Without the evidence, you can't make that determination.

### RAG-Augmented Context

Typical LLM security tools just send the alert JSON and ask if it's malicious. We use Retrieval-Augmented Generation with seven ChromaDB collections.

The `mitre_severity` collection contains 201 MITRE ATT&CK techniques with severity scores for mapping alerts to known attack patterns. The `historical_analyses` collection stores past alerts and how they were resolved so we can learn from precedent. The `business_rules` collection holds organization-specific policies like "Finance users don't run PowerShell." The `attack_patterns` collection contains real attack chains and IOCs for recognizing multi-stage attacks. The `detection_rules` collection has SIEM rule documentation to understand what triggered each alert. The `detection_signatures` collection provides context on why specific signatures fired. Finally, `company_infrastructure` contains asset inventory and criticality ratings so we know if we're looking at a critical server or a test VM.

The prompt to the LLM includes the alert with all forensic logs, OSINT enrichment on IPs, hashes, and domains, relevant documents from each RAG collection, and explicit instructions for chain-of-thought reasoning.

### Structured Output with Explainability

We don't just get a verdict. The LLM returns structured JSON with the verdict, a confidence score, an array of evidence points, step-by-step chain-of-thought reasoning, a narrative explanation, and actionable recommendations.

This matters because analysts can verify the AI's work, auditors can understand decisions, false positives can be debugged, and the AI's reasoning can be challenged.

### Cost-Optimized Model Selection

Running every alert through Claude Sonnet or GPT-4 costs $0.02-0.05 per alert. At 1000 alerts per day, that's $600-1500 per month. Our solution maps severity levels to appropriate models: critical and high alerts use claude-sonnet-4, medium alerts use claude-3-5-haiku at 80% less cost, and low alerts use claude-3-haiku at 90% less cost.

A low-severity alert analyzed by Haiku costs around $0.002 compared to $0.02 with Sonnet.

### Security Guards Against Prompt Injection

Since we're feeding untrusted data to an LLM, we need protection.

InputGuard scans incoming alerts for injection patterns, detects SQL injection, XSS, and command injection attempts, flags phrases like "ignore previous instructions," and sanitizes or blocks suspicious input. OutputGuard validates LLM response structure, checks that the verdict is valid, ensures confidence is in the 0-1 range, and scans recommendations for dangerous commands. DataProtectionGuard detects PII patterns like SSNs and credit cards, and can redact sensitive data before sending to the LLM.

### Auto-Triage for Low-Risk Benign Alerts

Between 70-90% of security alerts are false positives. Analysts waste time clicking "close" on routine activity. Our solution auto-closes alerts when the verdict is benign, confidence is at least 70%, and severity isn't critical or high.

We only auto-close if confidence exceeds 70%, never auto-close critical or high severity alerts, log the auto-close reason for audit, and analysts can still review in History.

### Real-Time Observability

The Debug Dashboard logs every API call with timing, every function call with parameters, and every AI decision with reasoning. You can filter by category and see real-time updates. The Performance Dashboard shows CPU and memory utilization, AI API costs per alert and total, token usage, queue depths, and error rates. The RAG Dashboard displays collection health status, query distribution, documents retrieved per alert, and which knowledge sources the AI actually used.

### S3 Failover System

The database is a single point of failure. If Supabase goes down, the entire system stops. Our S3 failover system enables continued operation during database outages.

In normal mode, reads and writes go to Supabase with background sync to S3 every 5 minutes. In failover mode when Supabase is down, reads fall back to S3 automatically and writes queue for sync back.

The system automatically detects failures after 3 consecutive DB failures and enters failover mode. All tables sync to S3 every 5 minutes. Query functions automatically try S3 when Supabase fails. When Supabase recovers, the system automatically exits failover mode. API endpoints are available at `/api/failover/status`, `/api/failover/sync`, and `/api/failover/test`.

One limitation: writes during failover are stored in S3 but not synced back to Supabase automatically. Manual reconciliation is required after recovery.

## Part 2: Honest Limitations

### LLM Hallucination Risk

LLMs can confidently state things that aren't true. Our chain-of-thought helps but doesn't eliminate this. We have output validation that checks basic structure, chain-of-thought that makes reasoning visible, and analysts can verify evidence citations. What we don't have is formal verification of reasoning, ground truth validation against a labeled dataset, or automated fact-checking of evidence claims.

Never use this system without human review for critical or high alerts. The AI assists; it doesn't decide.

### Garbage In, Garbage Out

If your SIEM isn't collecting quality logs, the AI has nothing to analyze. Forensic logs must be collected and stored, logs must be associated with alert IDs, and the log schema must match what we query. Without logs, the AI falls back to analyzing only alert metadata, which dramatically reduces accuracy.

### RAG Quality Depends on Seeding

The seven RAG collections are only as good as what you put in them. MITRE techniques are well-populated with 201 techniques. Historical alerts are empty until you've run for a while. Business rules and company infrastructure need to be defined and populated by you.

If collections are empty, the AI loses contextual awareness. It can't know "finance users don't run PowerShell" if you haven't told it.

### Cost Scales With Volume

At 1,000 alerts per day and $0.01 per alert, you're looking at $300 per month. At 10,000 alerts per day, that's $3,000 per month. At 100,000 alerts per day, that's $30,000 per month.

With our optimization assuming 70% low severity using Haiku, 20% medium using Haiku 3.5, and 10% high/critical using Sonnet, 100K alerts per month costs around $8,400 instead of $30,000. Still not free. Budget accordingly.

### API Dependency

We depend on Anthropic's API. If it's down, analysis stops. We have retry with exponential backoff, a queue system to hold alerts, and fallback rule-based classification. What we don't have is local LLM fallback, multi-provider failover, or offline analysis capability.

### No Active Response

This system analyzes and recommends. It does not isolate endpoints, block IPs, kill processes, send emails, or create tickets. Automated response is dangerous. An AI hallucination that auto-isolates the CEO's laptop would be catastrophic. Integrate with SOAR platforms for response, with human approval gates.

### Single-Tenant Architecture

This is designed for one organization. There's no multi-tenant isolation, per-customer data separation, usage billing per tenant, or role-based access control. Not suitable as a SaaS product without significant re-architecture.

### No Continuous Learning

The AI doesn't automatically learn from analyst decisions. What would be better: analyst closes as "False Positive" and the AI learns this pattern, analyst escalates and the AI learns this was serious, feedback loop improves over time. Currently, historical alerts are stored but there's no automated retraining or fine-tuning.

### English-Only

Prompts, UI, and analysis are all in English. Alerts with content in other languages may not be analyzed correctly.

### No Threat Hunting

This is reactive, not proactive. It analyzes alerts but doesn't hunt for threats. It only sees what your existing security tools detect.

## Part 3: What Would Make This Production-Ready

A labeled dataset with 1000+ alerts and ground truth verdicts would allow measuring precision, recall, and F1 scores, and tracking performance over time. A fine-tuned model trained on your organization's historical data would reduce hallucination for your specific context.

A feedback loop where analyst verdicts feed back to improve RAG, along with an automated retraining pipeline, would make the system learn over time. High availability would require multi-region deployment, API failover to a secondary provider, and local LLM fallback using models like Llama or Mistral.

RBAC and audit capabilities would need role-based access for analysts, managers, and admins, a complete audit trail, and SIEM integration for compliance. SOAR integration would enable automated playbook triggers, bi-directional case management, and response action orchestration.

## Summary

We did well on evidence-based analysis with full forensic context, RAG-augmented knowledge retrieval, explainable AI with chain-of-thought, cost optimization via model selection, security guards against prompt injection, auto-triage for low-risk alerts, full observability and transparency, and S3 failover for database resilience.

What's missing for production: ground truth validation, continuous learning loop, multi-provider AI failover, active response integration, multi-tenant architecture, and threat hunting capabilities.

This is a functional prototype that demonstrates the architecture and approach. It's suitable for learning and experimentation, small-scale deployment with human oversight, and proof-of-concept for stakeholders. It's not ready for unsupervised production deployment, high-volume enterprise SOC, or regulated environments without additional controls.

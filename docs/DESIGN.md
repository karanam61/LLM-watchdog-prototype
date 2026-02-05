# AI-SOC Watchdog Design Decisions

This document explains the thinking behind key design choices, from initial concept through full implementation.

## Starting Point: Understanding Log Processing

Applications interpret security logs through a straightforward pipeline. Logs arrive via HTTPS or message queues, a worker extracts structured fields like IPs, ports, and timestamps, then normalizes everything to a common schema. The system matches normalized data against rules and triggers actions when patterns match.

We decided early to accept both raw logs (from tools like Zeek) and pre-built alerts (from Splunk). A unified parser normalizes everything, so the rest of the system doesn't care about the source.

## Severity Classification

We use binary severity rather than numeric scores. Alerts are either CRITICAL_HIGH (ransomware, data exfiltration, infrastructure damage) or MEDIUM_LOW (reconnaissance, discovery, information gathering). Binary classification is simpler and matches how analysts actually work: they need to know whether to act now or whether it can wait.

## Queue Architecture

The system uses two queues with priority interruption. Critical alerts go to a priority queue and are processed immediately. Medium alerts go to a standard queue for batched processing. If a critical alert arrives while a medium alert is being processed, the system pauses and handles the critical one first. This prevents wasting AI budget on low-priority work when something urgent needs attention.

## Adding AI

Rule-based systems handle known patterns well but struggle with novel attacks, context-dependent decisions, and explaining their reasoning. We added Claude AI with retrieval-augmented generation to address these gaps.

We chose Claude 3.5 Sonnet over GPT-4 and local models after testing. Claude shows better reasoning for security analysis, costs less per token, follows structured output formats more reliably, and gives consistent responses at low temperature settings.

## Security Pipeline

AI systems processing external input face manipulation risks. An attacker could craft alert content designed to trick the AI into wrong verdicts. We built a six-phase pipeline with multiple protection layers.

Input guards check for prompt injection patterns before anything reaches the AI. Schema validation using Pydantic ensures data structure is correct. Data protection modules handle PII and credentials. The AI phase includes retry logic, rate limiting, timeouts, and fallback behavior for when the API fails. Output guards sanitize AI responses before they reach users. Finally, observability features track every decision for audit purposes.

We also track API costs with a daily budget limit and cache responses to avoid duplicate processing. These optimizations keep operational costs predictable.

## Knowledge Base Design

AI without context makes poor decisions. A PowerShell alert on a developer machine is very different from one on the CEO's laptop. We use ChromaDB to store seven collections of reference knowledge: MITRE ATT&CK technique descriptions, historical verdicts, organizational business rules, known attack patterns, detection rules, signature patterns, and infrastructure asset context.

For critical alerts, the system queries all seven collections. Medium alerts get reduced context to save costs. Cached results skip the AI entirely.

## Verdict Categories

We use three verdicts: malicious (confirmed threat needing immediate action), suspicious (possibly bad, needs investigation), and benign (false positive or authorized activity). Binary classification loses important nuance. Three categories match how analysts actually think about alerts.

Every AI response includes structured chain-of-thought reasoning. Analysts don't trust black boxes. Showing the AI's reasoning step by step builds trust and helps catch mistakes.

## Frontend Design

The dashboard has four focused pages rather than one cluttered view. The Analyst Console handles alert triage, which is the main workflow. The AI Dashboard shows performance metrics and costs. RAG Visualization provides transparency into what knowledge the AI accessed. System Debug shows real-time operation logs.

Different users need different information. Analysts care about verdicts, administrators care about costs, developers care about logs. Separate pages serve each role without cluttering the others.

We use a dark theme because SOC analysts work long hours and dark interfaces reduce eye strain. Color-coded verdicts (red, yellow, green) provide instant visual recognition of severity.

## Key Trade-offs

Budget versus accuracy was the biggest tension. More context means better AI decisions but higher costs. We chose adaptive context: critical alerts get full knowledge base queries, medium alerts get reduced context, and cached results skip the AI entirely.

For AI failures, we retry up to three times with exponential backoff, then fall back to rule-based classification. The system never leaves an alert stuck in limbo.

On security versus usability, we chose strict input validation even though it occasionally blocks legitimate alerts with unusual content. Blocked content gets logged for review and administrators can whitelist patterns if false positives occur. In a SOC context, security takes priority over convenience.

## What We Chose Not to Build

We skipped real-time streaming because batch processing handles alert volumes well enough. We avoided multi-model ensembles because a single model is simpler and sufficient. We didn't fine-tune a custom model because it's expensive and base Claude works well. We kept humans in the loop rather than automating remediation because automated responses are too risky. We didn't build a mobile app because SOC work is desktop-focused.

## Architecture Principles

The system follows defense in depth with multiple validation layers. When uncertain, it fails safe by classifying as suspicious rather than benign. Every decision gets logged with reasoning for audit purposes. The system degrades gracefully when the AI fails. Cost tracking prevents runaway API spending. Transparency shows users how decisions are made.

## Future Directions

Future work could add feedback loops to learn from analyst corrections, integrate threat intelligence feeds to update attack patterns automatically, support multiple organizations in a multi-tenant setup, or connect to SOAR platforms for playbook automation.

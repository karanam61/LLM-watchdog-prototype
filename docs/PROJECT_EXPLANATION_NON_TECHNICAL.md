# AI-SOC Watchdog: What It Actually Does

This is a prototype tool that helps security analysts triage alerts faster. It's not magic, and it doesn't replace analysts. It just saves them time on the tedious parts.

## The Problem

Security teams get flooded with alerts. Most are false alarms, but real attacks hide in there too. Analysts spend a lot of time on each alert gathering context, looking up IP addresses, checking what processes were running, cross-referencing threat databases. It's repetitive work.

## What This Tool Does

When an alert comes in, the system automatically gathers the relevant logs and context, checks threat intelligence databases for known bad IPs or file hashes, and sends everything to an AI (Claude) for analysis. The AI provides a verdict with its reasoning.

The analyst still decides what to do. The tool just does the legwork of gathering information and provides a second opinion.

## A Concrete Example

Say you get an alert: "PowerShell executed encoded command on FINANCE-WS-001."

Without this tool, you'd need to log into your endpoint security console, pull the process tree, decode the PowerShell command yourself, look up any external IPs, and piece together what happened.

With this tool, you'd see something like:

**Verdict: Likely Malicious (92% confidence)**

PowerShell was spawned from Microsoft Word, which suggests a macro. The command was base64 encoded and reached out to 185.220.101.45, which is a known Tor exit node. A file was downloaded to the Temp folder and executed. This matches common malware delivery patterns.

You can see the actual logs, the AI's reasoning, and decide whether to isolate the machine. The tool just got you to that decision faster.

## What It's Not

This is a prototype. It's not production-ready enterprise software. It doesn't learn from your company's specific environment in any sophisticated way. It can be wrong. It doesn't take any automated actions.

It's a proof of concept showing that AI can help with alert triage by handling the initial evidence gathering and providing analysis. Analysts remain in the loop for all decisions.

## The Technical Bits (briefly)

The backend ingests alerts, collects logs from simulated sources, queries threat intelligence APIs, and uses RAG (retrieval-augmented generation) to give the AI relevant context from a knowledge base of attack techniques. The frontend is a dashboard where analysts can review alerts and the AI's analysis.

There are safety checks to validate the AI's outputs make sense, and cost tracking since AI API calls aren't free.

That's it. A tool to help analysts work faster, not replace them.

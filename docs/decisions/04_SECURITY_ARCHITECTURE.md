# Security Architecture

Document 04 of 08
Last Updated: January 9, 2026
Status: Architecture Defined, Implementation Priorities Set

## Security Philosophy

### Core Principle: Defense in Depth

Never rely on one security control. An attacker must break through seven layers to compromise the system:

Layer 1: Network security (HTTPS, firewall)
Layer 2: Authentication (API keys, sessions)
Layer 3: Authorization (role-based access)
Layer 4: Input validation (SQL injection defense)
Layer 5: Output encoding (XSS defense)
Layer 6: Audit logging (detect breaches)
Layer 7: Encryption at rest (limit breach damage)

### Security vs Usability Trade-offs

Multi-Factor Authentication: Worth it for admin roles, not for analysts.

Data Encryption: Worth it for sensitive fields only to minimize performance cost (+10ms per query).

Zero Trust with Local AI: Not worth it for portfolio; document as a production trade-off due to high cost ($500k/year) and lower quality.

### Our Security Posture

Prioritized: Injection/XSS prevention, encryption/tokenization, audit logging, safe failure states.

Accepted Risks: External AI API (data leaves network), no zero-trust, single tenant isolation.

## AI Security (Guard Rails)

### Threat Landscape

Prompt Injection: Manipulating AI via crafted input.
Jailbreaking: Bypassing safety controls (e.g., "DAN" prompts).
Data Leakage: Extracting sensitive training or alert data.
Model Inversion: Reverse-engineering security rules.
Adversarial Examples: Imperceptible noise used to fool detection.

### Multi-Layer Guard Rails

Layer 1 - Input Sanitization (ML + Regex): Uses Lakera ML (95% detection) and Regex backups (80% detection) to block malicious phrasings and special tokens.

Layer 2 - Structured Prompts: Forces the AI into a strict "SOC Analyst" role with critical rules to ignore alert-text instructions.

Layer 3 - Output Validation: Checks for dangerous commands (`rm -rf /`), logical contradictions, and hallucinations (canary tokens).

Layer 4 - Pydantic Schema Enforcement: Forces AI to return structured, validated data or trigger an error.

## Data Privacy: The Great Debate

### Final Approach: Pragmatic Security

Database Tokenization (Implemented): Tokenize sensitive fields before storage to protect against DB breaches.

Real Data for AI (Implemented): Send real data to AI to maintain semantic context for analysis and RAG similarity.

Contractual Protection: Rely on Anthropic's policy (no training on API data, 30-day deletion, SOC 2 Type II).

Maximum Controls (Designed): Implement Lakera ML, audit logging, and rate limiting.

## Application Security: 10 Critical Gaps

1. API Authentication - Critical, Pending. Solution: Implement API keys and `@require_api_key` decorators.

2. SQL Injection - Critical, Fixed. Solution: Use Supabase ORM/Parameterized queries.

3. Command Injection - Critical, Fixed. Solution: Avoid `os.system()`; use `subprocess.run(shell=False)`.

4. Secrets Management - Important, Partial. Solution: Use `.env` with strict permissions; avoid logging keys.

5. Encryption at Rest - Important, Pending. Solution: Use Fernet or Supabase built-in encryption.

6. Session Management - Important, Pending. Solution: Implement 8-hour max sessions and 30-min inactivity timeouts.

7. Rate Limiting - Important, Pending. Solution: Implement per-user limits based on role (Analyst/Admin).

8. Audit Logging - Critical, Pending. Solution: Log "Who, What, When, Where, Why" to immutable logs.

9. Input Validation - Critical, Pending. Solution: Use Pydantic schemas for every API endpoint.

10. Error Handling - Important, Pending. Solution: Use generic error IDs for users; log full traces internally.

## Threat Model

External Attacker: Focuses on automated scanning and API abuse.
Malicious User: Focuses on alert manipulation and data exfiltration.
Insider Threat: Focuses on sabotage or data theft via legitimate access.
AI Attacker: Focuses on prompt injection to bypass security controls.

## Security Gaps and Roadmap

### Current Posture

Implemented: DB Tokenization, Supabase RLS, Basic Regex, S3 Backups, HTTPS.

Designed: Lakera Guard, Pydantic validation, Audit logging, API Auth, Rate limiting.

Known Gaps: See the 10 critical gaps above for pending items.

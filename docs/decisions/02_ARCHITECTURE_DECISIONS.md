# Architecture Decisions Record

**Document:** 02 of 08  
**Last Updated:** January 9, 2026  
**Status:** Backend Architecture 70% Complete

---

## Table of Contents
1. [System Architecture Overview](#system-architecture-overview)
2. [Alert Parser Design](#alert-parser-design)
3. [MITRE ATT&CK Mapper](#mitre-attck-mapper)
4. [Severity Classifier](#severity-classifier)
5. [Queue Manager Architecture](#queue-manager-architecture)
6. [Dynamic Budget Tracker](#dynamic-budget-tracker)
7. [Tokenization System](#tokenization-system)
8. [Database Architecture](#database-architecture)
9. [Actual Project Structure](#actual-project-structure)
10. [Component Integration](#component-integration)

---

## Documentation Note

**Code Snippets:** This document shows design decisions and architecture with code glimpses for understanding. Full production-ready code will be pushed to repository after AI analyzer completion.

**What's Shown:** Conceptual implementations demonstrating the design thinking behind each component.

**Actual Files:** See "Actual Project Structure" section for what's currently in the codebase.

---

## System Architecture Overview

### High-Level Flow

```
Alert Source (SIEM/IDS)
    ↓
[Parser] ← Extract structured fields
    ↓
[MITRE Mapper] ← Classify attack technique
    ↓
[Severity Classifier] ← Calculate risk score
    ↓
[Queue Manager] ← Route to priority/standard queue
    ↓
[Budget Tracker] ← Check budget availability
    ↓
[Tokenizer] ← Protect sensitive data (DB storage)
    ↓
[AI Analyzer] ← Claude API analysis
    ↓
[RAG] ← Historical context
    ↓
Result: Verdict + Confidence + Reasoning
```

### Technology Stack

**Backend (Implemented):**
- Language: Python 3.13
- Framework: Flask (REST API)
- Background Processing: Threading
- Alert Formats: Zeek, Suricata, Sysmon, Splunk (JSON)

**Database (Implemented):**
- Primary: Supabase (PostgreSQL)
- Features: Row Level Security, real-time subscriptions
- Backup: AWS S3 (via Terraform)

**AI/ML (In Progress):**
- Primary AI: Claude Sonnet 4.5 (Anthropic API)
- Vector DB: ChromaDB (planned for RAG)
- ML Security: Lakera Guard (designed, not yet integrated)
- Validation: Pydantic (designed, not yet integrated)

**Frontend (Basic Structure):**
- Framework: React
- Dev Server: Vite (localhost:5173)
- State Management: TBD

**Infrastructure (Implemented):**
- IaC: Terraform (AWS S3 backup - working)
- Secrets: .env files (API_key claude.txt, AWSkey.txt)
- Deployment: TBD (Docker planned)

---

## Alert Parser Design

### Purpose
Convert raw alert data from various sources (Zeek, Suricata, Sysmon) into standardized format for processing.

### Input Formats Supported

**1. Zeek Logs (Network monitoring)**
```json
{
    "ts": 1704672345.123456,
    "uid": "CXY9a54Dpn9UH4tq4j",
    "id.orig_h": "192.168.1.100",
    "id.orig_p": 45678,
    "id.resp_h": "203.0.113.50",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "conn_state": "SF"
}
```

**2. Suricata Alerts (IDS)**
```json
{
    "timestamp": "2024-01-07T19:45:23.582Z",
    "alert": {
        "signature": "ET MALWARE Suspicious Outbound Connection",
        "category": "Potential Corporate Privacy Violation",
        "severity": 2
    },
    "src_ip": "10.0.0.45",
    "dest_ip": "8.8.8.8",
    "proto": "UDP"
}
```

**3. Sysmon Events (Windows monitoring)**
```json
{
    "EventID": 1,
    "UtcTime": "2024-01-07 19:45:23.582",
    "ProcessId": 1234,
    "Image": "C:\\Windows\\System32\\powershell.exe",
    "CommandLine": "powershell.exe -enc JABhAD0A...",
    "User": "DOMAIN\\john.smith"
}
```

**4. Splunk Format (Enterprise SIEM)**
```json
{
    "_time": "2024-01-07T19:45:23.582Z",
    "sourcetype": "windows:security",
    "host": "DESKTOP-001",
    "source": "WinEventLog:Security",
    "EventCode": 4625,
    "Account_Name": "john.smith",
    "Workstation_Name": "DESKTOP-001",
    "Source_Network_Address": "192.168.1.100",
    "_raw": "An account failed to log on..."
}
```

### Standardized Output Schema

```python
{
    'alert_id': 'ALERT_1704672345_001',
    'alert_name': 'Suspicious PowerShell Execution',
    'description': 'PowerShell executed with encoded command',
    'source_ip': '192.168.1.100',
    'dest_ip': '203.0.113.50',
    'username': 'john.smith@company.com',
    'hostname': 'DESKTOP-WIN10-001',
    'timestamp': '2024-01-07T19:45:23.582Z',
    'raw_log': {...},  # Original alert
    'source_system': 'sysmon'
}
```

### Design Decision: Field Mapping Strategy

**Challenge:** Different alert sources use different field names.

**Options Considered:**
1. **Hardcode mapping per source** - Fast but brittle
2. **AI-based field extraction** - Flexible but expensive
3. **Configurable mapping rules** - Middle ground

**Decision:** Configurable mapping with sensible defaults

**Implementation:**
```python
class AlertParser:
    """
    Parse alerts from multiple sources into standard format
    """
    
    FIELD_MAPPINGS = {
        'zeek': {
            'source_ip': 'id.orig_h',
            'dest_ip': 'id.resp_h',
            'timestamp': 'ts'
        },
        'suricata': {
            'source_ip': 'src_ip',
            'dest_ip': 'dest_ip',
            'alert_name': 'alert.signature',
            'severity': 'alert.severity'
        },
        'sysmon': {
            'username': 'User',
            'process': 'Image',
            'command_line': 'CommandLine',
            'timestamp': 'UtcTime'
        },
        'splunk': {
            'timestamp': '_time',
            'hostname': 'host',
            'source_ip': 'Source_Network_Address',
            'username': 'Account_Name',
            'alert_name': 'sourcetype',
            'description': '_raw'
        }
    }
    
    def parse(self, alert, source_system):
        """
        Extract fields based on source system
        """
        mapping = self.FIELD_MAPPINGS.get(source_system, {})
        
        standardized = {}
        for standard_field, source_field in mapping.items():
            value = self._extract_nested_field(alert, source_field)
            if value:
                standardized[standard_field] = value
        
        return standardized
```

**Reasoning:**
- Easy to add new sources (just add mapping)
- Testable (unit test each mapping)
- Maintainable (mappings in one place)

### Critical Bug Found & Fixed (Day 1)

**Problem:**
```python
# parser.py returned this format:
{
    'alert': {
        'alert_name': 'Test',
        'description': 'Test alert'
    }
}

# But app.py expected:
{
    'alert_name': 'Test',
    'description': 'Test alert'
}

# Result: All alerts failed with "Missing alert_name"
```

**Root Cause:** Parser wrapped output in extra 'alert' key.

**Fix:**
```python
# Before (wrong):
return {'alert': standardized_alert}

# After (correct):
return standardized_alert
```

**Lesson Learned:** Always test integration points, not just individual components.

---

## MITRE ATT&CK Mapper + Attack Damage Integration

### Purpose
Classify alerts into MITRE ATT&CK techniques AND assign economic damage scores for risk-based prioritization.

### File Structure (Integrated System)
```
backend/core/
├── mitre_mapping.py        # Pattern matching + classification
└── attack_damage_data.py   # Damage costs (0-100) for 100+ techniques
```

**These work together:** mitre_mapping.py identifies technique → attack_damage_data.py provides damage cost.

### MITRE ATT&CK Framework Context

**What is MITRE ATT&CK?**
- Globally recognized knowledge base of adversary tactics and techniques
- Based on real-world observations
- Used by security teams worldwide for threat detection and classification

**Example Techniques with Damage Scores:**
```
T1059 - Command and Scripting Interpreter    (Damage: 65)
T1486 - Data Encrypted for Impact            (Damage: 95 - Ransomware)
T1078 - Valid Accounts                       (Damage: 75 - Stolen Creds)
T1190 - Exploit Public-Facing Application    (Damage: 85)
```

### Mapping Strategy

**Input:** Alert with description/signature  
**Output:** MITRE technique ID + confidence

**Approach:** Rule-based pattern matching (Phase 1)

```python
class MitreMapper:
    """
    Map alerts to MITRE ATT&CK techniques
    """
    
    TECHNIQUE_PATTERNS = {
        'T1059': {  # Command and Scripting Interpreter
            'patterns': [
                r'powershell.*-enc',
                r'cmd\.exe.*&&',
                r'bash.*curl.*\|.*sh',
                r'python.*-c'
            ],
            'name': 'Command and Scripting Interpreter',
            'tactic': 'Execution'
        },
        'T1486': {  # Ransomware
            'patterns': [
                r'encrypt.*files',
                r'\.locked$',
                r'ransom.*note',
                r'crypto.*locker'
            ],
            'name': 'Data Encrypted for Impact',
            'tactic': 'Impact'
        },
        'T1078': {  # Stolen Credentials
            'patterns': [
                r'failed.*login.*\d+.*times',
                r'brute.*force',
                r'credential.*dump',
                r'mimikatz'
            ],
            'name': 'Valid Accounts',
            'tactic': 'Initial Access'
        }
    }
    
    def map_technique(self, alert):
        """
        Identify MITRE technique from alert content
        """
        description = alert.get('description', '').lower()
        alert_name = alert.get('alert_name', '').lower()
        
        search_text = f"{alert_name} {description}"
        
        for technique_id, technique_data in self.TECHNIQUE_PATTERNS.items():
            for pattern in technique_data['patterns']:
                if re.search(pattern, search_text, re.IGNORECASE):
                    return {
                        'mitre_technique': technique_id,
                        'technique_name': technique_data['name'],
                        'tactic': technique_data['tactic'],
                        'confidence': 0.8  # Rule-based = high confidence
                    }
        
        # No match found
        return {
            'mitre_technique': 'UNKNOWN',
            'technique_name': 'Unclassified',
            'tactic': 'Unknown',
            'confidence': 0.0
        }
```

### Critical Design Decision: Handling Unknown Techniques

**Challenge:** What if alert doesn't match any known pattern?

**Options Considered:**

1. **Reject alert** - Don't process unknowns
   - ❌ Loses potentially valuable alerts
   - ❌ Can't learn from novel attacks

2. **Default to generic technique** - Assign T0000
   - ❌ Pollutes MITRE database with fake IDs
   - ❌ Confusion in reporting

3. **Use "UNKNOWN" sentinel value** - Special marker
   - ✅ Clear that technique wasn't identified
   - ✅ Can still process alert
   - ✅ Can track classification rate

**Decision:** Use "UNKNOWN" as special sentinel value

**Implementation:**
```python
# In database:
mitre_technique = 'UNKNOWN'  # String, not NULL

# In queue manager:
if alert['mitre_technique'] == 'UNKNOWN':
    # Route to standard queue (lower priority)
    # AI will need to classify from scratch
```

**Critical Bug Found (Day 3):**

**Problem:**
```python
# mitre_mapping.py tried to lookup damage score:
damage = db.get_damage_score(mitre_technique)

# But db.get_damage_score() returned None for 'UNKNOWN'
# Code crashed: int(None) * risk_score
```

**Fix:**
```python
def get_damage_score(self, technique):
    if technique == 'UNKNOWN':
        return 50  # Default medium severity
    
    result = db.query(technique)
    if result:
        return result['damage_cost']
    else:
        return 50  # Fallback
```

**Reasoning:**
- UNKNOWN alerts should still be processed
- Default to medium severity (not high, not low)
- Prevents crashes from missing database entries

### Future Enhancement: ML-Based Classification

**Phase 2 Plan:**
- Train ML model on labeled alerts
- Use embeddings for semantic similarity
- Confidence scores based on model certainty
- Fallback to rule-based if confidence < 0.7

---

## Severity Classifier

### Purpose
Calculate risk score (0-200) based on multiple factors to prioritize alerts.

### Risk Scoring Formula

```python
Risk Score = Base Severity + MITRE Impact + Context Multipliers

Where:
- Base Severity: Alert source's native severity (0-50)
- MITRE Impact: Attack technique damage score (0-100)
- Context Multipliers: Additional risk factors
```

### Implementation

```python
class SeverityClassifier:
    """
    Calculate risk score for alert prioritization
    """
    
    SEVERITY_WEIGHTS = {
        'CRITICAL': 50,
        'HIGH': 40,
        'MEDIUM': 25,
        'LOW': 10,
        'INFO': 0
    }
    
    def classify(self, alert):
        """
        Calculate risk score (0-200 scale)
        """
        
        # Component 1: Base severity from alert source
        base_severity = self._get_base_severity(alert)
        
        # Component 2: MITRE technique damage score
        mitre_impact = self._get_mitre_impact(alert)
        
        # Component 3: Context multipliers
        multiplier = self._calculate_multipliers(alert)
        
        # Final score
        risk_score = (base_severity + mitre_impact) * multiplier
        
        # Classify into buckets
        if risk_score >= 150:
            severity_class = 'CRITICAL_HIGH'
        elif risk_score >= 100:
            severity_class = 'HIGH'
        elif risk_score >= 50:
            severity_class = 'MEDIUM'
        else:
            severity_class = 'LOW'
        
        return {
            'risk_score': min(risk_score, 200),  # Cap at 200
            'severity_class': severity_class,
            'components': {
                'base': base_severity,
                'mitre': mitre_impact,
                'multiplier': multiplier
            }
        }
    
    def _calculate_multipliers(self, alert):
        """
        Context-based risk multipliers
        """
        multiplier = 1.0
        
        # External IP = higher risk
        dest_ip = alert.get('dest_ip', '')
        if not dest_ip.startswith(('10.', '192.168', '172.')):
            multiplier *= 1.3
        
        # Privileged user = higher risk
        username = alert.get('username', '').lower()
        if 'admin' in username or 'root' in username:
            multiplier *= 1.5
        
        # Known bad indicators
        description = alert.get('description', '').lower()
        if any(word in description for word in ['malware', 'ransomware', 'exploit']):
            multiplier *= 1.4
        
        return multiplier
```

### Design Decision: Why Risk Scores, Not Just Severity?

**Challenge:** Different alert sources use different severity scales.

**Problem:**
```
Zeek: conn_state = "S0" (no reply) → Severity unknown
Suricata: severity = 2 → High
Sysmon: No severity field at all
```

**Options Considered:**

1. **Use source severity only** - Simple but inconsistent
2. **Normalize all to 1-5 scale** - Loses nuance
3. **Calculate unified risk score** - Complex but accurate

**Decision:** Calculate unified 0-200 risk score

**Reasoning:**
- Combines multiple signals (severity + MITRE + context)
- Comparable across all alert sources
- Enables fine-grained prioritization
- Supports budget allocation decisions

**Trade-off:** More complex, requires tuning, but much better prioritization.

---

## Queue Manager Architecture

### Purpose
Route alerts to appropriate processing queue (priority vs standard) based on risk and attack damage potential.

### Queue Strategy Evolution

**Initial Approach (Day 1-2): Tier-Based Filtering**
```
Tier 1 (Rules): Filter obvious benign → 70% filtered
Tier 2 (AI): Analyze rest → 30% analyzed
Budget: Split evenly between tiers
```

**Problem Identified (Day 2):**
```
User question: "What if all high-priority alerts arrive at once?"

Issue:
- Priority tier budget: $5/day
- 100 ransomware alerts arrive
- Cost to analyze all: $15
- Result: 67% of priority alerts skipped!
```

**Realization:** Static tier budgets waste resources and miss threats.

### New Approach: Dynamic Queue-Based Allocation

**Key Insight:** Budgets should be dynamic, not static.

**Architecture:**
```
Two Queues:
├── Priority Queue (high risk, high damage potential)
└── Standard Queue (lower risk)

Budget Allocation:
├── Process priority queue FIRST
├── Use budget until exhausted
├── Switch to standard queue with remaining budget
└── Reserve 10% for late-arriving priority alerts
```

**Implementation:**
```python
class QueueManager:
    """
    Risk-based alert routing with dynamic budget allocation
    """
    
    def __init__(self):
        self.priority_queue = []
        self.standard_queue = []
        self.risk_threshold = 100  # Configurable
    
    def route_alert(self, alert):
        """
        Route alert to appropriate queue
        
        Priority queue if:
        - Risk score >= 100, OR
        - MITRE technique has high damage cost (>70)
        """
        
        risk_score = alert.get('risk_score', 0)
        mitre_technique = alert.get('mitre_technique')
        attack_damage = self._get_attack_damage(mitre_technique)
        
        if risk_score >= self.risk_threshold or attack_damage >= 70:
            self.priority_queue.append(alert)
            alert['queue'] = 'priority'
        else:
            self.standard_queue.append(alert)
            alert['queue'] = 'standard'
        
        return alert
    
    def get_next_for_analysis(self):
        """
        Get next alert to analyze (priority first)
        """
        
        # Always process priority queue first
        if self.priority_queue:
            return self.priority_queue.pop(0)
        
        # Fallback to standard queue
        if self.standard_queue:
            return self.standard_queue.pop(0)
        
        return None
```

### Critical Design Decision: Priority Queue Criteria

**Question:** What makes an alert "priority"?

**Options Considered:**

1. **Risk score only** - Simple but ignores attack impact
   ```python
   if risk_score > 100: priority
   ```

2. **MITRE technique only** - Ignores context
   ```python
   if technique in ['T1486', 'T1190']: priority
   ```

3. **Hybrid approach** - Best of both
   ```python
   if (risk_score > 100) OR (attack_damage > 70): priority
   ```

**Decision:** Hybrid approach (risk OR damage)

**Reasoning:**
```
Example 1: Low-severity alert, but T1486 (ransomware)
- Risk score: 60 (below threshold)
- Attack damage: 95 (catastrophic)
- Decision: PRIORITY (damage trumps risk score)

Example 2: High-risk alert, unknown technique
- Risk score: 120 (above threshold)
- Attack damage: 0 (unknown technique)
- Decision: PRIORITY (risk score sufficient)

Example 3: Medium alert, low-impact technique
- Risk score: 50
- Attack damage: 20 (port scan)
- Decision: STANDARD (neither criteria met)
```

**User's Critical Question (Day 2):**
> "What if we get flooded with priority alerts? All budget goes to priority?"

**Answer:** Reserve mechanism (10% budget held back for late arrivals).

---

## Dynamic Budget Tracker

### Purpose
Ensure AI analysis costs stay within daily budget while maximizing threat coverage.

### Budget Philosophy Evolution

**Phase 1: Static Tier Splits (Rejected)**
```
Daily budget: $10
Split: $5 priority, $5 standard

Problem:
- What if only 30 priority alerts arrive? ($3 used)
- Remaining $2 wasted (can't be used for standard)
- Or: 200 priority alerts arrive ($20 needed)
- Only first 50 get analyzed, rest skipped
```

**Phase 2: Dynamic Allocation (Current)**
```
Daily budget: $10
Strategy:
1. Process priority queue with 90% of budget ($9)
2. Switch to standard queue with remaining 10% ($1)
3. Reserve kicks in if priority alerts arrive late
```

### Implementation

```python
class DynamicBudgetTracker:
    """
    Track and enforce AI analysis budget
    """
    
    def __init__(self, daily_budget=10.0):
        self.daily_budget = daily_budget
        self.spent_today = 0.0
        self.reserve_percent = 0.10  # 10% reserve
        self.priority_spent = 0.0
        self.standard_spent = 0.0
    
    def can_analyze(self, alert_queue):
        """
        Check if budget allows analysis
        
        Returns: (can_analyze, budget_available, reason)
        """
        
        usable_budget = self.daily_budget * (1 - self.reserve_percent)
        
        if alert_queue == 'priority':
            # Priority can use up to 90% of daily budget
            if self.spent_today < usable_budget:
                return (True, usable_budget - self.spent_today, "Budget available")
            else:
                return (False, 0, "Priority budget exhausted, using reserve")
        
        else:  # standard queue
            # Standard queue uses remaining budget
            remaining = self.daily_budget - self.spent_today
            if remaining > 0:
                return (True, remaining, "Using remaining budget")
            else:
                return (False, 0, "Daily budget exhausted")
    
    def record_cost(self, cost, alert_queue):
        """
        Record cost after analysis
        """
        self.spent_today += cost
        
        if alert_queue == 'priority':
            self.priority_spent += cost
        else:
            self.standard_spent += cost
        
        print(f"💰 Spent: ${cost:.4f} | Total: ${self.spent_today:.2f}/${self.daily_budget}")
```

### Key Design Decision: Reserve Budget

**User Question (Day 2):**
> "What if a critical ransomware alert arrives at 11:59pm when budget is exhausted?"

**Problem:**
```
11:50 PM: Budget exhausted ($10/$10)
11:59 PM: T1486 ransomware alert arrives
Decision: Skip analysis (no budget)
Result: Ransomware goes undetected
```

**Solution:** Reserve mechanism
```python
# Reserve 10% ($1) of daily budget
reserve = daily_budget * 0.10

# Priority queue can use:
# - 90% of budget normally
# - Tap into reserve if critical alert late in day

if alert_queue == 'priority' and is_late_in_day():
    can_use_reserve = True
```

**Reasoning:**
- Critical threats shouldn't be skipped due to timing
- 10% reserve = ~1-2 extra priority analyses
- Balance between coverage and cost control

### Budget Reset Logic

```python
def check_reset(self):
    """
    Reset budget at midnight UTC
    """
    
    current_date = datetime.now(timezone.utc).date()
    
    if current_date != self.last_reset_date:
        print(f"\n🔄 Budget reset: {self.last_reset_date} → {current_date}")
        print(f"   Yesterday: ${self.spent_today:.2f}")
        print(f"   Priority: ${self.priority_spent:.2f}")
        print(f"   Standard: ${self.standard_spent:.2f}")
        
        # Reset counters
        self.spent_today = 0.0
        self.priority_spent = 0.0
        self.standard_spent = 0.0
        self.last_reset_date = current_date
```

---

## Tokenization System

### Purpose
Protect sensitive data (usernames, emails, hostnames) when stored in database.

### Why Tokenization? (Not for AI)

**Critical User Insight:**
> "We have tokenizer.py for database. Why do we need it for AI?"

**Answer:** We DON'T tokenize for AI. Here's why:

**Tokenization for Database (Good):**
```
Alert arrives
    ↓
AI analyzes with REAL data (needs it for semantic understanding)
    ↓
Store in DB with TOKENIZED data (protect against DB breach)
    ↓
Analyst views DETOKENIZED data (needs it for investigation)
```

**Tokenization for AI (Bad):**
```
Alert: "john.smith accessed server"
Tokenized: "TOKEN_123 accessed server"
Send to Claude: "TOKEN_123 accessed server"

Problems:
1. AI has no context ("who is TOKEN_123?")
2. RAG can't find similar incidents (semantic similarity broken)
3. Still correlatable across requests (Claude sees TOKEN_123 multiple times)
```

### Implementation

```python
class Tokenizer:
    """
    Tokenize sensitive fields for database storage
    """
    
    def __init__(self):
        self.token_map = {}  # value → token
        self.reverse_map = {}  # token → value
        self.counter = 0
    
    def tokenize(self, value):
        """
        Convert value to token
        """
        if value in self.token_map:
            return self.token_map[value]
        
        token = f"TOKEN_{self.counter:06d}"
        self.counter += 1
        
        self.token_map[value] = token
        self.reverse_map[token] = value
        
        return token
    
    def detokenize(self, token):
        """
        Convert token back to original value
        """
        return self.reverse_map.get(token)
    
    def tokenize_alert(self, alert):
        """
        Tokenize sensitive fields only
        """
        tokenized = alert.copy()
        
        # Tokenize identifiers
        if 'username' in tokenized:
            tokenized['username'] = self.tokenize(tokenized['username'])
        
        if 'hostname' in tokenized:
            tokenized['hostname'] = self.tokenize(tokenized['hostname'])
        
        # DON'T tokenize IPs or attack indicators
        # (needed for analysis)
        
        return tokenized
```

### What Gets Tokenized

```python
✅ TOKENIZE (for database storage):
- username
- email
- employee_id
- hostname (if contains user info)

❌ DON'T TOKENIZE:
- source_ip (needed for threat intel)
- dest_ip (needed for threat intel)
- description (contains attack indicators)
- file_hash (needed for IOC matching)
- command_line (needed for malware analysis)
- MITRE technique (classification data)
```

### User's Critical Question (Day 9):
> "So tokenizer.py is basically shit?"

**Answer:** NO! It's essential for database security.

**Correct Usage:**
```
1. Alert arrives (real data)
2. AI analyzes (real data - needs semantic context)
3. Store in DB (tokenized data - protect against breach)
4. Analyst views (detokenized data - needs to investigate)
```

**The tokenizer protects data AT REST, not in transit to AI.**

---

## Database Architecture

### Technology: Supabase (PostgreSQL)

**Why Supabase?**
- ✅ Managed PostgreSQL (don't manage own DB)
- ✅ Built-in Row Level Security (RLS)
- ✅ Real-time subscriptions (for dashboard updates)
- ✅ RESTful API out of the box
- ✅ Free tier sufficient for demo

### Schema Design

**Primary Tables:**

```sql
-- Alerts table
CREATE TABLE alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    alert_name TEXT NOT NULL,
    description TEXT NOT NULL,
    
    -- Tokenized fields
    username_token TEXT,
    hostname_token TEXT,
    
    -- Network info (not tokenized)
    source_ip TEXT,
    dest_ip TEXT,
    
    -- Classification
    mitre_technique TEXT NOT NULL,
    severity_class TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    queue TEXT NOT NULL,  -- 'priority' or 'standard'
    
    -- AI analysis
    ai_analyzed BOOLEAN DEFAULT FALSE,
    ai_verdict TEXT,
    ai_confidence REAL,
    ai_reasoning TEXT,
    ai_cost REAL,
    ai_tokens INTEGER,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    analyzed_at TIMESTAMP,
    
    -- Raw data
    raw_log JSONB
);

-- Token mappings
CREATE TABLE token_mappings (
    id BIGSERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    encrypted_value TEXT NOT NULL,  -- Fernet encrypted
    created_at TIMESTAMP DEFAULT NOW()
);

-- MITRE attack damage database
CREATE TABLE mitre_techniques (
    technique_id TEXT PRIMARY KEY,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    damage_cost INTEGER NOT NULL,
    description TEXT,
    examples TEXT[]
);

-- Feedback for accuracy tracking
CREATE TABLE feedback (
    id BIGSERIAL PRIMARY KEY,
    alert_id BIGINT REFERENCES alerts(id),
    ai_verdict TEXT NOT NULL,
    ai_confidence REAL NOT NULL,
    analyst_verdict TEXT NOT NULL,
    ai_was_correct BOOLEAN NOT NULL,
    was_helpful BOOLEAN NOT NULL,
    analyst_notes TEXT,
    feedback_timestamp TIMESTAMP DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    action TEXT NOT NULL,
    user_id INTEGER,
    user_ip TEXT,
    details JSONB
);
```

### Row Level Security (RLS)

**Why RLS?**
- User A shouldn't see User B's alerts
- Analyst role can view, Engineer role can modify
- Database-level enforcement (can't bypass)

**Implementation:**
```sql
-- Enable RLS
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own organization's alerts
CREATE POLICY user_org_isolation ON alerts
    FOR SELECT
    USING (org_id = current_user_org());

-- Policy: Only admins can delete
CREATE POLICY admin_delete ON alerts
    FOR DELETE
    USING (is_admin(current_user_id()));
```

### Backup Strategy

**Primary:** Supabase automatic backups (daily)  
**Secondary:** AWS S3 (via Terraform)

```hcl
# terraform/s3_backup.tf
resource "aws_s3_bucket" "alert_backup" {
  bucket = "ai-soc-watchdog-backup"
  
  versioning {
    enabled = true
  }
  
  lifecycle_rule {
    enabled = true
    
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
}
```

**Backup Schedule:**
- Daily: Supabase automatic
- Weekly: Export to S3
- Monthly: Verify restore capability

### Attack Damage Data Integration

**File:** `backend/core/attack_damage_data.py`

**Purpose:** Store economic damage costs for 100+ MITRE techniques

**Data Structure:**
```python
ATTACK_DAMAGE_SCORES = {
    'T1486': {
        'name': 'Data Encrypted for Impact',
        'tactic': 'Impact',
        'damage_cost': 95,
        'description': 'Ransomware encryption',
        'examples': ['WannaCry', 'Ryuk', 'REvil']
    },
    'T1190': {
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access', 
        'damage_cost': 85,
        'description': 'Web app exploitation',
        'examples': ['Log4Shell', 'ProxyLogon']
    },
    # ... 100+ more techniques
}
```

**How mitre_mapping.py Uses It:**
```python
# In mitre_mapping.py
from backend.core.attack_damage_data import ATTACK_DAMAGE_SCORES

class MitreMapper:
    def map_technique(self, alert):
        # Step 1: Identify technique
        technique_id = self._pattern_match(alert)
        
        # Step 2: Get damage score
        damage_data = ATTACK_DAMAGE_SCORES.get(technique_id)
        
        return {
            'mitre_technique': technique_id,
            'technique_name': damage_data['name'],
            'damage_cost': damage_data['damage_cost'],
            'tactic': damage_data['tactic']
        }
```

### Damage Cost Scale (0-100)

```
90-100: Catastrophic (ransomware, data destruction)
70-89:  Severe (data breach, system compromise)
50-69:  High (malware execution, privilege escalation)
30-49:  Medium (reconnaissance, persistence)
10-29:  Low (scanning, probing)
0-9:    Minimal (info gathering, failed attempts)
```

**Data Sources:**
- IBM Cost of Data Breach Report
- Verizon DBIR
- Ponemon Institute studies
- CISA advisories

---

## Actual Project Structure

### Current Directory Layout (As Implemented)

```
AI PROJECT/
├── backend/
│   ├── ai/
│   │   ├── __init__.py
│   │   └── dynamic_budget_tracker.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── attack_damage_data.py      # 100+ MITRE damage scores
│   │   ├── mitre_mapping.py           # Pattern matching
│   │   ├── parser.py                  # Multi-source parsing
│   │   ├── Queue_manager.py           # Priority routing
│   │   └── Severity.py                # Risk scoring
│   ├── security/
│   │   ├── __init__.py
│   │   └── tokenizer.py               # DB tokenization
│   └── storage/
│       └── __init__.py
├── soc-dashboard/                     # React frontend
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── assets/
│   ├── package.json
│   └── vite.config.js
├── terraform-s3/                      # AWS backup
│   ├── main.tf
│   └── terraform.tfstate
├── docs/
├── tests/
├── .env                               # Secrets (not committed)
├── app.py                             # Flask API
└── README.md
```

### What's IMPLEMENTED (In Codebase)

```
✅ Alert parser (Zeek, Suricata, Sysmon, Splunk)
✅ MITRE mapper + attack damage integration
✅ Severity classifier
✅ Queue manager
✅ Dynamic budget tracker
✅ Tokenizer (database-level)
✅ Supabase schema
✅ Terraform S3 backup
✅ React frontend (basic structure)
✅ Flask API (app.py)
```

### What's DESIGNED But Not Yet Coded

```
⏳ AI Analyzer (architecture complete, code in progress)
⏳ Pydantic validation (discussed, not implemented)
⏳ Lakera Guard (integration designed)
⏳ RAG with ChromaDB (planned)
⏳ Production AI analyzer (this document)
```

**Note:** This documentation describes both what EXISTS and what's PLANNED. Each section clearly marks implementation status.

---

## Attack Damage Database

*[Section removed - integrated with MITRE mapper above]*

---

## Component Integration

### Worker Architecture

**Design:** Background processing with Flask API

```python
# worker.py
class AlertWorker:
    """
    Background worker that processes alerts
    """
    
    def __init__(self):
        self.parser = AlertParser()
        self.mitre_mapper = MitreMapper()
        self.severity_classifier = SeverityClassifier()
        self.queue_manager = QueueManager()
        self.budget_tracker = DynamicBudgetTracker()
        self.tokenizer = Tokenizer()
        self.running = False
    
    def start(self):
        """
        Start worker in background thread
        """
        self.running = True
        thread = threading.Thread(target=self._process_loop)
        thread.daemon = True
        thread.start()
    
    def _process_loop(self):
        """
        Continuous processing loop
        """
        while self.running:
            # Get next alert from queue
            alert = self.queue_manager.get_next_for_analysis()
            
            if alert is None:
                time.sleep(1)
                continue
            
            # Check budget
            can_analyze, budget, reason = self.budget_tracker.can_analyze(alert['queue'])
            
            if not can_analyze:
                print(f"⏭️ Skipping alert (budget exhausted): {alert['alert_id']}")
                continue
            
            # Analyze with AI
            result = self.ai_analyzer.analyze(alert)
            
            # Record cost
            self.budget_tracker.record_cost(result['_metadata']['cost'], alert['queue'])
            
            # Tokenize before storing
            tokenized_alert = self.tokenizer.tokenize_alert(alert)
            
            # Store result
            self.db.store_analysis(tokenized_alert, result)
```

### Flask API Integration

```python
# app.py
from flask import Flask, request, jsonify
from worker import AlertWorker

app = Flask(__name__)
worker = AlertWorker()

@app.route('/api/alert', methods=['POST'])
def submit_alert():
    """
    Receive alert from SIEM/IDS
    """
    try:
        # Parse alert
        raw_alert = request.json
        parsed = worker.parser.parse(raw_alert, source='zeek')
        
        # Map MITRE technique
        mitre_result = worker.mitre_mapper.map_technique(parsed)
        parsed.update(mitre_result)
        
        # Calculate severity
        severity_result = worker.severity_classifier.classify(parsed)
        parsed.update(severity_result)
        
        # Route to queue
        worker.queue_manager.route_alert(parsed)
        
        return jsonify({
            'status': 'queued',
            'alert_id': parsed['alert_id'],
            'queue': parsed['queue'],
            'risk_score': parsed['risk_score']
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    # Start worker
    worker.start()
    
    # Start API
    app.run(port=5000)
```

### Critical Debugging: Python Module System (Day 3)

**Problem:**
```python
# Running as script:
python backend/worker/worker.py

# Import fails:
from backend.parser import AlertParser
# ModuleNotFoundError: No module named 'backend'
```

**Root Cause:** Python's `sys.path` doesn't include project root when running as script.

**Solution Options:**

1. **Run as module (correct):**
```bash
python -m backend.worker.worker
```

2. **Add to PYTHONPATH:**
```bash
export PYTHONPATH=/path/to/project:$PYTHONPATH
python backend/worker/worker.py
```

3. **Modify sys.path in code (hacky):**
```python
import sys
sys.path.insert(0, '/path/to/project')
```

**Decision:** Always run as module (`python -m`)

**Project Structure:**
```
ai-soc-watchdog/
├── backend/
│   ├── __init__.py
│   ├── parser/
│   │   ├── __init__.py
│   │   └── parser.py
│   ├── worker/
│   │   ├── __init__.py
│   │   └── worker.py
│   └── ai/
│       ├── __init__.py
│       └── analyzer.py
├── test_alert.py
└── app.py
```

**Lesson Learned:** Proper Python package structure is essential for imports.

---

## Key Takeaways

### What Worked Well

1. **Modular design** - Each component testable independently
2. **Queue-based processing** - Dynamic, efficient resource use
3. **Risk-based prioritization** - Threats get attention first
4. **Database tokenization** - Protects sensitive data at rest
5. **Iterative debugging** - Fixed issues as they appeared

### What We'd Change in Production

1. **Message queue** - Use RabbitMQ/Redis instead of in-memory
2. **Distributed workers** - Multiple workers for scale
3. **Better monitoring** - Prometheus metrics, Grafana dashboards
4. **Circuit breakers** - Prevent cascade failures
5. **Health checks** - Automated system health monitoring

### Critical Questions That Improved Design

1. **"What if priority queue gets all budget?"** → Reserve mechanism
2. **"How do we handle UNKNOWN techniques?"** → Sentinel value + default damage
3. **"Why tokenize for AI?"** → Realized we shouldn't, only for DB
4. **"What if worker isn't running?"** → Need automated health checks

---

**Next Document:** [03_AI_ANALYZER_DESIGN.md →](03_AI_ANALYZER_DESIGN.md)

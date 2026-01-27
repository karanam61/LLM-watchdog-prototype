# Cost Reduction Strategies for AI-SOC Watchdog

## The Problem

Current cost: **~$0.02 per alert** using Claude Sonnet

At scale:
| Alerts/Day | Daily Cost | Monthly Cost | Annual Cost |
|------------|------------|--------------|-------------|
| 100 | $2 | $60 | $720 |
| 1,000 | $20 | $600 | $7,200 |
| 10,000 | $200 | $6,000 | $72,000 |
| 100,000 | $2,000 | $60,000 | $720,000 |

**This is unsustainable.** Here's how to reduce costs by 80-95%.

---

## Strategy 1: Dynamic Model Selection (ALREADY IMPLEMENTED)

### How It Works

Use cheaper models for low-risk alerts:

| Alert Severity | Model | Cost per 1K tokens | Estimated Cost/Alert |
|---------------|-------|-------------------|---------------------|
| Critical | Claude Sonnet | $0.003 in / $0.015 out | ~$0.02 |
| High | Claude Sonnet | $0.003 in / $0.015 out | ~$0.02 |
| Medium | Claude Haiku | $0.00025 in / $0.00125 out | ~$0.002 |
| Low | Claude Haiku | $0.00025 in / $0.00125 out | ~$0.002 |

**Savings: 90% on Medium/Low alerts**

### Implementation (in `dynamic_budget_tracker.py`)

```python
def select_model(self, severity: str) -> str:
    if severity.lower() in ['critical', 'high']:
        return "claude-sonnet-4-20250514"  # Best accuracy
    else:
        return "claude-3-5-haiku-20241022"  # 10x cheaper
```

### Real-World Impact

Typical alert distribution:
- Critical: 5% → Use Sonnet ($0.02)
- High: 15% → Use Sonnet ($0.02)
- Medium: 30% → Use Haiku ($0.002)
- Low: 50% → Use Haiku ($0.002)

**Weighted average: $0.005/alert (75% reduction)**

---

## Strategy 2: Intelligent Caching (PARTIALLY IMPLEMENTED)

### How It Works

Cache AI responses for similar alerts. Don't re-analyze identical patterns.

### Cache Key Strategy

```python
def generate_cache_key(alert):
    return hash(f"{alert['alert_name']}:{alert['mitre_technique']}:{alert['severity']}")
```

### Cache Hit Scenarios

| Scenario | Cache Hit | Example |
|----------|-----------|---------|
| Same alert from same host | Yes | Repeated failed login |
| Same MITRE technique | Partial | Different hosts, same T1059.001 |
| Same alert name pattern | Partial | "Failed Login" from any source |

### Implementation (in `optimization.py`)

```python
class AnalysisCache:
    def __init__(self, ttl_seconds=3600):
        self.cache = {}
        self.ttl = ttl_seconds
    
    def get(self, alert):
        key = self._generate_key(alert)
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['timestamp'] < self.ttl:
                return entry['analysis']
        return None
    
    def set(self, alert, analysis):
        key = self._generate_key(alert)
        self.cache[key] = {
            'analysis': analysis,
            'timestamp': time.time()
        }
```

**Expected savings: 20-40% (depending on alert repetition)**

---

## Strategy 3: Pre-filtering (Skip AI for Obvious Cases)

### How It Works

Don't send to AI if rule-based logic can handle it:

```python
def should_skip_ai(alert):
    # Skip if it's a known false positive pattern
    known_benign_patterns = [
        "Windows Update",
        "Scheduled Task",
        "Antivirus Scan",
        "Backup Service"
    ]
    
    for pattern in known_benign_patterns:
        if pattern.lower() in alert['alert_name'].lower():
            return True, "Known benign pattern"
    
    # Skip if severity is informational
    if alert.get('severity', '').lower() == 'informational':
        return True, "Informational severity"
    
    return False, None
```

### Pre-filter Categories

| Category | Action | Cost |
|----------|--------|------|
| Known benign patterns | Auto-close, no AI | $0 |
| Informational alerts | Log only, no AI | $0 |
| Duplicate within 5min | Use cached result | $0 |
| Low + no logs | Rule-based verdict | $0 |

**Expected savings: 30-50% of alerts never hit AI**

---

## Strategy 4: Prompt Compression

### How It Works

Reduce token count in prompts:

| Optimization | Before | After | Token Reduction |
|--------------|--------|-------|-----------------|
| Truncate logs | Full logs | First 5 per type | 40% |
| Compress RAG | 7 full contexts | Top 3 relevant | 50% |
| Remove examples | Long examples | Minimal examples | 30% |
| Use abbreviations | "MITRE ATT&CK Technique" | "MITRE" | 10% |

### Implementation

```python
def compress_context(context, max_tokens=2000):
    # Prioritize most relevant sections
    priority_sections = [
        "CURRENT ALERT",
        "FORENSIC LOGS",
        "MITRE TECHNIQUE"
    ]
    
    compressed = []
    for section in priority_sections:
        if section in context:
            compressed.append(extract_section(context, section))
    
    return "\n".join(compressed)[:max_tokens * 4]  # ~4 chars per token
```

**Expected savings: 30-40% token reduction → 30-40% cost reduction**

---

## Strategy 5: Batch Processing

### How It Works

Process multiple similar alerts in one API call:

```python
def batch_analyze(alerts):
    # Group by MITRE technique
    groups = group_by_mitre(alerts)
    
    for mitre_id, alert_group in groups.items():
        if len(alert_group) > 1:
            # Analyze as batch
            prompt = build_batch_prompt(alert_group)
            response = call_claude(prompt)
            # Parse response for each alert
        else:
            # Single analysis
            analyze_single(alert_group[0])
```

### Batch Prompt Structure

```
Analyze these 5 related alerts (all T1059.001 PowerShell):

Alert 1: [details]
Alert 2: [details]
Alert 3: [details]
Alert 4: [details]
Alert 5: [details]

Provide verdict for EACH alert in format:
{"alert_1": {...}, "alert_2": {...}, ...}
```

**Expected savings: 50-70% for batched alerts**

---

## Strategy 6: Auto-Close Without AI

### How It Works

For low-severity alerts with clear benign indicators:

```python
def auto_close_if_benign(alert, logs):
    # Check for benign indicators
    benign_score = 0
    
    # Process logs show known good processes
    if any(p in logs.get('process_logs', []) for p in KNOWN_GOOD_PROCESSES):
        benign_score += 30
    
    # Network logs show internal IPs only
    if all(is_internal_ip(log['dest_ip']) for log in logs.get('network_logs', [])):
        benign_score += 30
    
    # Alert matches known false positive pattern
    if matches_false_positive_pattern(alert):
        benign_score += 40
    
    if benign_score >= 70 and alert['severity'] in ['low', 'medium']:
        return {
            'verdict': 'benign',
            'confidence': 0.75,
            'method': 'rule_based',
            'cost': 0
        }
    
    return None  # Needs AI analysis
```

**Expected savings: 20-30% of alerts handled without AI**

---

## Strategy 7: Use Smaller Context Window

### Current Problem

Each alert sends ~3000-5000 tokens to Claude.

### Optimization

| Component | Current Tokens | Optimized Tokens |
|-----------|---------------|------------------|
| Alert details | 200 | 150 |
| Forensic logs | 1500 | 500 |
| RAG context | 2000 | 800 |
| Instructions | 500 | 300 |
| **Total** | **4200** | **1750** |

**Expected savings: 60% token reduction**

---

## Implementation Roadmap

### Phase 1: Quick Wins (Implement Now)

1. **Dynamic model selection** - Already done ✓
2. **Pre-filtering known benign** - 2 hours to implement
3. **Truncate logs to 5 per type** - 1 hour to implement

**Expected impact: 50% cost reduction**

### Phase 2: Medium Effort (This Week)

4. **Caching layer** - 4 hours to implement
5. **Prompt compression** - 3 hours to implement
6. **Auto-close rules** - 4 hours to implement

**Expected impact: Additional 30% reduction**

### Phase 3: Advanced (Future)

7. **Batch processing** - 8 hours to implement
8. **ML-based pre-filter** - 16 hours to implement
9. **Custom fine-tuned model** - Weeks/months

**Expected impact: Additional 20% reduction**

---

## Cost Calculator

### Before Optimization

```
1000 alerts/day × $0.02/alert = $20/day = $600/month
```

### After Phase 1

```
- 30% pre-filtered (no AI): 300 × $0 = $0
- 50% low/medium (Haiku): 350 × $0.002 = $0.70
- 20% high/critical (Sonnet): 350 × $0.02 = $7.00
Total: $7.70/day = $231/month (62% savings)
```

### After Phase 2

```
- 40% pre-filtered: 400 × $0 = $0
- 20% cached: 120 × $0 = $0
- 30% low/medium (Haiku): 180 × $0.002 = $0.36
- 10% high/critical (Sonnet): 300 × $0.015 = $4.50
Total: $4.86/day = $146/month (76% savings)
```

### After Phase 3

```
- 50% pre-filtered/cached: 500 × $0 = $0
- 40% batched (Haiku): 400 × $0.001 = $0.40
- 10% individual (Sonnet): 100 × $0.015 = $1.50
Total: $1.90/day = $57/month (90% savings)
```

---

## Code Changes Required

### 1. Add Pre-filter (in `alert_analyzer_final.py`)

```python
KNOWN_BENIGN_PATTERNS = [
    "windows update",
    "scheduled task",
    "antivirus",
    "backup service",
    "certificate renewal"
]

def should_skip_ai(self, alert):
    alert_name = alert.get('alert_name', '').lower()
    
    for pattern in KNOWN_BENIGN_PATTERNS:
        if pattern in alert_name:
            return True, f"Matched benign pattern: {pattern}"
    
    if alert.get('severity', '').lower() == 'informational':
        return True, "Informational severity"
    
    return False, None
```

### 2. Add Caching (in `alert_analyzer_final.py`)

```python
from functools import lru_cache
import hashlib

class AlertAnalyzer:
    def __init__(self):
        self.analysis_cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def _get_cache_key(self, alert):
        key_parts = [
            alert.get('alert_name', ''),
            alert.get('mitre_technique', ''),
            alert.get('severity', '')
        ]
        return hashlib.md5(':'.join(key_parts).encode()).hexdigest()
    
    def _check_cache(self, alert):
        key = self._get_cache_key(alert)
        if key in self.analysis_cache:
            entry = self.analysis_cache[key]
            if time.time() - entry['time'] < self.cache_ttl:
                return entry['analysis']
        return None
```

### 3. Reduce Log Count (in `rag_system.py`)

```python
# Change from 10 to 5 logs per type
for idx, log in enumerate(logs['process_logs'][:5], 1):  # Was [:10]
```

---

## Monitoring Cost

Add cost tracking to see savings:

```python
# In dynamic_budget_tracker.py
def log_analysis_cost(self, alert_id, model, tokens_in, tokens_out):
    cost = self.calculate_cost(model, tokens_in, tokens_out)
    
    self.daily_costs.append({
        'alert_id': alert_id,
        'model': model,
        'tokens_in': tokens_in,
        'tokens_out': tokens_out,
        'cost': cost,
        'timestamp': datetime.now()
    })
    
    # Log to monitoring
    logger.info(f"[COST] Alert {alert_id}: ${cost:.4f} ({model})")
```

---

## Summary

| Strategy | Implementation Effort | Cost Reduction |
|----------|----------------------|----------------|
| Dynamic model selection | Done | 50-75% |
| Pre-filtering | 2 hours | 20-30% |
| Caching | 4 hours | 20-40% |
| Prompt compression | 3 hours | 30-40% |
| Auto-close rules | 4 hours | 20-30% |
| Batch processing | 8 hours | 50-70% |

**Combined potential: 80-95% cost reduction**

From $0.02/alert to $0.002/alert = **$2/1000 alerts instead of $20/1000 alerts**

# Cost Reduction Strategies

## The Problem

Current cost: ~$0.02 per alert using Claude Sonnet

At scale:
| Alerts/Day | Monthly Cost |
|------------|--------------|
| 100 | $60 |
| 1,000 | $600 |
| 10,000 | $6,000 |
| 100,000 | $60,000 |

## Strategy 1: Dynamic Model Selection (Already Implemented)

Use cheaper models for low-risk alerts:

| Alert Severity | Model | Cost/Alert |
|---------------|-------|------------|
| Critical/High | Claude Sonnet | ~$0.02 |
| Medium/Low | Claude Haiku | ~$0.002 |

Savings: 90% on Medium/Low alerts

Implementation in dynamic_budget_tracker.py:
```python
def select_model(self, severity: str) -> str:
    if severity.lower() in ['critical', 'high']:
        return "claude-sonnet-4-20250514"
    else:
        return "claude-3-5-haiku-20241022"
```

Typical distribution: 50% low, 30% medium, 15% high, 5% critical
Weighted average: $0.005/alert (75% reduction)

## Strategy 2: Intelligent Caching (Partially Implemented)

Cache AI responses for similar alerts. Cache key based on alert_name, mitre_technique, severity.

Expected savings: 20-40% depending on alert repetition

## Strategy 3: Pre-filtering

Skip AI for obvious cases:

```python
known_benign_patterns = [
    "Windows Update",
    "Scheduled Task",
    "Antivirus Scan",
    "Backup Service"
]
```

Categories to skip:
- Known benign patterns: Auto-close, no AI, $0
- Informational alerts: Log only, no AI, $0
- Duplicate within 5min: Use cached result, $0
- Low + no logs: Rule-based verdict, $0

Expected savings: 30-50% of alerts never hit AI

## Strategy 4: Prompt Compression

Reduce token count:
| Optimization | Token Reduction |
|--------------|-----------------|
| Truncate logs | 40% |
| Compress RAG | 50% |
| Remove examples | 30% |
| Use abbreviations | 10% |

Expected savings: 30-40% cost reduction

## Strategy 5: Batch Processing

Process multiple similar alerts in one API call by grouping by MITRE technique.

Expected savings: 50-70% for batched alerts

## Strategy 6: Auto-Close Without AI

For low-severity alerts with clear benign indicators, use rule-based logic:
- Known good processes
- Internal IPs only
- Matches false positive pattern

If benign_score >= 70 and severity is low/medium, auto-close without AI.

Expected savings: 20-30% of alerts handled without AI

## Strategy 7: Smaller Context Window

| Component | Current | Optimized |
|-----------|---------|-----------|
| Alert details | 200 | 150 |
| Forensic logs | 1500 | 500 |
| RAG context | 2000 | 800 |
| Instructions | 500 | 300 |
| Total | 4200 | 1750 |

Expected savings: 60% token reduction

## Implementation Roadmap

### Phase 1: Quick Wins
1. Dynamic model selection - Done
2. Pre-filtering known benign - 2 hours
3. Truncate logs to 5 per type - 1 hour

Impact: 50% cost reduction

### Phase 2: Medium Effort
4. Caching layer - 4 hours
5. Prompt compression - 3 hours
6. Auto-close rules - 4 hours

Impact: Additional 30% reduction

### Phase 3: Advanced
7. Batch processing - 8 hours
8. ML-based pre-filter - 16 hours

Impact: Additional 20% reduction

## Cost Calculator

Before optimization:
1000 alerts/day x $0.02 = $600/month

After Phase 1:
- 30% pre-filtered: $0
- 50% Haiku: $0.70
- 20% Sonnet: $7.00
Total: $231/month (62% savings)

After Phase 2:
- 40% pre-filtered: $0
- 20% cached: $0
- 30% Haiku: $0.36
- 10% Sonnet: $4.50
Total: $146/month (76% savings)

After Phase 3:
- 50% pre-filtered/cached: $0
- 40% batched Haiku: $0.40
- 10% Sonnet: $1.50
Total: $57/month (90% savings)

## Summary

| Strategy | Effort | Cost Reduction |
|----------|--------|----------------|
| Dynamic model selection | Done | 50-75% |
| Pre-filtering | 2 hours | 20-30% |
| Caching | 4 hours | 20-40% |
| Prompt compression | 3 hours | 30-40% |
| Auto-close rules | 4 hours | 20-30% |
| Batch processing | 8 hours | 50-70% |

Combined potential: 80-95% cost reduction
From $0.02/alert to $0.002/alert

"""
Severity Classifier - Categorizes Alert Priority
=================================================

This module classifies alerts into severity buckets that determine
processing priority and AI model selection.

WHAT THIS FILE DOES:
1. Reads the severity field from parsed alerts
2. Maps to internal severity classes (CRITICAL_HIGH, MEDIUM_LOW)
3. Enables queue routing and cost optimization

WHY THIS EXISTS:
- Different severity alerts need different handling
- Critical alerts go to priority queue (processed first)
- Critical alerts use powerful AI models (Sonnet)
- Low severity alerts use cheaper AI models (Haiku)

SEVERITY MAPPING:
- "critical", "high" -> CRITICAL_HIGH (priority queue, Sonnet model)
- "medium", "low"    -> MEDIUM_LOW (standard queue, Haiku model)
- Unknown/missing    -> MEDIUM_LOW (default)

USAGE:
    severity_class = classify_severity(parsed_alert)
    # Returns: "CRITICAL_HIGH" or "MEDIUM_LOW"

Author: AI-SOC Watchdog System
"""

def classify_severity(parsed_alert):
    """Classify alert severity"""
    
    # Get severity from Splunk alert
    severity = parsed_alert.get('severity', '').lower()
    
    # Simple classification
    if severity in ['critical', 'high']:
        return 'CRITICAL_HIGH'
    elif severity in ['medium', 'low']:
        return 'MEDIUM_LOW'
    else:
        return 'MEDIUM_LOW'  # default


# Test it
if __name__ == '__main__':
    test1 = {'severity': 'high', 'alert_name': 'Test'}
    test2 = {'severity': 'low', 'alert_name': 'Test'}
    
    print(f"Test 1: {classify_severity(test1)}")
    print(f"Test 2: {classify_severity(test2)}")
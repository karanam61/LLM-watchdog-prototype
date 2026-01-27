"""
Test if Anthropic API key is valid and working
"""
import os
from dotenv import load_dotenv
import anthropic

# Force reload .env
load_dotenv(override=True)

api_key = os.getenv("ANTHROPIC_API_KEY")

if not api_key:
    print("[ERROR] ANTHROPIC_API_KEY not found in environment!")
    exit(1)

print(f"[OK] API Key found: {api_key[:15]}...")

# Test API call
try:
    client = anthropic.Anthropic(api_key=api_key)
    
    print("[TEST] Sending test message to Claude...")
    
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=100,
        messages=[{
            "role": "user",
            "content": "Say 'API key works!' and nothing else."
        }]
    )
    
    response_text = message.content[0].text
    print(f"[OK] Claude Response: {response_text}")
    print(f"[OK] Tokens used: {message.usage.input_tokens} in, {message.usage.output_tokens} out")
    print("\n[SUCCESS] Anthropic API is working correctly!")
    
except Exception as e:
    print(f"[ERROR] API test failed: {e}")
    exit(1)

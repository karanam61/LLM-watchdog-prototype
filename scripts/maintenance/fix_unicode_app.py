"""Remove all Unicode emojis from app.py"""
import re

replacements = {
    '🔄': '[RELOAD]',
    '✅': '[OK]',
    '❌': '[ERROR]',
    '👉': '->',
    '🌊': '[QUEUE]',
    '⚡': '[API]',
    '🤖': '[AI]',
    '📥': '[INGEST]',
    '→': '->',
}

content = open('app.py', 'r', encoding='utf-8').read()

for emoji, replacement in replacements.items():
    content = content.replace(emoji, replacement)

open('app.py', 'w', encoding='utf-8').write(content)
print(f"[OK] Removed {len(replacements)} emoji types from app.py")

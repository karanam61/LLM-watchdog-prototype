"""
Remove ALL Unicode emojis from ALL Python files in backend/
"""
import os
import re
from pathlib import Path

# Emoji replacements
replacements = {
    '🚀': '[START]',
    '✅': '[OK]',
    '❌': '[ERROR]',
    '⚠️': '[WARNING]',
    '🔍': '[CHECK]',
    '🛡️': '[GUARD]',
    '⚡': '[FAST]',
    '📚': '[CONTEXT]',
    '🤖': '[AI]',
    '📊': '[STATS]',
    '🔄': '[RELOAD]',
    '👉': '->',
    '🌊': '[QUEUE]',
    '📥': '[INGEST]',
    '→': '->',
    '✓': '[OK]',
    '✗': '[ERROR]',
    '🧾': '[COST]',
    '📦': '[DATA]',
    '💾': '[SAVE]',
    '⏱️': '[TIME]',
    '🔥': '[PRIORITY]',
    '🎯': '[TARGET]',
}

def clean_file(filepath):
    """Remove emojis from a single file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Replace all known emojis
        for emoji, replacement in replacements.items():
            content = content.replace(emoji, replacement)
        
        # Replace any remaining Unicode characters outside ASCII range
        # But keep the actual code logic intact
        content = re.sub(r'[^\x00-\x7F]+', lambda m: replacements.get(m.group(), '[*]'), content)
        
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"  [ERROR] {filepath}: {e}")
        return False

# Find all Python files in backend/
backend_dir = Path('backend')
modified_count = 0

print("Cleaning Unicode from backend Python files...")
print("="*70)

for py_file in backend_dir.rglob('*.py'):
    if clean_file(py_file):
        print(f"  [FIXED] {py_file}")
        modified_count += 1

print("="*70)
print(f"[OK] Modified {modified_count} files")

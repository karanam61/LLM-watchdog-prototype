import sys

# Read file
with open('master_launch.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace Unicode
content = content.replace('✓', '[OK]')
content = content.replace('✗', '[ERROR]')
content = content.replace('→', '->')
content = content.replace('⚙', '[*]')
content = content.replace('🚀', '[START]')
content = content.replace('📊', '[INFO]')

# Write back
with open('master_launch.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed Unicode characters in master_launch.py")

"""
Reorganize project structure
Run this ONCE to move files to proper locations
"""

import os
import shutil

# Current directory
root = os.getcwd()

# Create folder structure
folders = [
    'backend',
    'backend/core',
    'backend/ai',
    'backend/security',
    'backend/storage',
    'tests',
    'docs'
]

print("Creating folder structure...")
for folder in folders:
    os.makedirs(folder, exist_ok=True)
    # Create __init__.py
    init_file = os.path.join(folder, '__init__.py')
    if not os.path.exists(init_file):
        open(init_file, 'w').close()
    print(f"✓ Created {folder}/__init__.py")

# Move files
moves = [
    # Core logic
    ('parser.py', 'backend/core/parser.py'),
    ('mitre_mapping.py', 'backend/core/mitre_mapping.py'),
    ('Severity.py', 'backend/core/Severity.py'),
    ('Queue_manager.py', 'backend/core/Queue_manager.py'),
    
    # Security
    ('tokenizer.py', 'backend/security/tokenizer.py'),
    
    # Storage
    ('database.py', 'backend/storage/database.py'),
    ('backup.py', 'backend/storage/backup.py'),
    
    # Tests
    ('test_ai.py', 'tests/test_ai.py'),
    ('test_alert.py', 'tests/test_alert.py'),
    ('test-claude.py', 'tests/test_claude.py'),
]

print("\nMoving files...")
for src, dst in moves:
    src_path = os.path.join(root, src)
    dst_path = os.path.join(root, dst)
    
    if os.path.exists(src_path):
        shutil.move(src_path, dst_path)
        print(f"✓ Moved {src} → {dst}")
    else:
        print(f"⚠ Skipped {src} (not found)")

print("\n✅ Project reorganized!")
print("\nNext steps:")
print("1. Update imports in app.py")
print("2. Update imports in test files")
print("3. Test that everything still works")
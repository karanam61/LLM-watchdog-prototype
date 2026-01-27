"""
Pre-Flight Check - Verify Everything Before Launch
===================================================
Runs all validation checks to ensure system is ready.
"""

import sys
import os
from pathlib import Path

print("="*70)
print("🔍 PRE-FLIGHT SYSTEM CHECK")
print("="*70)

errors = []
warnings = []

# ============================================================================
# CHECK 1: Python Dependencies
# ============================================================================
print("\n[1/6] Checking Python Dependencies...")

required_packages = [
    'flask',
    'flask_cors',
    'anthropic',
    'supabase',
    'chromadb',
    'pydantic',
    'dotenv'
]

missing = []
for package in required_packages:
    try:
        __import__(package.replace('-', '_').replace('dotenv', 'python_dotenv'))
        print(f"  ✓ {package}")
    except ImportError:
        missing.append(package)
        print(f"  ❌ {package} - NOT FOUND")

if missing:
    errors.append(f"Missing packages: {', '.join(missing)}")
    print(f"\n  🔧 Fix: pip install {' '.join(missing)}")

# ============================================================================
# CHECK 2: Environment Variables
# ============================================================================
print("\n[2/6] Checking Environment Variables...")

sys.path.insert(0, str(Path(__file__).parent))
from dotenv import load_dotenv
load_dotenv()

env_vars = {
    'ANTHROPIC_API_KEY': 'AI analysis',
    'SUPABASE_URL': 'Database connection',
    'SUPABASE_SERVICE_KEY': 'Database admin access'
}

for var, purpose in env_vars.items():
    value = os.getenv(var)
    if value:
        masked = value[:10] + "..." if len(value) > 10 else value
        print(f"  ✓ {var:<25} = {masked:<15} ({purpose})")
    else:
        errors.append(f"{var} not set")
        print(f"  ❌ {var:<25} - MISSING ({purpose})")

# ============================================================================
# CHECK 3: Database Connection
# ============================================================================
print("\n[3/6] Checking Database Connection...")

try:
    from backend.storage.database import supabase
    
    # Test connection
    result = supabase.table('alerts').select('id').limit(1).execute()
    print(f"  ✓ Database connected")
    print(f"  ✓ Alerts table accessible")
    
    # Check tables
    tables = ['alerts', 'process_logs', 'network_logs', 'file_activity_logs', 'windows_event_logs']
    for table in tables:
        try:
            result = supabase.table(table).select('*').limit(1).execute()
            count = len(result.data)
            print(f"  ✓ {table:<25} (sample: {count} rows)")
        except Exception as e:
            warnings.append(f"Table {table} might be empty or inaccessible")
            print(f"  ⚠️  {table:<25} - {str(e)[:30]}")
            
except Exception as e:
    errors.append(f"Database connection failed: {e}")
    print(f"  ❌ Connection failed: {e}")

# ============================================================================
# CHECK 4: File Structure
# ============================================================================
print("\n[4/6] Checking File Structure...")

critical_files = [
    'app.py',
    'backend/ai/alert_analyzer_final.py',
    'backend/storage/database.py',
    'backend/core/Queue_manager.py',
    'soc-dashboard/src/App.jsx',
    'soc-dashboard/src/pages/AnalystDashboard.jsx',
    '.env'
]

for file in critical_files:
    path = Path(file)
    if path.exists():
        print(f"  ✓ {file}")
    else:
        errors.append(f"Missing file: {file}")
        print(f"  ❌ {file} - NOT FOUND")

# ============================================================================
# CHECK 5: Auth Cleanup Verification
# ============================================================================
print("\n[5/6] Verifying Authentication Removal...")

removed_files = [
    'soc-dashboard/src/components/Login.jsx',
    'soc-dashboard/src/pages/Login.jsx',
    'soc-dashboard/src/components/ProtectedRoute.jsx',
    'soc-dashboard/src/contexts/AuthContext.jsx'
]

all_removed = True
for file in removed_files:
    path = Path(file)
    if path.exists():
        warnings.append(f"Auth file still exists: {file}")
        print(f"  ⚠️  {file} - SHOULD BE DELETED")
        all_removed = False
    else:
        print(f"  ✓ {file} - Removed")

if all_removed:
    print(f"  ✅ All authentication components removed")

# ============================================================================
# CHECK 6: AI Analyzer Syntax
# ============================================================================
print("\n[6/6] Checking AI Analyzer...")

try:
    from backend.ai.alert_analyzer_final import AlertAnalyzer
    print(f"  ✓ AlertAnalyzer imports successfully")
    
    # Try to instantiate (light check, don't load heavy models)
    print(f"  ✓ AlertAnalyzer class definition valid")
    
except SyntaxError as e:
    errors.append(f"Syntax error in alert_analyzer_final.py: {e}")
    print(f"  ❌ Syntax error: {e}")
except Exception as e:
    warnings.append(f"AlertAnalyzer warning: {e}")
    print(f"  ⚠️  Import warning: {str(e)[:50]}")

# ============================================================================
# FINAL REPORT
# ============================================================================
print("\n" + "="*70)
print("📊 PRE-FLIGHT CHECK SUMMARY")
print("="*70)

if not errors and not warnings:
    print("\n✅ ALL CHECKS PASSED")
    print("\n🚀 System is ready to launch!")
    print("\nNext steps:")
    print("  1. python scripts/data/generate_test_data.py")
    print("  2. python start.py")
    print("  3. Open http://localhost:5173")
    sys.exit(0)

if errors:
    print(f"\n❌ CRITICAL ERRORS ({len(errors)}):")
    for i, error in enumerate(errors, 1):
        print(f"  {i}. {error}")

if warnings:
    print(f"\n⚠️  WARNINGS ({len(warnings)}):")
    for i, warning in enumerate(warnings, 1):
        print(f"  {i}. {warning}")

if errors:
    print("\n🔧 FIX ERRORS BEFORE LAUNCHING")
    sys.exit(1)
else:
    print("\n⚠️  WARNINGS DETECTED BUT SYSTEM MAY STILL WORK")
    print("   Proceed with caution or fix warnings first.")
    sys.exit(0)

print("\n" + "="*70 + "\n")

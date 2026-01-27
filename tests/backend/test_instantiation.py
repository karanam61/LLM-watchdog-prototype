
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    print("Step 1: Importing AlertAnalyzer...")
    from backend.ai.alert_analyzer_final import AlertAnalyzer
    print("   Success.")
except ImportError as e:
    print(f"   Failed to import: {e}")
    sys.exit(1)

try:
    print("Step 2: Instantiating AlertAnalyzer...")
    analyzer = AlertAnalyzer()
    print("   Success.")
    
    print("Step 3: Checking attributes...")
    if hasattr(analyzer, 'input_guard'):
        print("   [OK] input_guard exists")
    else:
        print("   [ERROR] input_guard MISSING")
        
    print(f"   Attributes: {dir(analyzer)}")
    
except Exception as e:
    print(f"   [ERROR] Instantiation failed: {e}")
    import traceback
    traceback.print_exc()

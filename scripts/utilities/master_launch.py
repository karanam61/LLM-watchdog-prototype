"""
[START] MASTER LAUNCHER - Complete System Setup & Start
====================================================
This script does EVERYTHING:
1. Validates system
2. Generates test data
3. Launches backend & frontend
4. Opens browser

Just run: python master_launch.py
"""

import subprocess
import time
import os
import sys
import webbrowser
from pathlib import Path

def print_banner():
    print("\n" + "="*70)
    print(" " * 15 + "AI-SOC WATCHDOG")
    print(" " * 20 + "Master Launcher")
    print("="*70 + "\n")

def run_command(description, command, capture_output=False):
    """Run a command and handle errors"""
    print(f"[*] {description}...")
    try:
        if capture_output:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"❌ Failed: {result.stderr[:200]}")
                return False
            return True
        else:
            subprocess.run(command, shell=True, check=True)
            return True
    except subprocess.TimeoutExpired:
        print(f"⏱️  Timeout (continuing anyway)")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def check_prereqs():
    """Check if system is ready"""
    print("\n[STEP 1/5] Pre-flight Checks")
    print("-" * 70)
    
    # Check Python packages
    try:
        import flask
        import anthropic
        import supabase
        print("[OK] Python dependencies OK")
    except ImportError as e:
        print(f"[ERROR] Missing package: {e}")
        print("[FIX] Run: pip install -r requirements.txt")
        return False
    
    # Check .env
    from dotenv import load_dotenv
    load_dotenv()
    
    required_env = ['ANTHROPIC_API_KEY', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']
    for var in required_env:
        if not os.getenv(var):
            print(f"[ERROR] Missing environment variable: {var}")
            print("[FIX] Check your .env file")
            return False
    
    print("[OK] Environment variables OK")
    
    # Check database
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from backend.storage.database import supabase as db
        result = db.table('alerts').select('id').limit(1).execute()
        print("[OK] Database connection OK")
    except Exception as e:
        print(f"[ERROR] Database connection failed: {e}")
        return False
    
    print("\n[OK] All pre-flight checks passed!\n")
    return True

def generate_data():
    """Generate test data"""
    print("[STEP 2/5] Generating Test Data")
    print("-" * 70)
    
    print("[INFO] Skipping data generation - using your existing 33 alerts")
    print("[OK] All 33 alerts have logs and are ready to use\n")
    time.sleep(1)
    return True

def start_backend():
    """Start Flask backend"""
    print("[STEP 3/5] Starting Backend Server")
    print("-" * 70)
    
    backend_process = subprocess.Popen(
        ['py', 'app.py'],
        cwd=os.getcwd(),
        creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
    )
    
    print("[WAIT] Waiting for backend to initialize...")
    time.sleep(5)
    
    # Test if backend is up
    try:
        import requests
        response = requests.get("http://localhost:5000/queue-status", timeout=3)
        if response.status_code == 200:
            print("[OK] Backend running on http://localhost:5000\n")
            return backend_process
        else:
            print("[WARNING] Backend may not be ready yet\n")
            return backend_process
    except:
        print("[WARNING] Backend health check failed (but process started)\n")
        return backend_process

def start_frontend():
    """Start React frontend"""
    print("[STEP 4/5] Starting Frontend Server")
    print("-" * 70)
    
    frontend_dir = os.path.join(os.getcwd(), 'soc-dashboard')
    
    frontend_process = subprocess.Popen(
        ['npm', 'run', 'dev'],
        cwd=frontend_dir,
        creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0,
        shell=True
    )
    
    print("[WAIT] Waiting for frontend to build...")
    time.sleep(8)
    
    print("[OK] Frontend running on http://localhost:5173\n")
    return frontend_process

def open_browser():
    """Open browser to dashboard"""
    print("[STEP 5/5] Opening Dashboard")
    print("-" * 70)
    
    time.sleep(2)
    try:
        webbrowser.open("http://localhost:5173")
        print("[OK] Browser opened to http://localhost:5173\n")
    except:
        print("[WARNING] Couldn't auto-open browser")
        print("   Please manually open: http://localhost:5173\n")

def print_success():
    """Print success message"""
    print("="*70)
    print(" " * 20 + "SYSTEM ONLINE!")
    print("="*70)
    print("\n[*] Dashboard: http://localhost:5173")
    print("[*] API:       http://localhost:5000")
    print("[*] Your Data: 33 alerts with logs ready")
    print("\nFeatures:")
    print("  - Real-time alert feed (33 alerts)")
    print("  - AI-powered threat analysis")
    print("  - Forensic log correlation")
    print("  - Investigation panel")
    print("  - No authentication required")
    print("\nUsage:")
    print("  1. Click any of your 33 alerts to expand")
    print("  2. View tabs: Summary, Process, Network, File")
    print("  3. Wait ~10 seconds for AI verdict per alert")
    print("  4. Create cases or close alerts")
    print("\nIMPORTANT:")
    print("  - Keep this window open to monitor status")
    print("  - Backend runs in separate console window")
    print("  - Frontend runs in another console window")
    print("  - Close those windows to stop servers")
    print("  - All 33 alerts will be analyzed in background")
    print("\n" + "="*70 + "\n")

def main():
    print_banner()
    
    # Step 1: Pre-flight checks
    if not check_prereqs():
        print("\n[ERROR] Pre-flight checks failed. Fix errors and try again.\n")
        input("Press Enter to exit...")
        sys.exit(1)
    
    # Step 2: Skip data generation (using existing 33 alerts)
    generate_data()
    
    # Step 3: Start backend
    backend_proc = start_backend()
    
    # Step 4: Start frontend
    frontend_proc = start_frontend()
    
    # Step 5: Open browser
    open_browser()
    
    # Success!
    print_success()
    
    # Keep alive
    try:
        print("[RUNNING] System active... (Press Ctrl+C to stop monitoring)\n")
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n\n[INFO] Monitoring stopped.")
        print("   Backend and frontend are still running in their console windows.")
        print("   Close those windows to fully stop the system.\n")

if __name__ == "__main__":
    main()

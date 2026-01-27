
import subprocess
import time
import os
import sys

def start_services():
    print("\n" + "="*50)
    print("🚀 ONE-CLICK LAUNCHER")
    print("="*50)
    
    # 1. Start Backend
    print("\n[1/2] Starting Backend (Port 5000)...")
    backend = subprocess.Popen(
        ['python', 'app.py'], 
        cwd=os.getcwd(),
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )
    
    time.sleep(3)
    
    # 2. Start Frontend
    print("[2/2] Starting Frontend (Port 5173)...")
    frontend_dir = os.path.join(os.getcwd(), 'soc-dashboard')
    frontend = subprocess.Popen(
        ['npm', 'run', 'dev'], 
        cwd=frontend_dir,
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        shell=True
    )
    
    print("\n✅ SYSTEMS LAUNCHED!")
    print("--------------------------------")
    print("1. Backend: http://localhost:5000")
    print("1. Frontend: http://localhost:5173")
    print("--------------------------------")
    print("Auth: DISABLED (Open Access)")
    print("\n⚠️  KEEP THIS WINDOW OPEN TO MONITOR STATUS")
    print("   (Close the popup black windows to stop servers)")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        backend.terminate()
        frontend.terminate()

if __name__ == "__main__":
    start_services()

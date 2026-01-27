
import sys
import os
import traceback
import subprocess
import time

# Ensure logs dir exists
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "startup_crash.log")

print(f"[START] LAUNCHER: Starting app.py...")
print(f"   Listing logs to: {log_file}")

with open(log_file, "w") as f:
    f.write(f"--- STARTUP ATTEMPT {time.ctime()} ---\n")
    try:
        # Run app.py as a subprocess to capture its output
        app_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "app.py")
        
        process = subprocess.Popen(
            [sys.executable, app_path],
            stdout=f,
            stderr=f,
            text=True
        )
        f.write(f"Started process with PID: {process.pid}\n")
        print(f"   Process started (PID: {process.pid}). Waiting 5s...")
        
        # Wait a bit to see if it crashes immediately
        time.sleep(5)
        
        if process.poll() is not None:
             f.write(f"[ERROR] PROCESS DIED with code {process.returncode}\n")
             print(f"[ERROR] CRASH DETECTED! Check {log_file}")
        else:
             f.write("[OK] PROCESS RUNNING STABLE (so far)\n")
             print("[OK] Process is stable.")
             
    except Exception as e:
        f.write(f"[ERROR] LAUNCHER ERROR: {e}\n")
        traceback.print_exc(file=f)

print("Launcher exit.")

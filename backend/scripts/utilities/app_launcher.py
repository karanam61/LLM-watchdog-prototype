
import subprocess
import sys
import os

def launch_app():
    print("[START] Launcher starting app.py...")
    
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "startup_error.log")
    
    print(f"   Logs will be written to: {log_file}")
    
    with open(log_file, "w") as f:
        # Run app.py and redirect output
        process = subprocess.Popen(
            [sys.executable, "app.py"],
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            stdout=f,
            stderr=f,
            text=True
        )
        print(f"   Process started with PID: {process.pid}")
        
    print("   Launcher exiting (process continues in background)")

if __name__ == "__main__":
    launch_app()

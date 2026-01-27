
import subprocess
import os
import sys

def debug_frontend():
    print("DEBUG: Starting frontend diagnosis...")
    
    frontend_dir = os.path.join(os.getcwd(), 'soc-dashboard')
    if not os.path.exists(frontend_dir):
        print(f"ERROR: Frontend directory not found at {frontend_dir}")
        return

    print(f"DEBUG: Frontend dir: {frontend_dir}")
    
    # Check node version
    try:
        node_ver = subprocess.check_output(['node', '--version'], shell=True).decode().strip()
        print(f"DEBUG: Node version: {node_ver}")
    except Exception as e:
        print(f"ERROR: Node check failed: {e}")

    # Check npm version
    try:
        npm_ver = subprocess.check_output(['npm', '--version'], shell=True).decode().strip()
        print(f"DEBUG: NPM version: {npm_ver}")
    except Exception as e:
        print(f"ERROR: NPM check failed: {e}")

    # Try to run dev server for 5 seconds then kill
    print("DEBUG: Attempting 'npm run dev'...")
    try:
        proc = subprocess.Popen(
            ['npm', 'run', 'dev'], 
            cwd=frontend_dir, 
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        try:
            # Wait a bit to see if it crashes immediately
            stdout, stderr = proc.communicate(timeout=5)
            print("DEBUG: Process finished unexpectedly!")
            print(f"STDOUT: {stdout.decode()}")
            print(f"STDERR: {stderr.decode()}")
        except subprocess.TimeoutExpired:
            print("DEBUG: Process is running successfully (Timeout reached).")
            # It's running! Kill it and report success.
            proc.kill()
            outs, errs = proc.communicate()
            print(f"STDOUT (Partial): {outs.decode()}")
            print(f"STDERR (Partial): {errs.decode()}")

    except Exception as e:
        print(f"ERROR: Failed to launch npm: {e}")

if __name__ == "__main__":
    debug_frontend()

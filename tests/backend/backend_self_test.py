
# Add parent to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

log_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "logs", "backend_test.log")
os.makedirs(os.path.dirname(log_file), exist_ok=True)

with open(log_file, "w") as f:
    f.write("[FAST] STARTING BACKEND SELF-TEST\n")

    try:
        f.write("   Importing app.py...\n")
        from app import app
        f.write("[OK] App imoprted successfully.\n")
        
        f.write("   Creating Test Client...\n")
        client = app.test_client()
        
        payload = {
            "username": "analyst",
            "password": "analyst123"
        }
        
        f.write(f"   Simulating POST /api/login with {payload}...\n")
        response = client.post('/api/login', 
                               data=json.dumps(payload),
                               content_type='application/json')
        
        f.write(f"   Response Status: {response.status_code}\n")
        f.write(f"   Response Body: {response.data.decode('utf-8')}\n")
        
        if response.status_code == 200:
            f.write("\n[*] SUCCESS: Backend logic is PERFECT.\n")
        elif response.status_code == 401:
            f.write("\n[ERROR] AUTH FAILED: Backend logic runs, but password rejected.\n")
        else:
            f.write(f"\n[WARNING] ERROR: Backend returned {response.status_code}\n")

    except ImportError as e:
        f.write(f"\n[ERROR] FATAL IMPORT ERROR: {e}\n")
    except Exception as e:
        f.write(f"\n[ERROR] FATAL RUNTIME ERROR: {e}\n")
        import traceback
        traceback.print_exc(file=f)

    f.write("[FAST] TEST COMPLETE\n")

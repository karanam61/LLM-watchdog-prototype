
import os
import sys

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.storage.database import get_db_client
from werkzeug.security import generate_password_hash

def emergency_reset():
    print("[*] STARTING EMERGENCY PASSWORD RESET")
    
    supabase = get_db_client()
    
    # 1. Generate NEW hash for 'analyst123'
    # Use method='pbkdf2:sha256' to ensure compatibility
    new_hash = generate_password_hash('analyst123', method='pbkdf2:sha256')
    print(f"   Generated Hash: {new_hash[:20]}...")
    
    # 2. Update 'analyst' user
    try:
        response = supabase.table('users').update({
            'password_hash': new_hash
        }).eq('username', 'analyst').execute()
        
        print(f"[OK] 'analyst' password RESET. Response: {len(response.data)} rows updated.")
        
    except Exception as e:
        print(f"[ERROR] Update Failed: {e}")

    # 3. Verify
    verify = supabase.table('users').select("*").eq('username', 'analyst').execute()
    if verify.data:
        print(f"[CHECK] Verification: User 'analyst' exists with hash {verify.data[0]['password_hash'][:10]}...")
    else:
        print("[ERROR] Verification FAILED: User 'analyst' not found!")

if __name__ == "__main__":
    emergency_reset()

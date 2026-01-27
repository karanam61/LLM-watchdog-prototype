
import os
import sys
from werkzeug.security import check_password_hash

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.storage.database import get_db_client

def diagnose_login():
    print("="*60)
    print("[CHECK] LOGIN DIAGNOSTIC TOOL")
    print("="*60)
    
    supabase = get_db_client()
    username = "analyst"
    password = "analyst123"
    
    print(f"Target User: {username}")
    print(f"Target Pass: {password}")
    
    # 1. FETCH USER
    print("\n[Step 1] Fetching from DB...")
    response = supabase.table('users').select("*").eq('username', username).execute()
    
    if not response.data:
        print("[ERROR] CRITICAL: User not found in DB!")
        return
        
    user = response.data[0]
    stored_hash = user.get('password_hash')
    
    print(f"[OK] User Found. ID: {user['id']}")
    print(f"   Stored Hash: {stored_hash}")
    
    # 2. CHECK HASH
    print("\n[Step 2] Verifying Hash...")
    is_valid = check_password_hash(stored_hash, password)
    
    if is_valid:
        print("[OK] SUCCESS: Password matches hash.")
        print("   If login still fails in App, check:")
        print("   - Are you hitting the right backend URL?")
        print("   - Is the backend process stale?")
    else:
        print("[ERROR] FAILURE: Password does NOT match hash.")
        print("   The seed script likely generated an invalid hash or update failed.")

if __name__ == "__main__":
    diagnose_login()

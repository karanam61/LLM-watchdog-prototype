
import os
import sys
from werkzeug.security import check_password_hash, generate_password_hash

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.storage.database import get_db_client

def debug_auth():
    print("="*60)
    print("[*] AUTH DEBUGGER")
    print("="*60)
    
    supabase = get_db_client()
    username = "analyst"
    password = "analyst123"
    
    print(f"Checking user: {username}")
    
    try:
        # Fetch user
        response = supabase.table('users').select("*").eq('username', username).execute()
        
        if not response.data:
            print(f"[ERROR] User '{username}' NOT FOUND in database!")
            return
            
        user = response.data[0]
        stored_hash = user.get('password_hash', 'MISSING')
        
        print(f"Found User ID: {user.get('id')}")
        print(f"Stored Hash:   {stored_hash[:20]}... (Length: {len(stored_hash)})")
        
        # Test Verification
        algo = "unknown"
        if stored_hash.startswith("pbkdf2"): algo = "pbkdf2"
        elif stored_hash.startswith("scrypt"): algo = "scrypt"
        
        print(f"Hash Algo:     {algo}")
        
        is_valid = check_password_hash(stored_hash, password)
        
        if is_valid:
            print("[OK] check_password_hash: PASS")
        else:
            print("[ERROR] check_password_hash: FAIL")
            
            # Print what a new hash looks like
            new_hash = generate_password_hash(password)
            print(f"\nExpected format (generated now): {new_hash[:20]}...")
            
    except Exception as e:
        print(f"[ERROR] Database Error: {e}")

if __name__ == "__main__":
    debug_auth()

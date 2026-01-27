
import os
import sys
from dotenv import load_dotenv
from supabase import create_client
from werkzeug.security import generate_password_hash, check_password_hash

# Load env
load_dotenv()

# Setup Client
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")
client = create_client(url, key)

print("--- DIAGNOSING HASH MISMATCH ---")

# 1. Fetch User
try:
    response = client.table('users').select("*").eq('username', 'analyst').execute()
    if not response.data:
        print("[FAIL] User 'analyst' not found in DB!")
        sys.exit(1)
        
    user = response.data[0]
    stored_hash = user['password_hash']
    
    print(f"\n[1] Stored Hash Analysis:")
    print(f"    Hash: {stored_hash}")
    print(f"    Length: {len(stored_hash)}")
    
    # 2. Local Verification
    password_attempt = "analyst123"
    is_valid = check_password_hash(stored_hash, password_attempt)
    print(f"    check_password_hash(stored, '{password_attempt}') => {is_valid}")
    
    if is_valid:
        print("\n[SUCCESS] The stored hash IS valid locally. The issue might be input whitespace in the app?")
    else:
        print("\n[FAIL] The stored hash is INVALID locally.")
        
        # 3. Generate Fresh Hash to Compare
        print("\n[2] Generation Test:")
        fresh_hash = generate_password_hash(password_attempt)
        print(f"    New Fresh Hash: {fresh_hash}")
        print(f"    Length: {len(fresh_hash)}")
        
        check_fresh = check_password_hash(fresh_hash, password_attempt)
        print(f"    check_password_hash(fresh, '{password_attempt}') => {check_fresh}")
        
        if len(stored_hash) != len(fresh_hash):
            print(f"\n[CRITICAL] Length Mismatch! Stored={len(stored_hash)} vs New={len(fresh_hash)}")
            print("This suggests the database column is TRUNCATING the hash.")
            
except Exception as e:
    print(f"Error: {e}")

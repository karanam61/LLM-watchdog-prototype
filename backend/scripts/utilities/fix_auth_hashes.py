
import os
import sys
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.storage.database import supabase

def fix_hashes():
    print("="*60)
    print("[*] FIXING AUTH HASHES")
    print("="*60)
    
    users = [
        {"username": "analyst", "password": "analyst123"},
        {"username": "admin", "password": "admin123"},
        {"username": "dev", "password": "dev123"}
    ]
    
    for u in users:
        print(f"Updates for {u['username']}...")
        p_hash = generate_password_hash(u['password'])
        
        try:
            # Check if user exists
            res = supabase.table('users').select("*").eq('username', u['username']).execute()
            if res.data:
                # Update
                supabase.table('users').update({"password_hash": p_hash}).eq('username', u['username']).execute()
                print(f"   [OK] Updated hash for {u['username']}")
            else:
                # Insert (if missing)
                data = {
                    "username": u['username'],
                    "password_hash": p_hash,
                    "role": "analyst", # Default
                    "seniority": "senior"
                }
                supabase.table('users').insert(data).execute()
                print(f"   [OK] Created user {u['username']}")
                
        except Exception as e:
            print(f"   [ERROR] Error processing {u['username']}: {e}")

if __name__ == "__main__":
    load_dotenv()
    fix_hashes()

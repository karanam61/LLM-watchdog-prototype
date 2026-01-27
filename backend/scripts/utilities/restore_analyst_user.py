
import os
from backend.storage.database import supabase
from backend.api.auth import hash_password

def restore_analyst():
    print("RESTORING USER: analyst")
    try:
        # Check if exists
        res = supabase.table('users').select('*').eq('username', 'analyst').execute()
        if res.data:
            # Update password
            print("  User exists. Updating password to 'analyst123'...")
            pw_hash = hash_password('analyst123')
            supabase.table('users').update({'password_hash': pw_hash}).eq('username', 'analyst').execute()
        else:
            # Create new
            print("  User missing. Creating 'analyst'...")
            pw_hash = hash_password('analyst123')
            supabase.table('users').insert({
                'username': 'analyst',
                'password_hash': pw_hash,
                'role': 'analyst',
                'full_name': 'Senior SOC Analyst'
            }).execute()
            
        print("[OK] SUCCESS: You can now login as analyst / analyst123")
    except Exception as e:
        print(f"[ERROR] ERROR: {e}")

if __name__ == "__main__":
    restore_analyst()

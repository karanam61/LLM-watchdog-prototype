
import os
import sys
from dotenv import load_dotenv

# Add parent directory to path to import backend modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.storage.database import get_db_client
from werkzeug.security import generate_password_hash

def seed_users():
    supabase = get_db_client()
    
    users = [
        # Defaults (Using generic scrypt can be too long for some DB cols, switching to pbkdf2:sha256 for safety)
        {"username": "analyst", "password_hash": generate_password_hash("analyst123", method='pbkdf2:sha256'), "role": "analyst", "seniority": "junior"},
        {"username": "dev", "password_hash": generate_password_hash("dev123", method='pbkdf2:sha256'), "role": "developer", "seniority": "senior"},
        {"username": "senior", "password_hash": generate_password_hash("senior123", method='pbkdf2:sha256'), "role": "analyst", "seniority": "senior"},
        {"username": "admin", "password_hash": generate_password_hash("admin123", method='pbkdf2:sha256'), "role": "data_analyst", "seniority": "senior"},
        
        # User requested / attempted credentials
        {"username": "analyst1", "password_hash": generate_password_hash("securepass1", method='pbkdf2:sha256'), "role": "analyst", "seniority": "junior"}
    ]
    
    print("Seeding users (FORCE REWRITE)...")
    
    for user in users:
        try:
            # 1. Delete existing
            supabase.table('users').delete().eq('username', user['username']).execute()
            print(f"[Deleted] {user['username']}")
            
            # 2. Insert fresh
            result = supabase.table('users').insert(user).execute()
            print(f"[Created] {user['username']}")
                
        except Exception as e:
            print(f"[X] Failed to process {user['username']}: {e}")

if __name__ == "__main__":
    seed_users()

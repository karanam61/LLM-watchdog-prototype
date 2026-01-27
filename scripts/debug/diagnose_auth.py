
import os
import sys
from dotenv import load_dotenv

# Load env vars
load_dotenv()

from supabase import create_client
from werkzeug.security import check_password_hash, generate_password_hash

# Initialize Client
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")
service_key = os.getenv("SUPABASE_SERVICE_KEY")

print(f"URL: {url}")
print(f"Key (Anon): {key[:10]}...")
if service_key:
    print(f"Service Key: {service_key[:10]}...")
else:
    print("Service Key: Not Found")

# Try with Anon Key first
print("\n[1] Testing with ANON KEY...")
try:
    client = create_client(url, key)
    response = client.table('users').select("*").eq('username', 'analyst').execute()
    if response.data:
        user = response.data[0]
        print(f"   User Found: {user['username']}")
        print(f"   Stored Hash: {user['password_hash']}")
        print(f"   Hash Length: {len(user['password_hash'])}")
        
        # Verify
        test_pass = "analyst123"
        is_valid = check_password_hash(user['password_hash'], test_pass)
        print(f"   Verification ('{test_pass}'): {'PASS' if is_valid else 'FAIL'}")
        
        # Generate new hash to compare
        new_hash = generate_password_hash(test_pass)
        print(f"   New Hash would be: {new_hash}")
    else:
        print("   User 'analyst' NOT FOUND (RLS might be blocking read)")
except Exception as e:
    print(f"   Error: {e}")

# Try with Service Key if available
if service_key:
    print("\n[2] Testing with SERVICE KEY...")
    try:
        client = create_client(url, service_key)
        response = client.table('users').select("*").eq('username', 'analyst').execute()
        if response.data:
            user = response.data[0]
            print(f"   User Found: {user['username']}")
            print(f"   Verification: {'PASS' if check_password_hash(user['password_hash'], 'analyst123') else 'FAIL'}")
        else:
            print("   User 'analyst' NOT FOUND even with Service Key")
    except Exception as e:
        print(f"   Error: {e}")

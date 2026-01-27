
import os
import sys
from dotenv import load_dotenv
from supabase import create_client
from werkzeug.security import check_password_hash

load_dotenv()

# Setup
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")
client = create_client(url, key)

print("--- FINAL AUTH VERIFICATION ---")

# 1. Fetch
response = client.table('users').select("*").eq('username', 'analyst').execute()
if not response.data:
    print("[FAIL] User not found.")
    sys.exit(1)

user = response.data[0]
stored_hash = user['password_hash']
print(f"[INFO] Hash Length: {len(stored_hash)}")

# 2. Check Truncation
if len(stored_hash) < 60:
    print(f"[FAIL] TRUNCATION DETECTED! Length is only {len(stored_hash)}")
    print("Run the SQL 'ALTER TABLE users ALTER COLUMN password_hash TYPE TEXT;' immediately.")
else:
    print("[PASS] Hash length is healthy.")

# 3. Verify
is_valid = check_password_hash(stored_hash, "analyst123")
if is_valid:
    print("[SUCCESS] Login Verified! 'analyst123' works.")
else:
    print("[FAIL] Password mismatch. The stored hash does not match 'analyst123'.")

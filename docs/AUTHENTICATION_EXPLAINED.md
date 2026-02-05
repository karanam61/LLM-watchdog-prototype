# Authentication System Explained

## The Password Bug

For 1.5 days, login failed with "Incorrect Password" even though the password was correct.

The cause: Password hashing creates a long string (about 100 characters), but the database column was limited to 10 characters. The hash got truncated, so verification always failed.

The fix:
1. Changed the database column type to TEXT (unlimited length)
2. Re-ran seed_users.py to create users with complete hashes

## How Login Works

### Step 1: Frontend
File: src/components/Login.jsx

You enter credentials, the app packages them as JSON and sends to the backend.

### Step 2: Backend API
File: backend/api/auth.py

The server receives the request and asks the database for the stored user record.

### Step 3: Password Verification
File: backend/api/auth.py

The backend hashes your input and compares it to the stored hash using werkzeug.security.check_password_hash.

### Step 4: Token Creation
If the password matches, the server creates a JWT token containing your identity and expiration time, signed with a secret key.

### Step 5: Browser Storage
File: src/contexts/AuthContext.jsx

The frontend stores the token in localStorage.

### Step 6: Using Protected Routes
File: src/utils/api.js

For subsequent requests, the token is automatically attached to the Authorization header. The backend verifies the signature before allowing access.

## Glossary

| Term | Definition |
|------|------------|
| Plain Text | Password as typed (insecure to store) |
| Hashing | One-way scrambling of password into random characters |
| Salt | Random data added before hashing to prevent rainbow table attacks |
| JWT | JSON Web Token - a signed identity card |
| Bearer Token | Token sent in Authorization header |
| CORS | Cross-Origin Resource Sharing - browser security policy |
| Seed Script | Script that resets and recreates initial data |

## Why This Approach

1. We never store passwords, only hashes. Stolen database = useless data.
2. Stateless authentication. The token proves identity without server-side sessions.
3. Role-based access. The token contains the user role for authorization decisions.

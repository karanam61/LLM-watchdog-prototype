"""
Authentication Module - JWT-Based User Authentication
=======================================================

This module handles user authentication for the SOC dashboard using
JSON Web Tokens (JWT).

WHAT THIS FILE DOES:
1. Generates JWT tokens upon successful login
2. Validates JWT tokens on protected endpoints
3. Extracts user info (role, seniority) from tokens
4. Provides @require_auth decorator for protected routes

WHY THIS EXISTS:
- Dashboard needs user authentication
- Different users have different permissions (analyst, admin)
- JWT enables stateless authentication (no server-side sessions)
- Tokens expire after 24 hours for security

KEY FUNCTIONS:
- generate_token()  - Create JWT after successful login
- require_auth()    - Decorator to protect endpoints
- login_user()      - Authenticate user credentials

TOKEN PAYLOAD:
{
    "user_id": str,
    "username": str,
    "role": str,        # "analyst", "admin"
    "seniority": str,   # "junior", "senior"
    "exp": datetime     # Expiration time
}

Author: AI-SOC Watchdog System
"""

import datetime
import jwt
import os
from functools import wraps
from flask import request, jsonify, g
from backend.storage.database import get_db_client

# Secret key for JWT (should be in .env)
import logging
logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-in-prod")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

def generate_token(user_id, username, role, seniority):
    """Generates a JWT token for the user."""
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "seniority": seniority,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def require_auth(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Debug logging
        print(f"\n[AUTH DEBUG] Incoming request to: {request.path}")
        print(f"[AUTH DEBUG] All headers: {dict(request.headers)}")
        print(f"[AUTH DEBUG] Authorization header: {request.headers.get('Authorization', 'MISSING')}")

        auth_header = request.headers.get('Authorization', '')
        print(f"[AUTH DEBUG] Extracted auth_header: '{auth_header}'")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            print(f"[AUTH DEBUG] Extracted token: {token[:20]}...")
        else:
            print(f"[AUTH DEBUG] No valid Bearer token found")
        
        if not token:
            return jsonify({"error": "Missing Authorization Token"}), 401
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            g.user = payload # Store user info in global context
            print(f"[AUTH DEBUG] Token valid! User: {payload.get('username')}, Role: {payload.get('role')}")
        except jwt.ExpiredSignatureError:
            print(f"[AUTH DEBUG] Token expired!")
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError as e:
            print(f"[AUTH DEBUG] Invalid token: {e}")
            return jsonify({"error": "Invalid Token"}), 401
            
        return f(*args, **kwargs)
    return decorated

def require_role(allowed_roles):
    """Decorator to require specific roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user'):
                return jsonify({"error": "User not authenticated"}), 401
            
            if g.user['role'] not in allowed_roles:
                return jsonify({"error": "Insufficient Permissions"}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def login_user(data):
    """
    Authenticates user against Supabase 'users' table.
    Expects data: { "username": "...", "password": "..." }
    """
    username = data.get('username')
    password = data.get('password') # In real app, verify hash!
    
    supabase = get_db_client()
    
    # DEBUG: Step-by-Step Trace
    print(f"\n[AUTH TRACE] 1. Received login request for: '{username}'")
    
    # Query user
    response = supabase.table('users').select("*").eq('username', username).execute()
    
    if not response.data:
        print(f"[AUTH TRACE] 2. DB Query Result: User NOT found.")
        return {"error": "User not found", "status": 404}
    
    user = response.data[0]
    stored_hash = user['password_hash']
    print(f"[AUTH TRACE] 2. DB Query Result: User found! (Hash len: {len(stored_hash)})")
    print(f"[AUTH TRACE] 2.5. First 30 chars of stored hash: {stored_hash[:30]}")
    print(f"[AUTH TRACE] 2.6. Does it start with 'pbkdf2'? {stored_hash.startswith('pbkdf2')}")
    
    # Secure Password Check
    from werkzeug.security import check_password_hash
    
    print(f"[AUTH TRACE] 3. Verifying Password Hash...")
    is_valid = check_password_hash(stored_hash, password)
    
    print(f"[AUTH TRACE] 3.5. check_password_hash returned: {is_valid}")


    
    if not is_valid: 
         print(f"[AUTH TRACE] 4. Verdict: INVALID PASSWORD [ERROR]")
         return {"error": "Incorrect password", "status": 401}
    
    print(f"[AUTH TRACE] 4. Verdict: SUCCESS [OK]")
    
    # Generate Token
    token = generate_token(str(user['id']), user['username'], user['role'], user['seniority'])
    
    return {
        "token": token,
        "user": {
            "username": user['username'],
            "role": user['role'],
            "seniority": user['seniority']
        },
        "status": 200
    }

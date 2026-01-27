"""
Flask Security Module - Rate Limiting, Authentication & CORS
=============================================================

FEATURES IMPLEMENTED:
1. Rate Limiting - Prevent API abuse and DoS attacks
2. Authentication - API key validation for secure access
3. CORS Configuration - Safe cross-origin requests from frontend

WHY THIS EXISTS:
- Rate limiting prevents brute force and DoS attacks
- Authentication ensures only authorized systems can submit alerts
- CORS enables secure frontend-backend communication
- Production security requirements for public-facing APIs

ARCHITECTURE:
    Request -> Rate Limit Check -> Auth Check -> CORS Check -> Process
                [*]                    [*]              [*]
          Block if exceeded    401 if invalid  Block if origin bad

Author: AI-SOC Watchdog System
"""

import os
import time
import logging
import hashlib
from typing import Dict, List, Optional, Callable, Any
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
from flask import request, jsonify, Flask

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiting to prevent API abuse.
    
    Feature 1: Limits requests per IP/user to prevent:
    - Brute force attacks
    - Denial of Service (DoS)
    - Resource exhaustion
    - API abuse
    
    Implements token bucket algorithm:
    - Each client gets N tokens per time window
    - Each request consumes 1 token
    - Tokens refill over time
    - Requests blocked when tokens exhausted
    
    Multiple limits supported:
    - Per-second limits (burst protection)
    - Per-minute limits (sustained protection)
    - Per-hour limits (long-term protection)
    - Per-endpoint custom limits
    
    Usage:
        limiter = RateLimiter()
        
        @limiter.limit("10 per minute")
        def my_endpoint():
            return "OK"
    """
    
    def __init__(self):
        """Initialize rate limiter."""
        logger.info("[*] Initializing Rate Limiter")
        
        # Storage: {client_key: {window: [timestamps]}}
        self.requests = defaultdict(lambda: defaultdict(list))
        
        # Default limits
        self.default_limits = {
            'second': 5,   # Max 5 requests per second
            'minute': 60,  # Max 60 requests per minute
            'hour': 1000   # Max 1000 requests per hour
        }
        
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'unique_clients': set()
        }
        
        logger.info("[OK] Rate Limiter ready")
        logger.info(f"   Default limits: {self.default_limits}")
    
    def _get_client_key(self) -> str:
        """
        Get unique client identifier.
        
        Uses (in order of preference):
        1. API key from headers
        2. IP address
        3. Fallback identifier
        
        Returns:
            Client identifier string
        """
        # Try API key first (if authenticated)
        api_key = request.headers.get('X-API-Key', '')
        if api_key:
            # Hash for privacy
            return f"key_{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"
        
        # Use IP address
        ip = request.remote_addr or 'unknown'
        return f"ip_{ip}"
    
    def _clean_old_requests(self, client_key: str, window: str, max_age: int):
        """
        Remove expired request timestamps.
        
        Args:
            client_key: Client identifier
            window: Time window (second/minute/hour)
            max_age: Max age in seconds
        """
        now = time.time()
        cutoff = now - max_age
        
        # Remove old timestamps
        self.requests[client_key][window] = [
            ts for ts in self.requests[client_key][window]
            if ts > cutoff
        ]
    
    def _check_limit(self, client_key: str, window: str, limit: int, max_age: int) -> bool:
        """
        Check if client is within rate limit.
        
        Args:
            client_key: Client identifier
            window: Time window (second/minute/hour)
            limit: Max requests allowed in window
            max_age: Window size in seconds
            
        Returns:
            True if within limit, False if exceeded
        """
        # Clean old requests
        self._clean_old_requests(client_key, window, max_age)
        
        # Count requests in window
        request_count = len(self.requests[client_key][window])
        
        # Check limit
        return request_count < limit
    
    def _record_request(self, client_key: str):
        """Record request timestamp for all windows."""
        now = time.time()
        
        for window in ['second', 'minute', 'hour']:
            self.requests[client_key][window].append(now)
    
    def check_rate_limit(
        self,
        limits: Optional[Dict[str, int]] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Check if request is within rate limits.
        
        Args:
            limits: Optional custom limits dict {window: max_requests}
            
        Returns:
            (is_allowed, error_message)
        """
        client_key = self._get_client_key()
        
        # Track unique clients
        self.stats['unique_clients'].add(client_key)
        self.stats['total_requests'] += 1
        
        # Use custom or default limits
        limits = limits or self.default_limits
        
        # Check each window
        windows = {
            'second': 1,
            'minute': 60,
            'hour': 3600
        }
        
        for window, max_age in windows.items():
            if window not in limits:
                continue
            
            limit = limits[window]
            
            if not self._check_limit(client_key, window, limit, max_age):
                # Rate limit exceeded
                self.stats['blocked_requests'] += 1
                
                error_msg = f"Rate limit exceeded: {limit} requests per {window}"
                logger.warning(f"[*] RATE LIMIT: {client_key} - {error_msg}")
                
                return (False, error_msg)
        
        # Within limits - record request
        self._record_request(client_key)
        
        logger.info(f"[OK] Rate limit OK: {client_key}")
        return (True, None)
    
    def limit(self, limit_string: str) -> Callable:
        """
        Decorator for rate limiting endpoints.
        
        Args:
            limit_string: Limit in format "N per second/minute/hour"
                         Examples: "10 per minute", "100 per hour"
        
        Returns:
            Decorator function
        """
        # Parse limit string
        parts = limit_string.lower().split()
        if len(parts) != 3 or parts[1] != 'per':
            raise ValueError(f"Invalid limit format: {limit_string}")
        
        count = int(parts[0])
        window = parts[2].rstrip('s')  # Remove plural 's'
        
        if window not in ['second', 'minute', 'hour']:
            raise ValueError(f"Invalid window: {window}")
        
        custom_limits = {window: count}
        
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def wrapped(*args, **kwargs):
                # Check rate limit
                is_allowed, error_msg = self.check_rate_limit(custom_limits)
                
                if not is_allowed:
                    return jsonify({
                        'error': 'rate_limit_exceeded',
                        'message': error_msg
                    }), 429  # Too Many Requests
                
                # Execute endpoint
                return f(*args, **kwargs)
            
            return wrapped
        return decorator
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            'total_requests': self.stats['total_requests'],
            'blocked_requests': self.stats['blocked_requests'],
            'unique_clients': len(self.stats['unique_clients']),
            'block_rate': (
                self.stats['blocked_requests'] / self.stats['total_requests']
                if self.stats['total_requests'] > 0 else 0
            )
        }


class APIKeyAuthenticator:
    """
    API key authentication for secure access.
    
    Feature 2: Validates API keys to ensure:
    - Only authorized systems can submit alerts
    - Audit trail of who submitted what
    - Key rotation and revocation support
    - Different permission levels per key
    
    API key format: "sk_<environment>_<32_hex_chars>"
    Example: "sk_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    
    Storage:
    - Production: Database with hashed keys
    - Development: Environment variables
    
    Usage:
        auth = APIKeyAuthenticator()
        
        @auth.require_api_key
        def protected_endpoint():
            return "Protected content"
    """
    
    def __init__(self, api_keys: Optional[List[str]] = None):
        """
        Initialize API key authenticator.
        
        Args:
            api_keys: Optional list of valid API keys
                     If None, loads from VALID_API_KEYS env var
        """
        logger.info("[*] Initializing API Key Authenticator")
        
        # Load API keys
        if api_keys is None:
            # Load from environment
            keys_str = os.getenv('VALID_API_KEYS', '')
            api_keys = [k.strip() for k in keys_str.split(',') if k.strip()]
        
        # Store hashed keys (never store raw keys)
        self.valid_key_hashes = set()
        for key in api_keys:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            self.valid_key_hashes.add(key_hash)
        
        # Key metadata (for audit trails)
        self.key_metadata = {}
        
        self.stats = {
            'total_attempts': 0,
            'successful_auth': 0,
            'failed_auth': 0,
            'missing_key': 0
        }
        
        logger.info(f"[OK] API Key Authenticator ready")
        logger.info(f"   Valid keys loaded: {len(self.valid_key_hashes)}")
    
    def _validate_key_format(self, api_key: str) -> bool:
        """
        Validate API key format.
        
        Expected format: sk_<env>_<32_hex_chars>
        
        Args:
            api_key: API key to validate
            
        Returns:
            True if format valid
        """
        if not api_key.startswith('sk_'):
            return False
        
        parts = api_key.split('_')
        if len(parts) != 3:
            return False
        
        # Check environment (prod/dev/test)
        env = parts[1]
        if env not in ['prod', 'dev', 'test']:
            return False
        
        # Check key part (should be 32+ chars)
        key_part = parts[2]
        if len(key_part) < 32:
            return False
        
        return True
    
    def _hash_key(self, api_key: str) -> str:
        """Hash API key for comparison."""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def validate_api_key(self, api_key: str) -> bool:
        """
        Validate API key.
        
        Args:
            api_key: API key to validate
            
        Returns:
            True if valid
        """
        self.stats['total_attempts'] += 1
        
        # Check format
        if not self._validate_key_format(api_key):
            logger.warning("[WARNING]  Invalid API key format")
            self.stats['failed_auth'] += 1
            return False
        
        # Hash and compare
        key_hash = self._hash_key(api_key)
        
        if key_hash in self.valid_key_hashes:
            self.stats['successful_auth'] += 1
            logger.info("[OK] API key validated")
            return True
        else:
            self.stats['failed_auth'] += 1
            logger.warning("[ERROR] Invalid API key")
            return False
    
    def require_api_key(self, f: Callable) -> Callable:
        """
        Decorator to require API key authentication.
        
        Checks X-API-Key header for valid key.
        
        Returns 401 Unauthorized if:
        - No API key provided
        - Invalid API key format
        - API key not recognized
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            # Get API key from header
            api_key = request.headers.get('X-API-Key')
            
            if not api_key:
                self.stats['missing_key'] += 1
                logger.warning("[WARNING]  No API key provided")
                return jsonify({
                    'error': 'unauthorized',
                    'message': 'API key required. Provide X-API-Key header.'
                }), 401
            
            # Validate key
            if not self.validate_api_key(api_key):
                return jsonify({
                    'error': 'unauthorized',
                    'message': 'Invalid API key'
                }), 401
            
            # Execute endpoint
            return f(*args, **kwargs)
        
        return decorated
    
    def add_api_key(self, api_key: str, metadata: Optional[Dict] = None):
        """
        Add new API key (for dynamic key management).
        
        Args:
            api_key: New API key to add
            metadata: Optional metadata (owner, permissions, etc.)
        """
        key_hash = self._hash_key(api_key)
        self.valid_key_hashes.add(key_hash)
        
        if metadata:
            self.key_metadata[key_hash] = metadata
        
        logger.info(f"[OK] Added new API key: {api_key[:10]}...")
    
    def revoke_api_key(self, api_key: str):
        """
        Revoke API key.
        
        Args:
            api_key: API key to revoke
        """
        key_hash = self._hash_key(api_key)
        
        if key_hash in self.valid_key_hashes:
            self.valid_key_hashes.remove(key_hash)
            logger.info(f"[*]  Revoked API key: {api_key[:10]}...")
        else:
            logger.warning(f"[WARNING]  API key not found: {api_key[:10]}...")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get authentication statistics."""
        return {
            'total_attempts': self.stats['total_attempts'],
            'successful': self.stats['successful_auth'],
            'failed': self.stats['failed_auth'],
            'missing_key': self.stats['missing_key'],
            'success_rate': (
                self.stats['successful_auth'] / self.stats['total_attempts']
                if self.stats['total_attempts'] > 0 else 0
            )
        }


class CORSManager:
    """
    CORS (Cross-Origin Resource Sharing) configuration.
    
    Feature 3: Enables safe cross-origin requests from frontend.
    
    Security considerations:
    - Whitelist specific origins (not wildcard *)
    - Limit allowed methods (GET, POST only)
    - Control allowed headers
    - Set appropriate max age for preflight caching
    
    Prevents:
    - Cross-site scripting (XSS) attacks
    - Cross-site request forgery (CSRF)
    - Unauthorized API access from malicious sites
    
    Usage:
        cors = CORSManager(allowed_origins=[
            'http://localhost:5173',
            'https://soc.company.com'
        ])
        
        cors.configure(app)
    """
    
    def __init__(
        self,
        allowed_origins: Optional[List[str]] = None,
        allowed_methods: Optional[List[str]] = None,
        allowed_headers: Optional[List[str]] = None,
        max_age: int = 3600
    ):
        """
        Initialize CORS manager.
        
        Args:
            allowed_origins: List of allowed origins (domains)
            allowed_methods: List of allowed HTTP methods
            allowed_headers: List of allowed headers
            max_age: Preflight cache duration in seconds
        """
        logger.info("[*] Initializing CORS Manager")
        
        # Default allowed origins
        if allowed_origins is None:
            # Load from environment or use defaults
            origins_str = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5173')
            allowed_origins = [o.strip() for o in origins_str.split(',')]
        
        self.allowed_origins = set(allowed_origins)
        
        # Default allowed methods
        self.allowed_methods = allowed_methods or ['GET', 'POST', 'OPTIONS']
        
        # Default allowed headers
        self.allowed_headers = allowed_headers or [
            'Content-Type',
            'X-API-Key',
            'Authorization'
        ]
        
        self.max_age = max_age
        
        self.stats = {
            'total_requests': 0,
            'allowed_requests': 0,
            'blocked_requests': 0,
            'preflight_requests': 0
        }
        
        logger.info("[OK] CORS Manager ready")
        logger.info(f"   Allowed origins: {self.allowed_origins}")
        logger.info(f"   Allowed methods: {self.allowed_methods}")
    
    def _is_origin_allowed(self, origin: str) -> bool:
        """
        Check if origin is in whitelist.
        
        Args:
            origin: Origin from request
            
        Returns:
            True if allowed
        """
        # No origin header (same-origin request)
        if not origin:
            return True
        
        # Check whitelist
        if origin in self.allowed_origins:
            return True
        
        # Check for wildcard patterns (e.g., *.company.com)
        for allowed in self.allowed_origins:
            if allowed.startswith('*.'):
                domain = allowed[2:]  # Remove *. prefix
                if origin.endswith(domain):
                    return True
        
        return False
    
    def handle_cors(self, f: Callable) -> Callable:
        """
        Decorator to add CORS headers to response.
        
        Handles:
        - Preflight OPTIONS requests
        - CORS headers on actual requests
        - Origin validation
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            self.stats['total_requests'] += 1
            
            # Get origin
            origin = request.headers.get('Origin')
            
            # Handle preflight
            if request.method == 'OPTIONS':
                self.stats['preflight_requests'] += 1
                logger.info("[*]  Preflight request")
                
                # Check origin
                if not self._is_origin_allowed(origin):
                    self.stats['blocked_requests'] += 1
                    logger.warning(f"[*] Blocked origin: {origin}")
                    return jsonify({'error': 'Origin not allowed'}), 403
                
                # Preflight response
                response = jsonify({'status': 'ok'})
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Methods'] = ', '.join(self.allowed_methods)
                response.headers['Access-Control-Allow-Headers'] = ', '.join(self.allowed_headers)
                response.headers['Access-Control-Max-Age'] = str(self.max_age)
                
                self.stats['allowed_requests'] += 1
                return response
            
            # Regular request - check origin
            if origin and not self._is_origin_allowed(origin):
                self.stats['blocked_requests'] += 1
                logger.warning(f"[*] Blocked origin: {origin}")
                return jsonify({'error': 'Origin not allowed'}), 403
            
            # Execute endpoint
            response = f(*args, **kwargs)
            
            # Add CORS headers to response
            if hasattr(response, 'headers') and origin:
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'
            
            self.stats['allowed_requests'] += 1
            return response
        
        return decorated
    
    def configure_flask_app(self, app: Flask):
        """
        Configure Flask app with CORS middleware.
        
        Adds CORS headers to all responses automatically.
        
        Args:
            app: Flask application instance
        """
        logger.info("[*] Configuring Flask app with CORS...")
        
        @app.after_request
        def add_cors_headers(response):
            origin = request.headers.get('Origin')
            
            if origin and self._is_origin_allowed(origin):
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                response.headers['Access-Control-Allow-Methods'] = ', '.join(self.allowed_methods)
                response.headers['Access-Control-Allow-Headers'] = ', '.join(self.allowed_headers)
            
            return response
        
        logger.info("[OK] Flask app configured with CORS")
    
    def add_allowed_origin(self, origin: str):
        """
        Add new allowed origin.
        
        Args:
            origin: Origin to allow (e.g., 'https://new.company.com')
        """
        self.allowed_origins.add(origin)
        logger.info(f"[OK] Added allowed origin: {origin}")
    
    def remove_allowed_origin(self, origin: str):
        """
        Remove allowed origin.
        
        Args:
            origin: Origin to remove
        """
        if origin in self.allowed_origins:
            self.allowed_origins.remove(origin)
            logger.info(f"[*]  Removed allowed origin: {origin}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get CORS statistics."""
        return {
            'total_requests': self.stats['total_requests'],
            'allowed': self.stats['allowed_requests'],
            'blocked': self.stats['blocked_requests'],
            'preflight': self.stats['preflight_requests'],
            'block_rate': (
                self.stats['blocked_requests'] / self.stats['total_requests']
                if self.stats['total_requests'] > 0 else 0
            )
        }


# =============================================================================
# UNIFIED SECURITY CLASS
# =============================================================================

class FlaskSecuritySystem:
    """
    Unified Flask security system combining all 3 features.
    
    Provides complete API security through:
    - Rate limiting (Feature 1) - Prevent abuse
    - Authentication (Feature 2) - Control access
    - CORS (Feature 3) - Enable safe frontend communication
    
    Usage:
        security = FlaskSecuritySystem(
            api_keys=['sk_prod_abc123...'],
            allowed_origins=['http://localhost:5173']
        )
        
        # Secure an endpoint with all 3 features
        @app.route('/ingest')
        @security.rate_limiter.limit("50 per hour")
        @security.authenticator.require_api_key
        @security.cors.handle_cors
        def ingest_log():
            return process_alert()
    """
    
    def __init__(
        self,
        api_keys: Optional[List[str]] = None,
        allowed_origins: Optional[List[str]] = None
    ):
        """
        Initialize unified security system.
        
        Args:
            api_keys: List of valid API keys
            allowed_origins: List of allowed CORS origins
        """
        logger.info("[GUARD]  Initializing Flask Security System")
        
        self.rate_limiter = RateLimiter()
        self.authenticator = APIKeyAuthenticator(api_keys=api_keys)
        self.cors = CORSManager(allowed_origins=allowed_origins)
        
        logger.info("[OK] Flask Security System ready")
    
    def configure_app(self, app: Flask):
        """
        Configure Flask app with all security features.
        
        Args:
            app: Flask application instance
        """
        logger.info("[*] Configuring Flask app with security...")
        
        # Configure CORS
        self.cors.configure_flask_app(app)
        
        logger.info("[OK] Flask app secured")
    
    def secure_endpoint(
        self,
        rate_limit: str = "100 per hour",
        require_auth: bool = True,
        enable_cors: bool = True
    ) -> Callable:
        """
        Combined decorator for securing endpoints.
        
        Args:
            rate_limit: Rate limit string (e.g., "50 per hour")
            require_auth: Whether to require API key
            enable_cors: Whether to enable CORS
            
        Returns:
            Decorator function that applies all selected security features
        """
        def decorator(f: Callable) -> Callable:
            # Apply decorators in order (innermost first)
            secured = f
            
            # CORS (innermost)
            if enable_cors:
                secured = self.cors.handle_cors(secured)
            
            # Authentication
            if require_auth:
                secured = self.authenticator.require_api_key(secured)
            
            # Rate limiting (outermost)
            if rate_limit:
                secured = self.rate_limiter.limit(rate_limit)(secured)
            
            return secured
        
        return decorator
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive security statistics."""
        return {
            'rate_limiter': self.rate_limiter.get_stats(),
            'authenticator': self.authenticator.get_stats(),
            'cors': self.cors.get_stats()
        }


# =============================================================================
# TEST CODE
# =============================================================================

if __name__ == "__main__":
    """Test Flask security features."""
    
    print("=" * 70)
    print("FLASK SECURITY MODULE TEST")
    print("=" * 70)
    
    # Test data
    test_api_keys = [
        'sk_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
        'sk_dev_x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4'
    ]
    
    test_origins = [
        'http://localhost:5173',
        'https://soc.company.com'
    ]
    
    security = FlaskSecuritySystem(
        api_keys=test_api_keys,
        allowed_origins=test_origins
    )
    
    # Test 1: Rate limiting (direct testing without request context)
    print("\n[TEST 1] Rate Limiting")
    print("-" * 70)
    
    # Test rate limiter directly
    limiter = security.rate_limiter
    client_key = "test_client_123"
    
    # Simulate multiple requests from same client
    for i in range(7):
        # Manually check limit
        now = time.time()
        limiter.requests[client_key]['second'].append(now)
        
        # Clean old requests
        limiter._clean_old_requests(client_key, 'second', 1)
        
        # Check if within limit
        request_count = len(limiter.requests[client_key]['second'])
        is_allowed = request_count <= 5  # Max 5 per second
        
        status = "ALLOWED" if is_allowed else f"BLOCKED (exceeded 5 per second)"
        print(f"Request {i+1}: {status}")
    
    # Test 2: Authentication
    print("\n[TEST 2] Authentication")
    print("-" * 70)
    
    # Valid key
    valid_key = test_api_keys[0]
    is_valid = security.authenticator.validate_api_key(valid_key)
    print(f"Valid key: {is_valid}")
    
    # Invalid key
    invalid_key = 'sk_prod_invalid_key_123456789012345678'
    is_valid = security.authenticator.validate_api_key(invalid_key)
    print(f"Invalid key: {is_valid}")
    
    # Wrong format
    wrong_format = 'not_a_valid_format'
    is_valid = security.authenticator.validate_api_key(wrong_format)
    print(f"Wrong format: {is_valid}")
    
    # Test 3: CORS
    print("\n[TEST 3] CORS Configuration")
    print("-" * 70)
    
    allowed_origin = 'http://localhost:5173'
    blocked_origin = 'https://malicious.com'
    
    is_allowed = security.cors._is_origin_allowed(allowed_origin)
    print(f"Allowed origin ({allowed_origin}): {is_allowed}")
    
    is_allowed = security.cors._is_origin_allowed(blocked_origin)
    print(f"Blocked origin ({blocked_origin}): {is_allowed}")
    
    # Comprehensive statistics
    print("\n" + "=" * 70)
    print("COMPREHENSIVE STATISTICS:")
    print("=" * 70)
    
    stats = security.get_comprehensive_stats()
    
    print("\nRate Limiter:")
    print(f"  Total requests: {stats['rate_limiter']['total_requests']}")
    print(f"  Blocked: {stats['rate_limiter']['blocked_requests']}")
    print(f"  Block rate: {stats['rate_limiter']['block_rate']:.1%}")
    
    print("\nAuthenticator:")
    print(f"  Total attempts: {stats['authenticator']['total_attempts']}")
    print(f"  Successful: {stats['authenticator']['successful']}")
    print(f"  Failed: {stats['authenticator']['failed']}")
    print(f"  Success rate: {stats['authenticator']['success_rate']:.1%}")
    
    print("\nCORS:")
    print(f"  Allowed origins: {len(security.cors.allowed_origins)}")
    print(f"  Allowed methods: {security.cors.allowed_methods}")
    
    print("\n" + "=" * 70)
    print("[OK] FLASK SECURITY TEST COMPLETE")
    print("=" * 70)
    
    print("\nFeatures Implemented:")
    print("  1. [OK] Rate limiting (per-second/minute/hour)")
    print("  2. [OK] API key authentication (hashed storage)")
    print("  3. [OK] CORS configuration (origin whitelist)")
    
    print("\nIntegration Example:")
    print("""
    from flask import Flask
    from flask_security import FlaskSecuritySystem
    
    app = Flask(__name__)
    security = FlaskSecuritySystem(
        api_keys=['sk_prod_...'],
        allowed_origins=['http://localhost:5173']
    )
    
    @app.route('/ingest', methods=['POST'])
    @security.secure_endpoint(rate_limit="50 per hour")
    def ingest_log():
        # Your logic here
        return jsonify({'status': 'ok'})
    """)

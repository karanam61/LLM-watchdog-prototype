"""
Tokenizer - Converts Sensitive Data to Safe Tokens
===================================================

This module tokenizes sensitive infrastructure data before it's sent to
the AI for analysis. This protects real IP addresses, hostnames, and
other identifiable information.

WHAT THIS FILE DOES:
1. Replaces real IPs with tokens (10.1.2.3 -> [TOKEN_IP_001])
2. Replaces hostnames with tokens (FINANCE-DC-01 -> [TOKEN_HOST_001])
3. Stores mappings in database for reverse lookup
4. Caches tokens in memory for performance

WHY THIS EXISTS:
- AI models should not see real infrastructure details
- Prevents accidental data leakage to AI APIs
- Enables safe logging and debugging
- Supports compliance requirements (data minimization)

USAGE:
    tokenizer = SecureTokenizer()
    tokenized_alert = tokenizer.tokenize(alert_data)
    # Real IPs and hostnames are now tokens

Author: AI-SOC Watchdog System
"""

import os
from dotenv import load_dotenv
load_dotenv()


import re
import uuid
from datetime import datetime
from supabase import create_client


# Use centralized client
from backend.storage.database import get_db_client

class SecureTokenizer:
    """
    Converts sensitive infrastructure data to tokens.
    """
    
    def __init__(self, client=None):
        """
        Initialize tokenizer with Supabase connection.
        """
        self.client = client if client else get_db_client()
        self.cache = {}  # In-memory cache for speed
        self.token_cache = {} # Reverse cache for detokenization
        
    def tokenize(self, entity_type, real_value):
        """
        Convert a real value to a token.
        """
        # Check cache first
        cache_key = f"{entity_type}:{real_value}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Check if this value was already tokenized (in database)
        result = self.client.table('token_map')\
            .select('token')\
            .eq('real_value', real_value)\
            .eq('entity_type', entity_type)\
            .execute()
        
        if result.data:
            # Already exists, return existing token
            token = result.data[0]['token']
            self.cache[cache_key] = token
            self.token_cache[token] = real_value
            return token
        
        # Create new token
        token = self._generate_token(entity_type)
        
        # Store in database
        self.client.table('token_map').insert({
            'token': token,
            'real_value': real_value,
            'entity_type': entity_type
        }).execute()
        
        # Cache it
        self.cache[cache_key] = token
        self.token_cache[token] = real_value
        
        return token
    
    def detokenize(self, token):
        """
        Convert a token back to real value.
        ONLY use this for displaying to analysts!
        """
        # Check cache first
        if token in self.token_cache:
            return self.token_cache[token]

        result = self.client.table('token_map')\
            .select('real_value')\
            .eq('token', token)\
            .execute()
        
        if result.data:
            real_value = result.data[0]['real_value']
            self.token_cache[token] = real_value
            return real_value
        
        return token  # Return as-is if not found
    
    def _generate_token(self, entity_type):
        """Generate a new unique token."""
        prefix_map = {
            'ip': 'IP',
            'hostname': 'HOST',
            'username': 'USER',
            'email': 'EMAIL'
        }
        
        prefix = prefix_map.get(entity_type, 'TOKEN')
        unique_id = uuid.uuid4().hex[:8]
        
        return f"{prefix}-{unique_id}"

# Create singleton instance
tokenizer = SecureTokenizer()
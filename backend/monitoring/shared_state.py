"""
Shared State - Global Singleton Registry
=========================================

This module provides a single source of truth for shared instances
(like the live_logger) that need to be accessed across different modules.

WHAT THIS FILE DOES:
1. Stores global singleton instances
2. Provides getter/setter functions
3. Ensures same object regardless of import path
4. Solves circular import issues

WHY THIS EXISTS:
- Python's import system can create multiple instances
- Different import paths (relative vs absolute) create separate objects
- Monitoring blueprints need access to the same logger instance
- Centralizing shared state prevents bugs

USAGE:
    # In app.py (initialization):
    from backend.monitoring import shared_state
    shared_state.set_live_logger(live_logger)
    
    # In any other module:
    from backend.monitoring import shared_state
    logger = shared_state.get_live_logger()

Author: AI-SOC Watchdog System
"""

# This will be set by app.py at startup
_live_logger = None

def set_live_logger(logger):
    global _live_logger
    _live_logger = logger

def get_live_logger():
    global _live_logger
    return _live_logger

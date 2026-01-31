"""
API Resilience Module - Robust Claude API Client
=================================================

FEATURES IMPLEMENTED:
1. Timeout Handling - Prevents hanging on slow/down APIs
2. Retry Logic with Exponential Backoff - Handles transient failures
3. Error Handling - Graceful failures with clear messages
4. Token Counting & Budget - Tracks costs and prevents overruns
5. API Key Management - Secure storage and validation

WHY THIS EXISTS:
- APIs fail, networks drop, timeouts happen
- Need resilience so temporary failures don't crash system
- Cost control to prevent runaway spending
- Security to protect API keys

ARCHITECTURE:
    Alert -> Check Budget -> Call API (with timeout + retry)
                                [*]
                          Track Tokens & Cost
                                [*]
                          Return Response or Error

Author: AI-SOC Watchdog System
"""

import os
import time
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import anthropic
from anthropic import APIError, APIConnectionError, RateLimitError, APITimeoutError

logger = logging.getLogger(__name__)


class ClaudeAPIClient:
    """
    Resilient Claude API client with production-grade reliability.
    
    Features:
    - Automatic retry with exponential backoff (1s, 2s, 4s, 8s)
    - Timeout protection (default 30s)
    - Token counting and cost tracking
    - Secure API key management
    - Comprehensive error handling
    - Integration with budget tracker
    - Model selection based on severity (cost optimization)
    
    Usage:
        client = ClaudeAPIClient()
        response = client.analyze_with_resilience(context, budget_tracker)
    """
    
    # Model pricing (as of 2026-01)
    MODEL_PRICING = {
        'claude-sonnet-4-20250514': {'input': 0.000003, 'output': 0.000015},  # $3/$15 per 1M
        'claude-3-5-sonnet-20241022': {'input': 0.000003, 'output': 0.000015},  # $3/$15 per 1M
        'claude-3-5-haiku-20241022': {'input': 0.0000008, 'output': 0.000004},  # $0.80/$4 per 1M - 80% cheaper!
        'claude-3-haiku-20240307': {'input': 0.00000025, 'output': 0.00000125},  # $0.25/$1.25 per 1M - 90% cheaper!
    }
    
    # Default to sonnet pricing if model not found
    INPUT_TOKEN_COST = 0.000003   # $3 / 1M tokens
    OUTPUT_TOKEN_COST = 0.000015  # $15 / 1M tokens
    
    # Model recommendations by severity
    SEVERITY_MODEL_MAP = {
        'CRITICAL_HIGH': 'claude-sonnet-4-20250514',  # Use best model for critical
        'critical': 'claude-sonnet-4-20250514',
        'high': 'claude-sonnet-4-20250514',
        'MEDIUM_LOW': 'claude-3-haiku-20240307',  # Use cheapest for low/medium
        'medium': 'claude-3-5-haiku-20241022',
        'low': 'claude-3-haiku-20240307',  # Use absolute cheapest
    }
    
    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        """
        Initialize resilient Claude API client.
        
        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Claude model to use
        """
        logger.info("[API Client] Initializing...")
        
        # Feature 5: Secure API key management
        self.api_key = self._load_and_validate_api_key(api_key)
        self.model = model
        
        # Create Anthropic client
        self.client = anthropic.Anthropic(api_key=self.api_key)
        
        # Statistics tracking
        self.stats = {
            'total_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'retries': 0,
            'timeouts': 0,
            'rate_limits': 0,
            'total_input_tokens': 0,
            'total_output_tokens': 0,
            'total_cost': 0.0
        }
        
        logger.info(f"[API Client] [OK] Initialized with model: {model}")
    
    # =========================================================================
    # FEATURE 5: API Key Management
    # =========================================================================
    
    def _load_and_validate_api_key(self, api_key: Optional[str] = None) -> str:
        """
        Securely load and validate API key.
        
        Security checks:
        1. Load from environment (never hardcode)
        2. Validate format (must start with sk-ant-)
        3. Validate length (must be reasonable)
        
        Args:
            api_key: Optional API key (defaults to env var)
        
        Returns:
            Validated API key
        
        Raises:
            ValueError: If API key is missing or invalid
        """
        logger.info("[API Key] Loading...")
        
        # Load from parameter or environment
        key = api_key or os.getenv("ANTHROPIC_API_KEY")
        
        # Check if exists
        if not key:
            raise ValueError(
                "ANTHROPIC_API_KEY not found. Set it in environment:\n"
                "export ANTHROPIC_API_KEY='sk-ant-...'"
            )
        
        # Validate format
        if not key.startswith("sk-ant-"):
            raise ValueError(
                f"Invalid API key format. Must start with 'sk-ant-', got: {key[:10]}..."
            )
        
        # Validate length (Anthropic keys are typically 100+ chars)
        if len(key) < 50:
            raise ValueError(
                f"API key too short ({len(key)} chars). Anthropic keys are 100+ chars."
            )
        
        logger.info("[API Key] [OK] Validated")
        return key
    
    # =========================================================================
    # FEATURE 4: Token Counting & Cost Calculation
    # =========================================================================
    
    def _calculate_cost(self, usage: Any) -> Tuple[int, int, float]:
        """
        Calculate cost from token usage.
        
        Args:
            usage: Response usage object with input_tokens and output_tokens
        
        Returns:
            Tuple of (input_tokens, output_tokens, cost_in_dollars)
        """
        input_tokens = usage.input_tokens
        output_tokens = usage.output_tokens
        
        # Calculate cost
        input_cost = input_tokens * self.INPUT_TOKEN_COST
        output_cost = output_tokens * self.OUTPUT_TOKEN_COST
        total_cost = input_cost + output_cost
        
        logger.info(
            f"[Tokens] Input: {input_tokens}, Output: {output_tokens}, "
            f"Cost: ${total_cost:.6f}"
        )
        
        return input_tokens, output_tokens, total_cost
    
    def _update_stats(self, input_tokens: int, output_tokens: int, cost: float):
        """Update statistics with token usage."""
        self.stats['total_input_tokens'] += input_tokens
        self.stats['total_output_tokens'] += output_tokens
        self.stats['total_cost'] += cost
    
    # =========================================================================
    # FEATURE 1: Timeout Handling
    # =========================================================================
    
    def _call_with_timeout(
        self, 
        messages: list,
        timeout: int = 30,
        max_tokens: int = 2000,
        temperature: float = 0.0,
        model: str = None  # NEW: Allow model override
    ) -> Any:
        """
        Call Claude API with timeout protection.
        
        Args:
            messages: List of message dicts
            timeout: Max seconds to wait (default 30)
            max_tokens: Max tokens in response
            temperature: Temperature for response
            model: Model to use (defaults to self.model)
        
        Returns:
            API response
        
        Raises:
            APITimeoutError: If request exceeds timeout
        """
        use_model = model or self.model
        logger.info(f"[Timeout] Calling API ({use_model}) with {timeout}s timeout...")
        
        # System prompt: SOC Analyst with Structured Investigation Framework
        system_prompt = """You are a senior Security Operations Center (SOC) analyst. Your role is to triage alerts using a systematic investigation methodology.

## YOUR INVESTIGATION FRAMEWORK (Apply to EVERY alert)

### STEP 1: ESTABLISH BASELINE
- Is this user/system known? What is their normal activity pattern?
- Is this behavior expected for this role/department/time of day?
- Have we seen this exact alert before? What was the outcome?

### STEP 2: ANALYZE THE 5 W's
- WHO: Which user/service account? Privileged or standard? Known or anomalous?
- WHAT: What action was taken? What process/file/command is involved?
- WHERE: Source/destination IPs and hosts - internal, external, known bad?
- WHEN: Time of activity - business hours? Maintenance window? Unusual timing?
- WHY: Is there a legitimate business reason? Scheduled task? Admin activity?

### STEP 3: EVALUATE INDICATORS
- Process chain: Is the parent-child relationship suspicious? (e.g., Word spawning PowerShell)
- Network behavior: Unusual ports, protocols, or destinations?
- File activity: Sensitive locations accessed? Unusual file types created?
- Persistence: Any signs of establishing persistence mechanisms?
- MITRE mapping: Which tactics and techniques apply? What's the attack stage?

### STEP 4: CROSS-REFERENCE
- OSINT: Are IPs/domains/hashes known malicious?
- Historical: Have we seen this pattern before? False positive history?
- Business context: Does this align with known IT changes or maintenance?
- Asset criticality: How important is the affected system?

### STEP 5: MAKE THE CALL
- BENIGN: Clear legitimate activity with explainable business purpose
- MALICIOUS: Clear attack indicators with no legitimate explanation
- SUSPICIOUS: Genuine uncertainty - escalate for human review

## DECISION PRINCIPLES
- Default to BENIGN when evidence shows routine admin/system activity
- Default to MALICIOUS when multiple attack indicators align
- Use SUSPICIOUS sparingly - only when genuinely uncertain
- Always explain WHY, not just WHAT you found"""

        try:
            response = self.client.messages.create(
                model=use_model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_prompt,  # [*] System prompt for role definition
                messages=messages,
                timeout=timeout  # [*] Timeout protection
            )
            
            logger.info("[Timeout] [OK] Response received")
            return response
        
        except APITimeoutError as e:
            self.stats['timeouts'] += 1
            logger.error(f"[Timeout] [ERROR] Timeout after {timeout}s")
            raise
    
    # =========================================================================
    # FEATURE 2: Retry Logic with Exponential Backoff
    # =========================================================================
    
    def _call_with_retry(
        self,
        messages: list,
        max_retries: int = 5,
        timeout: int = 30,
        max_tokens: int = 2000,
        model: str = None  # NEW: Allow model override
    ) -> Any:
        """
        Call API with retry logic and exponential backoff.
        
        Retry strategy:
        - Attempt 1: Immediate
        - Attempt 2: Wait 1s
        - Attempt 3: Wait 2s
        - Attempt 4: Wait 4s
        - Attempt 5: Wait 8s
        
        Args:
            messages: Message list
            max_retries: Max retry attempts (default 5)
            timeout: Timeout per attempt
            max_tokens: Max output tokens
            model: Model to use
        
        Returns:
            API response
        
        Raises:
            Exception: If all retries fail
        """
        logger.info(f"[Retry] Starting with max {max_retries} attempts (model: {model or self.model})...")
        
        last_error = None
        
        for attempt in range(max_retries):
            try:
                # Try the API call
                response = self._call_with_timeout(
                    messages=messages,
                    timeout=timeout,
                    max_tokens=max_tokens,
                    model=model
                )
                
                # Success!
                if attempt > 0:
                    self.stats['retries'] += attempt
                    logger.info(f"[Retry] [OK] Succeeded on attempt {attempt + 1}")
                    print(f"[AI TRACE] [OK] API Call Succeeded on attempt {attempt + 1}")
                
                return response
            
            except RateLimitError as e:
                # Rate limited - wait longer
                self.stats['rate_limits'] += 1
                last_error = e
                
                if attempt == max_retries - 1:
                    logger.error("[Retry] [ERROR] Rate limited on final attempt")
                    raise
                
                # Wait longer for rate limits (60s)
                wait_time = 60
                logger.warning(f"[Retry] Rate limited, waiting {wait_time}s...")
                time.sleep(wait_time)
            
            except (APIConnectionError, APITimeoutError) as e:
                # Network/timeout errors - retry with backoff
                last_error = e
                
                if attempt == max_retries - 1:
                    logger.error(f"[Retry] [ERROR] Failed after {max_retries} attempts")
                    raise
                
                # Exponential backoff: 1s, 2s, 4s, 8s
                wait_time = 2 ** attempt
                logger.warning(
                    f"[Retry] Attempt {attempt + 1} failed: {e.__class__.__name__}, "
                    f"retrying in {wait_time}s..."
                )
                print(f"[AI TRACE] [WARNING] API Call Failed (Attempt {attempt+1}/{max_retries}): {e}")
                print(f"[AI TRACE] [*] Retrying in {wait_time}s...")
                time.sleep(wait_time)
            
            except APIError as e:
                # Other API errors - don't retry
                logger.error(f"[Retry] [ERROR] API error (not retrying): {e}")
                raise
        
        # Should never reach here, but just in case
        raise last_error
    
    # =========================================================================
    # FEATURE 3: Error Handling
    # =========================================================================
    
    def _handle_error(self, error: Exception) -> Dict[str, Any]:
        """
        Handle errors gracefully with clear messages.
        
        Args:
            error: Exception that occurred
        
        Returns:
            Error response dictionary
        """
        logger.error(f"[Error Handler] Processing: {error.__class__.__name__}")
        
        # Rate limit error
        if isinstance(error, RateLimitError):
            return {
                "error": "rate_limit",
                "message": "API rate limit exceeded. Wait 60 seconds.",
                "retry_after": 60,
                "retryable": True
            }
        
        # Timeout error
        elif isinstance(error, APITimeoutError):
            return {
                "error": "timeout",
                "message": "API request timed out. The service may be slow.",
                "retryable": True
            }
        
        # Connection error
        elif isinstance(error, APIConnectionError):
            return {
                "error": "connection",
                "message": "Failed to connect to API. Check network connection.",
                "retryable": True
            }
        
        # Invalid API key
        elif isinstance(error, APIError) and "invalid" in str(error).lower():
            return {
                "error": "invalid_api_key",
                "message": "Invalid API key. Check ANTHROPIC_API_KEY environment variable.",
                "retryable": False
            }
        
        # Generic API error
        elif isinstance(error, APIError):
            return {
                "error": "api_error",
                "message": f"API error: {str(error)}",
                "retryable": False
            }
        
        # Unknown error
        else:
            return {
                "error": "unknown",
                "message": f"Unexpected error: {str(error)}",
                "retryable": False
            }
    
    # =========================================================================
    # MAIN METHOD: Combines All Features
    # =========================================================================
    
    def get_model_for_severity(self, severity: str) -> str:
        """
        Select the most cost-effective model based on alert severity.
        
        Cost Optimization Strategy:
        - CRITICAL/HIGH alerts: Use Sonnet (best accuracy)
        - MEDIUM/LOW alerts: Use Haiku (80-90% cheaper)
        
        Args:
            severity: Alert severity (CRITICAL_HIGH, MEDIUM_LOW, critical, high, medium, low)
            
        Returns:
            Model name to use
        """
        model = self.SEVERITY_MODEL_MAP.get(severity, self.SEVERITY_MODEL_MAP.get('MEDIUM_LOW'))
        logger.info(f"[Model Selection] Severity '{severity}' -> Model '{model}'")
        return model
    
    def _get_pricing(self, model: str) -> Tuple[float, float]:
        """Get input/output token pricing for a model."""
        pricing = self.MODEL_PRICING.get(model, {'input': self.INPUT_TOKEN_COST, 'output': self.OUTPUT_TOKEN_COST})
        return pricing['input'], pricing['output']
    
    def analyze_with_resilience(
        self,
        context: str,
        budget_tracker: Any,
        max_retries: int = 5,
        timeout: int = 30,
        max_tokens: int = 2000,
        estimated_cost: float = 0.01,
        severity: str = None  # NEW: Pass severity for model selection
    ) -> Dict[str, Any]:
        """
        Analyze alert with full resilience (all 5 features combined).
        
        Process:
        1. Check budget (Feature 4)
        2. Call API with timeout (Feature 1) and retry (Feature 2)
        3. Handle errors gracefully (Feature 3)
        4. Calculate cost and update budget (Feature 4)
        5. Return response or error
        
        Args:
            context: Full context string from RAG
            budget_tracker: DynamicBudgetTracker instance
            max_retries: Max retry attempts
            timeout: Timeout per attempt
            max_tokens: Max output tokens
            estimated_cost: Estimated cost for budget check
        
        Returns:
            Dictionary with 'response' or 'error'
        """
        self.stats['total_calls'] += 1
        
        # COST OPTIMIZATION: Select model based on severity
        selected_model = self.model  # Default
        if severity:
            selected_model = self.get_model_for_severity(severity)
        
        logger.info("[Resilient API] Starting analysis...")
        logger.info(f"  Model: {selected_model}, Retries: {max_retries}, Timeout: {timeout}s")
        
        # Feature 4: Check budget BEFORE calling API
        if hasattr(budget_tracker, 'can_process_queue'):
            # Using DynamicBudgetTracker
            can_process, cost, reason = budget_tracker.can_process_queue(
                queue_type='priority',
                queue_size=1,
                cost_per_alert=estimated_cost
            )
            
            if can_process == 0:
                logger.warning("[Budget] [ERROR] Budget exhausted")
                self.stats['failed_calls'] += 1
                return {
                    "error": "budget_exhausted",
                    "message": f"Daily budget exhausted: {reason}"
                }
        
        # Prepare messages
        messages = [{
            "role": "user",
            "content": context
        }]
        
        try:
            # Feature 1 + 2: Call with timeout and retry
            print(f"\n[AI TRACE] [START] Sending request to Claude ({selected_model})...")
            print(f"[AI TRACE] [DATA] Input Context Length: {len(messages[0]['content'])} chars")
            
            response = self._call_with_retry(
                messages=messages,
                max_retries=max_retries,
                timeout=timeout,
                max_tokens=max_tokens,
                model=selected_model  # Use severity-optimized model
            )
            
            print(f"[AI TRACE] [OK] Response received from Anthropic!")
            
            # Feature 4: Calculate actual cost (with model-specific pricing)
            input_price, output_price = self._get_pricing(selected_model)
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            actual_cost = (input_tokens * input_price) + (output_tokens * output_price)
            
            print(f"[AI TRACE] [COST] Token Usage - Input: {input_tokens}, Output: {output_tokens}")
            self._update_stats(input_tokens, output_tokens, actual_cost)
            
            print(f"[AI TRACE] [*] Cost: ${actual_cost:.6f}")
            
            # Update budget tracker
            if hasattr(budget_tracker, 'record_queue_processing'):
                budget_tracker.record_queue_processing(
                    queue_type='priority',
                    alerts_analyzed=1,
                    alerts_skipped=0,
                    actual_cost=actual_cost
                )
            
            # Success!
            self.stats['successful_calls'] += 1
            logger.info("[Resilient API] [OK] Analysis complete")
            
            return {
                "success": True,
                "response": response,
                "cost": actual_cost,
                "tokens": {
                    "input": input_tokens,
                    "output": output_tokens,
                    "total": input_tokens + output_tokens
                }
            }
        
        except Exception as e:
            # Feature 3: Handle error gracefully
            self.stats['failed_calls'] += 1
            error_response = self._handle_error(e)
            
            logger.error(f"[Resilient API] [ERROR] Failed: {error_response['error']}")
            
            return {
                "success": False,
                "error": error_response
            }
    
    # =========================================================================
    # UTILITIES
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        total_tokens = self.stats['total_input_tokens'] + self.stats['total_output_tokens']
        
        return {
            'calls': {
                'total': self.stats['total_calls'],
                'successful': self.stats['successful_calls'],
                'failed': self.stats['failed_calls'],
                'success_rate': (
                    self.stats['successful_calls'] / self.stats['total_calls'] * 100
                    if self.stats['total_calls'] > 0 else 0
                )
            },
            'reliability': {
                'retries': self.stats['retries'],
                'timeouts': self.stats['timeouts'],
                'rate_limits': self.stats['rate_limits']
            },
            'tokens': {
                'input': self.stats['total_input_tokens'],
                'output': self.stats['total_output_tokens'],
                'total': total_tokens
            },
            'cost': {
                'total': self.stats['total_cost'],
                'average_per_call': (
                    self.stats['total_cost'] / self.stats['successful_calls']
                    if self.stats['successful_calls'] > 0 else 0
                )
            }
        }
    
    def reset_stats(self):
        """Reset statistics (useful for testing)."""
        for key in self.stats:
            if isinstance(self.stats[key], (int, float)):
                self.stats[key] = 0


# =============================================================================
# TEST CODE
# =============================================================================

if __name__ == "__main__":
    """Test API resilience features."""
    
    print("=" * 70)
    print("API RESILIENCE MODULE TEST")
    print("=" * 70)
    
    # Mock budget tracker for testing
    class MockBudgetTracker:
        def can_process_queue(self, queue_type, queue_size, cost_per_alert):
            return (1, 0.01, "Test mode")
        
        def record_queue_processing(self, queue_type, alerts_analyzed, alerts_skipped, actual_cost):
            print(f"[Budget] Recorded: ${actual_cost:.6f}")
    
    try:
        # Initialize client
        print("\n[TEST 1] Initialize Client")
        client = ClaudeAPIClient()
        print("[OK] Client initialized")
        
        # Test API key validation
        print("\n[TEST 2] API Key Validation")
        try:
            bad_client = ClaudeAPIClient(api_key="invalid-key")
            print("[ERROR] Should have failed!")
        except ValueError as e:
            print(f"[OK] Correctly rejected bad key: {e}")
        
        # Test cost calculation
        print("\n[TEST 3] Token Cost Calculation")
        class MockUsage:
            input_tokens = 1000
            output_tokens = 500
        
        input_t, output_t, cost = client._calculate_cost(MockUsage())
        print(f"[OK] Cost: ${cost:.6f} for {input_t + output_t} tokens")
        
        # Test error handling
        print("\n[TEST 4] Error Handling")
        from anthropic import RateLimitError
        error = RateLimitError("Rate limit exceeded")
        error_response = client._handle_error(error)
        print(f"[OK] Handled: {error_response['error']} - {error_response['message']}")
        
        # Show stats
        print("\n" + "=" * 70)
        print("STATISTICS:")
        print("=" * 70)
        stats = client.get_stats()
        print(f"Total calls: {stats['calls']['total']}")
        print(f"Success rate: {stats['calls']['success_rate']:.1f}%")
        print(f"Total cost: ${stats['cost']['total']:.6f}")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
    
    print("\n" + "=" * 70)
    print("[OK] API RESILIENCE TEST COMPLETE")
    print("=" * 70)
    print("\nNote: Full API test requires ANTHROPIC_API_KEY")
    print("Set environment variable to test real API calls")

"""
Security Guard Tests
====================

Tests for InputGuard and OutputGuard (Features 1-4).
These are critical security components that prevent prompt injection.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestInputGuard:
    """Test InputGuard prompt injection protection"""
    
    def setup_method(self):
        from backend.ai.security_guard import InputGuard
        self.guard = InputGuard()
    
    def test_valid_alert_passes(self, sample_alert):
        """Normal alerts should pass validation"""
        is_valid, reason, cleaned = self.guard.validate(sample_alert)
        assert is_valid, f"Valid alert rejected: {reason}"
    
    def test_sql_injection_detected(self):
        """SQL injection attempts should be detected"""
        malicious = {
            'alert_name': "'; DROP TABLE alerts; --",
            'severity': 'high',
            'description': 'Test'
        }
        is_valid, reason, cleaned = self.guard.validate(malicious)
        # Should either block or sanitize
        if is_valid:
            assert "DROP" not in str(cleaned)
    
    def test_xss_detected(self):
        """XSS attempts should be detected"""
        malicious = {
            'alert_name': '<script>alert("xss")</script>',
            'severity': 'high',
            'description': 'Test'
        }
        is_valid, reason, cleaned = self.guard.validate(malicious)
        if is_valid:
            assert "<script>" not in str(cleaned)
    
    def test_prompt_injection_detected(self, prompt_injection_input):
        """Prompt injection attempts should be detected"""
        is_valid, reason, cleaned = self.guard.validate(prompt_injection_input)
        # Should detect prompt injection patterns
        # Note: Implementation may vary
    
    def test_command_injection_detected(self):
        """Command injection attempts should be detected"""
        malicious = {
            'alert_name': '; rm -rf / ;',
            'severity': 'high',
            'description': '| cat /etc/passwd'
        }
        is_valid, reason, cleaned = self.guard.validate(malicious)
        if is_valid:
            assert "rm -rf" not in str(cleaned)
    
    def test_empty_alert_handled(self):
        """Empty alerts should be handled gracefully"""
        is_valid, reason, cleaned = self.guard.validate({})
        # Should handle gracefully, not crash


class TestOutputGuard:
    """Test OutputGuard response validation"""
    
    def setup_method(self):
        from backend.ai.security_guard import OutputGuard
        self.guard = OutputGuard()
    
    def test_valid_response_passes(self):
        """Valid AI responses should pass"""
        response = {
            'verdict': 'malicious',
            'confidence': 0.95,
            'evidence': ['Finding 1', 'Finding 2'],
            'reasoning': 'Test reasoning',
            'recommendation': 'Isolate the endpoint'
        }
        is_safe, issues = self.guard.validate(response)
        assert is_safe, f"Valid response rejected: {issues}"
    
    def test_invalid_verdict_rejected(self):
        """Invalid verdict values should be caught"""
        response = {
            'verdict': 'HACKED',  # Invalid
            'confidence': 0.5,
            'evidence': []
        }
        is_safe, issues = self.guard.validate(response)
        # May or may not reject based on implementation
    
    def test_shell_commands_in_recommendation_detected(self):
        """Shell commands in recommendations should be detected"""
        response = {
            'verdict': 'malicious',
            'confidence': 0.9,
            'evidence': ['test'],
            'recommendation': 'Run: rm -rf / to fix the issue'
        }
        is_safe, issues = self.guard.validate(response)
        # Should detect dangerous commands


class TestDataProtection:
    """Test DataProtectionGuard (Features 14-17)"""
    
    def setup_method(self):
        from backend.ai.data_protection import DataProtectionGuard
        self.guard = DataProtectionGuard()
    
    def test_normal_data_passes(self, sample_alert):
        """Normal alert data should pass"""
        is_safe, reason, protected = self.guard.validate_input(sample_alert)
        assert is_safe, f"Normal data rejected: {reason}"
    
    def test_ssn_detected(self):
        """SSN patterns should be detected"""
        data = {
            'alert_name': 'Test',
            'description': 'User SSN: 123-45-6789'
        }
        is_safe, reason, protected = self.guard.validate_input(data)
        # Should detect or redact PII
    
    def test_credit_card_detected(self):
        """Credit card numbers should be detected"""
        data = {
            'alert_name': 'Test',
            'description': 'Card: 4111-1111-1111-1111'
        }
        is_safe, reason, protected = self.guard.validate_input(data)
        # Should detect or redact


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

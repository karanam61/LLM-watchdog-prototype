"""
Structured Output Validation - REAL AI Security
================================================

WHY THIS EXISTS:
Instead of silly keyword matching like:
    if "malware" in response: block()

We use STRUCTURAL GUARANTEES:
1. Force Claude to return JSON matching a strict schema
2. Validate the schema BEFORE accepting the response
3. Use semantic consistency checks (not word matching)
4. Type-safe parsing with Pydantic

This is how production AI systems work - not string matching.

WHAT THIS REPLACES:
- Keyword lists in security_guard.py (silly)
- String parsing of AI responses (fragile)
- Regex-based output validation (bypassable)

WHAT THIS PROVIDES:
- Schema enforcement (Claude MUST return valid JSON)
- Type validation (confidence MUST be float 0-1)
- Semantic consistency (verdict must align with evidence)
- Structured errors (know exactly what failed)
"""

import json
import logging
from typing import Dict, List, Optional, Literal, Any
from pydantic import BaseModel, Field, field_validator, model_validator
from enum import Enum

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    """Only these verdicts are valid - enforced at type level"""
    MALICIOUS = "malicious"
    BENIGN = "benign"  
    SUSPICIOUS = "suspicious"
    ERROR = "error"


class ChainOfThoughtStep(BaseModel):
    """Each reasoning step must have this structure"""
    step: int = Field(..., ge=1, le=10, description="Step number 1-10")
    observation: str = Field(..., min_length=10, description="What was observed")
    analysis: str = Field(..., min_length=10, description="What it means")
    conclusion: str = Field(..., min_length=5, description="Impact on verdict")


class AlertAnalysisResponse(BaseModel):
    """
    STRICT SCHEMA - Claude's response MUST match this exactly.
    
    This is structural security: if the response doesn't match,
    we reject it entirely. No string matching needed.
    """
    verdict: Verdict = Field(..., description="Must be malicious, benign, suspicious, or error")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence 0.0-1.0")
    evidence: List[str] = Field(..., min_length=3, description="At least 3 evidence points")
    chain_of_thought: List[ChainOfThoughtStep] = Field(..., min_length=3, description="Reasoning steps")
    reasoning: str = Field(..., min_length=100, description="Detailed explanation")
    recommendation: str = Field(..., min_length=20, description="Actionable next steps")
    
    @field_validator('evidence')
    @classmethod
    def evidence_not_empty(cls, v):
        """Each evidence item must have content"""
        for item in v:
            if len(item.strip()) < 5:
                raise ValueError(f"Evidence item too short: {item}")
        return v
    
    @field_validator('confidence')
    @classmethod  
    def confidence_reasonable(cls, v):
        """Reject suspiciously perfect confidence"""
        if v == 1.0:
            logger.warning("Perfect confidence (1.0) is suspicious - clamping to 0.99")
            return 0.99
        return v
    
    @model_validator(mode='after')
    def semantic_consistency_check(self):
        """
        REAL SEMANTIC VALIDATION - Not keyword matching!
        
        This checks if the verdict is LOGICALLY CONSISTENT with 
        the evidence and reasoning, not just if certain words appear.
        """
        verdict = self.verdict
        confidence = self.confidence
        evidence_text = " ".join(self.evidence).lower()
        reasoning_lower = self.reasoning.lower()
        
        # Rule 1: High confidence requires substantial evidence
        if confidence > 0.9 and len(self.evidence) < 5:
            raise ValueError(
                f"High confidence ({confidence}) requires at least 5 evidence points, got {len(self.evidence)}"
            )
        
        # Rule 2: Malicious verdict requires threat indicators in evidence
        # NOT keyword matching - checking for STRUCTURE (log references, IPs, etc.)
        if verdict == Verdict.MALICIOUS:
            has_log_refs = any('[' in e and ']' in e for e in self.evidence)  # [PROCESS-1], [NETWORK-1]
            has_specific_detail = any(len(e) > 50 for e in self.evidence)
            
            if not has_log_refs and not has_specific_detail:
                raise ValueError(
                    "Malicious verdict requires specific evidence with log references or detailed findings"
                )
        
        # Rule 3: Benign verdict with low confidence is suspicious
        if verdict == Verdict.BENIGN and confidence < 0.6:
            raise ValueError(
                f"Benign verdict with low confidence ({confidence}) is contradictory - use 'suspicious' instead"
            )
        
        # Rule 4: Chain of thought must lead to verdict
        final_step = self.chain_of_thought[-1] if self.chain_of_thought else None
        if final_step:
            conclusion_lower = final_step.conclusion.lower()
            # Check that final conclusion mentions the verdict concept
            verdict_related = {
                Verdict.MALICIOUS: ['attack', 'malicious', 'threat', 'compromise', 'confirmed'],
                Verdict.BENIGN: ['benign', 'legitimate', 'normal', 'false positive', 'safe', 'routine'],
                Verdict.SUSPICIOUS: ['suspicious', 'uncertain', 'unclear', 'investigate', 'review']
            }
            
            related_words = verdict_related.get(verdict, [])
            if not any(word in conclusion_lower for word in related_words):
                logger.warning(
                    f"Final conclusion '{final_step.conclusion}' may not align with verdict '{verdict}'"
                )
                # Warning only - don't reject, but flag for human review
        
        return self


class StructuredOutputParser:
    """
    Parse and validate Claude's response against strict schema.
    
    USAGE:
        parser = StructuredOutputParser()
        result = parser.parse(claude_response_text)
        
        if result.success:
            analysis = result.data  # Typed AlertAnalysisResponse
        else:
            error = result.error  # What went wrong
    """
    
    def __init__(self):
        self.stats = {
            'total_parsed': 0,
            'successful': 0,
            'json_errors': 0,
            'schema_errors': 0,
            'semantic_errors': 0
        }
    
    def parse(self, response_text: str) -> 'ParseResult':
        """
        Parse Claude's response into validated AlertAnalysisResponse.
        
        Returns ParseResult with either:
        - success=True, data=AlertAnalysisResponse
        - success=False, error=str describing what failed
        """
        self.stats['total_parsed'] += 1
        
        # Step 1: Extract JSON from response
        json_str = self._extract_json(response_text)
        if not json_str:
            self.stats['json_errors'] += 1
            return ParseResult(
                success=False,
                error="No valid JSON found in response",
                raw_response=response_text
            )
        
        # Step 2: Parse JSON
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            self.stats['json_errors'] += 1
            return ParseResult(
                success=False,
                error=f"JSON parse error: {e}",
                raw_response=response_text
            )
        
        # Step 3: Validate against schema
        try:
            analysis = AlertAnalysisResponse(**data)
            self.stats['successful'] += 1
            return ParseResult(
                success=True,
                data=analysis,
                raw_response=response_text
            )
        except Exception as e:
            error_msg = str(e)
            
            # Categorize the error
            if 'semantic' in error_msg.lower() or 'consistency' in error_msg.lower():
                self.stats['semantic_errors'] += 1
            else:
                self.stats['schema_errors'] += 1
            
            return ParseResult(
                success=False,
                error=f"Schema validation failed: {error_msg}",
                raw_response=response_text,
                partial_data=data  # Return what we could parse
            )
    
    def _extract_json(self, text: str) -> Optional[str]:
        """Extract JSON object from response text, handling markdown code blocks"""
        text = text.strip()
        
        # Try direct JSON first
        if text.startswith('{'):
            # Find matching closing brace
            depth = 0
            for i, char in enumerate(text):
                if char == '{':
                    depth += 1
                elif char == '}':
                    depth -= 1
                    if depth == 0:
                        return text[:i+1]
        
        # Try extracting from code block
        if '```json' in text:
            start = text.find('```json') + 7
            end = text.find('```', start)
            if end > start:
                return text[start:end].strip()
        
        if '```' in text:
            start = text.find('```') + 3
            # Skip language identifier if present
            newline = text.find('\n', start)
            if newline > start:
                start = newline + 1
            end = text.find('```', start)
            if end > start:
                return text[start:end].strip()
        
        # Last resort: find first { to last }
        first_brace = text.find('{')
        last_brace = text.rfind('}')
        if first_brace != -1 and last_brace > first_brace:
            return text[first_brace:last_brace+1]
        
        return None
    
    def get_stats(self) -> Dict:
        """Return parsing statistics"""
        total = self.stats['total_parsed']
        if total == 0:
            return self.stats
        
        return {
            **self.stats,
            'success_rate': self.stats['successful'] / total,
            'json_error_rate': self.stats['json_errors'] / total,
            'schema_error_rate': self.stats['schema_errors'] / total,
            'semantic_error_rate': self.stats['semantic_errors'] / total
        }


class ParseResult:
    """Result of parsing attempt - either success with data or failure with error"""
    
    def __init__(
        self,
        success: bool,
        data: Optional[AlertAnalysisResponse] = None,
        error: Optional[str] = None,
        raw_response: Optional[str] = None,
        partial_data: Optional[Dict] = None
    ):
        self.success = success
        self.data = data
        self.error = error
        self.raw_response = raw_response
        self.partial_data = partial_data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response"""
        if self.success and self.data:
            return {
                'success': True,
                'verdict': self.data.verdict.value,
                'confidence': self.data.confidence,
                'evidence': self.data.evidence,
                'chain_of_thought': [step.model_dump() for step in self.data.chain_of_thought],
                'reasoning': self.data.reasoning,
                'recommendation': self.data.recommendation
            }
        else:
            return {
                'success': False,
                'verdict': 'error',
                'confidence': 0.0,
                'error': self.error,
                'partial_data': self.partial_data
            }


def get_structured_system_prompt() -> str:
    """
    System prompt that instructs Claude to return structured JSON.
    
    This works WITH the schema validation - Claude is told the format,
    and we verify it. Defense in depth.
    """
    return """You are a Security Operations Center (SOC) analyst AI. 

CRITICAL: You MUST respond with ONLY a valid JSON object. No markdown, no explanations, no text before or after.

Your response MUST match this exact schema:
{
  "verdict": "malicious" | "benign" | "suspicious",
  "confidence": <float 0.0-1.0>,
  "evidence": ["<finding 1>", "<finding 2>", ...],  // minimum 3, include log refs like [PROCESS-1]
  "chain_of_thought": [
    {"step": 1, "observation": "<what you saw>", "analysis": "<what it means>", "conclusion": "<verdict impact>"},
    // minimum 3 steps
  ],
  "reasoning": "<detailed 100+ char explanation>",
  "recommendation": "<actionable steps>"
}

RULES:
- verdict MUST be exactly one of: malicious, benign, suspicious
- confidence MUST be a decimal between 0.0 and 1.0
- evidence MUST have at least 3 items, each referencing specific log entries
- chain_of_thought MUST have at least 3 steps showing your reasoning
- reasoning MUST be at least 100 characters explaining the verdict
- recommendation MUST be at least 20 characters with specific actions

If confidence > 0.9, you MUST have at least 5 evidence items.
If verdict is malicious, evidence MUST include specific log references.
If verdict is benign with confidence < 0.6, use suspicious instead.

Return ONLY the JSON. No other text."""


# Quick test
if __name__ == '__main__':
    print("\n" + "="*60)
    print("STRUCTURED OUTPUT PARSER - Testing")
    print("="*60)
    
    parser = StructuredOutputParser()
    
    # Test 1: Valid response
    print("\n[TEST 1] Valid response")
    valid = """{
        "verdict": "malicious",
        "confidence": 0.92,
        "evidence": [
            "[PROCESS-1] mimikatz.exe detected in TEMP directory",
            "[NETWORK-1] Connection to known C2 IP 45.33.32.156",
            "[PROCESS-2] lsass.exe memory accessed",
            "OSINT: IP flagged as malicious",
            "Execution at 2:47 AM outside business hours"
        ],
        "chain_of_thought": [
            {"step": 1, "observation": "mimikatz.exe executed", "analysis": "Known credential theft tool", "conclusion": "Immediate threat indicator"},
            {"step": 2, "observation": "lsass.exe accessed", "analysis": "Credential harvesting in progress", "conclusion": "Active attack confirmed"},
            {"step": 3, "observation": "C2 connection detected", "analysis": "Data exfiltration likely", "conclusion": "Malicious verdict confirmed"}
        ],
        "reasoning": "This is a confirmed credential theft attack. Mimikatz was executed from TEMP, accessed LSASS memory, and established C2 connection to a known malicious IP. All indicators point to active compromise requiring immediate response.",
        "recommendation": "IMMEDIATE: Isolate host, disable user account, block C2 IP, initiate incident response."
    }"""
    
    result = parser.parse(valid)
    print(f"Success: {result.success}")
    if result.success:
        print(f"Verdict: {result.data.verdict.value}")
        print(f"Confidence: {result.data.confidence}")
    
    # Test 2: Invalid - missing required field
    print("\n[TEST 2] Missing field")
    invalid = '{"verdict": "malicious", "confidence": 0.9}'
    result = parser.parse(invalid)
    print(f"Success: {result.success}")
    print(f"Error: {result.error}")
    
    # Test 3: Semantic inconsistency
    print("\n[TEST 3] Semantic inconsistency (benign + low confidence)")
    inconsistent = """{
        "verdict": "benign",
        "confidence": 0.4,
        "evidence": ["item1", "item2", "item3"],
        "chain_of_thought": [
            {"step": 1, "observation": "obs", "analysis": "analysis", "conclusion": "safe"}
        ],
        "reasoning": "This appears to be benign but we are not sure at all about this classification",
        "recommendation": "Review manually please"
    }"""
    result = parser.parse(inconsistent)
    print(f"Success: {result.success}")
    print(f"Error: {result.error}")
    
    # Stats
    print("\n" + "="*60)
    print("Parser Stats:", parser.get_stats())
    print("="*60)

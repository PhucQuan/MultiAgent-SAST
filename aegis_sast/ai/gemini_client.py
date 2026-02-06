"""
Gemini API client for vulnerability verification.

Handles communication with Google's Gemini API for AI-based analysis.
"""

import json
from typing import Dict, Any, Optional
from datetime import datetime

import google.generativeai as genai
from tenacity import retry, stop_after_attempt, wait_exponential

from aegis_sast.core.config import get_config
from aegis_sast.core.models import AIVerification, VulnerabilityType
from aegis_sast.ai.prompts import get_verification_prompt
from aegis_sast.ai.cache_manager import CacheManager


class GeminiClient:
    """Client for Gemini API with retry logic and caching."""
    
    def __init__(self):
        """Initialize Gemini client."""
        self.config = get_config()
        self.cache = CacheManager()
        
        # Configure Gemini API
        if self.config.enable_ai_verification:
            self.config.validate_ai_config()
            genai.configure(api_key=self.config.gemini_api_key)
            self.model = genai.GenerativeModel(self.config.gemini_model)
        else:
            self.model = None
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def _call_api(self, prompt: str) -> str:
        """
        Call Gemini API with retry logic.
        
        Args:
            prompt: The prompt to send
            
        Returns:
            API response text
        """
        if not self.model:
            raise RuntimeError("AI verification is disabled")
        
        response = self.model.generate_content(prompt)
        return response.text
    
    def verify_vulnerability(
        self,
        vuln_type: VulnerabilityType,
        source_code: str,
        dataflow_path: list,
        sink_code: str
    ) -> Optional[AIVerification]:
        """
        Verify if a potential vulnerability is real using AI.
        
        Args:
            vuln_type: Type of vulnerability
            source_code: Source code snippet
            dataflow_path: List of dataflow steps
            sink_code: Sink code snippet
            
        Returns:
            AIVerification object or None if AI is disabled
        """
        if not self.config.enable_ai_verification:
            return None
        
        # Check cache first
        cached_result = self.cache.get(source_code, dataflow_path, sink_code)
        if cached_result:
            return self._parse_verification_result(
                cached_result,
                from_cache=True
            )
        
        # Generate prompt
        prompt = get_verification_prompt(
            vuln_type=vuln_type,
            source_code=source_code,
            dataflow_path=dataflow_path,
            sink_code=sink_code
        )
        
        try:
            # Call API
            response_text = self._call_api(prompt)
            
            # Parse JSON response
            # Extract JSON from markdown code blocks if present
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(response_text)
            
            # Cache result
            self.cache.set(source_code, dataflow_path, sink_code, result)
            
            return self._parse_verification_result(result)
        
        except Exception as e:
            # Fallback to unknown if API fails
            return AIVerification(
                is_vulnerable=True,  # Assume vulnerable to be safe
                confidence=0.5,
                explanation=f"AI verification failed: {str(e)}",
                recommendation="Manual review required",
                model_used=self.config.gemini_model
            )
    
    def _parse_verification_result(
        self,
        result: Dict[str, Any],
        from_cache: bool = False
    ) -> AIVerification:
        """
        Parse API response into AIVerification object.
        
        Args:
            result: Parsed JSON response
            from_cache: Whether result came from cache
            
        Returns:
            AIVerification object
        """
        return AIVerification(
            is_vulnerable=result.get("is_vulnerable", True),
            confidence=float(result.get("confidence", 0.8)),
            explanation=result.get("explanation", "No explanation provided"),
            recommendation=result.get("recommendation", "Review manually"),
            model_used=self.config.gemini_model + (" (cached)" if from_cache else "")
        )

"""
Gemini API client for vulnerability verification.

Handles communication with Google's Gemini API for AI-based analysis.
"""

import json
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

from tenacity import retry, stop_after_attempt, wait_exponential

from aegis_sast.core.config import AegisConfig, get_config
from aegis_sast.core.models import AIVerification, VulnerabilityType
from aegis_sast.ai.prompts import get_verification_prompt
from aegis_sast.ai.cache_manager import CacheManager

try:
    from google import genai
    from google.genai import types
except ImportError:  # pragma: no cover - depends on optional AI install
    genai = None
    types = None


class GeminiClient:
    """Client for Gemini API with retry logic and caching."""
    
    def __init__(self, config: Optional[AegisConfig] = None):
        """Initialize Gemini client."""
        self.config = config or get_config()
        self.provider_name = "gemini"
        self.model_name = self.config.gemini_model
        self.cache = CacheManager()
        self.client = None

        # Configure Gemini API
        if self.config.enable_ai_verification:
            self.config.validate_ai_config()
            if self.config.enable_ai_verification:
                if genai is None or types is None:
                    raise RuntimeError(
                        "AI verification requires the optional package "
                        "'google-genai'. Install 'requirements-ai.txt' "
                        "or run with '--no-ai'."
                    )
                self.client = genai.Client(api_key=self.config.gemini_api_key)
            
        # Semaphore to limit concurrent API calls
        self.semaphore = asyncio.Semaphore(10)
    
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
        if not self.config.enable_ai_verification or not self.client:
            raise RuntimeError("AI verification is disabled")
        
        response = self.client.models.generate_content(
            model=self.config.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2, # Low temperature for more deterministic analysis
                response_mime_type="application/json"
            )
        )
        return response.text
    
    async def async_verify_vulnerability(
        self,
        vuln_type: VulnerabilityType,
        source_code: str,
        dataflow_path: list,
        sink_code: str
    ) -> Optional[AIVerification]:
        """Async version of verify_vulnerability."""
        async with self.semaphore:
            # Check cache first (still synchronous is fine for diskcache)
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
                # Call API in a thread pool since genai is currently blocking
                if hasattr(asyncio, 'to_thread'):
                    response_text = await asyncio.to_thread(self._call_api, prompt)
                else:
                    loop = asyncio.get_event_loop()
                    response_text = await loop.run_in_executor(None, self._call_api, prompt)
                
                # Parse JSON response
                import re
                
                # Check if it's wrapped in a json codeblock
                json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    response_text = json_match.group(1).strip()
                else:
                    # Try to extract anything looking like a JSON object if markdown blocks are missing or wrong
                    obj_match = re.search(r'(\{.*?\})', response_text, re.DOTALL)
                    if obj_match:
                        response_text = obj_match.group(1).strip()
                    else:
                        response_text = response_text.strip()
                
                # If still not starting with {, there's an issue
                if not response_text.startswith('{'):
                    raise ValueError(f"Gemini did not return JSON: {response_text[:50]}")
                
                result = json.loads(response_text)
                self.cache.set(source_code, dataflow_path, sink_code, result)
                return self._parse_verification_result(result)
                
            except Exception as e:
                return AIVerification(
                    is_vulnerable=True,
                    confidence=0.5,
                    explanation=f"AI verification failed: {str(e)}",
                    recommendation="Manual review required",
                    model_used=self.config.gemini_model
                )

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
            import re
            
            # Check if it's wrapped in a json codeblock
            json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
            if json_match:
                response_text = json_match.group(1).strip()
            else:
                # Try to extract anything looking like a JSON object if markdown blocks are missing or wrong
                obj_match = re.search(r'(\{.*?\})', response_text, re.DOTALL)
                if obj_match:
                    response_text = obj_match.group(1).strip()
                else:
                    response_text = response_text.strip()
            
            # If still not starting with {, there's an issue
            if not response_text.startswith('{'):
                raise ValueError(f"Gemini did not return JSON: {response_text[:50]}")
            
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

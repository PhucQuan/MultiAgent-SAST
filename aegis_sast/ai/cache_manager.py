"""
Hash-based cache manager for AI verification results.

Uses SHA256 hashing to cache and retrieve previous AI analysis results.
"""

import hashlib
import json
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from diskcache import Cache

from aegis_sast.core.config import get_config


class CacheManager:
    """Manages hash-based caching of AI verification results."""
    
    def __init__(self):
        """Initialize cache manager."""
        config = get_config()
        self.enabled = config.cache_enabled
        self.cache_dir = config.cache_dir
        self.ttl_days = config.cache_ttl_days
        
        if self.enabled:
            self.cache = Cache(str(self.cache_dir))
        else:
            self.cache = None
    
    def _generate_hash(self, source_code: str, dataflow: list, sink_code: str) -> str:
        """
        Generate SHA256 hash for cache key.
        
        Args:
            source_code: Source code snippet
            dataflow: Dataflow path
            sink_code: Sink code snippet
            
        Returns:
            Hexadecimal hash string
        """
        # Combine all inputs into a single string
        combined = f"{source_code}|{json.dumps(dataflow)}|{sink_code}"
        
        # Generate SHA256 hash
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def get(self, source_code: str, dataflow: list, sink_code: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached AI verification result.
        
        Args:
            source_code: Source code snippet
            dataflow: Dataflow path
            sink_code: Sink code snippet
            
        Returns:
            Cached result dict or None if not found/expired
        """
        if not self.enabled or not self.cache:
            return None
        
        cache_key = self._generate_hash(source_code, dataflow, sink_code)
        
        try:
            cached_data = self.cache.get(cache_key)
            
            if cached_data:
                # Check if expired
                timestamp = cached_data.get("timestamp")
                if timestamp:
                    cached_time = datetime.fromisoformat(timestamp)
                    expiry_time = cached_time + timedelta(days=self.ttl_days)
                    
                    if datetime.now() > expiry_time:
                        # Expired - remove from cache
                        self.cache.delete(cache_key)
                        return None
                
                return cached_data.get("result")
        
        except Exception:
            return None
    
    def set(
        self,
        source_code: str,
        dataflow: list,
        sink_code: str,
        result: Dict[str, Any]
    ):
        """
        Store AI verification result in cache.
        
        Args:
            source_code: Source code snippet
            dataflow: Dataflow path
            sink_code: Sink code snippet
            result: AI verification result to cache
        """
        if not self.enabled or not self.cache:
            return
        
        cache_key = self._generate_hash(source_code, dataflow, sink_code)
        
        cached_data = {
            "timestamp": datetime.now().isoformat(),
            "result": result
        }
        
        try:
            self.cache.set(cache_key, cached_data)
        except Exception:
            # Silently fail if cache write fails
            pass
    
    def clear(self):
        """Clear all cached data."""
        if self.enabled and self.cache:
            self.cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        if not self.enabled or not self.cache:
            return {"enabled": False}
        
        return {
            "enabled": True,
            "size": len(self.cache),
            "ttl_days": self.ttl_days,
            "cache_dir": str(self.cache_dir)
        }

"""
Rule engine for loading and matching security rules.

Handles YAML/JSON rule file parsing and provides rule lookup functionality.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import yaml
import json


class RuleEngine:
    """Manages security rules for vulnerability detection."""
    
    def __init__(self, rules_path: Optional[Path] = None, language: str = "python"):
        """
        Initialize rule engine.
        
        Args:
            rules_path: Path to custom rules file (YAML/JSON).
            language: Language name (python/javascript/java/php) for auto rule loading.
        """
        self.rules: Dict[str, Any] = {}
        self.rules_path = Path(rules_path) if rules_path else None
        self.language = language
        self._language_cache: Dict[str, "RuleEngine"] = {}
        
        if self.rules_path:
            self.load_rules(self.rules_path)
        else:
            # Load rules matching the specific language
            rules_dir = Path(__file__).parent.parent.parent / "rules"
            lang_rules = rules_dir / f"{language}.yaml"
            if lang_rules.exists():
                self.load_rules(lang_rules)
            else:
                # Fallback to python rules
                default_rules = rules_dir / "python.yaml"
                if default_rules.exists():
                    self.load_rules(default_rules)
    
    def load_rules(self, rules_path: Path):
        """
        Load rules from YAML or JSON file.
        
        Args:
            rules_path: Path to rules file
        """
        if not rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {rules_path}")
        
        extension = rules_path.suffix.lower()
        
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                if extension in ['.yaml', '.yml']:
                    self.rules = yaml.safe_load(f)
                elif extension == '.json':
                    self.rules = json.load(f)
                else:
                    raise ValueError(f"Unsupported rule file format: {extension}")
        
        except Exception as e:
            raise RuntimeError(f"Failed to load rules from {rules_path}: {e}")
    
    def get_sources(self) -> list:
        """Get source rules."""
        return self.rules.get("sources", [])
    
    def get_sinks(self) -> Dict[str, Any]:
        """Get sink rules organized by category."""
        return self.rules.get("sinks", {})
    
    def get_sanitizers(self) -> list:
        """Get sanitizer rules."""
        return self.rules.get("sanitizers", [])
    
    def get_safe_patterns(self) -> list:
        """Get safe patterns that don't propagate taint."""
        return self.rules.get("safe_patterns", [])
    
    def get_rules(self) -> Dict[str, Any]:
        """Get all rules."""
        return self.rules

    def for_language(self, language: str) -> "RuleEngine":
        """
        Resolve the effective rule engine for one language.

        Custom rules are treated as an explicit override contract and are reused
        unchanged for every file. When no custom rules were provided, the engine
        lazily loads and caches built-in rule sets per language so multi-language
        scans respect each plugin's default rules.
        """
        if self.rules_path is not None:
            return self

        normalized = language.strip().lower()
        if normalized == self.language and self.rules:
            return self

        cached = self._language_cache.get(normalized)
        if cached is None:
            cached = RuleEngine(language=normalized)
            self._language_cache[normalized] = cached
        return cached

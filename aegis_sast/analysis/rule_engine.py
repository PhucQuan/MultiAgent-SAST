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
    
    def __init__(self, rules_path: Optional[Path] = None):
        """
        Initialize rule engine.
        
        Args:
            rules_path: Path to custom rules file (YAML/JSON)
        """
        self.rules: Dict[str, Any] = {}
        
        if rules_path:
            self.load_rules(rules_path)
        else:
            # Load default Python rules
            default_rules = Path(__file__).parent.parent.parent / "rules" / "python.yaml"
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
        
        # Determine file type
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

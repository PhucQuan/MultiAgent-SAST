"""
Plugin interface for language-specific analyzers.

Defines the abstract base class that all language plugins must implement,
following the Strategy Pattern for extensibility.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path

from aegis_sast.core.models import TaintSource, TaintSink, Sanitizer, DataFlowPath


class ILanguagePlugin(ABC):
    """
    Abstract base class for language-specific security analysis plugins.
    
    Each plugin is responsible for:
    - Parsing source code into an AST
    - Identifying taint sources, sinks, and sanitizers
    - Tracking dataflow between sources and sinks
    """
    
    @abstractmethod
    def get_language_name(self) -> str:
        """
        Get the name of the programming language this plugin supports.
        
        Returns:
            Language name (e.g., "python", "javascript", "php")
        """
        pass
    
    @abstractmethod
    def get_file_extensions(self) -> List[str]:
        """
        Get the file extensions this plugin handles.
        
        Returns:
            List of extensions without dots (e.g., ["py", "pyw"])
        """
        pass
    
    @abstractmethod
    def can_analyze(self, file_path: Path) -> bool:
        """
        Check if this plugin can analyze the given file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the plugin can analyze this file
        """
        pass
    
    @abstractmethod
    def parse_file(self, file_path: Path) -> Optional[Any]:
        """
        Parse a source file into an AST.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            AST object (tree-sitter Tree) or None if parsing fails
        """
        pass
    
    @abstractmethod
    def extract_sources(
        self,
        ast: Any,
        file_path: Path,
        rules: Dict[str, Any]
    ) -> List[TaintSource]:
        """
        Extract taint sources from the AST.
        
        Args:
            ast: The parsed AST
            file_path: Path to the source file
            rules: Source rules from configuration
            
        Returns:
            List of identified taint sources
        """
        pass
    
    @abstractmethod
    def extract_sinks(
        self,
        ast: Any,
        file_path: Path,
        rules: Dict[str, Any]
    ) -> List[TaintSink]:
        """
        Extract taint sinks from the AST.
        
        Args:
            ast: The parsed AST
            file_path: Path to the source file
            rules: Sink rules from configuration
            
        Returns:
            List of identified taint sinks
        """
        pass
    
    @abstractmethod
    def extract_sanitizers(
        self,
        ast: Any,
        file_path: Path,
        rules: Dict[str, Any]
    ) -> List[Sanitizer]:
        """
        Extract sanitization functions from the AST.
        
        Args:
            ast: The parsed AST
            file_path: Path to the source file
            rules: Sanitizer rules from configuration
            
        Returns:
            List of identified sanitizers
        """
        pass
    
    @abstractmethod
    def track_dataflow(
        self,
        ast: Any,
        file_path: Path,
        source: TaintSource,
        sinks: List[TaintSink],
        sanitizers: List[Sanitizer],
        max_depth: int = 5
    ) -> List[DataFlowPath]:
        """
        Track dataflow from a taint source to potential sinks.
        
        This implements inter-procedural taint analysis within the file
        and across local module imports.
        
        Args:
            ast: The parsed AST
            file_path: Path to the source file
            source: The taint source to track
            sinks: List of potential sinks to check
            sanitizers: List of sanitizer functions
            max_depth: Maximum depth for inter-procedural tracking
            
        Returns:
            List of dataflow paths from source to sinks
        """
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get plugin metadata.
        
        Returns:
            Dictionary with plugin information
        """
        return {
            "language": self.get_language_name(),
            "extensions": self.get_file_extensions(),
            "version": "1.0.0",
        }

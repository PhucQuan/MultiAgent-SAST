"""Plugin registry for managing language-specific analyzers."""

from importlib import import_module
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from aegis_sast.core.plugin_interface import ILanguagePlugin


class PluginRegistry:
    """Registry for managing language analysis plugins."""
    
    def __init__(self):
        self._plugins: Dict[str, ILanguagePlugin] = {}
        self._extension_map: Dict[str, str] = {}  # extension -> language name
        self._import_failures: Dict[str, str] = {}
    
    def register(self, plugin: ILanguagePlugin):
        """
        Register a language plugin.
        
        Args:
            plugin: The plugin instance to register
        """
        language = plugin.get_language_name()
        
        if language in self._plugins:
            raise ValueError(f"Plugin for language '{language}' already registered")
        
        self._plugins[language] = plugin
        self._import_failures.pop(language, None)
        
        # Map file extensions to language
        for ext in plugin.get_file_extensions():
            self._extension_map[ext] = language
    
    def get_plugin(self, language: str) -> Optional[ILanguagePlugin]:
        """
        Get a plugin by language name.
        
        Args:
            language: The language name (e.g., "python")
            
        Returns:
            The plugin instance or None if not found
        """
        return self._plugins.get(language)
    
    def get_plugin_for_file(self, file_path: Path) -> Optional[ILanguagePlugin]:
        """
        Get the appropriate plugin for a file based on its extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            The plugin instance or None if no plugin handles this file type
        """
        extension = file_path.suffix.lstrip(".")
        language = self._extension_map.get(extension)
        
        if language:
            return self._plugins.get(language)
        
        return None
    
    def get_all_plugins(self) -> List[ILanguagePlugin]:
        """
        Get all registered plugins.
        
        Returns:
            List of all registered plugins
        """
        return list(self._plugins.values())
    
    def get_supported_languages(self) -> List[str]:
        """
        Get list of supported language names.
        
        Returns:
            List of supported languages
        """
        return list(self._plugins.keys())
    
    def get_supported_extensions(self) -> List[str]:
        """
        Get list of all supported file extensions.
        
        Returns:
            List of supported extensions
        """
        return list(self._extension_map.keys())

    def record_import_failure(self, language: str, error: str) -> None:
        """Record why a built-in analyzer could not be loaded."""
        self._import_failures[language] = error

    def get_import_failures(self) -> Dict[str, str]:
        """Return built-in analyzers that failed to import."""
        return dict(self._import_failures)
    
    def unregister(self, language: str):
        """
        Unregister a plugin by language name.
        
        Args:
            language: The language name
        """
        if language in self._plugins:
            plugin = self._plugins[language]
            
            # Remove extension mappings
            for ext in plugin.get_file_extensions():
                self._extension_map.pop(ext, None)
            
            # Remove plugin
            del self._plugins[language]
    
    def clear(self):
        """Clear all registered plugins."""
        self._plugins.clear()
        self._extension_map.clear()
        self._import_failures.clear()


# Global registry instance
_registry: Optional[PluginRegistry] = None
_BUILTIN_PLUGINS: Tuple[Tuple[str, str, str], ...] = (
    ("python", "aegis_sast.plugins.python_plugin", "PythonPlugin"),
    ("javascript", "aegis_sast.plugins.javascript_plugin", "JavaScriptPlugin"),
    ("java", "aegis_sast.plugins.java_plugin", "JavaPlugin"),
    ("php", "aegis_sast.plugins.php_plugin", "PHPPlugin"),
)


def get_registry() -> PluginRegistry:
    """Get the global plugin registry instance."""
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
        _auto_register_plugins()
    return _registry


def _auto_register_plugins():
    """Auto-register available plugins."""
    for language, module_name, class_name in _BUILTIN_PLUGINS:
        try:
            module = import_module(module_name)
            plugin_class = getattr(module, class_name)
            _registry.register(plugin_class())
        except ImportError as exc:
            _registry.record_import_failure(language, str(exc))
        except ValueError:
            continue
        except Exception as exc:
            _registry.record_import_failure(language, str(exc))

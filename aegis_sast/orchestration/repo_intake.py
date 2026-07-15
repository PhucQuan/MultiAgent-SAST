"""Repo intake helpers for language detection, framework hints, and scan profiles."""

from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from aegis_sast.core.registry import PluginRegistry, get_registry
from aegis_sast.orchestration.state import RepoProfile


class RepoIntake:
    """Build a conservative repo profile before or after scanning."""

    SUPPORTED_EXTENSION_LANGUAGE = {
        "py": "python",
        "pyw": "python",
        "js": "javascript",
        "mjs": "javascript",
        "cjs": "javascript",
        "java": "java",
        "php": "php",
        "phtml": "php",
    }

    CONFIG_FILE_NAMES = {
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "composer.json",
        "manage.py",
        "next.config.js",
        "next.config.mjs",
        "vite.config.js",
        "vite.config.ts",
    }

    FRAMEWORK_PATTERNS = {
        "python": {
            "flask": ["from flask", "import flask", "Flask("],
            "django": ["from django", "import django", "DJANGO_SETTINGS_MODULE"],
            "fastapi": ["from fastapi", "import fastapi", "FastAPI("],
            "sqlalchemy": [
                "from sqlalchemy",
                "import sqlalchemy",
                "create_engine(",
                "sessionmaker(",
            ],
        },
        "javascript": {
            "express": [
                "require('express')",
                'require("express")',
                "from 'express'",
                'from "express"',
                "express()",
            ],
            "koa": [
                "require('koa')",
                'require("koa")',
                "from 'koa'",
                'from "koa"',
                "new Koa(",
            ],
            "node:http": [
                "require('http')",
                'require("http")',
                "from 'http'",
                'from "http"',
                "createServer(",
            ],
            "nextjs": ['"next"', "'next'", "next.config.js", "next.config.mjs"],
        },
        "java": {
            "spring": [
                "org.springframework",
                "@RestController",
                "@Controller",
                "@RequestMapping",
                "@GetMapping",
                "spring-boot",
            ],
            "servlet": [
                "HttpServletRequest",
                "HttpServletResponse",
                "javax.servlet",
                "jakarta.servlet",
            ],
            "jdbc": [
                "java.sql.",
                "PreparedStatement",
                "Statement.execute",
                "executeQuery(",
                "DriverManager.getConnection(",
            ],
        },
        "php": {
            "laravel": ["Illuminate\\", "Route::", "artisan"],
            "symfony": ["Symfony\\", "bin/console"],
        },
    }

    FILE_NAME_HINTS = {
        "django": {"manage.py"},
        "nextjs": {"next.config.js", "next.config.mjs"},
        "laravel": {"artisan"},
    }

    def __init__(
        self,
        registry: Optional[PluginRegistry] = None,
        max_inspected_files: int = 24,
    ):
        self.registry = registry or get_registry()
        self.max_inspected_files = max_inspected_files
        self._ensure_builtin_plugins()

    def analyze_target(self, target_path: Path) -> RepoProfile:
        """Inspect a scan target and return language and framework metadata."""
        target = Path(target_path)
        supported_files = self._collect_supported_files(target)
        language_counts = self._count_languages(supported_files)
        detected_languages = sorted(language_counts)
        config_files = self._collect_config_files(target)
        framework_hints = self._detect_framework_hints(
            target=target,
            supported_files=supported_files,
            config_files=config_files,
            detected_languages=detected_languages,
        )
        scan_profile = self.choose_scan_profile(detected_languages)
        analysis_plan = self.build_analysis_plan(detected_languages)

        return RepoProfile(
            target_path=str(target),
            scan_profile=scan_profile,
            detected_languages=detected_languages,
            framework_hints=framework_hints,
            files_scanned=len(supported_files),
            metadata={
                "target_kind": "directory" if target.is_dir() else "file",
                "supported_file_count": len(supported_files),
                "language_file_counts": language_counts,
                "analysis_plan": analysis_plan,
                "config_files": [
                    self._relative_or_name(path, target) for path in config_files[:12]
                ],
                "sample_files": [
                    self._relative_or_name(path, target)
                    for path in supported_files[:12]
                ],
            },
        )

    @staticmethod
    def choose_scan_profile(detected_languages: Iterable[str]) -> str:
        """Select a conservative scan profile from detected languages."""
        languages = sorted({language for language in detected_languages if language})
        if not languages:
            return "generic"
        if languages == ["python"]:
            return "python-deep"
        if languages == ["javascript"]:
            return "javascript-intra-file"
        if languages == ["java"]:
            return "java-intra-file"
        if languages == ["php"]:
            return "php-intra-file"
        if "python" in languages:
            return "polyglot-python-priority"
        return "polyglot-intra-file"

    @staticmethod
    def build_analysis_plan(detected_languages: Iterable[str]) -> Dict[str, str]:
        """Return the intended analysis depth per language."""
        plan: Dict[str, str] = {}
        for language in sorted({language for language in detected_languages if language}):
            if language == "python":
                plan[language] = "deep"
            elif language in {"javascript", "java", "php"}:
                plan[language] = "intra-file"
            else:
                plan[language] = "generic"
        return plan

    @staticmethod
    def infer_language_from_target(target_path: str) -> Optional[str]:
        """Infer a language from a file target when no scan output exists yet."""
        suffix = Path(target_path).suffix.lower()
        return {
            ".py": "python",
            ".pyw": "python",
            ".js": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".java": "java",
            ".php": "php",
        }.get(suffix)

    def _collect_supported_files(self, target: Path) -> List[Path]:
        """Collect files handled by the registered language plugins."""
        extension_map = self._get_extension_language_map()
        if target.is_file():
            extension = target.suffix.lstrip(".").lower()
            return [target] if extension in extension_map else []

        supported_files: List[Path] = []
        for extension in extension_map:
            supported_files.extend(sorted(target.rglob(f"*.{extension}")))
        return supported_files

    def _collect_config_files(self, target: Path) -> List[Path]:
        """Collect project-level config files that may reveal framework hints."""
        if target.is_file():
            parent = target.parent
            candidates = [
                parent / name for name in sorted(self.CONFIG_FILE_NAMES)
                if (parent / name).exists()
            ]
            if target.name in self.CONFIG_FILE_NAMES:
                candidates.append(target)
            return sorted({path for path in candidates if path.exists()})

        config_files: List[Path] = []
        for name in sorted(self.CONFIG_FILE_NAMES):
            config_files.extend(sorted(target.rglob(name)))
        return sorted({path for path in config_files if path.exists()})

    def _count_languages(self, supported_files: Iterable[Path]) -> Dict[str, int]:
        """Count supported files by registered language plugin."""
        extension_map = self._get_extension_language_map()
        counts: Dict[str, int] = {}
        for file_path in supported_files:
            extension = file_path.suffix.lstrip(".").lower()
            language = extension_map.get(extension)
            if not language:
                continue
            counts[language] = counts.get(language, 0) + 1
        return counts

    def _ensure_builtin_plugins(self) -> None:
        """Register built-in plugins when the registry is still empty."""
        if self.registry.get_supported_extensions():
            return

        plugin_classes = []
        try:
            from aegis_sast.plugins.python_plugin import PythonPlugin

            plugin_classes.append(PythonPlugin)
        except ImportError:
            pass
        try:
            from aegis_sast.plugins.javascript_plugin import JavaScriptPlugin

            plugin_classes.append(JavaScriptPlugin)
        except ImportError:
            pass
        try:
            from aegis_sast.plugins.java_plugin import JavaPlugin

            plugin_classes.append(JavaPlugin)
        except ImportError:
            pass
        try:
            from aegis_sast.plugins.php_plugin import PHPPlugin

            plugin_classes.append(PHPPlugin)
        except ImportError:
            pass

        for plugin_class in plugin_classes:
            try:
                self.registry.register(plugin_class())
            except ValueError:
                continue

    def _get_extension_language_map(self) -> Dict[str, str]:
        """Return extension-to-language mappings with safe built-in fallbacks."""
        extension_map = dict(self.SUPPORTED_EXTENSION_LANGUAGE)
        for plugin in self.registry.get_all_plugins():
            for extension in plugin.get_file_extensions():
                extension_map[extension] = plugin.get_language_name()
        return extension_map

    def _detect_framework_hints(
        self,
        target: Path,
        supported_files: List[Path],
        config_files: List[Path],
        detected_languages: List[str],
    ) -> List[str]:
        """Detect a small set of framework hints from filenames and contents."""
        hints: Set[str] = set()
        candidate_files: List[Path] = []
        for path in config_files + supported_files:
            if path not in candidate_files:
                candidate_files.append(path)
            if len(candidate_files) >= self.max_inspected_files:
                break

        for path in candidate_files:
            if path.name in self.FILE_NAME_HINTS.get("django", set()):
                hints.add("django")
            if path.name in self.FILE_NAME_HINTS.get("nextjs", set()):
                hints.add("nextjs")
            if path.name in self.FILE_NAME_HINTS.get("laravel", set()):
                hints.add("laravel")

            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for language in detected_languages:
                for hint, patterns in self.FRAMEWORK_PATTERNS.get(language, {}).items():
                    if any(pattern in text for pattern in patterns):
                        hints.add(hint)

        return sorted(hints)

    @staticmethod
    def _relative_or_name(path: Path, target: Path) -> str:
        """Render a compact path relative to the target when possible."""
        if target.is_file():
            base = target.parent
        else:
            base = target

        try:
            return str(path.relative_to(base))
        except ValueError:
            return path.name

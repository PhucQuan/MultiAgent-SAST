"""
Call Graph module for Aegis-SAST — Level B (Import Tracking).

Provides:
  - FunctionIndex: Scans all Python files in a project and records every
    function definition with its parameters, return variables, and the
    functions it calls.
  - ImportResolver: Parses 'from X import Y' statements and resolves
    function names to the file that defines them.

Scope: explicit static imports only.  Dynamic imports (__import__,
importlib) are NOT resolved here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

# We reuse the tree-sitter Python grammar that is already installed.
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node

from aegis_sast.core.models import FunctionEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _collect_identifiers(node: Node) -> List[str]:
    """Recursively collect all identifier names inside a node."""
    names: List[str] = []
    if node.type == "identifier":
        names.append(_decode(node))
    for child in node.children:
        names.extend(_collect_identifiers(child))
    return names


# ---------------------------------------------------------------------------
# FunctionIndex
# ---------------------------------------------------------------------------

class FunctionIndex:
    """
    Indexes every Python function definition found in a project.

    After calling ``build()``, ``self.index`` maps::

        "function_name" -> FunctionEntry(file_path, line, params, ...)
    """

    def __init__(self) -> None:
        self._lang = Language(tspython.language())
        self._parser = Parser(self._lang)
        # key: plain function name (not qualified)
        self.index: Dict[str, FunctionEntry] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, project_root: Path) -> None:
        """Scan every *.py file under *project_root* and index functions."""
        for py_file in sorted(project_root.rglob("*.py")):
            self._index_file(py_file)

    def get(self, name: str) -> Optional[FunctionEntry]:
        return self.index.get(name)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _index_file(self, file_path: Path) -> None:
        try:
            source = file_path.read_bytes()
        except OSError:
            return

        tree = self._parser.parse(source)
        self._visit(tree.root_node, file_path)

    def _visit(self, node: Node, file_path: Path) -> None:
        if node.type == "function_definition":
            entry = self._extract_function(node, file_path)
            # Prefer the first definition found (avoids shadowing issues)
            if entry.name not in self.index:
                self.index[entry.name] = entry

        for child in node.children:
            self._visit(child, file_path)

    def _extract_function(self, node: Node, file_path: Path) -> FunctionEntry:
        name = ""
        params: List[str] = []
        return_vars: List[str] = []
        calls: List[str] = []

        for child in node.children:
            if child.type == "identifier" and not name:
                name = _decode(child)

            elif child.type == "parameters":
                for p in child.children:
                    if p.type == "identifier":
                        params.append(_decode(p))

            elif child.type == "block":
                # Collect return variables and called functions from the body
                return_vars = self._collect_return_vars(child)
                calls = self._collect_calls(child)

        return FunctionEntry(
            name=name,
            file_path=str(file_path),
            line_number=node.start_point[0] + 1,
            params=params,
            return_vars=return_vars,
            calls=calls,
        )

    @staticmethod
    def _collect_return_vars(block: Node) -> List[str]:
        """Return the identifiers found in every return statement."""
        vars_: List[str] = []
        for node in _iter_all(block):
            if node.type == "return_statement":
                for child in node.children:
                    if child.type not in ("return", "comment"):
                        vars_.extend(_collect_identifiers(child))
        return vars_

    @staticmethod
    def _collect_calls(block: Node) -> List[str]:
        """Return the name of every function called inside the block."""
        names: List[str] = []
        for node in _iter_all(block):
            if node.type == "call":
                func_child = node.child_by_field_name("function")
                if func_child:
                    text = _decode(func_child)
                    # Normalise: keep only the last component (e.g. os.system → os.system)
                    names.append(text)
        return names


# ---------------------------------------------------------------------------
# ImportResolver
# ---------------------------------------------------------------------------

class ImportResolver:
    """
    Parses Python source files to map imported names → source file paths.

    Handles:
      ``from utils import get_user_id``      → {"get_user_id": Path("utils.py")}
      ``from .helpers import sanitize``      → {"sanitize": Path("helpers.py")}
    """

    def __init__(self, project_root: Path) -> None:
        self._root = project_root
        self._lang = Language(tspython.language())
        self._parser = Parser(self._lang)

    def resolve_imports(self, file_path: Path) -> Dict[str, Path]:
        """
        Return a mapping of {imported_name: resolved_source_file} for all
        static 'from X import Y' imports in *file_path*.
        """
        results: Dict[str, Path] = {}
        try:
            source_text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return results

        # Pattern: from <module> import <names>
        # Handles: from utils import foo, bar
        #          from .helpers import baz
        #          from app.utils import (foo, bar)
        import_re = re.compile(
            r"^from\s+(\.*)(\S+)\s+import\s+(.+)$",
            re.MULTILINE,
        )

        for m in import_re.finditer(source_text):
            dots = len(m.group(1))          # number of leading dots
            module_str = m.group(2).strip()
            names_str = m.group(3).strip().strip("()")

            # Parse individual imported names, strip aliases ("foo as f" → "foo")
            # and inline comments ("foo  # note" → "foo")
            names: List[str] = []
            for part in names_str.split(","):
                part = part.strip()
                # Strip trailing inline comment
                if "#" in part:
                    part = part[:part.index("#")].strip()
                if " as " in part:
                    part = part.split(" as ")[0].strip()
                if part and part != "*":
                    names.append(part)

            resolved = self._resolve_module(module_str, file_path, dots)
            if resolved and resolved.exists():
                for name in names:
                    results[name] = resolved

        return results

    def _resolve_module(self, module_str: str, importer: Path,
                        dots: int) -> Optional[Path]:
        """
        Convert a module string such as 'utils' or 'app.helpers' to a
        Path object relative to the project root.
        """
        parts = module_str.split(".")

        if dots > 0:
            # Relative import: climb *dots* directories from the importer
            base = importer.parent
            for _ in range(dots - 1):
                base = base.parent
        else:
            base = self._root

        candidate = base.joinpath(*parts).with_suffix(".py")
        if candidate.exists():
            return candidate

        # Try as package (__init__.py)
        pkg = base.joinpath(*parts, "__init__.py")
        if pkg.exists():
            return pkg

        return None


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _iter_all(node: Node):
    """Yield *node* and all its descendants (DFS)."""
    yield node
    for child in node.children:
        yield from _iter_all(child)

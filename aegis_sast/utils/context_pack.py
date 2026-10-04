"""Prompt-ready context pack builder for large-repo AI workflows."""

from __future__ import annotations

import ast
import os
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


CODE_LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript-react",
    ".ts": "typescript",
    ".tsx": "typescript-react",
}

DEFAULT_IGNORED_DIRECTORIES = {
    ".aegis_cache",
    ".codex",
    ".git",
    ".idea",
    ".next",
    ".pytest_cache",
    ".venv",
    ".venv-cpython",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
}

ROOT_ONLY_IGNORED_DIRECTORIES = {
    "benchmarks",
    "datasets",
    "refs",
    "reports",
}

READ_FIRST_FILES = [
    (
        Path("AGENTS.md"),
        "Repo workflow rules and lane boundaries for all project work.",
    ),
    (
        Path("README.md"),
        "High-level product overview, install flow, and CLI positioning.",
    ),
    (
        Path("docs/thesis/00-tong-hop-da-lam.md"),
        "Current implementation snapshot and claim-safe project summary.",
    ),
    (
        Path("docs/thesis/04-kien-truc-muc-tieu.md"),
        "Target architecture and layer boundaries before major changes.",
    ),
    (
        Path("pyproject.toml"),
        "Python packaging, dependencies, and repo-wide tooling defaults.",
    ),
]

KNOWN_MODULE_LABELS = {
    "aegis_sast": "scanner core package",
    "apps/findings-dashboard": "dashboard product layer",
    "scripts": "operational scripts",
    "tests": "regression suite",
}


@dataclass(frozen=True)
class ReadFirstFile:
    path: str
    reason: str


@dataclass(frozen=True)
class ModuleSummary:
    module: str
    label: str
    file_count: int
    line_count: int
    languages: list[str]
    largest_file: str
    largest_file_lines: int


@dataclass(frozen=True)
class EntryPoint:
    path: str
    kind: str
    module: str


@dataclass(frozen=True)
class Hotspot:
    path: str
    module: str
    language: str
    line_count: int


@dataclass(frozen=True)
class ImportHub:
    module: str
    imports: int
    imported_by: int


@dataclass(frozen=True)
class ContextPack:
    repo_root: str
    generated_at: str
    ignored_directories: list[str]
    read_first: list[ReadFirstFile]
    module_summaries: list[ModuleSummary]
    entry_points: list[EntryPoint]
    hotspots: list[Hotspot]
    import_hubs: list[ImportHub]
    prompt_starter: list[str]


@dataclass(frozen=True)
class FileStat:
    path: str
    module: str
    language: str
    line_count: int


def _is_ignored_directory(parent_relative: Path, name: str) -> bool:
    if name.startswith(".tmp") or name in DEFAULT_IGNORED_DIRECTORIES:
        return True

    return parent_relative == Path(".") and name in ROOT_ONLY_IGNORED_DIRECTORIES


def _count_lines(file_path: Path) -> int:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    if not text:
        return 0
    return len(text.splitlines())


def _iter_code_files(repo_root: Path) -> Iterable[Path]:
    for current_root, directories, file_names in os.walk(repo_root):
        current_path = Path(current_root)
        parent_relative = current_path.relative_to(repo_root)
        directories[:] = [
            directory
            for directory in directories
            if not _is_ignored_directory(parent_relative, directory)
        ]
        for file_name in file_names:
            file_path = current_path / file_name
            if file_path.suffix.lower() not in CODE_LANGUAGE_BY_EXTENSION:
                continue
            yield file_path


def _derive_module_name(relative_path: Path) -> str:
    parts = relative_path.parts
    if not parts:
        return "root"
    if parts[0] == "apps" and len(parts) >= 2:
        return f"apps/{parts[1]}"
    return parts[0]


def _collect_file_stats(repo_root: Path) -> list[FileStat]:
    stats: list[FileStat] = []
    for file_path in _iter_code_files(repo_root):
        relative_path = file_path.relative_to(repo_root)
        stats.append(
            FileStat(
                path=relative_path.as_posix(),
                module=_derive_module_name(relative_path),
                language=CODE_LANGUAGE_BY_EXTENSION[file_path.suffix.lower()],
                line_count=_count_lines(file_path),
            )
        )
    return stats


def collect_read_first_files(repo_root: Path) -> list[ReadFirstFile]:
    files: list[ReadFirstFile] = []

    for relative_path, reason in READ_FIRST_FILES:
        absolute_path = repo_root / relative_path
        if absolute_path.exists():
            files.append(ReadFirstFile(path=relative_path.as_posix(), reason=reason))

    for claude_file in sorted((repo_root / "apps").glob("*/CLAUDE.md")):
        relative_path = claude_file.relative_to(repo_root).as_posix()
        app_name = claude_file.parent.name
        files.append(
            ReadFirstFile(
                path=relative_path,
                reason=f"{app_name} app-specific agent instructions and local context.",
            )
        )

    return files


def summarize_modules(file_stats: list[FileStat]) -> list[ModuleSummary]:
    buckets: dict[str, list[FileStat]] = defaultdict(list)
    for file_stat in file_stats:
        buckets[file_stat.module].append(file_stat)

    summaries: list[ModuleSummary] = []
    for module, items in buckets.items():
        largest = max(items, key=lambda item: (item.line_count, item.path))
        language_counts = Counter(item.language for item in items)
        summaries.append(
            ModuleSummary(
                module=module,
                label=KNOWN_MODULE_LABELS.get(module, "module slice"),
                file_count=len(items),
                line_count=sum(item.line_count for item in items),
                languages=[
                    language
                    for language, _ in sorted(
                        language_counts.items(),
                        key=lambda pair: (-pair[1], pair[0]),
                    )
                ],
                largest_file=largest.path,
                largest_file_lines=largest.line_count,
            )
        )

    return sorted(
        summaries,
        key=lambda item: (-item.line_count, -item.file_count, item.module),
    )


def _infer_entry_point_kind(relative_path: Path) -> str | None:
    posix_path = relative_path.as_posix()
    if posix_path == "aegis_sast/cli.py":
        return "CLI entrypoint"

    if posix_path.startswith("scripts/") and relative_path.suffix == ".py":
        stem = relative_path.stem
        if stem.startswith("run_"):
            return "Runner script"
        if stem.startswith("scan_"):
            return "Scan helper"
        if stem.startswith("build_"):
            return "Build helper"
        if stem.startswith("report_"):
            return "Review console helper"
        return "Operational script"

    if "/src/app/api/" in posix_path and relative_path.name.startswith("route."):
        return "Next.js API route"

    if posix_path.endswith("/src/app/page.tsx") or posix_path.endswith("/src/app/page.ts"):
        return "Next.js page"

    return None


def collect_entry_points(file_stats: list[FileStat]) -> list[EntryPoint]:
    entry_points: list[EntryPoint] = []
    for file_stat in file_stats:
        relative_path = Path(file_stat.path)
        kind = _infer_entry_point_kind(relative_path)
        if not kind:
            continue
        entry_points.append(
            EntryPoint(
                path=file_stat.path,
                kind=kind,
                module=file_stat.module,
            )
        )

    return sorted(entry_points, key=lambda item: (item.module, item.path))


def collect_hotspots(file_stats: list[FileStat], *, limit: int = 12) -> list[Hotspot]:
    hotspots = [
        Hotspot(
            path=item.path,
            module=item.module,
            language=item.language,
            line_count=item.line_count,
        )
        for item in sorted(
            file_stats,
            key=lambda entry: (-entry.line_count, entry.path),
        )[: max(limit, 0)]
    ]
    return hotspots


def _python_module_name(relative_path: Path) -> str:
    without_suffix = relative_path.with_suffix("")
    parts = list(without_suffix.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_import_base(
    *,
    current_module: str,
    current_is_package: bool,
    module: str | None,
    level: int,
) -> str | None:
    if level == 0:
        return module

    package_parts = current_module.split(".")
    if not current_is_package:
        package_parts = package_parts[:-1]

    levels_up = level - 1
    if levels_up > len(package_parts):
        return None

    base_parts = package_parts[: len(package_parts) - levels_up]
    if module:
        base_parts.extend(module.split("."))
    return ".".join(part for part in base_parts if part)


def _canonical_local_module(module_name: str, local_modules: set[str]) -> str:
    if module_name in local_modules:
        return module_name

    package_prefix = f"{module_name}."
    if any(module.startswith(package_prefix) for module in local_modules):
        return module_name

    return module_name


def _collect_import_targets(
    *,
    module_name: str,
    current_is_package: bool,
    source_code: str,
    local_modules: set[str],
) -> set[str]:
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return set()

    targets: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_module = alias.name
                if not imported_module.startswith("aegis_sast"):
                    continue
                targets.add(_canonical_local_module(imported_module, local_modules))

        if isinstance(node, ast.ImportFrom):
            base_module = _resolve_import_base(
                current_module=module_name,
                current_is_package=current_is_package,
                module=node.module,
                level=node.level,
            )
            if not base_module or not base_module.startswith("aegis_sast"):
                continue

            for alias in node.names:
                if alias.name == "*":
                    targets.add(_canonical_local_module(base_module, local_modules))
                    continue

                candidate = f"{base_module}.{alias.name}"
                if candidate in local_modules:
                    targets.add(candidate)
                else:
                    targets.add(_canonical_local_module(base_module, local_modules))

    targets.discard(module_name)
    return targets


def collect_import_hubs(
    repo_root: Path,
    *,
    limit: int = 12,
) -> list[ImportHub]:
    package_root = repo_root / "aegis_sast"
    if not package_root.exists():
        return []

    python_files = sorted(package_root.rglob("*.py"))
    local_modules = {
        _python_module_name(file_path.relative_to(repo_root))
        for file_path in python_files
    }

    imports_by_source: dict[str, set[str]] = defaultdict(set)
    imported_by_target: dict[str, set[str]] = defaultdict(set)

    for file_path in python_files:
        relative_path = file_path.relative_to(repo_root)
        module_name = _python_module_name(relative_path)
        source_code = file_path.read_text(encoding="utf-8", errors="ignore")
        targets = _collect_import_targets(
            module_name=module_name,
            current_is_package=file_path.name == "__init__.py",
            source_code=source_code,
            local_modules=local_modules,
        )

        for target in targets:
            imports_by_source[module_name].add(target)
            imported_by_target[target].add(module_name)

    all_modules = sorted(local_modules | set(imported_by_target) | set(imports_by_source))
    hubs = [
        ImportHub(
            module=module,
            imports=len(imports_by_source.get(module, set())),
            imported_by=len(imported_by_target.get(module, set())),
        )
        for module in all_modules
        if imports_by_source.get(module) or imported_by_target.get(module)
    ]

    return sorted(
        hubs,
        key=lambda item: (-item.imported_by, -item.imports, item.module),
    )[: max(limit, 0)]


def build_prompt_starter(pack: ContextPack) -> list[str]:
    starter = [
        "Read the repo guardrails first, then load only the target lane instead of the whole codebase.",
    ]

    if pack.read_first:
        starter.append(
            "Start with: "
            + ", ".join(item.path for item in pack.read_first[:4])
            + "."
        )

    if pack.entry_points:
        starter.append(
            "Anchor new work from an entrypoint: "
            + ", ".join(item.path for item in pack.entry_points[:3])
            + "."
        )

    if pack.hotspots:
        starter.append(
            "Treat large files as hotspots and edit them with narrow diffs: "
            + ", ".join(item.path for item in pack.hotspots[:3])
            + "."
        )

    if pack.import_hubs:
        starter.append(
            "When expanding context, follow internal import hubs before opening extra files: "
            + ", ".join(item.module for item in pack.import_hubs[:3])
            + "."
        )

    starter.append(
        "After each change, rerun the narrowest matching test or smoke script before moving on.",
    )
    return starter


def build_context_pack(
    repo_root: Path,
    *,
    hotspot_limit: int = 12,
    import_hub_limit: int = 12,
) -> ContextPack:
    repo_root = repo_root.resolve()
    file_stats = _collect_file_stats(repo_root)
    read_first = collect_read_first_files(repo_root)
    module_summaries = summarize_modules(file_stats)
    entry_points = collect_entry_points(file_stats)
    hotspots = collect_hotspots(file_stats, limit=hotspot_limit)
    import_hubs = collect_import_hubs(repo_root, limit=import_hub_limit)

    pack_without_starter = ContextPack(
        repo_root=str(repo_root),
        generated_at=datetime.now(timezone.utc).isoformat(),
        ignored_directories=sorted(
            DEFAULT_IGNORED_DIRECTORIES | ROOT_ONLY_IGNORED_DIRECTORIES
        ),
        read_first=read_first,
        module_summaries=module_summaries,
        entry_points=entry_points,
        hotspots=hotspots,
        import_hubs=import_hubs,
        prompt_starter=[],
    )

    return ContextPack(
        repo_root=pack_without_starter.repo_root,
        generated_at=pack_without_starter.generated_at,
        ignored_directories=pack_without_starter.ignored_directories,
        read_first=pack_without_starter.read_first,
        module_summaries=pack_without_starter.module_summaries,
        entry_points=pack_without_starter.entry_points,
        hotspots=pack_without_starter.hotspots,
        import_hubs=pack_without_starter.import_hubs,
        prompt_starter=build_prompt_starter(pack_without_starter),
    )


def context_pack_to_dict(pack: ContextPack) -> dict[str, object]:
    return asdict(pack)


def render_context_pack_markdown(pack: ContextPack) -> str:
    lines = [
        "# Codebase Context Pack",
        "",
        f"- Generated at: `{pack.generated_at}`",
        f"- Repo root: `{pack.repo_root}`",
        "",
        "## Read First",
        "",
    ]

    if pack.read_first:
        for item in pack.read_first:
            lines.append(f"- `{item.path}`: {item.reason}")
    else:
        lines.append("- No read-first files were detected.")

    lines.extend(
        [
            "",
            "## Ignore By Default",
            "",
            "- " + ", ".join(f"`{name}`" for name in pack.ignored_directories),
            "",
            "## Module Overview",
            "",
            "| Module | Role | Files | Lines | Languages | Largest file |",
            "|---|---|---:|---:|---|---|",
        ]
    )

    for item in pack.module_summaries:
        lines.append(
            f"| `{item.module}` | {item.label} | {item.file_count} | {item.line_count} | "
            f"{', '.join(item.languages)} | `{item.largest_file}` ({item.largest_file_lines}) |"
        )

    lines.extend(
        [
            "",
            "## Entry Points",
            "",
        ]
    )
    if pack.entry_points:
        for item in pack.entry_points:
            lines.append(f"- `{item.path}`: {item.kind} in `{item.module}`")
    else:
        lines.append("- No entry points detected.")

    lines.extend(
        [
            "",
            "## Hotspots",
            "",
            "| File | Module | Language | Lines |",
            "|---|---|---|---:|",
        ]
    )
    for item in pack.hotspots:
        lines.append(
            f"| `{item.path}` | `{item.module}` | {item.language} | {item.line_count} |"
        )

    lines.extend(
        [
            "",
            "## Internal Python Import Hubs",
            "",
            "| Module | Imports | Imported by |",
            "|---|---:|---:|",
        ]
    )
    if pack.import_hubs:
        for item in pack.import_hubs:
            lines.append(
                f"| `{item.module}` | {item.imports} | {item.imported_by} |"
            )
    else:
        lines.append("| _none_ | 0 | 0 |")

    lines.extend(
        [
            "",
            "## Prompt Starter",
            "",
        ]
    )
    for item in pack.prompt_starter:
        lines.append(f"- {item}")

    lines.append("")
    return "\n".join(lines)

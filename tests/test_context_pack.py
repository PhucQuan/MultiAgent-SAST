"""Tests for the large-repo context pack generator."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from aegis_sast.utils.context_pack import build_context_pack, render_context_pack_markdown


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_context_pack.py"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("build_context_pack", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _create_fixture_repo(repo_root: Path) -> None:
    _write(repo_root / "AGENTS.md", "# agents\n")
    _write(repo_root / "README.md", "# readme\n")
    _write(repo_root / "pyproject.toml", "[tool.poetry]\nname='demo'\n")
    _write(repo_root / "docs" / "thesis" / "00-tong-hop-da-lam.md", "# summary\n")
    _write(repo_root / "docs" / "thesis" / "04-kien-truc-muc-tieu.md", "# target\n")
    _write(repo_root / "apps" / "findings-dashboard" / "CLAUDE.md", "@AGENTS.md\n")

    _write(repo_root / "aegis_sast" / "__init__.py", "")
    _write(
        repo_root / "aegis_sast" / "cli.py",
        "from aegis_sast.analysis.engine import run_scan\n\nrun_scan = run_scan\n",
    )
    _write(repo_root / "aegis_sast" / "analysis" / "__init__.py", "")
    _write(
        repo_root / "aegis_sast" / "analysis" / "engine.py",
        "from aegis_sast.core.models import Finding\n\n"
        "def run_scan():\n"
        "    return Finding()\n",
    )
    _write(repo_root / "aegis_sast" / "core" / "__init__.py", "")
    _write(
        repo_root / "aegis_sast" / "core" / "models.py",
        "class Finding:\n"
        "    pass\n",
    )
    _write(
        repo_root / "scripts" / "run_scan_pipeline_json.py",
        "def main():\n"
        "    return 0\n",
    )
    _write(
        repo_root / "apps" / "findings-dashboard" / "src" / "app" / "page.tsx",
        "export default function Page() {\n"
        "  return <div>dashboard</div>;\n"
        "}\n",
    )
    _write(
        repo_root
        / "apps"
        / "findings-dashboard"
        / "src"
        / "app"
        / "api"
        / "reports"
        / "route.ts",
        "export async function GET() {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )

    _write(repo_root / ".venv" / "ignored.py", "raise RuntimeError('ignore me')\n")
    _write(repo_root / "reports" / "noise.py", "raise RuntimeError('ignore me')\n")


def test_build_context_pack_summarizes_modules_and_entry_points(tmp_path):
    _create_fixture_repo(tmp_path)

    pack = build_context_pack(tmp_path, hotspot_limit=5, import_hub_limit=5)

    read_first_paths = {item.path for item in pack.read_first}
    assert "AGENTS.md" in read_first_paths
    assert "docs/thesis/00-tong-hop-da-lam.md" in read_first_paths
    assert "apps/findings-dashboard/CLAUDE.md" in read_first_paths

    modules = {item.module: item for item in pack.module_summaries}
    assert "aegis_sast" in modules
    assert "scripts" in modules
    assert "apps/findings-dashboard" in modules
    assert modules["aegis_sast"].file_count == 6

    entry_paths = {item.path for item in pack.entry_points}
    assert "aegis_sast/cli.py" in entry_paths
    assert "scripts/run_scan_pipeline_json.py" in entry_paths
    assert "apps/findings-dashboard/src/app/page.tsx" in entry_paths
    assert "apps/findings-dashboard/src/app/api/reports/route.ts" in entry_paths

    hotspot_paths = {item.path for item in pack.hotspots}
    assert ".venv/ignored.py" not in hotspot_paths
    assert "reports/noise.py" not in hotspot_paths

    hubs = {item.module: item for item in pack.import_hubs}
    assert "aegis_sast.core.models" in hubs
    assert hubs["aegis_sast.core.models"].imported_by >= 1


def test_render_context_pack_markdown_contains_key_sections(tmp_path):
    _create_fixture_repo(tmp_path)

    pack = build_context_pack(tmp_path, hotspot_limit=3, import_hub_limit=3)
    markdown = render_context_pack_markdown(pack)

    assert "# Codebase Context Pack" in markdown
    assert "## Read First" in markdown
    assert "## Module Overview" in markdown
    assert "## Entry Points" in markdown
    assert "## Hotspots" in markdown
    assert "## Internal Python Import Hubs" in markdown
    assert "## Prompt Starter" in markdown
    assert "`aegis_sast/cli.py`" in markdown


def test_build_context_pack_script_writes_markdown_and_json(tmp_path):
    _create_fixture_repo(tmp_path / "repo")
    output_md = tmp_path / "artifacts" / "context.md"
    output_json = tmp_path / "artifacts" / "context.json"
    module = _load_script_module()

    exit_code = module.main(
        [
            "--repo-root",
            str(tmp_path / "repo"),
            "--output",
            str(output_md),
            "--json-output",
            str(output_json),
            "--hotspots",
            "2",
            "--import-hubs",
            "2",
        ]
    )

    assert exit_code == 0
    assert output_md.exists()
    assert output_json.exists()

    payload = json.loads(output_json.read_text(encoding="utf-8"))
    assert payload["read_first"]
    assert payload["entry_points"]
    assert payload["hotspots"]

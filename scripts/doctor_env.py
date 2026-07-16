"""Diagnose whether the current Python environment is suitable for Aegis-SAST."""

from __future__ import annotations

from pathlib import Path
import os
import platform
import sys
import sysconfig


def _read_pyvenv_cfg(python_executable: Path) -> dict[str, str]:
    """Read pyvenv.cfg next to a virtualenv interpreter when available."""
    cfg_path = python_executable.parent.parent / "pyvenv.cfg"
    if not cfg_path.exists():
        return {}

    data: dict[str, str] = {}
    try:
        for raw_line in cfg_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in raw_line:
                continue
            key, value = raw_line.split("=", 1)
            data[key.strip()] = value.strip()
    except OSError:
        return {}
    return data


def diagnose_environment() -> tuple[bool, list[str], list[str]]:
    """Return compatibility status, detected issues, and recommendations."""
    executable = Path(sys.executable)
    platform_tag = sysconfig.get_platform()
    pyvenv = _read_pyvenv_cfg(executable)

    issues: list[str] = []
    recommendations: list[str] = []

    executable_lower = str(executable).lower()
    home_lower = pyvenv.get("home", "").lower()

    is_msys_python = (
        platform_tag.startswith("mingw_")
        or "msys64" in executable_lower
        or "msys64" in home_lower
        or "gcc ucrt" in sys.version.lower()
    )

    if os.name == "nt" and is_msys_python:
        issues.append(
            "Dang dung Python cua MSYS2/UCRT. Pip thuong khong dung duoc wheel "
            "win_amd64 cho stack native nhu tree-sitter-* va cryptography."
        )
        issues.append(
            "Moi truong hien tai de roi sang build source bang GCC, trong khi mot so "
            "goi Python native ky vong toolchain / ABI cua CPython Windows chuan."
        )
        recommendations.extend(
            [
                "Dung CPython Windows chuan tu python.org hoac launcher `py` tren PowerShell.",
                "Tao virtualenv moi bang `py -3.12 -m venv .venv-cpython`.",
                "Kich hoat bang `.\\.venv-cpython\\Scripts\\Activate.ps1`.",
                "Cai scanner core truoc: `python -m pip install -r requirements.txt`.",
                "Neu can AI moi cai them: `python -m pip install -r requirements-ai.txt`.",
            ]
        )

    if os.name == "nt" and executable.parts and "bin" in executable.parts:
        issues.append(
            "Cau truc virtualenv dang theo kieu Unix (`.venv/bin/python.exe`). "
            "Day thuong la dau hieu venv duoc tao tu MSYS2/Git Bash thay vi CPython Windows."
        )

    compatible = not issues
    return compatible, issues, recommendations


def main() -> int:
    """Print a concise environment report."""
    executable = Path(sys.executable)
    platform_tag = sysconfig.get_platform()
    pyvenv = _read_pyvenv_cfg(executable)
    compatible, issues, recommendations = diagnose_environment()

    print("Aegis-SAST environment doctor")
    print(f"- executable: {executable}")
    print(f"- version: {sys.version.splitlines()[0]}")
    print(f"- implementation: {platform.python_implementation()}")
    print(f"- sysconfig platform: {platform_tag}")
    if pyvenv:
        print(f"- venv home: {pyvenv.get('home', '<unknown>')}")

    if compatible:
        print("- status: compatible")
        return 0

    print("- status: incompatible for native dependency install")
    print("- issues:")
    for issue in issues:
        print(f"  - {issue}")

    if recommendations:
        print("- recommendations:")
        for item in recommendations:
            print(f"  - {item}")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

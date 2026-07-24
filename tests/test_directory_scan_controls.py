"""Regression tests for directory-scan exclusions and progress updates."""

from pathlib import Path

import aegis_sast.analysis.vulnerability_detector as detector_module
from aegis_sast.analysis.rule_engine import RuleEngine
from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector
from aegis_sast.core.models import (
    CodeLocation,
    DataFlowPath,
    Severity,
    TaintSink,
    TaintSource,
    Vulnerability,
    VulnerabilityType,
)


def _write_file(root: Path, relative_path: str, content: str = "pass\n") -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _make_vulnerability(
    file_path: Path,
    source_line: int,
    sink_line: int,
    vuln_type: VulnerabilityType = VulnerabilityType.PATH_TRAVERSAL,
    sink_function: str = "open",
    sink_pattern: str = "open(",
) -> Vulnerability:
    source = TaintSource(
        location=CodeLocation(
            file_path=str(file_path),
            line_number=source_line,
            column_number=0,
            code_snippet=f"source_{source_line} = input()",
        ),
        source_type="USER_INPUT",
        variable_name=f"source_{source_line}",
        pattern="input(",
    )
    sink = TaintSink(
        location=CodeLocation(
            file_path=str(file_path),
            line_number=sink_line,
            column_number=4,
            code_snippet=f"{sink_function}(value)",
        ),
        sink_type=vuln_type,
        function_name=sink_function,
        pattern=sink_pattern,
        arguments=["value"],
    )
    return Vulnerability(
        id=f"RAW-{source_line}-{sink_line}",
        vuln_type=vuln_type,
        severity=Severity.HIGH,
        dataflow=DataFlowPath(source=source, sink=sink),
    )


def test_analyze_directory_respects_exclusions(tmp_path, monkeypatch):
    _write_file(tmp_path, "src/app.py")
    _write_file(tmp_path, "src/keep.js", "console.log('keep');\n")
    _write_file(tmp_path, "src/skip.min.js", "console.log('skip');\n")
    _write_file(tmp_path, "test/test_app.py")
    _write_file(tmp_path, "third_party/vendor.py")

    detector = VulnerabilityDetector(RuleEngine(language="python"))
    monkeypatch.setattr(detector.registry, "get_supported_extensions", lambda: ["py", "js"])

    captured = {}

    class FakeFunctionIndex:
        def __init__(self):
            self.index = {}

        def build(self, root, exclude_dir_names=None, exclude_globs=None):
            captured["root"] = root
            captured["exclude_dirs"] = set(exclude_dir_names or [])
            captured["exclude_globs"] = list(exclude_globs or [])

    monkeypatch.setattr(detector_module, "FunctionIndex", FakeFunctionIndex)

    scanned = []

    def fake_analyze_file(file_path, project_root=None, _func_index=None):
        scanned.append(
            (
                file_path.relative_to(tmp_path).as_posix(),
                project_root,
                _func_index,
            )
        )
        return []

    monkeypatch.setattr(detector, "analyze_file", fake_analyze_file)

    result = detector.analyze_directory(
        tmp_path,
        exclude_dir_names=["test", "third_party"],
        exclude_globs=["*.min.js"],
    )

    assert [path for path, _, _ in scanned] == ["src/app.py", "src/keep.js"]
    assert result.files_scanned == 2
    assert captured["root"] == tmp_path
    assert captured["exclude_dirs"] == {"test", "third_party"}
    assert captured["exclude_globs"] == ["*.min.js"]
    assert all(project_root == tmp_path for _, project_root, _ in scanned)
    assert all(isinstance(index_obj, FakeFunctionIndex) for _, _, index_obj in scanned)


def test_analyze_directory_reports_progress(tmp_path, monkeypatch):
    _write_file(tmp_path, "a.py")
    _write_file(tmp_path, "b.py")
    _write_file(tmp_path, "nested/c.py")

    detector = VulnerabilityDetector(RuleEngine(language="python"))
    monkeypatch.setattr(detector.registry, "get_supported_extensions", lambda: ["py"])

    class FakeFunctionIndex:
        def __init__(self):
            self.index = {}

        def build(self, root, exclude_dir_names=None, exclude_globs=None):
            self.index["sample"] = object()

    monkeypatch.setattr(detector_module, "FunctionIndex", FakeFunctionIndex)
    monkeypatch.setattr(detector, "analyze_file", lambda file_path, project_root=None, _func_index=None: [])

    updates = []
    result = detector.analyze_directory(
        tmp_path,
        progress_callback=updates.append,
        progress_every=2,
    )

    events = [update["event"] for update in updates]
    assert events == [
        "index-start",
        "index-complete",
        "scan-start",
        "progress",
        "progress",
        "complete",
    ]

    progress_updates = [update for update in updates if update["event"] == "progress"]
    assert [update["files_processed"] for update in progress_updates] == [2, 3]
    assert updates[0]["total_files"] == 3
    assert updates[1]["indexed_functions"] == 1
    assert Path(progress_updates[-1]["current_file"]).name == "c.py"
    assert updates[-1]["files_scanned"] == 3
    assert result.files_scanned == 3


def test_analyze_directory_dedupes_duplicate_findings_and_renumbers_ids(tmp_path, monkeypatch):
    first_file = _write_file(tmp_path, "a.py")
    second_file = _write_file(tmp_path, "b.py")

    detector = VulnerabilityDetector(RuleEngine(language="python"))
    monkeypatch.setattr(detector.registry, "get_supported_extensions", lambda: ["py"])

    class FakeFunctionIndex:
        def __init__(self):
            self.index = {}

        def build(self, root, exclude_dir_names=None, exclude_globs=None):
            self.index = {}

    monkeypatch.setattr(detector_module, "FunctionIndex", FakeFunctionIndex)

    duplicate_group = [
        _make_vulnerability(first_file, source_line=1, sink_line=9),
        _make_vulnerability(first_file, source_line=2, sink_line=9),
    ]
    unique_vulnerability = _make_vulnerability(
        second_file,
        source_line=3,
        sink_line=7,
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        sink_function="os.system",
        sink_pattern="os.system(",
    )

    def fake_analyze_file(file_path, project_root=None, _func_index=None):
        if file_path == first_file:
            return list(duplicate_group)
        return [unique_vulnerability]

    monkeypatch.setattr(detector, "analyze_file", fake_analyze_file)

    result = detector.analyze_directory(tmp_path)

    assert len(result.vulnerabilities) == 2
    assert [v.id for v in result.vulnerabilities] == ["VULN-001", "VULN-002"]
    dedupe_keys = [
        detector._vulnerability_dedupe_key(vulnerability)
        for vulnerability in result.vulnerabilities
    ]
    assert len(dedupe_keys) == len(set(dedupe_keys))

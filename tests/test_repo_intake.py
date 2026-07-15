"""Tests for repository intake, language detection, and scan profiling."""

from pathlib import Path
from tempfile import TemporaryDirectory

from aegis_sast.orchestration import RepoIntake


def test_repo_intake_detects_languages_frameworks_and_profile():
    """Directory intake should detect languages, frameworks, and analysis plan."""
    with TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / "app.py").write_text(
            "\n".join(
                [
                    "from flask import Flask",
                    "from sqlalchemy import create_engine",
                    "app = Flask(__name__)",
                ]
            ),
            encoding="utf-8",
        )
        (root / "server.js").write_text(
            "\n".join(
                [
                    "const express = require('express');",
                    "const app = express();",
                ]
            ),
            encoding="utf-8",
        )
        (root / "Controller.java").write_text(
            "\n".join(
                [
                    "import org.springframework.web.bind.annotation.RestController;",
                    "import java.sql.PreparedStatement;",
                    "@RestController",
                    "public class Controller {}",
                ]
            ),
            encoding="utf-8",
        )
        (root / "package.json").write_text(
            '{"dependencies": {"express": "^5.0.0"}}',
            encoding="utf-8",
        )
        (root / "pom.xml").write_text(
            "<artifactId>spring-boot-starter-web</artifactId>",
            encoding="utf-8",
        )

        profile = RepoIntake().analyze_target(root)

        assert profile.scan_profile == "polyglot-python-priority"
        assert profile.detected_languages == ["java", "javascript", "python"]
        assert "express" in profile.framework_hints
        assert "flask" in profile.framework_hints
        assert "spring" in profile.framework_hints
        assert "sqlalchemy" in profile.framework_hints
        assert profile.metadata["language_file_counts"] == {
            "java": 1,
            "javascript": 1,
            "python": 1,
        }
        assert profile.metadata["analysis_plan"] == {
            "java": "intra-file",
            "javascript": "intra-file",
            "python": "deep",
        }


def test_repo_intake_handles_single_file_targets():
    """Single-file intake should infer a focused scan profile."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "handler.py"
        target.write_text(
            "\n".join(
                [
                    "from fastapi import FastAPI",
                    "app = FastAPI()",
                ]
            ),
            encoding="utf-8",
        )

        profile = RepoIntake().analyze_target(target)

        assert profile.scan_profile == "python-deep"
        assert profile.detected_languages == ["python"]
        assert "fastapi" in profile.framework_hints
        assert profile.metadata["target_kind"] == "file"
        assert profile.metadata["supported_file_count"] == 1

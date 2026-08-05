"""Tiny HTTP workbench for reviewed rule bundles."""

from __future__ import annotations

import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .models import RuleWorkbenchBundleRequest, RuleWorkbenchDraftRequest
from .service import (
    SUPPORTED_PROFILES,
    WORKBENCH_V1_FAMILIES,
    RuleWorkbenchService,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_ARTIFACT_PREVIEW_CHARS = 250_000
DEFAULT_WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATIC_DIR = DEFAULT_WORKSPACE_ROOT / "apps" / "rule_workbench"
DEFAULT_SEED_INPUT_DIR = (
    DEFAULT_WORKSPACE_ROOT / "datasets" / "synthetic" / "rule_review_v1" / "seed_inputs"
)


class RuleWorkbenchWebApp:
    """Project-local backend for the V1 rule authoring workbench."""

    def __init__(
        self,
        *,
        workspace_root: Path | None = None,
        static_dir: Path | None = None,
        seed_input_dir: Path | None = None,
        service: RuleWorkbenchService | None = None,
    ) -> None:
        self.workspace_root = (workspace_root or DEFAULT_WORKSPACE_ROOT).resolve()
        self.static_dir = (static_dir or self.workspace_root / "apps" / "rule_workbench").resolve()
        self.seed_input_dir = (
            seed_input_dir
            or self.workspace_root / "datasets" / "synthetic" / "rule_review_v1" / "seed_inputs"
        ).resolve()
        self.service = service or RuleWorkbenchService()

    def get_config(self) -> dict[str, Any]:
        """Return the frontend bootstrap config."""
        return {
            "workspace_root": str(self.workspace_root),
            "seed_inputs": self.list_seed_inputs(),
            "languages": ["python"],
            "families": sorted(WORKBENCH_V1_FAMILIES),
            "profiles": sorted(SUPPORTED_PROFILES),
            "defaults": {
                "language": "python",
                "family": "COMMAND_INJECTION",
                "profile": "python-rule-workbench-v1",
                "normalized_format": "json",
                "validation_format": "json",
                "legacy_format": "yaml",
                "provenance_source": "manual-semgrep-fixture",
                "snapshot_version": "local-seed-v1",
            },
        }

    def list_seed_inputs(self) -> list[dict[str, str]]:
        """List reviewable seed fixtures available inside the workspace."""
        if not self.seed_input_dir.exists():
            return []

        seed_inputs = []
        for path in sorted(self.seed_input_dir.rglob("*")):
            if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
                continue
            if not path.is_file():
                continue
            seed_inputs.append(
                {
                    "name": path.name,
                    "path": self.to_workspace_relative(path),
                    "format": path.suffix.lower().lstrip("."),
                }
            )
        return seed_inputs

    def to_workspace_relative(self, path: Path) -> str:
        """Return a stable workspace-relative path with POSIX separators."""
        return path.resolve().relative_to(self.workspace_root).as_posix()

    def resolve_workspace_path(self, raw_path: str, *, must_exist: bool) -> Path:
        """Resolve a user-supplied path and keep it inside the workspace."""
        normalized = (raw_path or "").strip()
        if not normalized:
            raise ValueError("A workspace-relative path is required.")

        candidate = Path(normalized)
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate

        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError as exc:
            raise ValueError("Paths must stay inside the project workspace.") from exc

        if must_exist and not resolved.exists():
            raise FileNotFoundError(f"Path does not exist: {normalized}")
        return resolved

    def default_output_dir_for(self, input_path: Path) -> Path:
        """Return the default review output directory for one seed input."""
        return self.workspace_root / "reports" / "rule_review" / input_path.stem

    def default_draft_output_dir_for(self, input_path: Path) -> Path:
        """Return the default draft output directory for one seed input."""
        return self.workspace_root / "reports" / "rule_review" / f"{input_path.stem}_draft"

    def build_bundle_from_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build one review bundle from a JSON payload sent by the UI."""
        input_path = self.resolve_workspace_path(str(payload.get("input_path", "")), must_exist=True)
        output_dir_value = str(payload.get("output_dir", "")).strip()
        output_dir = self.resolve_workspace_path(output_dir_value, must_exist=False) if output_dir_value else self.default_output_dir_for(input_path)

        request = RuleWorkbenchBundleRequest(
            input_path=input_path,
            output_dir=output_dir,
            language=_none_if_blank(payload.get("language")),
            family=_none_if_blank(payload.get("family")),
            limit=_coerce_int(payload.get("limit")),
            normalized_format=str(payload.get("normalized_format") or "json"),
            validation_format=str(payload.get("validation_format") or "json"),
            profile=str(payload.get("profile") or "generic"),
            provenance_source=str(payload.get("provenance_source") or "semgrep"),
            snapshot_version=str(payload.get("snapshot_version") or "manual-seed-v1"),
            legacy_format=_none_if_blank(payload.get("legacy_format")),
        )

        result = self.service.build_review_bundle(request)
        return {
            "input_path": self.to_workspace_relative(input_path),
            "output_dir": self.to_workspace_relative(output_dir),
            "bundle": {
                "valid": result.valid,
                "rules_checked": result.rules_checked,
                "error_count": result.error_count,
                "warning_count": result.warning_count,
                "artifacts": {
                    "normalized": self.to_workspace_relative(result.paths.normalized_path),
                    "validation": self.to_workspace_relative(result.paths.validation_path),
                    "legacy": (
                        self.to_workspace_relative(result.paths.legacy_path)
                        if result.paths.legacy_path
                        else None
                    ),
                    "legacy_report": (
                        self.to_workspace_relative(result.paths.legacy_report_path)
                        if result.paths.legacy_report_path
                        else None
                    ),
                },
            },
        }

    def build_draft_from_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build one natural-language draft bundle from a JSON payload sent by the UI."""
        description = str(payload.get("description", "")).strip()
        if not description:
            raise ValueError("A natural-language description is required.")

        seed_input_path = self.resolve_workspace_path(
            str(payload.get("seed_input_path", "")),
            must_exist=True,
        )
        output_dir_value = str(payload.get("output_dir", "")).strip()
        output_dir = (
            self.resolve_workspace_path(output_dir_value, must_exist=False)
            if output_dir_value
            else self.default_draft_output_dir_for(seed_input_path)
        )

        request = RuleWorkbenchDraftRequest(
            description=description,
            seed_input_path=seed_input_path,
            output_dir=output_dir,
            language=str(payload.get("language") or "python"),
            family=str(payload.get("family") or "COMMAND_INJECTION"),
            profile=str(payload.get("profile") or "generic"),
            normalized_format=str(payload.get("normalized_format") or "json"),
            validation_format=str(payload.get("validation_format") or "json"),
            provenance_source=str(payload.get("provenance_source") or "ai-adapted"),
            snapshot_version=str(payload.get("snapshot_version") or "draft-v1"),
            legacy_format=_none_if_blank(payload.get("legacy_format")),
            rule_id=_none_if_blank(payload.get("rule_id")),
            title=_none_if_blank(payload.get("title")),
        )
        result = self.service.build_draft_bundle(request).to_mapping()

        return {
            "seed_input_path": self.to_workspace_relative(seed_input_path),
            "output_dir": self.to_workspace_relative(output_dir),
            "draft": {
                "valid": result["valid"],
                "rules_checked": result["rules_checked"],
                "error_count": result["error_count"],
                "warning_count": result["warning_count"],
                "artifacts": {
                    "draft": self.to_workspace_relative(result["draft_path"]),
                    "validation": self.to_workspace_relative(result["validation_path"]),
                    "prompt": self.to_workspace_relative(result["prompt_path"]),
                    "seed_context": self.to_workspace_relative(result["seed_context_path"]),
                    "legacy": (
                        self.to_workspace_relative(result["legacy_path"])
                        if result["legacy_path"]
                        else None
                    ),
                    "legacy_report": (
                        self.to_workspace_relative(result["legacy_report_path"])
                        if result["legacy_report_path"]
                        else None
                    ),
                },
            },
        }

    def read_artifact(self, raw_path: str) -> dict[str, Any]:
        """Load one generated artifact for browser preview."""
        path = self.resolve_workspace_path(raw_path, must_exist=True)
        content = path.read_text(encoding="utf-8", errors="replace")
        truncated = False
        if len(content) > MAX_ARTIFACT_PREVIEW_CHARS:
            content = content[:MAX_ARTIFACT_PREVIEW_CHARS]
            truncated = True
        return {
            "path": self.to_workspace_relative(path),
            "content": content,
            "truncated": truncated,
            "content_type": mimetypes.guess_type(str(path))[0] or "text/plain",
        }

    def make_handler_class(self) -> type[BaseHTTPRequestHandler]:
        """Create a request handler bound to this app instance."""
        app = self

        class RuleWorkbenchHandler(BaseHTTPRequestHandler):
            """HTTP handler serving the minimal rule-workbench UI and API."""

            server_version = "AegisRuleWorkbench/1.0"

            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                parsed = urlparse(self.path)
                if parsed.path == "/api/config":
                    self._send_json(app.get_config())
                    return

                if parsed.path == "/api/artifact":
                    params = parse_qs(parsed.query)
                    artifact_path = params.get("path", [""])[0]
                    try:
                        self._send_json(app.read_artifact(artifact_path))
                    except FileNotFoundError as exc:
                        self._send_error_json(HTTPStatus.NOT_FOUND, str(exc))
                    except ValueError as exc:
                        self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                    return

                self._serve_static(parsed.path)

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                parsed = urlparse(self.path)
                try:
                    payload = self._read_json_body()
                    if parsed.path == "/api/build-review-bundle":
                        self._send_json(app.build_bundle_from_payload(payload))
                        return
                    if parsed.path == "/api/build-draft-bundle":
                        self._send_json(app.build_draft_from_payload(payload))
                        return
                    self._send_error_json(HTTPStatus.NOT_FOUND, "Unknown API route.")
                except FileNotFoundError as exc:
                    self._send_error_json(HTTPStatus.NOT_FOUND, str(exc))
                except ValueError as exc:
                    self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                except Exception as exc:  # pragma: no cover - thin HTTP shell
                    self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - stdlib signature
                """Keep the default server quiet unless a request fails."""
                if len(args) > 1 and isinstance(args[1], str) and args[1].startswith("5"):
                    super().log_message(format, *args)

            def _serve_static(self, raw_path: str) -> None:
                requested = "index.html" if raw_path in {"", "/"} else raw_path.lstrip("/")
                asset_path = (app.static_dir / requested).resolve()

                try:
                    asset_path.relative_to(app.static_dir)
                except ValueError:
                    self._send_error_json(HTTPStatus.BAD_REQUEST, "Static asset path escaped the app directory.")
                    return

                if not asset_path.exists() or not asset_path.is_file():
                    self._send_error_json(HTTPStatus.NOT_FOUND, f"Static asset not found: {requested}")
                    return

                content_type = mimetypes.guess_type(str(asset_path))[0] or "application/octet-stream"
                body = asset_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json_body(self) -> dict[str, Any]:
                content_length = int(self.headers.get("Content-Length", "0"))
                if content_length <= 0:
                    raise ValueError("Expected a JSON request body.")
                raw_body = self.rfile.read(content_length)
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    raise ValueError("Request body must be valid JSON.") from exc
                if not isinstance(payload, dict):
                    raise ValueError("Request body must be a JSON object.")
                return payload

            def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
                body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_error_json(self, status: HTTPStatus, message: str) -> None:
                self._send_json({"error": message, "status": int(status)}, status=status)

        return RuleWorkbenchHandler


def serve_rule_workbench(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    workspace_root: Path | None = None,
) -> None:
    """Run the local workbench development server."""
    app = RuleWorkbenchWebApp(workspace_root=workspace_root)
    server = ThreadingHTTPServer((host, port), app.make_handler_class())
    print(
        "Rule Workbench listening on "
        f"http://{host}:{port} "
        f"(workspace={app.workspace_root})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nRule Workbench stopped.")
    finally:
        server.server_close()


def _coerce_int(value: Any) -> int | None:
    """Convert a form-like value to int or None."""
    if value in {None, ""}:
        return None
    return int(value)


def _none_if_blank(value: Any) -> str | None:
    """Normalize blank form values to None."""
    normalized = str(value).strip() if value is not None else ""
    return normalized or None

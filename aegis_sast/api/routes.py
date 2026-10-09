"""FastAPI endpoints for asynchronous Aegis-SAST scans."""

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from aegis_sast.orchestration import ScanPipelineRequest, ScanPipelineService


class ScanPipelineConfig(BaseModel):
    """Optional scan settings accepted by the REST API."""

    enable_ai_verification: bool = False
    max_analysis_depth: int = Field(default=5, ge=1, le=20)
    rules_path: str | None = None
    append_rules_paths: list[str] = Field(default_factory=list)
    exclude_dir_names: list[str] = Field(
        default_factory=lambda: [
            ".git",
            ".hg",
            ".svn",
            ".venv",
            "venv",
            "env",
            "node_modules",
            "vendor",
            "third_party",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".tox",
            ".nox",
            "dist",
            "build",
            "target",
            "coverage",
            ".cache",
            ".next",
            ".nuxt",
        ]
    )
    exclude_globs: list[str] = Field(default_factory=list)
    scan_engine: str = "semgrep"
    rule_profile: str = "auto"


class ScanPipelineRequestModel(BaseModel):
    """Public request contract for starting a scan."""

    path: str | None = Field(default=None, min_length=1)
    repo_path: str | None = Field(default=None, min_length=1)
    target_path: str | None = Field(default=None, min_length=1)
    language: str | None = None
    config: ScanPipelineConfig = Field(default_factory=ScanPipelineConfig)

    def resolved_path(self) -> str:
        """Accept the names used by both the dashboard and older API clients."""
        value = self.path or self.repo_path or self.target_path
        if not value:
            raise ValueError("path, repo_path, or target_path is required.")
        return value


class ScanJob(BaseModel):
    """Serializable state shared by status and results endpoints."""

    scan_id: str
    status: str
    progress: list[dict[str, Any]] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: str
    finished_at: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DispositionPayload(BaseModel):
    """Payload for persisting reviewer disposition on a finding."""

    disposition: str
    note: str | None = None
    reviewer: str = "security-engineer"


class ScanJobStore:
    """Thread-safe persistent job store for scans."""

    def __init__(self, storage_dir: Path = Path("reports/scans")) -> None:
        self.jobs: dict[str, ScanJob] = {}
        self.storage_dir = storage_dir
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aegis-scan")
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            for file_path in self.storage_dir.glob("*.json"):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    job = ScanJob.model_validate(data)
                    self.jobs[job.scan_id] = job
                except Exception:
                    continue
        except Exception:
            pass

    def _save_to_disk(self, job: ScanJob) -> None:
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            file_path = self.storage_dir / f"{job.scan_id}.json"
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(job.model_dump(), f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def create(self, payload: ScanPipelineRequestModel) -> ScanJob:
        scan_id = str(uuid.uuid4())
        job = ScanJob(
            scan_id=scan_id,
            status="queued",
            started_at=_now(),
            progress=[{"event": "stage", "stage": "queued", "message": "Scan queued."}],
        )
        with self.lock:
            self.jobs[scan_id] = job
            self._save_to_disk(job)
        self.executor.submit(self._run, scan_id, payload)
        return job

    def get(self, scan_id: str) -> ScanJob | None:
        with self.lock:
            return self.jobs.get(scan_id)

    def list_all(self) -> list[ScanJob]:
        with self.lock:
            return sorted(self.jobs.values(), key=lambda j: j.started_at, reverse=True)

    def _append_progress(self, scan_id: str, event: dict[str, Any]) -> None:
        with self.lock:
            job = self.jobs.get(scan_id)
            if job:
                job.progress.append(event)

    def _run(self, scan_id: str, payload: ScanPipelineRequestModel) -> None:
        with self.lock:
            job = self.jobs[scan_id]
            job.status = "running"
            self._save_to_disk(job)
        try:
            target = Path(payload.resolved_path()).expanduser().resolve()
            if not target.exists():
                raise FileNotFoundError(f"Target path does not exist: {target}")

            config = payload.config
            reports_dir = Path("reports")
            request = ScanPipelineRequest(
                target_path=target,
                rules_path=(
                    Path(config.rules_path).expanduser().resolve()
                    if config.rules_path
                    else None
                ),
                append_rules_paths=[
                    Path(path).expanduser().resolve()
                    for path in config.append_rules_paths
                    if isinstance(path, str) and path.strip()
                ],
                enable_ai_verification=config.enable_ai_verification,
                max_analysis_depth=config.max_analysis_depth,
                exclude_dir_names=config.exclude_dir_names,
                exclude_globs=config.exclude_globs,
                output_formats=["json", "sarif", "markdown"],
                export_reports=True,
                output_dir=reports_dir,
                scan_engine=config.scan_engine,
                rule_profile=config.rule_profile,
            )
            service = ScanPipelineService()
            result = service.run(
                request,
                progress_callback=lambda event: self._append_progress(scan_id, event),
            )
            findings = [
                vulnerability.to_normalized_finding().to_dict()
                for vulnerability in result.scan_result.vulnerabilities
            ]
            triage_records = [record.to_dict() for record in result.triage_records]
            if triage_records:
                findings = [
                    record["finding"]
                    for record in triage_records
                    if isinstance(record.get("finding"), dict)
                ]
            evidence_bundles = [
                finding["evidence"]
                for finding in findings
                if isinstance(finding.get("evidence"), dict)
            ]
            exported_reports = {
                fmt: str(path) for fmt, path in result.exported_reports.items()
            }
            with self.lock:
                job = self.jobs[scan_id]
                job.status = "completed"
                job.finished_at = _now()
                job.result = {
                    "scan_id": scan_id,
                    "summary": result.scan_result.get_summary(),
                    "repo_profile": result.repo_profile.to_dict(),
                    "findings": findings,
                    "evidence_bundles": evidence_bundles,
                    "triage_records": triage_records,
                    "workflow_metadata": result.workflow_metadata,
                    "exported_reports": exported_reports,
                    "ai": {
                        "requested": result.ai_requested,
                        "enabled": result.ai_enabled,
                        "error": result.ai_error,
                    },
                }
                self._save_to_disk(job)
        except Exception as exc:
            with self.lock:
                job = self.jobs[scan_id]
                job.status = "failed"
                job.finished_at = _now()
                job.error = str(exc)
                self._save_to_disk(job)


store = ScanJobStore()
router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.post("/scan", response_model=ScanJob, status_code=202)
def start_scan(payload: ScanPipelineRequestModel) -> ScanJob:
    """Start a scan and return its identifier for status polling."""
    return store.create(payload)


@router.get("/scans", response_model=list[ScanJob])
def list_scans() -> list[ScanJob]:
    """Return all past scan jobs ordered by start date."""
    return store.list_all()


@router.get("/scan/{scan_id}/status", response_model=ScanJob)
def scan_status(scan_id: str) -> ScanJob:
    """Return progress events collected for a scan."""
    job = store.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return job


@router.get("/scan/{scan_id}/results")
def scan_results(scan_id: str) -> dict[str, Any]:
    """Return normalized findings, evidence bundles, and triage records."""
    job = store.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if job.status == "failed":
        raise HTTPException(status_code=422, detail=job.error or "Scan failed.")
    if job.status != "completed" or job.result is None:
        raise HTTPException(status_code=409, detail="Scan is not complete.")
    return job.result


@router.get("/scan/{scan_id}/export/sarif")
def export_sarif(scan_id: str) -> Response:
    """Download scan findings as a standardized SARIF v2.1.0 document."""
    job = store.get(scan_id)
    if job is None or not job.result:
        raise HTTPException(status_code=404, detail="Scan or results not found.")

    exported = job.result.get("exported_reports", {})
    sarif_path_str = exported.get("sarif")
    if sarif_path_str and Path(sarif_path_str).exists():
        content = Path(sarif_path_str).read_text(encoding="utf-8")
    else:
        # Generate on the fly
        from aegis_sast.integrations.sarif_formatter import SARIFFormatter
        from aegis_sast.core.models import ScanResult
        formatter = SARIFFormatter(output_dir=Path("reports"))
        scan_result = ScanResult(
            target_path=job.result.get("repo_profile", {}).get("target_path", "unknown"),
            vulnerabilities=[],
        )
        report_data = formatter._build_report(scan_result, None, job.result.get("workflow_metadata"))
        content = json.dumps(report_data, indent=2, ensure_ascii=False)

    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="aegis-scan-{scan_id}.sarif"'
        },
    )


@router.get("/scan/{scan_id}/export/markdown")
def export_markdown(scan_id: str) -> Response:
    """Download scan findings as a human-readable Markdown report."""
    job = store.get(scan_id)
    if job is None or not job.result:
        raise HTTPException(status_code=404, detail="Scan or results not found.")

    exported = job.result.get("exported_reports", {})
    md_path_str = exported.get("markdown")
    if md_path_str and Path(md_path_str).exists():
        content = Path(md_path_str).read_text(encoding="utf-8")
    else:
        findings = job.result.get("findings", [])
        content = f"# Aegis-SAST Scan Report\n\n**Scan ID**: `{scan_id}`\n**Findings**: {len(findings)}\n"

    return Response(
        content=content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="aegis-scan-{scan_id}.md"'
        },
    )


@router.get("/scan/{scan_id}/export/patch")
def export_patch(scan_id: str) -> Response:
    """Export all AI-generated Unified Diff remediation patches as a single .patch file."""
    job = store.get(scan_id)
    if job is None or not job.result:
        raise HTTPException(status_code=404, detail="Scan or results not found.")

    findings = job.result.get("findings", [])
    patches = []
    for idx, f in enumerate(findings, 1):
        meta = f.get("metadata") or {}
        patch = meta.get("remediation_patch") or meta.get("triage", {}).get("remediation_patch")
        if patch and isinstance(patch, dict) and patch.get("unified_diff"):
            title = f.get("title") or f.get("rule_id") or "Vulnerability"
            patches.append(
                f"# ========================================================\n"
                f"# Patch {idx}: {title} [{f.get('severity', 'UNKNOWN')}]\n"
                f"# File: {patch.get('file_path', 'unknown')}\n"
                f"# Explanation: {patch.get('explanation', '')}\n"
                f"# ========================================================\n"
                f"{patch['unified_diff']}\n"
            )

    combined_patch = "\n".join(patches) if patches else "# No remediation patches available for this scan.\n"

    return Response(
        content=combined_patch,
        media_type="text/x-diff",
        headers={
            "Content-Disposition": f'attachment; filename="aegis-remediation-{scan_id}.patch"'
        },
    )


@router.post("/findings/{fingerprint}/disposition")
def update_finding_disposition(fingerprint: str, payload: DispositionPayload) -> dict[str, str]:
    """Persist human-in-the-loop reviewer disposition to disk."""
    memory_file = Path("reports/reviewer_memory.json")
    memory_file.parent.mkdir(parents=True, exist_ok=True)
    memory = {}
    if memory_file.exists():
        try:
            with open(memory_file, "r", encoding="utf-8") as f:
                memory = json.load(f)
        except Exception:
            memory = {}

    memory[fingerprint] = {
        "disposition": payload.disposition,
        "note": payload.note,
        "reviewer": payload.reviewer,
        "updated_at": _now(),
    }

    with open(memory_file, "w", encoding="utf-8") as f:
        json.dump(memory, f, indent=2, ensure_ascii=False)

    return {"status": "ok", "fingerprint": fingerprint, "disposition": payload.disposition}


@router.get("/reviewer-memory")
def get_reviewer_memory() -> dict[str, Any]:
    """Retrieve all persisted reviewer feedback memory."""
    memory_file = Path("reports/reviewer_memory.json")
    if not memory_file.exists():
        return {}
    try:
        with open(memory_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


app = FastAPI(title="Aegis-SAST API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)


@app.get("/api/health")
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "aegis-sast", "version": "1.0.0"}

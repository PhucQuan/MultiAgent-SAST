"""FastAPI endpoints for asynchronous Aegis-SAST scans."""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from aegis_sast.orchestration import ScanPipelineRequest, ScanPipelineService


class ScanPipelineConfig(BaseModel):
    """Optional scan settings accepted by the REST API."""

    enable_ai_verification: bool = False
    max_analysis_depth: int = Field(default=5, ge=1, le=20)
    rules_path: str | None = None
    exclude_dir_names: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)
    scan_engine: str = "semgrep"


class ScanPipelineRequestModel(BaseModel):
    """Public request contract for starting a scan."""

    path: str = Field(min_length=1)
    config: ScanPipelineConfig = Field(default_factory=ScanPipelineConfig)


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


class ScanJobStore:
    """Thread-safe in-memory job store for the local development API."""

    def __init__(self) -> None:
        self.jobs: dict[str, ScanJob] = {}
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aegis-scan")

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
        self.executor.submit(self._run, scan_id, payload)
        return job

    def get(self, scan_id: str) -> ScanJob | None:
        with self.lock:
            return self.jobs.get(scan_id)

    def _append_progress(self, scan_id: str, event: dict[str, Any]) -> None:
        with self.lock:
            job = self.jobs[scan_id]
            job.progress.append(event)

    def _run(self, scan_id: str, payload: ScanPipelineRequestModel) -> None:
        with self.lock:
            self.jobs[scan_id].status = "running"
        try:
            target = Path(payload.path).expanduser().resolve()
            if not target.exists():
                raise FileNotFoundError(f"Target path does not exist: {payload.path}")

            config = payload.config
            request = ScanPipelineRequest(
                target_path=target,
                rules_path=(
                    Path(config.rules_path).expanduser().resolve()
                    if config.rules_path
                    else None
                ),
                enable_ai_verification=config.enable_ai_verification,
                max_analysis_depth=config.max_analysis_depth,
                exclude_dir_names=config.exclude_dir_names,
                exclude_globs=config.exclude_globs,
                output_formats=[],
                export_reports=False,
                scan_engine=config.scan_engine,
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
                    "ai": {
                        "requested": result.ai_requested,
                        "enabled": result.ai_enabled,
                        "error": result.ai_error,
                    },
                }
        except Exception as exc:
            with self.lock:
                job = self.jobs[scan_id]
                job.status = "failed"
                job.finished_at = _now()
                job.error = str(exc)


store = ScanJobStore()
router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.post("/scan", response_model=ScanJob, status_code=202)
def start_scan(payload: ScanPipelineRequestModel) -> ScanJob:
    """Start a scan and return its identifier for status polling."""
    return store.create(payload)


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

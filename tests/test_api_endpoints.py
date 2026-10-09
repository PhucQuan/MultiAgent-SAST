"""Tests for FastAPI scan routes, persistent storage, and export endpoints."""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from aegis_sast.api.routes import app, store


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_list_scans_returns_list(client):
    response = client.get("/api/v1/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_scan_not_found_returns_404(client):
    response = client.get("/api/v1/scan/nonexistent-id/status")
    assert response.status_code == 404


def test_reviewer_memory_endpoint(client):
    # Set disposition
    resp = client.post(
        "/api/v1/findings/test-fingerprint-123/disposition",
        json={
            "disposition": "false-positive",
            "note": "Sanitized upstream by middleware",
            "reviewer": "auditor-alice",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["disposition"] == "false-positive"

    # Get memory
    mem_resp = client.get("/api/v1/reviewer-memory")
    assert mem_resp.status_code == 200
    data = mem_resp.json()
    assert "test-fingerprint-123" in data
    assert data["test-fingerprint-123"]["disposition"] == "false-positive"

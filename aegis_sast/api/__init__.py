"""HTTP API for running and inspecting Aegis-SAST scans."""

from aegis_sast.api.routes import app

__all__ = ["app"]

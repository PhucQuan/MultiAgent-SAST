"""ASGI entrypoint for the Aegis-SAST REST API.

Run with: uvicorn main:app --reload --port 8000
"""

from aegis_sast.api.routes import app

__all__ = ["app"]

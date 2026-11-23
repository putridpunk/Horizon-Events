"""Optionally serve the built frontend from the API process (used by the standalone executable)."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


def mount_frontend(app: FastAPI, directory: Path) -> None:
    """Serve `directory` (a Vite build) at `/`, falling back to index.html for client-side routes.

    Call after the API routers are registered so `/api/*` keeps priority.
    """
    directory = Path(directory).resolve()
    index = directory / "index.html"
    if not index.is_file():
        raise FileNotFoundError(f"Frontend build not found at {directory}")
    app.mount("/assets", StaticFiles(directory=directory / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "Not found")
        candidate = (directory / path).resolve()
        if path and candidate.is_file() and directory in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(index)

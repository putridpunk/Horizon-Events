"""FastAPI application entry point."""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.api import alerts, events, imports, intel, mitre, ml, reports, rules, statistics, watcher
from app.config import get_settings
from app.database.connection import get_engine, init_db
from app.services.ingestion import ensure_default_rules
from app.watcher.service import WatchService


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with Session(get_engine()) as session:
        ensure_default_rules(session)
        session.commit()
    watch_dir = os.environ.get("HORIZON_WATCH_DIR")
    app.state.watcher = None
    if watch_dir:  # live monitoring is opt-in: only when a watch folder is configured
        app.state.watcher = WatchService(Path(watch_dir), lambda: Session(get_engine(), expire_on_commit=False))
        app.state.watcher.start()
    try:
        yield
    finally:
        if app.state.watcher:
            app.state.watcher.stop()


app = FastAPI(title="Horizon Events", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(get_settings().cors_origins),
                   allow_methods=["*"], allow_headers=["*"])
for module in (imports, events, alerts, statistics, rules, reports, ml, mitre, watcher, intel):
    app.include_router(module.router)


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok"}

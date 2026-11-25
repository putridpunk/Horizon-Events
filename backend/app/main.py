"""FastAPI application entry point."""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.api import (alerts, collectors, events, imports, incidents, intel, mitigation, mitre, ml, reports, rules,
                     scans, statistics, suppressions, watcher)
from app.api import data as data_api
from app.api import desktop_settings
from app.shell.settings import ShellSettings
from app.data.service import DataService
from app.config import get_settings
from app.database.connection import get_engine, init_db
from app.database.incident_repository import IncidentRepository
from app.desktop import SessionGuard
from app.security import LocalRequestGuard
from app.incidents.manager import IncidentManager
from app.services.ingestion import ensure_default_rules
from app.system.manager import CollectorManager
from app.mitigation.service import MitigationService
from app.scanning.downloads import DownloadsWatcher
from app.scanning.service import ScanService
from app.system.registry import build_collectors
from app.watcher.service import WatchService


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with Session(get_engine()) as session:
        ensure_default_rules(session)
        IncidentManager(IncidentRepository(session)).backfill()  # group alerts that predate incidents
        session.commit()
    watch_dir = os.environ.get("HORIZON_WATCH_DIR")
    app.state.watcher = None
    if watch_dir:  # live monitoring is opt-in: only when a watch folder is configured
        app.state.watcher = WatchService(Path(watch_dir), lambda: Session(get_engine(), expire_on_commit=False))
        app.state.watcher.start()
    app.state.collectors = None
    if os.environ.get("HORIZON_SYSTEM_LOGS") == "1":  # the desktop app turns this on; server mode stays off
        app.state.collectors = CollectorManager(
            build_collectors(), lambda: Session(get_engine(), expire_on_commit=False))
        app.state.collectors.start()
    data_dir = os.environ.get("HORIZON_DATA_DIR")  # set by the desktop app; enables backup and restore
    app.state.data = DataService(lambda: Session(get_engine(), expire_on_commit=False), get_engine(),
                                 Path(data_dir) if data_dir else None)
    app.state.data.start()
    app.state.shell = None
    if os.environ.get("HORIZON_DESKTOP") == "1":  # the desktop app turns this on: tray, notifications, auto-start
        import sys
        app.state.shell = ShellSettings(lambda: Session(get_engine(), expire_on_commit=False), sys.executable)
    app.state.mitigation = None
    if os.environ.get("HORIZON_MITIGATION") == "1":  # the desktop app turns this on: actions change this PC
        quarantine_dir = Path(os.environ.get("HORIZON_QUARANTINE_DIR", "quarantine"))
        app.state.mitigation = MitigationService(lambda: Session(get_engine(), expire_on_commit=False), quarantine_dir)
    app.state.scans = None
    if os.environ.get("HORIZON_FILE_SCAN") == "1":  # the desktop app turns this on; server mode cannot see your files
        app.state.scans = ScanService(lambda: Session(get_engine(), expire_on_commit=False),
                                      mitigation=app.state.mitigation)
    app.state.downloads = None
    if app.state.scans is not None:  # new files in the Downloads folder can be scanned (opt-in, off by default)
        app.state.downloads = DownloadsWatcher(lambda: Session(get_engine(), expire_on_commit=False), app.state.scans)
        app.state.downloads.start()
    try:
        yield
    finally:
        app.state.data.stop()
        if app.state.downloads:
            app.state.downloads.stop()
        if app.state.watcher:
            app.state.watcher.stop()
        if app.state.collectors:
            app.state.collectors.stop()


app = FastAPI(title="Horizon Events", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(get_settings().cors_origins),
                   allow_methods=["*"], allow_headers=["*"])
app.add_middleware(LocalRequestGuard)  # checks Host and Origin
app.add_middleware(SessionGuard)  # outermost: desktop mode only (needs HORIZON_SESSION_SECRET)
for module in (imports, events, alerts, statistics, rules, reports, ml, mitre, watcher, intel, incidents,
               collectors, scans, mitigation, suppressions, data_api, desktop_settings):
    app.include_router(module.router)


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok"}

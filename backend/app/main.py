"""FastAPI application entry point."""
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.api import (alerts, collectors, events, imports, incidents, intel, mitigation, mitre, ml, notifications,
                     auth, geoip, report_schedules, reports, rules, scans, statistics, stream, suppressions, syslog, update, watcher)
from app.api import data as data_api
from app.api import desktop_settings
from app.shell.settings import ShellSettings
from app.data.service import DataService
from app.config import get_settings
from app.database.connection import get_engine, init_db
from app.database.incident_repository import IncidentRepository
from app.auth import service as auth_service
from app.auth.guard import AuthGuard
from app.desktop import SessionGuard
from app.update.check import AutoChecker
from app.version import __version__
from app.geo import settings as geo_settings
from app.security import LocalRequestGuard
from app.incidents.manager import IncidentManager
from app.services.ingestion import ensure_default_rules
from app.system.manager import CollectorManager
from app.mitigation.service import MitigationService
from app.scanning.downloads import DownloadsWatcher
from app.scanning.service import ScanService
from app.reports.scheduler import ReportScheduler
from app.syslog.receiver import SyslogReceiver
from app.system.registry import build_collectors
from app.watcher.service import WatchService


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with Session(get_engine()) as session:
        ensure_default_rules(session)
        IncidentManager(IncidentRepository(session)).backfill()  # group alerts that predate incidents
        session.commit()
        app.state.geo_error = geo_settings.load_on_start(session)  # optional location database
        app.state.setup_token = None
        if auth_service.enabled():  # sign-in is on: the first administrator comes from the environment or a one-time code
            if not auth_service.bootstrap_from_environment(session) and auth_service.user_count(session) == 0:
                app.state.setup_token = secrets.token_urlsafe(9)
                logging.getLogger("uvicorn.error").warning(
                    "Sign-in is on and has no users yet. Open the app and create the first administrator with the "
                    "setup code: %s", app.state.setup_token)
    watch_dir = os.environ.get("HORIZON_WATCH_DIR")
    app.state.watcher = None
    if watch_dir:  # live monitoring is opt-in: only when a watch folder is configured
        app.state.watcher = WatchService(Path(watch_dir), lambda: Session(get_engine(), expire_on_commit=False))
        app.state.watcher.start()
    app.state.syslog = None
    syslog_port = os.environ.get("HORIZON_SYSLOG_PORT", "").strip()
    if syslog_port:  # off unless asked for: it opens a network port
        try:
            app.state.syslog = SyslogReceiver(lambda: Session(get_engine(), expire_on_commit=False),
                                              os.environ.get("HORIZON_SYSLOG_BIND", "127.0.0.1"), int(syslog_port))
            app.state.syslog.start()
        except (OSError, ValueError) as exc:  # a busy or invalid port must not stop the app
            logging.getLogger(__name__).error("syslog receiver not started: %s", exc)
            app.state.syslog = None
    app.state.collectors = None
    if os.environ.get("HORIZON_SYSTEM_LOGS") == "1":  # the desktop app turns this on; server mode stays off
        app.state.collectors = CollectorManager(
            build_collectors(), lambda: Session(get_engine(), expire_on_commit=False))
        app.state.collectors.start()
    data_dir = os.environ.get("HORIZON_DATA_DIR")  # set by the desktop app; enables backup and restore
    app.state.data = DataService(lambda: Session(get_engine(), expire_on_commit=False), get_engine(),
                                 Path(data_dir) if data_dir else None)
    app.state.data.start()
    app.state.report_dir = os.environ.get("HORIZON_REPORT_DIR") or str(Path(data_dir or ".") / "reports")
    app.state.reports = ReportScheduler(lambda: Session(get_engine(), expire_on_commit=False),
                                        Path(app.state.report_dir))
    app.state.reports.start()
    app.state.updates = AutoChecker(lambda: Session(get_engine(), expire_on_commit=False))
    app.state.updates.start()
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
        app.state.reports.stop()
        app.state.updates.stop()
        if app.state.syslog:
            app.state.syslog.stop()
        if app.state.downloads:
            app.state.downloads.stop()
        if app.state.watcher:
            app.state.watcher.stop()
        if app.state.collectors:
            app.state.collectors.stop()


app = FastAPI(title="Horizon Events", version=__version__, lifespan=lifespan)
app.add_middleware(AuthGuard)  # innermost: checks the sign-in cookie after the host and origin checks
app.add_middleware(CORSMiddleware, allow_origins=list(get_settings().cors_origins),
                   allow_methods=["*"], allow_headers=["*"])
app.add_middleware(LocalRequestGuard)  # checks Host and Origin
app.add_middleware(SessionGuard)  # outermost: desktop mode only (needs HORIZON_SESSION_SECRET)
for module in (imports, events, alerts, statistics, rules, reports, ml, mitre, watcher, intel, incidents,
               collectors, scans, mitigation, suppressions, data_api, desktop_settings, notifications, report_schedules, stream, syslog, geoip, auth, update):
    app.include_router(module.router)
app.include_router(events.searches)


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok"}

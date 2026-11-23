"""Standalone launcher: serves API + dashboard on localhost and opens the browser.

Used as the PyInstaller entry point, but also runnable directly: `python run_app.py`.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import webbrowser
from pathlib import Path

BUNDLE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))


def _data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    path = Path(base) / "HorizonEvents"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _free_port(preferred: int = 8000) -> int:
    for port in (preferred, 0):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("No free port available")


def main() -> None:
    db_file = _data_dir() / "horizon.db"
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")

    import uvicorn
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from app.database.connection import get_engine, init_db
    from app.database.models import EventRow
    from app.main import app
    from app.seed import seed
    from app.web import mount_frontend

    init_db()
    samples = BUNDLE / "sample_logs"
    if samples.is_dir() and os.environ.get("HORIZON_SEED", "true").lower() == "true":
        with Session(get_engine(), expire_on_commit=False) as session:
            if not session.scalar(select(func.count(EventRow.id))):
                seed(session, samples)
                print("Imported the bundled sample logs.")
    mount_frontend(app, BUNDLE / "static")

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    print(f"Horizon Events running at {url}\nData: {db_file}\nPress Ctrl+C or close this window to stop.")
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()

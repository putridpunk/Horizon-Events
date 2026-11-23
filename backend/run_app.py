"""Horizon Events desktop launcher: runs the API on localhost and shows it in a native window.

Used as the PyInstaller entry point, and runnable directly with `python run_app.py` (needs
`requirements-desktop.txt`). For server or development use, run `uvicorn app.main:app` instead.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path

BUNDLE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
WEBVIEW2_URL = "https://developer.microsoft.com/microsoft-edge/webview2/"
TITLE = "Horizon Events"


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    path = Path(base) / "HorizonEvents"
    path.mkdir(parents=True, exist_ok=True)
    return path


def message_box(text: str, title: str = TITLE) -> None:
    """Show a native message (the app has no console). Falls back to stderr off Windows."""
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x10)  # MB_ICONERROR
    else:
        print(f"{title}: {text}", file=sys.stderr)


def focus_existing_window() -> bool:
    """Bring the already-running window to the front (Windows). Returns False if there is none to show."""
    if sys.platform != "win32":
        return False
    import ctypes
    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW(None, TITLE)
    if not hwnd:
        return False
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
    user32.SetForegroundWindow(hwnd)
    return True


def _configure_logging(data: Path) -> None:
    # A windowed executable has no stdout/stderr; anything that writes to them would crash.
    for stream in ("stdout", "stderr"):
        if getattr(sys, stream) is None:
            setattr(sys, stream, open(os.devnull, "w"))
    logging.basicConfig(filename=data / "desktop.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _run(data: Path) -> int:
    from app.desktop import make_secret, pick_free_port, wait_until_ready

    os.environ.setdefault("DATABASE_URL", f"sqlite:///{(data / 'horizon.db').as_posix()}")
    os.environ.setdefault("HORIZON_MODEL_PATH", str(data / "horizon_model.joblib"))
    os.environ.setdefault("HORIZON_WATCH_DIR", str(data / "watch"))
    secret = make_secret()
    os.environ["HORIZON_SESSION_SECRET"] = secret

    try:
        import webview
    except Exception:  # pragma: no cover - depends on the packaged environment
        logging.exception("pywebview could not be imported")
        message_box("The native window component is missing from this installation.")
        return 1

    import uvicorn
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from app.database.connection import get_engine, init_db
    from app.database.models import EventRow
    from app.intel.service import ensure_demo_feed
    from app.main import app
    from app.ml.service import ensure_model
    from app.seed import seed
    from app.web import mount_frontend

    init_db()
    ensure_model()
    samples = BUNDLE / "sample_logs"
    # Sample data is opt-in: a real monitor should not start with invented alerts.
    if samples.is_dir() and os.environ.get("HORIZON_SEED", "false").lower() == "true":
        with Session(get_engine(), expire_on_commit=False) as session:
            if not session.scalar(select(func.count(EventRow.id))):
                ensure_demo_feed(session)
                seed(session, samples)
    mount_frontend(app, BUNDLE / "static")

    port = pick_free_port()
    # access_log=False: the first request carries the session secret in its query string and must not be logged.
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, access_log=False))
    thread = threading.Thread(target=server.run, name="horizon-server", daemon=True)
    thread.start()
    if not wait_until_ready(f"http://127.0.0.1:{port}/api/health", timeout=30):
        logging.error("the local server did not start")
        message_box("The local server did not start. See desktop.log in the Horizon Events data folder.")
        return 1
    logging.info("serving on 127.0.0.1:%s", port)

    webview.create_window(TITLE, f"http://127.0.0.1:{port}/?hz={secret}", width=1360, height=860,
                          min_size=(1100, 700))
    try:
        webview.start(storage_path=str(data / "webview"), private_mode=False)
    except Exception:
        logging.exception("the native window could not start")
        message_box("The native window could not start. Horizon Events needs the Microsoft Edge WebView2 "
                    f"runtime.\n\nInstall it from:\n{WEBVIEW2_URL}")
        server.should_exit = True
        return 1
    server.should_exit = True  # the window was closed: stop the server and exit
    thread.join(timeout=10)
    return 0


def main() -> int:
    data = data_dir()
    _configure_logging(data)
    from app.desktop import SingleInstance
    lock = SingleInstance(data / "app.lock")
    if not lock.acquire():
        # Already running: show that window instead of starting a second collector. If it is still
        # starting up and has no window yet, say so.
        if not focus_existing_window():
            message_box("Horizon Events is already running.")
        return 0
    try:
        return _run(data)
    except Exception as exc:  # no console in the windowed build: make the failure visible
        logging.exception("Horizon Events failed to start")
        message_box(f"Horizon Events could not start.\n\n{type(exc).__name__}: {exc}\n\n"
                    f"Details: {data / 'desktop.log'}")
        return 1
    finally:
        lock.release()


if __name__ == "__main__":
    sys.exit(main())

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
    if not user32.IsWindowVisible(hwnd):
        user32.ShowWindow(hwnd, 5)  # SW_SHOW: it was hidden in the tray
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


class FilePicker:
    """The native Windows file and folder pickers, exposed to the page as `window.pywebview.api`. They only return
    the chosen paths: the page cannot read or list anything itself."""

    def __init__(self, webview_module):
        self._webview = webview_module
        self._window = None

    def _dialog(self, kind):
        dialog = getattr(self._webview, "FileDialog", None)
        legacy = {"OPEN": "OPEN_DIALOG", "FOLDER": "FOLDER_DIALOG", "SAVE": "SAVE_DIALOG"}[kind]
        return getattr(dialog, kind) if dialog else getattr(self._webview, legacy)

    def _open(self, kind, **options):
        if self._window is None:
            return []
        mode = self._dialog(kind)
        chosen = self._window.create_file_dialog(mode, **options)
        return [str(p) for p in chosen] if chosen else []

    def pick_save_file(self, suggested_name="backup.hzbackup"):
        chosen = self._window.create_file_dialog(self._dialog("SAVE"), save_filename=str(suggested_name)) if self._window else None
        return str(chosen[0] if isinstance(chosen, (list, tuple)) else chosen) if chosen else ""

    def pick_file(self):
        picked = self._open("OPEN")
        return picked[0] if picked else ""

    def pick_files(self):
        return self._open("OPEN", allow_multiple=True)

    def pick_folder(self):
        return self._open("FOLDER")


def _setup_tray(window, app, get_engine, bundle: Path):
    """Tray icon, background mode and notifications. Returns the notifier (or None if there is no tray)."""
    from sqlalchemy.orm import Session

    from app.shell.notifier import AlertNotifier
    from app.shell.tray import Tray

    state = {"quitting": False}

    def open_window():
        window.show()
        window.restore()

    def quit_app():
        state["quitting"] = True
        window.destroy()

    tray = Tray(TITLE, bundle / "assets" / "horizon.ico", open_window, quit_app)
    if not tray.start():
        return None
    shell = getattr(app.state, "shell", None)

    def on_closing():
        # With "keep running in the background" the close button hides the window; Quit in the tray really quits.
        if state["quitting"] or shell is None or not shell.keeps_running_in_background():
            return True
        window.hide()
        return False

    window.events.closing += on_closing
    window.events.closed += tray.stop
    notifier = AlertNotifier(lambda: Session(get_engine(), expire_on_commit=False), tray.notify)
    notifier.start()
    return notifier


def _run(data: Path) -> int:
    from app.desktop import make_secret, remembered_port, wait_until_ready

    os.environ.setdefault("DATABASE_URL", f"sqlite:///{(data / 'horizon.db').as_posix()}")
    os.environ.setdefault("HORIZON_MODEL_PATH", str(data / "horizon_model.joblib"))
    os.environ.setdefault("HORIZON_WATCH_DIR", str(data / "watch"))
    os.environ.setdefault("HORIZON_SYSTEM_LOGS", "1")  # collect this machine's own logs
    os.environ.setdefault("HORIZON_DESKTOP", "1")  # tray, notifications and starting with Windows
    os.environ.setdefault("HORIZON_DATA_DIR", str(data))  # backup and restore of the built-in database
    os.environ.setdefault("HORIZON_FILE_SCAN", "1")  # let the user scan files and folders
    os.environ.setdefault("HORIZON_MITIGATION", "1")  # let the user approve actions on alerts
    os.environ.setdefault("HORIZON_QUARANTINE_DIR", str(data / "quarantine"))
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

    from app.data.service import apply_pending_restore

    if apply_pending_restore(data, data / "horizon.db"):  # a backup the user chose to restore last time
        logging.info("a backup was restored; the previous database was kept as horizon.db.before-restore")
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

    port = remembered_port(data / "port")
    # access_log=False: the first request carries the session secret in its query string and must not be logged.
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, access_log=False))
    thread = threading.Thread(target=server.run, name="horizon-server", daemon=True)
    thread.start()
    if not wait_until_ready(f"http://127.0.0.1:{port}/api/health", timeout=30):
        logging.error("the local server did not start")
        message_box("The local server did not start. See desktop.log in the Horizon Events data folder.")
        return 1
    logging.info("serving on 127.0.0.1:%s", port)

    picker = FilePicker(webview)
    window = webview.create_window(TITLE, f"http://127.0.0.1:{port}/?hz={secret}", width=1360, height=860,
                                   min_size=(1100, 700), js_api=picker, hidden="--background" in sys.argv)
    picker._window = window
    notifier = _setup_tray(window, app, get_engine, BUNDLE)
    try:
        webview.start(storage_path=str(data / "webview"), private_mode=False)
    except Exception:
        logging.exception("the native window could not start")
        message_box("The native window could not start. Horizon Events needs the Microsoft Edge WebView2 "
                    f"runtime.\n\nInstall it from:\n{WEBVIEW2_URL}")
        server.should_exit = True
        return 1
    if notifier:
        notifier.stop()
    server.should_exit = True  # the window was closed: stop the server and exit
    thread.join(timeout=10)
    return 0


def main() -> int:
    if "--uninstall-cleanup" in sys.argv:  # run by the uninstaller after it has checked that no copy is running
        from app.uninstall import cleanup

        return cleanup()
    data = data_dir()
    _configure_logging(data)
    from app.desktop import SingleInstance
    lock = SingleInstance(data / "app.lock")
    if not lock.acquire():
        # Already running: show that window instead of starting a second collector. If it is still
        # starting up and has no window yet, say so.
        if "--background" in sys.argv:  # started by Windows at sign-in while already running: nothing to show
            return 0
        if not focus_existing_window():
            message_box("Horizon Events is already running.")
        return 0
    try:
        from app.uninstall import hold_running_mutex

        hold_running_mutex()  # lets the uninstaller see that the app is open
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

"""Settings for how the desktop app behaves around its window: keep running in the tray, notifications, auto-start."""
from __future__ import annotations

import json
from typing import Callable

from sqlalchemy.orm import Session

from app.database.collector_models import get_setting, set_setting
from app.shell import autostart

SETTING_KEY = "desktop"
NOTIFY_LEVELS = ("critical", "high", "off")
DEFAULTS = {"run_in_background": False, "notify": "critical"}


class ShellError(ValueError):
    """A request that cannot be accepted; the message is shown to the user."""


def load(session: Session) -> dict:
    try:
        stored = json.loads(get_setting(session, SETTING_KEY, "{}") or "{}")
    except ValueError:
        stored = {}
    out = dict(DEFAULTS)
    if isinstance(stored.get("run_in_background"), bool):
        out["run_in_background"] = stored["run_in_background"]
    if stored.get("notify") in NOTIFY_LEVELS:
        out["notify"] = stored["notify"]
    return out


class ShellSettings:
    def __init__(self, session_factory: Callable[[], Session], exe_path: str | None = None, registry=None,
                 frozen: bool | None = None):
        self.session_factory, self.exe_path, self.registry, self.frozen = session_factory, exe_path, registry, frozen

    def get(self) -> dict:
        with self.session_factory() as session:
            cfg = load(session)
        return {**cfg, "start_with_windows": autostart.is_enabled(self.exe_path, self.registry)}

    def update(self, run_in_background=None, notify=None, start_with_windows=None) -> dict:
        if notify is not None and notify not in NOTIFY_LEVELS:
            raise ShellError("Notifications can be critical, high or off.")
        if start_with_windows is not None:
            try:
                autostart.set_enabled(bool(start_with_windows), self.exe_path, self.registry, self.frozen)
            except autostart.AutostartError as exc:
                raise ShellError(str(exc)) from exc
        with self.session_factory() as session:
            cfg = load(session)
            if run_in_background is not None:
                cfg["run_in_background"] = bool(run_in_background)
            if notify is not None:
                cfg["notify"] = notify
            set_setting(session, SETTING_KEY, json.dumps(cfg))
            session.commit()
        return self.get()

    def keeps_running_in_background(self) -> bool:
        with self.session_factory() as session:
            return load(session)["run_in_background"]

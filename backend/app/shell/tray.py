"""The system tray icon: open the window, quit, and show Windows notifications. Needs pystray and Pillow; without
them (or off Windows) `ok` stays False and the app simply behaves as before."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)


class Tray:
    def __init__(self, title: str, icon_path: Path, on_open: Callable[[], None], on_quit: Callable[[], None]):
        self.title, self.icon_path, self.on_open, self.on_quit = title, icon_path, on_open, on_quit
        self.icon = None
        self.ok = False

    def start(self) -> bool:
        try:
            import pystray
            from PIL import Image

            image = Image.open(self.icon_path)
            menu = pystray.Menu(
                pystray.MenuItem(f"Open {self.title}", lambda *_: self.on_open(), default=True),
                pystray.MenuItem("Quit", lambda *_: self.on_quit()))
            self.icon = pystray.Icon("HorizonEvents", image, self.title, menu)
            self.icon.run_detached()
            self.ok = True
        except Exception:
            log.exception("the tray icon could not start; closing the window will quit the app")
            self.ok = False
        return self.ok

    def notify(self, title: str, message: str) -> None:
        if self.icon is not None:
            try:
                self.icon.notify(message, title)
            except Exception:
                log.exception("could not show a notification")

    def stop(self) -> None:
        if self.icon is not None:
            try:
                self.icon.stop()
            except Exception:
                pass

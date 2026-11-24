"""Move a flagged file out of the way, reversibly. Needs no administrator rights for the user's own files."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

SUFFIX = ".quarantined"


class QuarantineError(RuntimeError):
    """Raised with a message that is safe to show the user."""


def _protected(path: Path) -> bool:
    root = os.environ.get("SystemRoot")
    if not root:
        return False
    try:
        path.resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def quarantine(original: str, quarantine_dir: Path, entry_id: int) -> str:
    """Move `original` into the quarantine folder; returns the new path."""
    src = Path(original)
    if not src.is_absolute() or not src.is_file():
        raise QuarantineError("The file is no longer there.")
    if _protected(src):
        raise QuarantineError("Files in the Windows folder are never moved automatically.")
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    dest = quarantine_dir / f"{entry_id}{SUFFIX}"
    if dest.exists():
        raise QuarantineError("A quarantined file with this number already exists.")
    try:
        shutil.move(str(src), str(dest))
    except PermissionError as exc:
        raise QuarantineError("Windows would not let the file be moved (it may be in use or locked by Defender).") from exc
    except OSError as exc:
        raise QuarantineError(f"The file could not be moved: {exc.strerror or exc}") from exc
    return str(dest)


def restore(quarantined: str, original: str) -> None:
    src, dest = Path(quarantined), Path(original)
    if not src.is_file():
        raise QuarantineError("The quarantined copy is missing.")
    if dest.exists():
        raise QuarantineError("Something already exists at the original location; it was not overwritten.")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
    except OSError as exc:
        raise QuarantineError(f"The file could not be restored: {exc.strerror or exc}") from exc

"""Import the bundled synthetic sample logs: `python -m app.seed [sample_dir]`."""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.connection import get_engine, init_db
from app.database.models import EventRow
from app.intel.service import ensure_demo_feed
from app.ml.service import ensure_model
from app.services.ingestion import import_logs

SAMPLES = [
    ("linux_auth.log", "linux_auth"), ("linux_syslog.log", "linux_syslog"),
    ("windows_events.xml", "windows"), ("app.log", "application"), ("custom.json", "json"),
    ("slow_spray.log", "linux_auth"),
]


def default_dir() -> Path:
    for candidate in (Path("sample_logs"), Path("../sample_logs"), Path(__file__).resolve().parents[2] / "sample_logs"):
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("sample_logs directory not found")


def seed(session: Session, directory: Path | None = None, now=None) -> list[dict]:
    directory = directory or default_dir()
    return [import_logs(session, stype, name, (directory / name).read_bytes(), now) for name, stype in SAMPLES]


def main() -> None:
    init_db()
    if ensure_model():
        print("Trained the anomaly model on the synthetic baseline.")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    directory = Path(args[0]) if args else None
    with Session(get_engine(), expire_on_commit=False) as session:
        if "--if-empty" in sys.argv and session.scalar(select(func.count(EventRow.id))):
            print("Database already has events; skipping seed.")
            return
        ensure_demo_feed(session)
        for (name, _), res in zip(SAMPLES, seed(session, directory)):
            print(f"{name}: {res}")


if __name__ == "__main__":
    main()

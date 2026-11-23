"""CLI: `python -m app.ml.train [--source database|synthetic]`."""
from __future__ import annotations

import argparse

from sqlalchemy.orm import Session

from app.database.connection import get_engine, init_db
from app.ml import service
from app.ml.model import InsufficientData, model_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the HZ-007 anomaly model.")
    parser.add_argument("--source", choices=["database", "synthetic"], default="synthetic")
    args = parser.parse_args()
    if args.source == "synthetic":
        bundle = service.train_synthetic()
    else:
        init_db()
        with Session(get_engine()) as session:
            try:
                bundle = service.train_from_database(session)
            except InsufficientData as exc:
                raise SystemExit(f"{exc} Try --source synthetic.")
    print(f"Trained on {bundle.n_windows} windows ({bundle.source}); saved to {model_path()}")


if __name__ == "__main__":
    main()

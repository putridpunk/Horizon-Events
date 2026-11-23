"""FastAPI application entry point."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.api import alerts, events, imports, reports, rules, statistics
from app.config import get_settings
from app.database.connection import get_engine, init_db
from app.services.ingestion import ensure_default_rules


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    with Session(get_engine()) as session:
        ensure_default_rules(session)
        session.commit()
    yield


app = FastAPI(title="Horizon Events", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(get_settings().cors_origins),
                   allow_methods=["*"], allow_headers=["*"])
for module in (imports, events, alerts, statistics, rules, reports):
    app.include_router(module.router)


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok"}

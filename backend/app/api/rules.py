from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.schemas import RuleUpdate, rule_out
from app.database.connection import get_session
from app.database.repositories import RuleRepository
from app.services.ingestion import ensure_default_rules

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
def list_rules(session: Session = Depends(get_session)):
    ensure_default_rules(session)
    session.commit()
    return [rule_out(r) for r in RuleRepository(session).list()]


@router.patch("/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, session: Session = Depends(get_session)):
    repo = RuleRepository(session)
    ensure_default_rules(session)
    current = repo.get(rule_id)
    if current is None:
        raise HTTPException(404, "Rule not found")
    params = {**current.params, **body.params} if body.params is not None else None
    row = repo.update(rule_id, enabled=body.enabled, severity=body.severity.value if body.severity else None,
                      params=params)
    session.commit()
    return rule_out(row)

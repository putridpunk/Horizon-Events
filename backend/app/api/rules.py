from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import RuleUpdate, rule_out
from app.database.connection import get_session
from app.database.models import DetectionRuleRow
from app.database.repositories import RuleRepository
from app.detection import replay as replaying
from app.detection import sigma
from app.detection.custom import ID_PREFIX, RuleError, validate_params
from app.domain import Severity
from app.services.ingestion import ensure_default_rules

router = APIRouter(prefix="/api/rules", tags=["rules"])
MAX_CUSTOM = 50


class CustomRuleBody(BaseModel):
    name: str
    description: str = ""
    severity: Severity = Severity.medium
    params: dict
    enabled: bool = True


class SigmaBody(BaseModel):
    text: str
    save: bool = True
    enabled: bool = True


class ReplayBody(BaseModel):
    rule_id: str | None = None  # a stored rule; leave out to try a draft custom rule
    severity: Severity | None = None
    params: dict | None = None
    name: str = "Draft rule"
    days: int = 7


def _clean_text(value: str, what: str, limit: int, required: bool) -> str:
    text = " ".join(value.split())
    if (required and not text) or len(text) > limit:
        raise HTTPException(422, f"Give the rule a {what} of up to {limit} characters.")
    return text


def _validated(params: dict) -> dict:
    try:
        return validate_params(params)
    except RuleError as exc:
        raise HTTPException(422, str(exc)) from exc


def _next_id(session: Session) -> str:
    ids = [r for r in session.scalars(select(DetectionRuleRow.id)) if r.startswith(ID_PREFIX)]
    if len(ids) >= MAX_CUSTOM:
        raise HTTPException(422, f"You can have at most {MAX_CUSTOM} rules of your own.")
    taken = {int(i[len(ID_PREFIX):]) for i in ids if i[len(ID_PREFIX):].isdigit()}
    return f"{ID_PREFIX}{next(n for n in range(1, MAX_CUSTOM + 2) if n not in taken):03d}"


def _create(session: Session, name: str, description: str, severity: str, params: dict, enabled: bool) -> DetectionRuleRow:
    row = DetectionRuleRow(id=_next_id(session), name=name, description=description or name, severity=severity,
                           event_types=[], params=params, enabled=enabled)
    session.add(row)
    session.commit()
    return row


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
    if params is not None and rule_id.startswith(ID_PREFIX):
        params = _validated(params)
    row = repo.update(rule_id, enabled=body.enabled, severity=body.severity.value if body.severity else None,
                      params=params)
    session.commit()
    return rule_out(row)


# ---- rules the user writes -------------------------------------------------------------------------------------
@router.post("/custom", status_code=201)
def create_custom(body: CustomRuleBody, session: Session = Depends(get_session)):
    ensure_default_rules(session)
    name = _clean_text(body.name, "name", 100, True)
    description = _clean_text(body.description, "description", 1000, False)
    return rule_out(_create(session, name, description, body.severity.value, _validated(body.params), body.enabled))


@router.put("/custom/{rule_id}")
def replace_custom(rule_id: str, body: CustomRuleBody, session: Session = Depends(get_session)):
    row = session.get(DetectionRuleRow, rule_id)
    if row is None or not rule_id.startswith(ID_PREFIX):
        raise HTTPException(404, "Rule not found")
    row.name = _clean_text(body.name, "name", 100, True)
    row.description = _clean_text(body.description, "description", 1000, False) or row.name
    row.severity, row.params, row.enabled = body.severity.value, _validated(body.params), body.enabled
    session.commit()
    return rule_out(row)


@router.delete("/custom/{rule_id}")
def delete_custom(rule_id: str, session: Session = Depends(get_session)):
    row = session.get(DetectionRuleRow, rule_id)
    if row is None or not rule_id.startswith(ID_PREFIX):
        raise HTTPException(404, "Rule not found")
    session.delete(row)
    session.commit()
    return {"deleted": rule_id}


@router.post("/sigma", status_code=201)
def import_sigma(body: SigmaBody, session: Session = Depends(get_session)):
    """Turn a Sigma rule into a rule of your own. With `save: false` it only shows the result."""
    try:
        converted = sigma.convert(body.text)
    except sigma.SigmaError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not body.save:
        return {"saved": False, **converted}
    ensure_default_rules(session)
    row = _create(session, converted["name"], converted["description"], converted["severity"], converted["params"],
                  body.enabled)
    return {"saved": True, **rule_out(row)}


@router.post("/replay")
def replay_rule(body: ReplayBody, session: Session = Depends(get_session)):
    """What would this rule have flagged over the last `days` days? Nothing is saved or sent."""
    ensure_default_rules(session)
    if body.rule_id:
        row = session.get(DetectionRuleRow, body.rule_id)
        if row is None:
            raise HTTPException(404, "Rule not found")
        params = dict(row.params)
        if body.params is not None:
            params = _validated(body.params) if row.id.startswith(ID_PREFIX) else {**params, **body.params}
        definition = {"id": row.id, "name": row.name, "description": row.description,
                      "severity": (body.severity or Severity(row.severity)).value, "params": params}
    else:
        if body.params is None:
            raise HTTPException(422, "Give the rule's conditions to try.")
        definition = {"id": f"{ID_PREFIX}000", "name": _clean_text(body.name, "name", 100, True),
                      "description": "Draft rule", "severity": (body.severity or Severity.medium).value,
                      "params": _validated(body.params)}
    try:
        return replaying.replay(session, definition, body.days)
    except replaying.ReplayError as exc:
        raise HTTPException(422, str(exc)) from exc

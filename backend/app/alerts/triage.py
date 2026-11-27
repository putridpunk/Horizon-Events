"""Who is working on an alert, how it is labelled, and how long it has waited. Kept apart from the alert itself so
that existing databases need no column changes."""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AlertRow
from app.database.notification_models import AlertMetaRow
from app.domain import utcnow

UNASSIGNED = "unassigned"
MAX_TAGS = 10
MAX_TAG_LENGTH = 30
MAX_ASSIGNEE_LENGTH = 100
_TAG = re.compile(r"^[\w .:+-]+$", re.UNICODE)

# How long an alert may stay unresolved before it is flagged as late, by severity (minutes).
SLA_MINUTES = {"critical": 60, "high": 240, "medium": 1440, "low": 4320}


class TriageError(ValueError):
    """A value that cannot be accepted; the message is shown to the user."""


def clean_assignee(value) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    if len(text) > MAX_ASSIGNEE_LENGTH:
        raise TriageError(f"The name can have at most {MAX_ASSIGNEE_LENGTH} characters.")
    if text.lower() == UNASSIGNED:
        raise TriageError(f'"{UNASSIGNED}" is reserved; leave the name empty to unassign.')
    return text or None


def clean_tags(values) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise TriageError("Tags must be a list.")
    out: list[str] = []
    for raw in values:
        tag = " ".join(str(raw).split()).lower()
        if not tag:
            continue
        if len(tag) > MAX_TAG_LENGTH or not _TAG.match(tag):
            raise TriageError(f"A tag can have at most {MAX_TAG_LENGTH} letters, digits, spaces or . : + - _ characters.")
        if tag not in out:
            out.append(tag)
    if len(out) > MAX_TAGS:
        raise TriageError(f"An alert can have at most {MAX_TAGS} tags.")
    return out


def matching_alert_ids(session: Session, assignee: str | None, tag: str | None) -> list[int]:
    """Ids of alerts that satisfy both filters (a filter that is not given matches everything)."""
    metas = list(session.scalars(select(AlertMetaRow)))
    ids = set(session.scalars(select(AlertRow.id)))
    if assignee:
        if assignee == UNASSIGNED:
            ids -= {m.alert_id for m in metas if m.assignee}
        else:
            ids &= {m.alert_id for m in metas if (m.assignee or "").lower() == assignee.lower()}
    if tag:
        wanted = tag.strip().lower()
        ids &= {m.alert_id for m in metas if wanted in (m.tags or [])}
    return sorted(ids)


def metas_for(session: Session, alert_ids: list[int]) -> dict[int, AlertMetaRow]:
    if not alert_ids:
        return {}
    return {m.alert_id: m for m in session.scalars(select(AlertMetaRow).where(AlertMetaRow.alert_id.in_(alert_ids)))}


def view(alert: AlertRow, meta: AlertMetaRow | None, now=None) -> dict:
    """Triage fields for an alert: owner, tags, age and whether it is past its target time."""
    now = now or utcnow()
    target = SLA_MINUTES.get(alert.severity, SLA_MINUTES["low"])
    due = alert.created_at + timedelta(minutes=target)
    open_ = alert.status != "RESOLVED"
    return {
        "assignee": meta.assignee if meta else None, "tags": list(meta.tags or []) if meta else [],
        "age_minutes": max(0, int((now - alert.created_at).total_seconds() // 60)),
        "sla_minutes": target, "sla_due_at": due.isoformat(), "sla_breached": bool(open_ and now > due),
    }


def update(session: Session, alert: AlertRow, history, assignee=..., tags=...) -> AlertMetaRow:
    """Change the owner and/or tags (`...` leaves a field alone). Each change is written to the alert's history."""
    meta = session.get(AlertMetaRow, alert.id)
    if meta is None:
        meta = AlertMetaRow(alert_id=alert.id, assignee=None, tags=[])
        session.add(meta)
    if assignee is not ...:
        new = clean_assignee(assignee)
        if new != meta.assignee:
            note = f"Assigned to {new}" if new else "Unassigned"
            if meta.assignee and new:
                note += f" (was {meta.assignee})"
            history.add_history(alert.id, alert.status, alert.status, note)
            meta.assignee = new
    if tags is not ...:
        new_tags = clean_tags(tags)
        if new_tags != list(meta.tags or []):
            history.add_history(alert.id, alert.status, alert.status, "Tags: " + (", ".join(new_tags) or "none"))
            meta.tags = new_tags
    session.flush()
    return meta


def all_tags(session: Session) -> list[str]:
    return sorted({t for m in session.scalars(select(AlertMetaRow)) for t in (m.tags or [])})


def all_assignees(session: Session) -> list[str]:
    return sorted({m.assignee for m in session.scalars(select(AlertMetaRow)) if m.assignee}, key=str.lower)

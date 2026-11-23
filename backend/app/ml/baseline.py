"""Deterministic synthetic 'normal' activity used to train the demo model."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from app.domain import Event, EventType, Severity

_START = datetime(2026, 10, 1)


def synthetic_baseline(seed: int = 42, days: int = 21, n_ips: int = 30) -> list[Event]:
    """Mostly working-hours logins by one user per workstation, with the odd mistyped password."""
    rng = random.Random(seed)
    events: list[Event] = []

    def add(ts: datetime, etype: EventType, ip: str, user: str, i: int) -> None:
        sev = Severity.low if etype == EventType.authentication_success else Severity.medium
        events.append(Event(
            timestamp=ts, source="synthetic", event_type=etype, severity=sev, message="baseline",
            raw=f"baseline|{ts.isoformat()}|{ip}|{etype.value}|{i}", username=user, source_ip=ip))

    for day in range(days):
        date = _START + timedelta(days=day)
        for k in range(n_ips):
            if rng.random() > 0.7:
                continue
            ip, user = f"10.0.{k // 250}.{k % 250 + 1}", f"user{k}"
            hours = [h for h in range(8, 18) if rng.random() < 0.6]
            if rng.random() < 0.03:
                hours.append(rng.choice([6, 7, 19, 20, 22]))
            for h in hours:
                base = date + timedelta(hours=h, minutes=rng.randint(0, 40))
                for i in range(rng.randint(1, 4)):
                    add(base + timedelta(seconds=i), EventType.authentication_success, ip, user, i)
                if rng.random() < 0.15:
                    add(base + timedelta(minutes=5), EventType.authentication_failure, ip, user, 99)
                if rng.random() < 0.03:  # forgotten password: a few failures, then success
                    for j in range(rng.randint(2, 3)):
                        add(base + timedelta(minutes=10, seconds=j), EventType.authentication_failure, ip, user, 100 + j)
                    add(base + timedelta(minutes=11), EventType.authentication_success, ip, user, 200)
        # Shared gateways (VPN/NAT): many users behind one IP, a few failures among them.
        for g in range(3):
            ip = f"10.0.9.{g + 1}"
            for h in range(8, 18):
                if rng.random() < 0.7:
                    base = date + timedelta(hours=h, minutes=rng.randint(0, 40))
                    for i in range(rng.randint(8, 25)):
                        add(base + timedelta(seconds=i), EventType.authentication_success, ip,
                            f"staff{rng.randint(0, 7)}", 300 + i)
                    for j in range(rng.choice([0, 0, 1, 2, 3])):
                        add(base + timedelta(minutes=3, seconds=j), EventType.authentication_failure, ip,
                            f"staff{rng.randint(0, 7)}", 400 + j)
    return events

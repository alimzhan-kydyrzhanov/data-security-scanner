"""Insider Risk Management (IRM): 'data theft by departing users' style scoring.

Usernames are pseudonymised in alerts (privacy by design); only an authorised investigator
holding the salt can re-identify a user.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import date

from .dlp import Decision
from .labels import at_least

EXFIL_LOCATIONS = {"endpoint_usb", "endpoint_upload", "email"}
WINDOW_DAYS = 30
ALERT_THRESHOLD = 60


@dataclass
class InsiderAlert:
    user_pseudonym: str
    score: int
    departing: bool
    events: int
    blocked_attempts: int


def pseudonymize(user: str, salt: str | None = None) -> str:
    salt = salt if salt is not None else os.environ.get("DSSCAN_SALT", "demo-salt-change-me")
    return "user-" + hashlib.sha256((salt + user).encode()).hexdigest()[:10]


def score_users(events: list[dict], decisions: list[Decision], resignations: dict[str, str]) -> list[InsiderAlert]:
    by_id = {e["id"]: e for e in events}
    stats: dict[str, dict] = {}
    for d in decisions:
        ev = by_id[d.event_id]
        if d.location not in EXFIL_LOCATIONS or not at_least(d.label, "Confidential"):
            continue
        if d.location == "email" and ev.get("destination") != "external":
            continue
        s = stats.setdefault(d.user, {"events": 0, "blocked": 0, "in_window": 0})
        s["events"] += 1
        s["blocked"] += d.action == "block"
        resign = resignations.get(d.user)
        if resign:
            delta = (date.fromisoformat(ev["timestamp"][:10]) - date.fromisoformat(resign)).days
            s["in_window"] += -WINDOW_DAYS <= delta <= WINDOW_DAYS

    alerts = []
    for user, s in stats.items():
        departing = user in resignations
        score = 15 * s["events"] + 10 * s["blocked"] + 15 * s["in_window"] + (20 if departing else 0)
        alerts.append(InsiderAlert(pseudonymize(user), min(score, 100), departing, s["events"], s["blocked"]))
    return sorted(alerts, key=lambda a: a.score, reverse=True)

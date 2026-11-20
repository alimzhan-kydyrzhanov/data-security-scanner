"""Data Loss Prevention (DLP): policy-as-code evaluated against user activity events.

Locations mirror enterprise DLP: email, teams, endpoint_usb, endpoint_upload and genai
(prompts pasted into AI assistants - the AI security use case).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .classifiers import classify
from .labels import apply_label, at_least, recommend_label

ACTION_STRENGTH = {"allow": 0, "audit": 1, "block_with_override": 2, "block": 3}


@dataclass
class Policy:
    name: str
    locations: list[str]
    action: str
    min_label: str | None = None
    sit_any: list[str] = field(default_factory=list)
    min_count: int = 1
    destination: str | None = None  # None = any, otherwise internal | external

    def matches(self, event: dict, label: str, counts: dict[str, int]) -> str | None:
        if event["location"] not in self.locations:
            return None
        if self.destination and event.get("destination") != self.destination:
            return None
        if self.min_label and not at_least(label, self.min_label):
            return None
        if self.sit_any:
            hits = sum(counts.get(s, 0) for s in self.sit_any)
            if hits < self.min_count:
                return None
            return f"{hits} x {'/'.join(s for s in self.sit_any if counts.get(s))}"
        return f"label {label}"


@dataclass
class Decision:
    event_id: str
    user: str
    location: str
    action: str
    label: str
    policies: list[str]
    reasons: list[str]


def load_policies(path: Path) -> list[Policy]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    policies = [Policy(**p) for p in raw["policies"]]
    for p in policies:
        if p.action not in ACTION_STRENGTH:
            raise ValueError(f"Unknown action {p.action!r} in policy {p.name!r}")
    return policies


def evaluate(event: dict, policies: list[Policy]) -> Decision:
    result = classify(event.get("content", ""))
    recommended, _ = recommend_label(result)
    label = apply_label(event.get("label"), recommended)
    counts = result.counts()
    matched, reasons, action = [], [], "allow"
    for p in policies:
        reason = p.matches(event, label, counts)
        if reason:
            matched.append(p.name)
            reasons.append(reason)
            if ACTION_STRENGTH[p.action] > ACTION_STRENGTH[action]:
                action = p.action  # most restrictive action wins
    if event.get("override_justification") and action == "block_with_override":
        action = "allowed_with_override"
    return Decision(event["id"], event["user"], event["location"], action, label, matched, reasons)

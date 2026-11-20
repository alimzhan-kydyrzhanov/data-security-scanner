"""Data Security Posture Management (DSPM): turn discovered assets into prioritised findings."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from .discovery import DataAsset
from .labels import RANK, at_least

SENSITIVITY_WEIGHT = {"Public": 0, "Internal": 1, "Confidential": 3, "Highly Confidential": 5}
EXPOSURE = {"private": 1, "org": 2, "external": 3, "anyone_link": 4}
BROAD_GROUPS = {"Everyone", "All Employees", "Domain Users"}
STALE_DAYS = 365
EXCESSIVE_ACL = 10

FRAMEWORKS = {
    "OVERSHARED_SENSITIVE": ["GDPR Art. 32", "ISO 27001 A.5.15", "ISO 27001 A.8.12"],
    "UNLABELED_SENSITIVE": ["ISO 27001 A.5.12", "ISO 27001 A.5.13"],
    "EXCESSIVE_ACCESS": ["GDPR Art. 25", "ISO 27001 A.5.15", "ISO 27001 A.5.18"],
    "STALE_SENSITIVE": ["GDPR Art. 5(1)(e)", "ISO 27001 A.8.10"],
}

REMEDIATION = {
    "OVERSHARED_SENSITIVE": "Remove 'anyone'/external links and broad groups; restrict to a named security group.",
    "UNLABELED_SENSITIVE": "Apply the recommended sensitivity label (enables encryption and DLP).",
    "EXCESSIVE_ACCESS": "Run an access review; remove broad groups and unused permissions (least privilege).",
    "STALE_SENSITIVE": "Apply retention policy: archive or delete data no longer needed (storage limitation).",
}


@dataclass
class Finding:
    finding_type: str
    asset_id: str
    label: str
    risk_score: float
    detail: str
    remediation: str
    frameworks: list[str] = field(default_factory=list)
    priority: str = "P3"


def exposure_of(asset: DataAsset) -> int:
    level = EXPOSURE.get(asset.sharing, 1)
    if BROAD_GROUPS & set(asset.acl):
        level = max(level, 3)
    return level


def risk_score(asset: DataAsset) -> float:
    """risk = sensitivity x exposure x volume factor (log scale so 10 000 rows != 10 000x risk)."""
    volume = 1 + math.log10(1 + asset.sensitive_count)
    return round(SENSITIVITY_WEIGHT[asset.effective_label] * exposure_of(asset) * volume, 1)


def _priority(score: float) -> str:
    return "P1" if score >= 25 else "P2" if score >= 10 else "P3"


def assess(assets: list[DataAsset]) -> list[Finding]:
    findings: list[Finding] = []
    for a in assets:
        label = a.effective_label
        if not at_least(label, "Internal"):
            continue
        score = risk_score(a)

        def add(kind: str, detail: str, bonus: float = 0.0) -> None:
            s = round(score + bonus, 1)
            findings.append(Finding(kind, a.asset_id, label, s, detail, REMEDIATION[kind],
                                    FRAMEWORKS[kind], _priority(s)))

        if at_least(label, "Confidential") and exposure_of(a) >= 3:
            add("OVERSHARED_SENSITIVE", f"{label} data shared as '{a.sharing}', ACL {a.acl}")
        if a.existing_label is None or RANK.get(a.existing_label, -1) < RANK[a.recommended_label]:
            add("UNLABELED_SENSITIVE", f"Current label {a.existing_label!r}, recommended "
                f"{a.recommended_label!r}: {a.label_reason}", bonus=-score / 2)
        unused = [p for p in a.acl if p not in a.accessed_by and p not in BROAD_GROUPS]
        broad = sorted(BROAD_GROUPS & set(a.acl))
        if at_least(label, "Confidential") and (broad or len(a.acl) > EXCESSIVE_ACL or len(unused) >= 3):
            add("EXCESSIVE_ACCESS", f"Broad groups {broad}; {len(unused)} of {len(a.acl)} principals "
                f"never used their access: {unused[:5]}")
        if a.days_since_access > STALE_DAYS:
            add("STALE_SENSITIVE", f"Not accessed for {a.days_since_access} days", bonus=-score / 3)
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)

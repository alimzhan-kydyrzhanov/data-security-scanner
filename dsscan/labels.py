"""Sensitivity labels and auto-labeling rules (information protection / data classification)."""
from __future__ import annotations

from .classifiers import ClassificationResult

LABELS = ["Public", "Internal", "Confidential", "Highly Confidential"]
RANK = {name: i for i, name in enumerate(LABELS)}


def recommend_label(result: ClassificationResult) -> tuple[str, str]:
    """Return (label, reason). Rules go from most to least sensitive; the first match wins."""
    counts = result.counts()
    cats = result.categories()
    ids = counts.get("Czech Birth Number", 0) + counts.get("Kazakhstan IIN", 0)
    if "health" in cats and (ids or "personal" in cats):
        return "Highly Confidential", "Health data linked to a person (GDPR Art. 9 special category)"
    if ids >= 10 or ("financial" in cats and ids):
        return "Highly Confidential", f"Bulk national IDs ({ids}) or IDs combined with financial data"
    if ids or "financial" in cats:
        return "Confidential", "National ID or financial data present"
    if "personal" in cats:
        return "Internal", "Contact details (personal data under GDPR)"
    return "Public", "No sensitive information types detected"


def apply_label(existing: str | None, recommended: str) -> str:
    """Auto-labeling never downgrades a label a person set manually."""
    if existing in RANK and RANK[existing] >= RANK[recommended]:
        return existing
    return recommended


def at_least(label: str | None, minimum: str) -> bool:
    return label in RANK and RANK[label] >= RANK[minimum]

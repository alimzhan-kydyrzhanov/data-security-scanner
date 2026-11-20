"""Sensitive-data discovery across an on-premises file share and a cloud/SaaS inventory."""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

from .classifiers import ClassificationResult, classify
from .labels import apply_label, recommend_label

TEXT_SUFFIXES = {".csv", ".json", ".txt", ".md", ".log"}


@dataclass
class DataAsset:
    asset_id: str
    source: str  # on-prem | SharePoint | OneDrive | S3 | ...
    path: str
    owner: str = "unknown"
    sharing: str = "private"  # private | org | external | anyone_link
    acl: list[str] = field(default_factory=list)
    accessed_by: list[str] = field(default_factory=list)  # who really opened it in the last 90 days
    days_since_access: int = 0
    existing_label: str | None = None
    classification: ClassificationResult = field(default_factory=ClassificationResult)
    recommended_label: str = "Public"
    label_reason: str = ""

    @property
    def effective_label(self) -> str:
        return apply_label(self.existing_label, self.recommended_label)

    @property
    def sensitive_count(self) -> int:
        return sum(self.classification.counts().values())


def _finish(asset: DataAsset, text: str) -> DataAsset:
    asset.classification = classify(text)
    asset.recommended_label, asset.label_reason = recommend_label(asset.classification)
    return asset


def scan_file_share(root: Path) -> list[DataAsset]:
    """On-premises share: read every text file. ACL metadata comes from a sidecar _acl.json if present."""
    acl_meta = {}
    meta_file = root / "_acl.json"
    if meta_file.exists():
        acl_meta = json.loads(meta_file.read_text(encoding="utf-8"))
    assets = []
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in TEXT_SUFFIXES or path.name.startswith("_"):
            continue
        rel = str(path.relative_to(root))
        meta = acl_meta.get(rel, {})
        asset = DataAsset(asset_id=f"onprem:{rel}", source="on-prem", path=rel, **meta)
        assets.append(_finish(asset, read_text(path)))
    return assets


def read_text(path: Path) -> str:
    """CSV rows become 'column: value' lines so the column header acts as supporting evidence."""
    raw = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix.lower() != ".csv":
        return raw
    rows = csv.DictReader(io.StringIO(raw))
    return "\n".join("; ".join(f"{k}: {v}" for k, v in row.items()) for row in rows)


def scan_cloud_inventory(inventory_file: Path) -> list[DataAsset]:
    """Cloud/SaaS inventory as exported by a connector: metadata + a content sample per object."""
    items = json.loads(inventory_file.read_text(encoding="utf-8"))
    assets = []
    for item in items:
        content = item.pop("content", "")
        assets.append(_finish(DataAsset(**item), content))
    return assets

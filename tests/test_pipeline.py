import json
from pathlib import Path

import pytest

from dsscan.cli import run
from dsscan.discovery import DataAsset
from dsscan.dlp import Policy, evaluate
from dsscan.insider_risk import pseudonymize
from dsscan.classifiers import classify
from dsscan.labels import recommend_label
from dsscan.posture import assess
from scripts.generate_data import main as generate

ROOT = Path(__file__).resolve().parents[1]
PATIENT = "patient: Eva Novak; birth number: 736028/5163; diagnosis: E11.9"


def asset(text: str, **kw) -> DataAsset:
    a = DataAsset(asset_id="t", source="test", path="t", **kw)
    a.classification = classify(text)
    a.recommended_label, a.label_reason = recommend_label(a.classification)
    return a


def test_public_link_to_health_data_is_p1():
    findings = assess([asset(PATIENT, sharing="anyone_link", acl=["Everyone"])])
    types = {f.finding_type: f for f in findings}
    assert types["OVERSHARED_SENSITIVE"].priority == "P1"
    assert "UNLABELED_SENSITIVE" in types and "EXCESSIVE_ACCESS" in types
    assert findings == sorted(findings, key=lambda f: f.risk_score, reverse=True)


def test_well_protected_asset_has_no_findings():
    a = asset(PATIENT, acl=["dr"], accessed_by=["dr"], existing_label="Highly Confidential")
    assert assess([a]) == []


def test_dlp_most_restrictive_action_wins():
    policies = [Policy("audit all", ["email"], "audit", min_label="Internal"),
                Policy("block health", ["email"], "block", min_label="Highly Confidential",
                       destination="external")]
    ext = evaluate({"id": "1", "user": "u", "location": "email", "destination": "external",
                    "content": PATIENT}, policies)
    internal = evaluate({"id": "2", "user": "u", "location": "email", "destination": "internal",
                         "content": PATIENT}, policies)
    assert ext.action == "block" and len(ext.policies) == 2
    assert internal.action == "audit"


def test_genai_prompt_blocked():
    p = [Policy("genai", ["genai"], "block", sit_any=["Czech Birth Number"])]
    d = evaluate({"id": "3", "user": "u", "location": "genai", "content": PATIENT}, p)
    assert d.action == "block"


def test_pseudonymization_is_stable_and_salted():
    assert pseudonymize("petr", "s1") == pseudonymize("petr", "s1")
    assert pseudonymize("petr", "s1") != pseudonymize("petr", "s2")
    assert "petr" not in pseudonymize("petr", "s1")


@pytest.fixture()
def full_run(tmp_path):
    generate(tmp_path / "data")
    return run(tmp_path / "data", ROOT / "policies" / "dlp_policies.yaml", tmp_path / "reports"), tmp_path


def test_end_to_end(full_run):
    payload, tmp = full_run
    s = payload["summary"]
    assert s["assets_scanned"] == 12
    assert s["findings_by_priority"]["P1"] >= 1
    assert s["insider_alerts"] == 1
    labels = {a["asset_id"]: a["label"] for a in payload["assets"]}
    assert labels["onprem:notes_invalid_numbers.txt"] == "Public"  # checksums filtered false positives
    actions = {d["event_id"]: d["action"] for d in payload["dlp_decisions"]}
    assert actions["E04"] == "block" and actions["E05"] == "allow" and actions["E03"] == "allowed_with_override"
    report = (tmp / "reports" / "report.md").read_text()
    assert "petr.novak" not in report  # insider risk output is pseudonymised
    assert json.loads((tmp / "reports" / "findings.json").read_text())["summary"] == s

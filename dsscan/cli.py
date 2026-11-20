"""Run discovery -> classification -> DSPM findings -> DLP -> insider risk, and write reports."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .discovery import scan_cloud_inventory, scan_file_share
from .dlp import evaluate, load_policies
from .insider_risk import ALERT_THRESHOLD, score_users
from .posture import assess


def run(data: Path, policies_file: Path, out: Path) -> dict:
    assets = scan_file_share(data / "onprem_share") + scan_cloud_inventory(data / "cloud_inventory.json")
    findings = assess(assets)
    events = json.loads((data / "events.json").read_text(encoding="utf-8"))
    policies = load_policies(policies_file)
    decisions = [evaluate(e, policies) for e in events]
    resignations = json.loads((data / "hr_signals.json").read_text(encoding="utf-8"))
    alerts = score_users(events, decisions, resignations)

    summary = {
        "assets_scanned": len(assets),
        "labels": dict(Counter(a.effective_label for a in assets)),
        "findings_by_priority": dict(Counter(f.priority for f in findings)),
        "dlp_actions": dict(Counter(d.action for d in decisions)),
        "insider_alerts": sum(a.score >= ALERT_THRESHOLD for a in alerts),
    }
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": summary,
        "assets": [{"asset_id": a.asset_id, "source": a.source, "label": a.effective_label,
                    "reason": a.label_reason, "sit_counts": a.classification.counts()} for a in assets],
        "findings": [asdict(f) for f in findings],
        "dlp_decisions": [asdict(d) for d in decisions],
        "insider_risk": [asdict(a) for a in alerts],
    }
    (out / "findings.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(payload), encoding="utf-8")
    return payload


def render_markdown(p: dict) -> str:
    s = p["summary"]
    lines = ["# Data Security Assessment Report", "", "## Executive summary", "",
             f"- Assets scanned: **{s['assets_scanned']}** (on-premises share + cloud/SaaS inventory)",
             f"- Sensitivity labels: {s['labels']}",
             f"- Findings by priority: {s['findings_by_priority']}",
             f"- DLP decisions: {s['dlp_actions']}",
             f"- Insider risk alerts (score >= {ALERT_THRESHOLD}): {s['insider_alerts']}", "",
             "## Prioritised remediation plan", "",
             "| # | Priority | Risk | Finding | Asset | Remediation | Frameworks |",
             "|---|---|---|---|---|---|---|"]
    for i, f in enumerate(p["findings"], 1):
        lines.append(f"| {i} | {f['priority']} | {f['risk_score']} | {f['finding_type']} | {f['asset_id']} "
                     f"| {f['remediation']} | {', '.join(f['frameworks'])} |")
    lines += ["", "## DLP decisions", "", "| Event | Location | Label | Action | Policies |", "|---|---|---|---|---|"]
    for d in p["dlp_decisions"]:
        lines.append(f"| {d['event_id']} | {d['location']} | {d['label']} | **{d['action']}** "
                     f"| {'; '.join(d['policies']) or '-'} |")
    lines += ["", "## Insider risk (pseudonymised)", "", "| User | Score | Departing | Events | Blocked |",
              "|---|---|---|---|---|"]
    for a in p["insider_risk"]:
        lines.append(f"| {a['user_pseudonym']} | {a['score']} | {a['departing']} | {a['events']} "
                     f"| {a['blocked_attempts']} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Clinic & hotel data security scanner")
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--policies", type=Path, default=Path("policies/dlp_policies.yaml"))
    ap.add_argument("--out", type=Path, default=Path("reports"))
    ap.add_argument("--fail-on-p1", action="store_true", help="exit 1 if any P1 finding (CI gate)")
    args = ap.parse_args()
    payload = run(args.data, args.policies, args.out)
    print(json.dumps(payload["summary"], indent=2))
    if args.fail_on_p1 and payload["summary"]["findings_by_priority"].get("P1"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

# Clinic & Hotel Data Security Scanner

A small, runnable **data security** toolkit that shows the full engineering lifecycle of data protection
controls on a synthetic clinic + hotel data estate (on-premises file share + SharePoint / OneDrive / Teams / S3 inventory):

1. **Sensitive-data discovery** across cloud and on-premises locations
2. **Data classification** with Sensitive Information Types (regex + checksum + keyword evidence, confidence levels)
3. **Information protection**: sensitivity labels and auto-labeling (never downgrades a manual label)
4. **DSPM** (Data Security Posture Management): oversharing, unlabeled sensitive data, excessive access,
   stale data, with a risk score and a **prioritised remediation plan** mapped to GDPR and ISO 27001
5. **DLP** (Data Loss Prevention) policies as code for email, Teams, endpoint (USB/upload) and **GenAI prompts**
6. **Insider Risk Management**: "data theft by departing users" scoring with pseudonymised users

All data is **synthetic** (random names; identifiers have valid checksums so detection is realistic).

## Detected Sensitive Information Types
| SIT | Validation |
|---|---|
| Credit Card Number | Luhn |
| IBAN | ISO 7064 mod-97 |
| Czech Birth Number (rodné číslo) | date + mod-11 |
| Kazakhstan IIN | date + two-pass mod-11 |
| ICD-10 Diagnosis Code | requires supporting keyword |
| Email Address, Phone Number | pattern |

## Run
```bash
pip install -r requirements.txt
python scripts/generate_data.py data      # synthetic data estate
python -m dsscan.cli --data data --out reports
pytest -q
```
Output: `reports/report.md` (executive summary, remediation plan, DLP decisions, insider risk) and `reports/findings.json`.
`--fail-on-p1` makes the run exit with code 1 when P1 findings exist (use as a CI gate).

Docker:
```bash
docker build -t data-security-scanner . && docker run --rm data-security-scanner
```

## Project layout
```
dsscan/classifiers.py   Sensitive Information Types, checksums, confidence
dsscan/labels.py        Sensitivity labels + auto-labeling rules
dsscan/discovery.py     Scan on-prem share and cloud/SaaS inventory
dsscan/posture.py       DSPM findings, risk score, remediation, framework mapping
dsscan/dlp.py           DLP policy engine (policies/dlp_policies.yaml)
dsscan/insider_risk.py  Insider risk scoring with pseudonymisation
dsscan/cli.py           Orchestration + Markdown/JSON reports
scripts/generate_data.py  Synthetic data
```

## How this maps to Microsoft Purview
| This project | Microsoft Purview |
|---|---|
| `SITS` in classifiers.py | Sensitive information types (+ confidence levels) |
| labels.py | Sensitivity labels, auto-labeling policies |
| discovery.py | Content explorer / data map scans |
| posture.py | DSPM (oversharing assessments, recommendations) |
| dlp.py + YAML | DLP policies (Exchange, Teams, Endpoint, browser/AI) |
| insider_risk.py | Insider Risk Management policy templates |

This is a learning project that reproduces the concepts; it does not call Microsoft APIs.

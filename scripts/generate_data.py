"""Generate a SYNTHETIC clinic + hotel data estate. No real people: names are random, but
identifiers have valid checksums so the scanner is tested realistically."""
from __future__ import annotations

import json
import random
import sys
from datetime import date, timedelta
from pathlib import Path

rng = random.Random(42)
FIRST = ["Jan", "Petr", "Eva", "Anna", "Aliya", "Daniyar", "Tomas", "Lucie", "Aigerim", "Marek"]
LAST = ["Novak", "Svoboda", "Dvorak", "Seitkali", "Nurlanova", "Cerny", "Prochazka", "Abenov"]
ICD = ["J45.0", "E11.9", "I10", "K21.0", "M54.5", "F41.1", "N39.0", "S82.1"]


def name() -> str:
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


def rand_date(start=1955, end=2004) -> date:
    return date(start, 1, 1) + timedelta(days=rng.randint(0, (end - start) * 365))


def birth_number() -> str:
    d = rand_date()
    month = d.month + (50 if rng.random() < 0.5 else 0)
    first9 = int(f"{d:%y}{month:02d}{d:%d}{rng.randint(0, 999):03d}")
    check = first9 % 11 % 10  # remainder 10 -> check digit 0
    s = f"{first9:09d}{check}"
    return f"{s[:6]}/{s[6:]}"


def kz_iin() -> str:
    while True:
        d = rand_date(1960, 2004)
        century = (3 if d.year < 2000 else 5) + rng.randint(0, 1)
        base = f"{d:%y%m%d}{century}{rng.randint(0, 9999):04d}"
        digits = [int(c) for c in base]
        check = sum(digits[i] * (i + 1) for i in range(11)) % 11
        if check == 10:
            w = [3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 2]
            check = sum(digits[i] * w[i] for i in range(11)) % 11
        if check != 10:
            return base + str(check)


def card() -> str:
    body = [4] + [rng.randint(0, 9) for _ in range(14)]
    total = 0
    for i, d in enumerate(reversed(body)):
        total += (d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 == 0 else d
    s = "".join(map(str, body)) + str((10 - total % 10) % 10)
    return " ".join(s[i:i + 4] for i in range(0, 16, 4))


def iban() -> str:
    bban = "0800" + "".join(str(rng.randint(0, 9)) for _ in range(16))
    numeric = "".join(str(int(c, 36)) for c in bban + "CZ00")
    s = f"CZ{98 - int(numeric) % 97:02d}{bban}"
    return " ".join(s[i:i + 4] for i in range(0, len(s), 4))


def email(n: str) -> str:
    return n.lower().replace(" ", ".") + "@mail.example"


def phone() -> str:
    return f"+420 {rng.randint(600, 799)} {rng.randint(100, 999)} {rng.randint(100, 999)}"


def patient_rows(n: int) -> str:
    rows = ["patient,birth number,email,phone,diagnosis"]
    rows += [f"{(p := name())},{birth_number()},{email(p)},{phone()},{rng.choice(ICD)}" for _ in range(n)]
    return "\n".join(rows) + "\n"


def guest_rows(n: int) -> str:
    rows = ["guest,nationality,iin,birth number,room"]
    for _ in range(n):
        kz = rng.random() < 0.6
        rows.append(f"{name()},{'KZ' if kz else 'CZ'},{kz_iin() if kz else ''},"
                    f"{'' if kz else birth_number()},{rng.randint(101, 420)}")
    return "\n".join(rows) + "\n"


def as_lines(csv_text: str) -> str:
    head, *rows = csv_text.strip().splitlines()
    keys = head.split(",")
    return "\n".join("; ".join(f"{k}: {v}" for k, v in zip(keys, r.split(","))) for r in rows)


def main(out: Path) -> None:
    share = out / "onprem_share"
    (share / "public").mkdir(parents=True, exist_ok=True)
    (share / "patients_export.csv").write_text(patient_rows(30), encoding="utf-8")
    (share / "hotel_guests_police_report.csv").write_text(guest_rows(15), encoding="utf-8")
    (share / "payments_log.txt").write_text("\n".join(
        f"payment ok, card {card()}, refund account IBAN {iban()}" for _ in range(6)) + "\n", encoding="utf-8")
    (share / "public" / "menu.txt").write_text("Breakfast 7-10. Sauna on floor 2. Call reception.\n",
                                              encoding="utf-8")
    (share / "notes_invalid_numbers.txt").write_text(
        "order 4111 1111 1111 1112, ref 900101/1235, ticket 123456789012, IBAN CZ00 0800 0000 0000 0000 0000\n",
        encoding="utf-8")
    (share / "_acl.json").write_text(json.dumps({
        "patients_export.csv": {"owner": "it.admin", "sharing": "org", "acl": ["Domain Users", "dr.svoboda"],
                                "accessed_by": ["dr.svoboda"], "days_since_access": 20},
        "hotel_guests_police_report.csv": {"owner": "reception", "acl": ["reception", "night.audit"],
                                           "accessed_by": ["reception"], "days_since_access": 3},
        "payments_log.txt": {"owner": "finance", "acl": ["finance"], "accessed_by": ["finance"],
                             "days_since_access": 400, "existing_label": "Confidential"},
    }, indent=2), encoding="utf-8")

    staff = [f"user{i}" for i in range(14)]
    inventory = [
        {"asset_id": "sp:clinic/patients_2025", "source": "SharePoint", "path": "/sites/Clinic/patients_2025.csv",
         "owner": "dr.svoboda", "sharing": "anyone_link", "acl": staff, "accessed_by": staff[:2],
         "days_since_access": 12, "content": as_lines(patient_rows(40))},
        {"asset_id": "od:hr/payroll", "source": "OneDrive", "path": "/hr/payroll_2026.txt", "owner": "hr.lead",
         "sharing": "external", "acl": ["hr.lead", "accountant@partner.example"], "accessed_by": ["hr.lead"],
         "days_since_access": 30, "existing_label": "Internal",
         "content": "\n".join(f"employee {name()}, birth number {birth_number()}, salary account IBAN {iban()}"
                              for _ in range(8))},
        {"asset_id": "s3:hotel-guest-registrations/2026-10", "source": "S3",
         "path": "s3://hotel-guest-registrations/police/2026-10.csv", "owner": "reception", "sharing": "org",
         "acl": ["Everyone"], "accessed_by": ["reception"], "days_since_access": 5,
         "content": as_lines(guest_rows(25))},
        {"asset_id": "sp:marketing/brochure", "source": "SharePoint", "path": "/sites/Marketing/brochure.txt",
         "owner": "marketing", "sharing": "anyone_link", "acl": ["Everyone"], "accessed_by": [],
         "days_since_access": 2, "content": "Welcome to our clinic. Opening hours 8-18."},
        {"asset_id": "teams:reception/chat", "source": "Teams", "path": "/teams/reception/chat_export.txt",
         "owner": "reception", "sharing": "org", "acl": ["reception"], "accessed_by": ["reception"],
         "days_since_access": 1, "existing_label": "Internal",
         "content": "\n".join(f"guest {(p := name())} email {email(p)} tel {phone()}" for _ in range(5))},
        {"asset_id": "s3:clinic-archive/letters-2021", "source": "S3", "path": "s3://clinic-archive/letters-2021.txt",
         "owner": "it.admin", "sharing": "private", "acl": ["it.admin"], "accessed_by": [],
         "days_since_access": 900, "existing_label": "Highly Confidential",
         "content": as_lines(patient_rows(10))},
        {"asset_id": "od:doctor/notes", "source": "OneDrive", "path": "/dr.svoboda/notes.txt", "owner": "dr.svoboda",
         "sharing": "private", "acl": ["dr.svoboda"], "accessed_by": ["dr.svoboda"], "days_since_access": 1,
         "existing_label": "Highly Confidential", "content": as_lines(patient_rows(3))},
    ]
    (out / "cloud_inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")

    p = name()
    contacts = "\n".join(f"{(c := name())} email {email(c)}" for _ in range(25))
    patient = as_lines(patient_rows(3))
    events = [
        {"id": "E01", "user": "dr.svoboda", "timestamp": "2026-11-03T09:10", "location": "email",
         "destination": "external", "content": patient},
        {"id": "E02", "user": "reception", "timestamp": "2026-11-04T10:00", "location": "email",
         "destination": "external", "content": f"Guest {p} paid with card {card()}"},
        {"id": "E03", "user": "reception", "timestamp": "2026-11-04T10:05", "location": "email",
         "destination": "external", "content": f"Guest {p} paid with card {card()}",
         "override_justification": "Guest asked for receipt copy"},
        {"id": "E04", "user": "dr.svoboda", "timestamp": "2026-11-05T11:00", "location": "genai",
         "content": f"Summarise this patient for a referral: {patient.splitlines()[0]}"},
        {"id": "E05", "user": "reception", "timestamp": "2026-11-05T12:00", "location": "genai",
         "content": "Write a friendly welcome email for hotel guests about breakfast hours."},
        {"id": "E06", "user": "petr.novak", "timestamp": "2026-11-10T22:40", "location": "endpoint_usb",
         "content": as_lines(guest_rows(10))},
        {"id": "E07", "user": "petr.novak", "timestamp": "2026-11-11T23:05", "location": "endpoint_upload",
         "content": as_lines(patient_rows(20))},
        {"id": "E08", "user": "petr.novak", "timestamp": "2026-11-12T23:30", "location": "email",
         "destination": "external", "content": inventory[1]["content"]},
        {"id": "E09", "user": "dr.svoboda", "timestamp": "2026-11-13T08:00", "location": "email",
         "destination": "internal", "content": patient},
        {"id": "E10", "user": "marketing", "timestamp": "2026-11-14T15:00", "location": "email",
         "destination": "external", "content": contacts},
    ]
    (out / "events.json").write_text(json.dumps(events, indent=2), encoding="utf-8")
    (out / "hr_signals.json").write_text(json.dumps({"petr.novak": "2026-11-01"}), encoding="utf-8")
    print(f"Synthetic data written to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data"))

"""Sensitive Information Types (SITs): pattern + validator (checksum) + supporting keywords.

Modelled on how enterprise data security platforms (e.g. Microsoft Purview) detect sensitive data:
a regex finds candidates, a checksum removes false positives, nearby keywords raise confidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Callable, Optional

HIGH, MEDIUM, LOW = 85, 75, 65  # confidence levels, same scale as Purview
KEYWORD_WINDOW = 120  # characters before/after a match searched for supporting keywords


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def iban_ok(iban: str) -> bool:
    s = re.sub(r"\s", "", iban).upper()
    if len(s) < 15:
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def czech_birth_number_ok(value: str) -> bool:
    """Czech 'rodne cislo' YYMMDD/XXXX: valid date (+50 month for women) and mod-11 rule."""
    s = value.replace("/", "")
    if len(s) != 10 or not s.isdigit():
        return False
    yy, mm, dd = int(s[0:2]), int(s[2:4]), int(s[4:6])
    if mm > 50:
        mm -= 50
    year = 1900 + yy if yy >= 54 else 2000 + yy
    try:
        date(year, mm, dd)
    except ValueError:
        return False
    first9, check = int(s[:9]), int(s[9])
    rem = first9 % 11
    return (rem == 10 and check == 0) or rem == check


def kz_iin_ok(value: str) -> bool:
    """Kazakhstan IIN: 12 digits, YYMMDD + century/sex digit, two-pass mod-11 checksum."""
    if len(value) != 12 or not value.isdigit():
        return False
    d = [int(c) for c in value]
    if d[6] not in range(1, 7):
        return False
    try:
        century = {1: 1800, 2: 1800, 3: 1900, 4: 1900, 5: 2000, 6: 2000}[d[6]]
        date(century + int(value[0:2]), int(value[2:4]), int(value[4:6]))
    except ValueError:
        return False
    check = sum(d[i] * (i + 1) for i in range(11)) % 11
    if check == 10:
        weights = [3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 2]
        check = sum(d[i] * weights[i] for i in range(11)) % 11
        if check == 10:
            return False
    return check == d[11]


@dataclass(frozen=True)
class SensitiveInfoType:
    name: str
    pattern: re.Pattern
    validator: Optional[Callable[[str], bool]] = None
    keywords: tuple = ()
    keyword_required: bool = False  # weak patterns (e.g. ICD-10) only count with evidence
    category: str = "personal"  # personal | financial | health | national_id


# Order matters: more specific types first, so they claim overlapping text.
SITS: list[SensitiveInfoType] = [
    SensitiveInfoType("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b"), iban_ok,
                      ("iban", "account", "bank", "ucet"), category="financial"),
    SensitiveInfoType("Credit Card Number", re.compile(r"\b(?:\d[ -]?){13,19}\b"), luhn_ok,
                      ("card", "visa", "mastercard", "payment", "karta"), category="financial"),
    SensitiveInfoType("Czech Birth Number", re.compile(r"\b\d{6}/?\d{4}\b"), czech_birth_number_ok,
                      ("rodne cislo", "birth number", "rc", "pojistenec", "patient"), category="national_id"),
    SensitiveInfoType("Kazakhstan IIN", re.compile(r"\b\d{12}\b"), kz_iin_ok,
                      ("iin", "иин", "passport", "guest", "patient"), category="national_id"),
    SensitiveInfoType("ICD-10 Diagnosis Code", re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,2})?\b"), None,
                      ("diagnosis", "dg", "icd", "diagnoza"), keyword_required=True, category="health"),
    SensitiveInfoType("Email Address", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), None, ("email", "e-mail")),
    SensitiveInfoType("Phone Number", re.compile(r"(?<!\w)\+(?:420|7)[ ]?\d{3}[ ]?\d{3}[ ]?\d{3,4}\b"), None,
                      ("phone", "tel", "mobile")),
]


@dataclass
class Match:
    sit: str
    value: str
    confidence: int
    category: str


@dataclass
class ClassificationResult:
    matches: list[Match] = field(default_factory=list)

    def counts(self, min_confidence: int = MEDIUM) -> dict[str, int]:
        out: dict[str, int] = {}
        for m in self.matches:
            if m.confidence >= min_confidence:
                out[m.sit] = out.get(m.sit, 0) + 1
        return out

    def categories(self) -> set[str]:
        return {m.category for m in self.matches if m.confidence >= MEDIUM}


def _has_keyword(text: str, start: int, end: int, keywords: tuple) -> bool:
    window = text[max(0, start - KEYWORD_WINDOW): end + KEYWORD_WINDOW].lower()
    return any(re.search(rf"(?<![\w]){re.escape(k)}(?![\w])", window) for k in keywords)


def classify(text: str) -> ClassificationResult:
    result = ClassificationResult()
    taken: list[tuple[int, int]] = []  # spans already claimed; earlier (more specific) SITs win
    for sit in SITS:
        for m in sit.pattern.finditer(text):
            value = m.group(0).strip()
            if sit.validator and not sit.validator(value):
                continue  # failed checksum -> false positive, dropped
            evidence = _has_keyword(text, m.start(), m.end(), sit.keywords)
            if sit.keyword_required and not evidence:
                continue
            if any(m.start() < end and start < m.end() for start, end in taken):
                continue  # overlaps a match of a more specific SIT (e.g. card digits inside an IBAN)
            taken.append((m.start(), m.end()))
            if sit.validator:
                confidence = HIGH if evidence else MEDIUM
            else:
                confidence = MEDIUM if evidence or not sit.keywords else LOW
                if sit.name in ("Email Address", "Phone Number"):
                    confidence = max(confidence, MEDIUM)  # structure alone is strong enough
            result.matches.append(Match(sit.name, value, confidence, sit.category))
    return result

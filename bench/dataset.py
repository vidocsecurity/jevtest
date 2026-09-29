"""Load the benchmark corpus from reports/<severity>/<GHSA-ID>/."""
import os
from dataclasses import dataclass

SEVERITIES = ["critical", "high", "medium"]


@dataclass
class Report:
    ghsa: str
    severity: str
    stripped: str
    expected: str
    path: str


def load(root="reports", severities=None, limit_per_severity=None):
    out = []
    for sev in severities or SEVERITIES:
        sev_dir = os.path.join(root, sev)
        if not os.path.isdir(sev_dir):
            continue
        for ghsa in sorted(os.listdir(sev_dir)):
            d = os.path.join(sev_dir, ghsa)
            stripped, expected = os.path.join(d, "stripped.md"), os.path.join(d, "expected.txt")
            if not (os.path.isfile(stripped) and os.path.isfile(expected)):
                continue
            out.append(Report(
                ghsa=ghsa,
                severity=sev,
                stripped=open(stripped, encoding="utf-8").read().strip(),
                expected=open(expected, encoding="utf-8").read().strip(),
                path=d,
            ))
            if limit_per_severity and len([r for r in out if r.severity == sev]) >= limit_per_severity:
                break
    return out


def validate(reports):
    """Return list of problems. Catches a scrub that left the answer in the text."""
    from . import cvss
    problems = []
    for r in reports:
        _, ok = cvss.parse_vector(r.expected)
        if not ok:
            problems.append(f"{r.ghsa}: expected.txt is not a complete CVSS v3.1 base vector ({r.expected!r})")
        low = r.stripped.lower()
        for leak in ("cvss:3.1/", "cvss:3.0/", "cvss v3", "cvss:4.0/", "base score", "severity:"):
            if leak in low:
                problems.append(f"{r.ghsa}: stripped.md still contains {leak!r}")
        for sev in SEVERITIES:
            # a bare mention of the word is fine in prose; a labelled one is not
            if f"**{sev}**" in low or f"severity: {sev}" in low:
                problems.append(f"{r.ghsa}: stripped.md still labels severity {sev!r}")
    return problems

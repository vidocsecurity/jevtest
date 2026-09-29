"""CVSS v3.1 base metrics: table loading, vector parsing, scoring.

The metric table is NOT defined here. It is parsed from `prompts/cvss/metrics.md`,
which is also the text sent to models in the `spec` condition, so the prompt and the
code can never disagree about what a metric means.
"""
import os
import re

DATA_DIR = os.environ.get("BENCH_PROMPT_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts")
CVSS_DIR = os.path.join(DATA_DIR, "cvss")
# vector order; each has a file of the same name in CVSS_DIR
ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

_HEAD = re.compile(r"^## +([A-Z]{1,2}) +- +(.+?)\s*$", re.M)
_BULLET = re.compile(r"^- +`([A-Z]{1,2}):([A-Z])` +(\S+) +- +(.+?)\s*$", re.M)


def read_metric_file(code, directory=None):
    """The raw text of one metric's file: definition plus examples."""
    path = os.path.join(directory or CVSS_DIR, f"{code}.md")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"CVSS metric file missing: {path}")
    return open(path, encoding="utf-8").read().strip()


def _load(directory=None):
    """Parse cvss/<M>.md -> (order, {code: (name, intro, {value: (label, definition)})})."""
    table = {}
    for code in ORDER:
        text = read_metric_file(code, directory)
        head = _HEAD.search(text)
        if not head or head.group(1) != code:
            raise ValueError(f"{code}.md must start with '## {code} - <Name>'")
        # value bullets live above the second '## ' heading (Guidance / Examples / ...)
        heads = [h.start() for h in re.finditer(r"^## ", text, re.M)]
        defs_part = text[:heads[1]] if len(heads) > 1 else text
        vals = {}
        for owner, value, label, definition in (m.groups() for m in _BULLET.finditer(defs_part)):
            if owner != code:
                raise ValueError(f"{code}.md: contains a bullet for {owner}:{value}")
            if value in vals:
                raise ValueError(f"{code}.md: duplicate value {code}:{value}")
            vals[value] = (label, definition)
        if not vals:
            raise ValueError(f"{code}.md: no value bullets")
        intro = defs_part[head.end():defs_part.find("\n- `")].strip()
        if not intro:
            raise ValueError(f"{code}.md: no intro paragraph")
        table[code] = (head.group(2), intro, vals)
    return list(ORDER), table


METRIC_ORDER, METRICS = _load()


def reload(directory=None):
    """Re-read the table. Used by tests that edit the files."""
    global METRIC_ORDER, METRICS
    METRIC_ORDER, METRICS = _load(directory)
    return METRIC_ORDER, METRICS


def metric_name(m):
    return METRICS[m][0]


def metric_intro(m):
    return METRICS[m][1]


def values(m):
    """[(code, label, definition), ...] in file order."""
    return [(c, lbl, d) for c, (lbl, d) in METRICS[m][2].items()]


def definitions_and_guidance(code, directory=None):
    """One metric's file without its worked examples - definitions and guidance only."""
    return read_metric_file(code, directory).split("## Examples", 1)[0].strip()


def examples_by_value(code, directory=None):
    """{value: [example lines]} from one metric's Examples section."""
    body = read_metric_file(code, directory).split("## Examples", 1)
    if len(body) < 2:
        return {}
    out = {}
    for line in body[1].strip().splitlines():
        hit = re.search(r"`" + code + r":([A-Z])`", line)
        if hit:
            out.setdefault(hit.group(1), []).append(line.lstrip("- ").strip())
    return out


def definition(m, value):
    return METRICS[m][2][value][1]


def label_to_code(m, label):
    """'Scope: Changed' or 'Changed' or 'C' -> 'C'. Returns None if unresolvable."""
    if label is None:
        return None
    s = str(label).strip()
    if ":" in s:
        s = s.split(":", 1)[1].strip()
    s = s.lower()
    for code, (lbl, _) in METRICS[m][2].items():
        if s == lbl.lower() or s == code.lower():
            return code
    return None


def parse_vector(text):
    """Extract the base metrics from any string containing a CVSS v3.1 vector.

    Returns (metrics_dict, parse_ok). Missing or invalid metrics map to None.
    Tolerant on purpose: one malformed metric must not zero the other seven.
    """
    out = {m: None for m in METRIC_ORDER}
    if not text:
        return out, False
    upper = str(text).upper()
    for m in METRIC_ORDER:
        hit = re.search(r"(?<![A-Z])" + m + r":([A-Z])(?![A-Z])", upper)
        if hit and hit.group(1) in METRICS[m][2]:
            out[m] = hit.group(1)
    return out, all(out[m] is not None for m in METRIC_ORDER)


def format_vector(metrics):
    return "CVSS:3.1/" + "/".join(f"{m}:{metrics.get(m) or '?'}" for m in METRIC_ORDER)


def score_answer(expected_vector, got_metrics):
    """Per-metric comparison. Returns (n_correct, {metric: bool})."""
    exp, ok = parse_vector(expected_vector)
    if not ok:
        raise ValueError(f"expected vector is not a complete CVSS v3.1 base vector: {expected_vector!r}")
    per = {m: (got_metrics.get(m) == exp[m]) for m in METRIC_ORDER}
    return sum(per.values()), per

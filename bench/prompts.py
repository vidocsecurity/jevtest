"""Prompt loading.

Two templates, sent as written. The condition decides only whether the CVSS reference
material is included.

  prompts/llm.md        the whole user message for an LLM
  prompts/jev.md        the Jev `state`, nothing else
  prompts/cvss/<M>.md   one file per base metric: definition, guidance, examples

Tokens:
  {{REPORT}}   the report body
  {{CVSS}}     llm.md only. In `spec` it expands to all eight metric files, in `bare` to
               nothing.

Jev's request is structured, so it is not written as a template. It follows TypeSafe's
guidance: reference material belongs in `state`, questions stay short.

  bare  state is the advisory alone. Questions carry the metric name and the bare option
        labels, with no CVSS text anywhere - the same standing as the LLM bare prompt.
  spec  state is {advisory, cvss_specification} with the definitions and scoring guidance.
        Each option's criteria is an object: what it covers, what belongs to the other
        options, and that option's own worked examples.

Each choice key is "<Metric name>: <Value label>", which is what Jev answers with, so the
reply names the metric: `Scope: Changed`, not a bare `Changed`.
"""
import os
import re

from . import cvss

CONDITIONS = ["bare", "spec"]
PROMPT_DIR = os.environ.get("BENCH_PROMPT_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts")
REPORT, CVSS = "{{REPORT}}", "{{CVSS}}"

_cache = {}


def _read(name):
    path = os.path.join(PROMPT_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"prompt file missing: {path}")
    return open(path, encoding="utf-8").read()


def _check(condition):
    if condition not in CONDITIONS:
        raise ValueError(f"unknown condition {condition!r}, expected one of {CONDITIONS}")


def _tidy(text):
    """Collapse the blank lines left behind when {{CVSS}} expands to nothing."""
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _no_stray_tokens(text, where):
    stray = set(re.findall(r"\{\{([A-Za-z_]+)\}\}", text)) - {"REPORT"}
    if stray:
        raise ValueError(f"{where}: unknown token(s) {sorted(stray)}")


def choices_for(code, condition="bare"):
    """The criteria map for one metric, built from prompts/cvss/<CODE>.md.

    bare: the key is its own criteria, so no CVSS text reaches the model.
    spec: an object per option - what it covers, what the other options cover, and that
    option's worked examples.
    """
    name = cvss.metric_name(code)
    vals = cvss.values(code)
    if condition == "bare":
        return {f"{name}: {label}": f"{name}: {label}" for _, label, _ in vals}
    ex = cvss.examples_by_value(code)
    out = {}
    for c, label, definition in vals:
        opt = {"covers": definition,
               "belongs_to_another_option": [f"{l2} covers: {d2}" for c2, l2, d2 in vals if c2 != c]}
        if ex.get(c):
            opt["examples"] = ex[c]
        out[f"{name}: {label}"] = opt
    return out


def llm_template(condition):
    _check(condition)
    key = ("llm", condition)
    if key not in _cache:
        text = _read("llm.md")
        if REPORT not in text:
            raise ValueError(f"llm.md is missing {REPORT}")
        ref = "\n\n".join(cvss.read_metric_file(m) for m in cvss.METRIC_ORDER) if condition == "spec" else ""
        text = _tidy(text.replace(CVSS, ref))
        _no_stray_tokens(text, "llm.md")
        _cache[key] = text
    return _cache[key]


def llm_prompt(report_text, condition):
    return llm_template(condition).replace(REPORT, report_text)


def jev_template(condition):
    """(state_template, questions), {{REPORT}} not yet substituted."""
    _check(condition)
    key = ("jev", condition)
    if key in _cache:
        return _cache[key]

    state = _tidy(_read("jev.md"))
    if REPORT not in state:
        raise ValueError(f"jev.md is missing {REPORT}")
    _no_stray_tokens(state, "jev.md")

    questions = {}
    for m in cvss.METRIC_ORDER:
        questions[m] = {"type": "choice",
                        "instructions": f"{cvss.metric_name(m)} ({m})",
                        "criteria": choices_for(m, condition)}

    _validate(questions)
    _cache[key] = (state, questions)
    return _cache[key]


def _validate(questions):
    """Every metric present once, every choice key resolvable, unique and complete."""
    missing = [m for m in cvss.METRIC_ORDER if m not in questions]
    if missing:
        raise ValueError(f"missing metric question(s) {missing}")
    for m, q in questions.items():
        seen = {}
        for label in q["criteria"]:
            code = cvss.label_to_code(m, label)
            if code is None:
                raise ValueError(f"metric {m} choice {label!r} maps to no CVSS value")
            if code in seen:
                raise ValueError(f"metric {m} choices {seen[code]!r} and {label!r} both map to {m}:{code}")
            seen[code] = label
        want = {c for c, _, _ in cvss.values(m)}
        if set(seen) != want:
            raise ValueError(f"metric {m} covers {sorted(seen)}, expected {sorted(want)}")


def jev_questions(condition):
    return jev_template(condition)[1]


def jev_state(report_text, condition="bare"):
    """bare: the advisory alone. spec: an object carrying the specification beside it."""
    _check(condition)
    state = jev_template(condition)[0].replace(REPORT, report_text)
    if condition == "bare":
        return state
    return {"advisory": state,
            "cvss_specification": "\n\n".join(cvss.definitions_and_guidance(m)
                                               for m in cvss.METRIC_ORDER)}


def validate_all():
    problems = []
    for cond in CONDITIONS:
        for fn, label in ((llm_template, "llm"), (jev_template, "jev")):
            try:
                fn(cond)
            except Exception as exc:
                problems.append(f"{label} {cond}: {exc}")
    return problems

"""End-to-end check of the benchmark suite against the mock server."""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench import cvss, dataset, providers, prompts, score  # noqa: E402
from tests.mock_server import TRUTH, start                   # noqa: E402

FAILURES = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAILURES.append(msg)


def make_corpus(root):
    cases = [
        ("critical", "GHSA-aaaa-aaaa-aaaa", "normal report body"),
        ("high",     "GHSA-bbbb-bbbb-bbbb", "WRONG report body"),
        ("medium",   "GHSA-cccc-cccc-cccc", "PARTIAL report body"),
        ("medium",   "GHSA-dddd-dddd-dddd", "BROKEN report body"),
    ]
    for sev, ghsa, body in cases:
        d = os.path.join(root, sev, ghsa)
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "stripped.md"), "w").write(f"# Title\n\n{body}\n")
        open(os.path.join(d, "expected.txt"), "w").write(TRUTH + "\n")
        open(os.path.join(d, "original.md"), "w").write(f"CVSS:3.1 {TRUTH}\n")
    return cases


def main():
    srv, base = start()
    providers.OPENROUTER_URL = base + "/v1/chat/completions"
    providers.TYPESAFE_URL = base + "/v1/systemone"
    os.environ["OPENROUTER_API_KEY"] = "test"
    os.environ["TYPESAFE_API_KEY"] = "test"

    tmp = tempfile.mkdtemp()
    root = os.path.join(tmp, "reports")
    make_corpus(root)

    print("\n-- dataset --")
    reports = dataset.load(root)
    check(len(reports) == 4, f"loaded 4 reports (got {len(reports)})")
    check(dataset.validate(reports) == [], "clean corpus validates")
    bad = os.path.join(root, "medium", "GHSA-dddd-dddd-dddd", "stripped.md")
    open(bad, "a").write("\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n")
    check(len(dataset.validate(dataset.load(root))) == 1, "leaked vector in stripped.md is caught")
    open(bad, "w").write("# Title\n\nBROKEN report body\n")

    print("\n-- prompts --")
    check(prompts.validate_all() == [], "both templates parse and validate in both conditions")
    bare_llm, spec_llm = prompts.llm_prompt("BODY", "bare"), prompts.llm_prompt("BODY", "spec")
    check("bound to the network stack" not in bare_llm, "bare LLM prompt carries no CVSS definitions")
    check("bound to the network stack" in spec_llm, "spec LLM prompt carries the FIRST definitions")

    qb, qs = prompts.jev_questions("bare"), prompts.jev_questions("spec")
    check(list(qb) == cvss.METRIC_ORDER, "jev sends all 8 metrics in one request")
    check(list(qb["S"]["criteria"]) == ["Scope: Unchanged", "Scope: Changed"],
          "jev choice keys carry the metric name")
    check(qb["C"]["criteria"]["Confidentiality: High"] == "Confidentiality: High",
          "bare criteria are the bare option label - no CVSS text reaches the model")
    check(not any("total loss" in json.dumps(qb[m]) for m in cvss.METRIC_ORDER),
          "no CVSS definition text anywhere in the bare jev request")
    check(qs["C"]["criteria"]["Confidentiality: High"]["covers"].startswith("There is a total loss"),
          "spec criteria carry the verbatim definition under `covers`")
    check(all(cvss.metric_name(m) in k for m in cvss.METRIC_ORDER for k in qb[m]["criteria"]),
          "every choice key on every metric is prefixed with its metric name")
    check(list(qb["S"]["criteria"]) == list(qs["S"]["criteria"]),
          "the same option keys in both conditions, only their criteria differ")
    check(all(list(qb[m]["criteria"]) == [f"{cvss.metric_name(m)}: {lbl}"
                                          for _, lbl, _ in cvss.values(m)] for m in cvss.METRIC_ORDER),
          "option keys are derived from prompts/cvss/<M>.md, not written in a template")
    st_b, st_s = prompts.jev_state("BODY", "bare"), prompts.jev_state("BODY", "spec")
    check(isinstance(st_b, str) and isinstance(st_s, dict) and list(st_s) == ["advisory", "cvss_specification"],
          "spec puts the reference material in state, per TypeSafe's guidance")
    check(st_s["advisory"] == st_b, "the advisory itself is identical in both conditions")
    check("total loss" in st_s["cvss_specification"] and "## Examples" not in st_s["cvss_specification"],
          "state carries definitions and guidance, and the examples live per option instead")
    check(qs["S"]["instructions"] == qb["S"]["instructions"] == "Scope (S)",
          "questions stay short in both conditions")
    check(set(qs["S"]["criteria"]["Scope: Changed"]) == {"covers", "belongs_to_another_option", "examples"},
          "each spec option is an object: covers, what belongs elsewhere, its own examples")
    ex = cvss.examples_by_value("S")
    check(all(f"S:{c}" in " ".join(qs["S"]["criteria"][f"Scope: {lbl}"].get("examples", []))
              for c, lbl, _ in cvss.values("S") if ex.get(c)),
          "each option gets only its own examples, so no value is over-represented")
    check(all(cvss.definitions_and_guidance(m) in st_s["cvss_specification"]
              for m in cvss.METRIC_ORDER),
          "all eight metrics' definitions reach the model once, via state")

    print("\n-- reference material --")
    ac = cvss.read_metric_file("AC")
    check("the Base metrics should be scored assuming the vulnerable component is in that configuration" in ac,
          "AC file carries the assumed-configuration rule, verbatim from the spec")
    check("Following the guidance in Section 2.1.2 of the Specification Document" in ac,
          "AC file carries the MySQL replication example, verbatim from the examples doc")
    check(all("## Examples" in cvss.read_metric_file(m) for m in cvss.METRIC_ORDER),
          "every metric file has Examples")
    check(sum("## Scoring guidance" in cvss.read_metric_file(m) for m in cvss.METRIC_ORDER) == 5,
          "the 5 metrics with official scoring guidance carry it")
    check(spec_llm.count("CVE-") > 30, "spec prompt carries the worked examples")
    for name, text in (("llm bare", bare_llm), ("jev bare state", prompts.jev_state("BODY", "bare")),
                       ("the whole bare jev request", json.dumps(qb))):
        import re as _re
        check("CVE-" not in text and not _re.findall(r"CVSS:3\.1/AV:[NALP]", text),
              f"{name} carries no examples and no scored vectors")

    print("\n-- cvss table comes from the files --")
    check(cvss.METRIC_ORDER == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
          "one file per metric under prompts/cvss/")
    check(cvss.definition("S", "C").startswith("An exploited vulnerability can affect resources beyond"),
          "value definitions parsed from prompts/cvss/S.md")
    check(len(cvss.METRICS["AV"][2]) == 4 and "S:C" not in str(cvss.METRICS["AV"][2]),
          "Guidance and Examples sections are not parsed as value definitions")
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bench")
    hard = [f for f in os.listdir(src) if f.endswith(".py")
            and any(d in open(os.path.join(src, f), encoding="utf-8").read()
                    for d in ("total loss of confidentiality", "bound to the network stack",
                              "You are scoring a software vulnerability", "CVE-2012-1516"))]
    check(not hard, f"no prompt or definition text hardcoded in bench/ (found in {hard})")

    print("\n-- prompt files are the source of truth --")
    import tempfile as _tf
    d = os.path.join(_tf.mkdtemp(), "prompts")
    shutil.copytree(prompts.PROMPT_DIR, d)
    real_dir, prompts.PROMPT_DIR, prompts._cache = prompts.PROMPT_DIR, d, {}
    jev_md = os.path.join(d, "jev.md")
    _t = open(jev_md).read().replace("Vulnerability report:", "EDITED MARKER:")
    open(jev_md, "w").write(_t)
    check(prompts.jev_state("BODY", "bare").startswith("EDITED MARKER:"),
          "editing the template changes what is sent")
    open(jev_md, "w").write("{{REPORT}} {{NOPE}}\n")
    prompts._cache = {}
    probs = prompts.validate_all()
    check(len(probs) == 2 and all("NOPE" in p for p in probs), "an unknown token is rejected")
    prompts.PROMPT_DIR, prompts._cache = real_dir, {}
    shutil.rmtree(os.path.dirname(d), ignore_errors=True)
    check(prompts.validate_all() == [], "restored to the real prompt dir")

    print("\n-- providers --")
    llm = providers.OpenRouterModel("mock/model")
    r = llm.run("normal body", "bare")
    check(r.parse_ok and r.raw_answer == TRUTH, "LLM exact answer parsed")
    check(r.prompt_tokens == 1234 and r.completion_tokens == 21 and r.cost_usd == 0.00321,
          "LLM token split and cost captured from the API")
    check(r.latency_ms > 0, "LLM latency measured")

    r = llm.run("PARTIAL body", "bare")
    n, per = cvss.score_answer(TRUTH, r.metrics)
    check(not r.parse_ok and n == 7 and per["A"] is False,
          f"missing metric scores 7/8 and flags parse_ok=False (got {n}/8)")

    r = llm.run("BROKEN body", "bare")
    n, _ = cvss.score_answer(TRUTH, r.metrics)
    check(not r.parse_ok and n == 0, f"unparseable answer scores 0/8 (got {n}/8)")

    r = llm.run("WRONG body", "bare")
    n, _ = cvss.score_answer(TRUTH, r.metrics)
    check(r.parse_ok and n == 0, f"fully wrong vector scores 0/8 (got {n}/8)")

    jev = providers.JevModel()
    r = jev.run("normal body", "spec")
    check(r.parse_ok and r.raw_answer == TRUTH,
          "jev 'Scope: Changed' style answers map back to vector codes")
    check(r.prompt_tokens == 2048 and r.completion_tokens == 34 and r.cost_source == "computed"
          and abs(r.cost_usd - 2048 * providers.JEV_PRICE_PER_INPUT_TOKEN) < 1e-12,
          "jev cost computed from reported input tokens at $0.042/1M, output free")
    check(r.extra["probabilities"]["S"] and r.extra["confidence"]["S"] == 0.9,
          "jev per-answer probabilities and confidence kept")
    check(r.extra["model_version"] == "jev-1.13.0", "jev resolved model version recorded")

    r = jev.run("NOUSAGE body", "bare")
    check(r.prompt_tokens and r.cost_source == "estimated", "jev marks cost estimated when no usage returned")

    over = jev.run("x" * (providers.JEV_STATE_CONTEXT_TOKENS * 4 + 8000), "spec")
    check(over.error and "context budget" in over.error,
          "report over Jev's 64k/32k context budget is refused before the call")

    r = jev.run("RATELIMIT body", "bare")
    check(not r.error and r.extra["attempts"] == 2,
          "jev retries a 429 and succeeds (attempts=%s)" % r.extra.get("attempts"))

    r = jev.run("BROKEN body", "bare")
    n, per = cvss.score_answer(TRUTH, r.metrics)
    check(not r.parse_ok and n == 7 and per["S"] is False, f"jev unmappable choice scores 7/8 (got {n}/8)")

    print("\n-- runner + resume --")
    from bench import config, dataset as ds, run as runner
    config.OPENROUTER_MODELS = [("mock/model", "mockllm", True, True)]
    out = os.path.join(tmp, "results.jsonl")
    config.RESULTS, config.RUNS = out, 2
    _real_load = ds.load
    ds.load = lambda *a, **k: _real_load(root, *a[1:], **k)
    import io
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        runner.main([])
    recs = [json.loads(l) for l in open(out)]
    expect = 4 * 2 * 2 * 2   # reports x conditions x models x runs
    check(len(recs) == expect, f"ran the full matrix: {len(recs)} == {expect}")
    check({r["model"] for r in recs} == {"mockllm", "jev"}, "both backends ran")
    check(all(r["expected"] == TRUTH for r in recs), "expected vector recorded on every row")
    check(all(r.get("latency_ms") is not None for r in recs), "latency recorded on every row")

    with contextlib.redirect_stdout(io.StringIO()):
        runner.main([])
    check(len(list(open(out))) == expect, "re-run is a no-op (resume works)")
    ds.load = _real_load

    print("\n-- scoring --")
    loaded = score.load(out)
    text = score.summarize(loaded)
    check("PER METRIC" in text and "RUN-TO-RUN STABILITY" in text, "summary renders all sections")
    check("%" in text and "(" in text, "percentages carry raw values")
    csv_path = os.path.join(tmp, "r.csv")
    score.to_csv(loaded, csv_path)
    check(len(list(open(csv_path))) == expect + 1, "csv has one row per call plus header")

    srv.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{'ALL PASS' if not FAILURES else str(len(FAILURES)) + ' FAILURE(S)'}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())

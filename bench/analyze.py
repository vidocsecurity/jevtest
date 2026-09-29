"""Aggregate results into results/analysis.json for the charts.

    python -m bench.analyze

Re-runnable at any point. Safe on a partial run.

Exclusion rule (set by the analyst, 2026-09-28): a call counts only if it produced a
usable answer. Transport errors AND model refusals are both dropped from every
denominator, and counted separately so the omission stays visible.
"""
import json
import os
import statistics
from collections import defaultdict

from . import config, cvss

# opus-5 is not in config.py any more; it stays here so older result rows still sort
MODEL_ORDER = ["jev", "opus-5", "sonnet-5", "gpt-5.6-sol", "gpt-5.6-luna",
               "gemini-3.1-pro", "gemini-3.8-flash", "glm-5.3", "kimi-k3"]
CONDITIONS = ["bare", "spec"]
RUNS = config.RUNS


def load(path):
    """Last record wins per (ghsa, condition, model, run)."""
    recs = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                recs[(r["ghsa"], r["condition"], r["model"], r["run"])] = r
    return list(recs.values())


def is_refusal(r):
    """Model declined. error is null, so bench.score counts these as 0/8."""
    extra = r.get("extra") or {}
    if extra.get("finish_reason") in ("content_filter", "refusal"):
        return True
    try:
        return bool(r["raw_response"]["choices"][0]["message"].get("refusal"))
    except (KeyError, IndexError, TypeError):
        return False


def _stats(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return {"n": 0, "total": None, "mean": None, "median": None}
    return {"n": len(vals), "total": sum(vals),
            "mean": statistics.mean(vals), "median": statistics.median(vals)}


def build(recs, n_reports):
    usable, errored, refused = [], [], []
    for r in recs:
        (errored if r.get("error") else refused if is_refusal(r) else usable).append(r)

    by = defaultdict(list)
    for r in usable:
        by[(r["model"], r["condition"])].append(r)
    n_err = defaultdict(int)
    n_ref = defaultdict(int)
    for r in errored:
        n_err[(r["model"], r["condition"])] += 1
    for r in refused:
        n_ref[(r["model"], r["condition"])] += 1

    expected_calls = n_reports * RUNS          # per model x condition, when complete
    models = sorted({r["model"] for r in recs}, key=lambda m: (MODEL_ORDER + [m]).index(m))

    table = []
    for model in models:
        for cond in CONDITIONS:
            rs = by[(model, cond)]
            if not rs and not n_err[(model, cond)] and not n_ref[(model, cond)]:
                continue
            n = len(rs)
            hit = sum(r["n_correct"] for r in rs)
            think = [(r.get("extra") or {}).get("reasoning_tokens") for r in rs]
            # A model that mostly does not report reasoning tokens gets n/a, not 0:
            # Anthropic runs with reasoning.exclude=true and returns 0 (81 rows, one
            # stray 95), which is "not reported", not "did not think".
            reported = sum(1 for t in think if t)
            think = think if reported * 2 >= len(think) else []
            row = {
                "model": model, "condition": cond,
                "n_usable": n,
                "n_errored": n_err[(model, cond)],
                "n_refused": n_ref[(model, cond)],
                "n_expected": expected_calls,
                "metrics_hit": hit,
                "metrics_possible": 8 * n,
                "metrics_possible_complete": 8 * expected_calls,
                "accuracy": hit / (8 * n) if n else None,
                "exact8": sum(1 for r in rs if r["n_correct"] == 8),
                "parse_ok": sum(1 for r in rs if r.get("parse_ok")),
                "cost": _stats([r.get("cost_usd") for r in rs]),
                "thinking": _stats(think),
                "latency_ms": _stats([r.get("latency_ms") for r in rs]),
                "cost_sources": sorted({r.get("cost_source") for r in rs if r.get("cost_source")}),
            }
            row.update(confidence(rs))
            table.append(row)

    # metric x model x condition accuracy, for the heatmap + delta panel
    cells = defaultdict(lambda: [0, 0])
    for r in usable:
        for m, ok in (r.get("per_metric") or {}).items():
            cells[(r["model"], r["condition"], m)][1] += 1
            cells[(r["model"], r["condition"], m)][0] += int(bool(ok))
    heat = []
    for model in models:
        for m in cvss.METRIC_ORDER:
            cell = {"model": model, "metric": m}
            for cond in CONDITIONS:
                h, t = cells[(model, cond, m)]
                cell[cond] = {"hit": h, "total": t, "acc": (h / t if t else None)}
            b, s = cell["bare"]["acc"], cell["spec"]["acc"]
            cell["delta"] = (s - b) if (b is not None and s is not None) else None
            heat.append(cell)

    # advisory titles, straight from the corpus the models read
    titles = {}
    for sev in os.listdir("reports"):
        d = os.path.join("reports", sev)
        if not os.path.isdir(d):
            continue
        for ghsa in os.listdir(d):
            f = os.path.join(d, ghsa, "stripped.md")
            if os.path.isfile(f):
                with open(f, encoding="utf-8") as fh:
                    first = fh.readline().strip()
                titles[ghsa] = first.lstrip("#").strip()

    # per advisory: how hard was it, pooled over every model and run
    rep = defaultdict(lambda: {"hit": 0, "total": 0, "exact": 0, "calls": 0,
                               "per_metric": defaultdict(lambda: [0, 0])})
    for r in usable:
        d = rep[(r["condition"], r["ghsa"])]
        d["severity"] = r["severity"]
        d["expected"] = r["expected"]
        d["calls"] += 1
        d["hit"] += r["n_correct"]
        d["total"] += 8
        d["exact"] += int(r["n_correct"] == 8)
        for m, ok in (r.get("per_metric") or {}).items():
            d["per_metric"][m][1] += 1
            d["per_metric"][m][0] += int(bool(ok))
    reports = []
    for (cond, ghsa), d in rep.items():
        reports.append({
            "condition": cond, "ghsa": ghsa,
            "severity": d["severity"], "expected": d["expected"],
            "title": titles.get(ghsa, ghsa),
            "calls": d["calls"], "hit": d["hit"], "total": d["total"],
            "acc": d["hit"] / d["total"] if d["total"] else None,
            "exact": d["exact"],
            "per_metric": {m: {"hit": v[0], "total": v[1],
                               "acc": (v[0] / v[1] if v[1] else None)}
                           for m, v in d["per_metric"].items()},
        })
    reports.sort(key=lambda x: (x["condition"], x["acc"]))

    # run-to-run stability: for each (report, condition) the model answered 3 times.
    # A group counts as unstable if those runs did not all give the same value.
    groups = defaultdict(lambda: defaultdict(list))
    for r in usable:
        for m, v in (r.get("answer_metrics") or {}).items():
            groups[(r["model"], m)][(r["ghsa"], r["condition"])].append(v)
        groups[(r["model"], "VECTOR")][(r["ghsa"], r["condition"])].append(r.get("answer_vector"))
    stability = []
    for model in models:
        for m in cvss.METRIC_ORDER + ["VECTOR"]:
            g = groups[(model, m)]
            # only groups where every run landed, so a partial run cannot look stable
            full = [vs for vs in g.values() if len(vs) == RUNS]
            unstable = sum(1 for vs in full if len(set(vs)) > 1)
            stability.append({
                "model": model, "metric": m,
                "groups": len(full), "unstable": unstable,
                "rate": (unstable / len(full)) if full else None,
            })

    done = len(recs)
    # Counted over the models actually in the file: a model pulled from the run
    # (opus-5, dropped after refusing a third of the corpus) must not read as
    # missing data on the models that did finish.
    total = n_reports * len(CONDITIONS) * RUNS * len(models)
    return {
        "generated": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        "progress": {"done": done, "total": total,
                     "reports": n_reports, "runs": RUNS,
                     "severities": sorted({r["severity"] for r in recs}),
                     "n_usable": len(usable), "n_errored": len(errored),
                     "n_refused": len(refused)},
        "metric_order": cvss.METRIC_ORDER,
        "models": models,
        "table": table,
        "heatmap": heat,
        "stability": stability,
        "reports": reports,
    }


def confidence(rs):
    """Jev only: per-metric confidence, split by whether that metric was right.

    The LLMs emit a vector and nothing else, so they have no confidence to report.
    """
    right, wrong = [], []
    for r in rs:
        conf = (r.get("extra") or {}).get("confidence") or {}
        for m, c in conf.items():
            if c is None:
                continue
            (right if (r.get("per_metric") or {}).get(m) else wrong).append(c)
    if not right and not wrong:
        return {"conf_right": None, "conf_wrong": None,
                "conf_n_right": 0, "conf_n_wrong": 0}
    return {
        "conf_right": statistics.mean(right) if right else None,
        "conf_wrong": statistics.mean(wrong) if wrong else None,
        "conf_n_right": len(right), "conf_n_wrong": len(wrong),
    }


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="bench.analyze", description=__doc__.split("\n")[0])
    p.add_argument("--out", default="results/analysis.json")
    args = p.parse_args(argv)
    if not os.path.isfile(config.RESULTS):
        raise SystemExit(f"no results yet at {config.RESULTS}")
    recs = load(config.RESULTS)
    n_reports = sum(len(os.listdir(os.path.join("reports", s)))
                    for s in os.listdir("reports")
                    if os.path.isdir(os.path.join("reports", s)))
    data = build(recs, n_reports)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    pr = data["progress"]
    print(f"{args.out}: {pr['done']}/{pr['total']} calls "
          f"({100.0 * pr['done'] / pr['total']:.2f}%) | usable {pr['n_usable']} | "
          f"errored {pr['n_errored']} | refused {pr['n_refused']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

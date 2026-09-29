"""Summarise the results.

    python -m bench.score

Prints the tables and writes results/calls.csv, one row per call.
"""
import json
import os
import statistics
from collections import defaultdict

from . import config, cvss


def load(path):
    """Last record wins per (ghsa, condition, model, run)."""
    recs = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            recs[(r["ghsa"], r["condition"], r["model"], r["run"])] = r
    return list(recs.values())


def _pct(num, den):
    return f"{100.0 * num / den:.2f}% ({num}/{den})" if den else "n/a (0/0)"


def _table(rows, headers):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
              for i, h in enumerate(headers)]
    out = ["  ".join(str(h).ljust(w) for h, w in zip(headers, widths)),
           "  ".join("-" * w for w in widths)]
    for r in rows:
        out.append("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return "\n".join(out)


def summarize(recs):
    ok = [r for r in recs if not r.get("error")]
    errs = [r for r in recs if r.get("error")]
    out = []

    out.append(f"records: {len(recs)} | usable: {len(ok)} | errored: {len(errs)}\n")

    # per model x condition
    agg = defaultdict(list)
    for r in ok:
        agg[(r["model"], r["condition"])].append(r)
    rows = []
    for (model, cond), rs in sorted(agg.items()):
        n = len(rs)
        metrics_total = 8 * n
        metrics_hit = sum(r["n_correct"] for r in rs)
        exact = sum(1 for r in rs if r["n_correct"] == 8)
        parse = sum(1 for r in rs if r.get("parse_ok"))
        lat = [r["latency_ms"] for r in rs if r.get("latency_ms") is not None]
        cost = [r["cost_usd"] for r in rs if r.get("cost_usd") is not None]
        tin = [r["prompt_tokens"] for r in rs if r.get("prompt_tokens") is not None]
        tout = [r["completion_tokens"] for r in rs if r.get("completion_tokens") is not None]
        rows.append([
            model, cond, n,
            _pct(metrics_hit, metrics_total),
            _pct(exact, n),
            _pct(parse, n),
            f"{statistics.median(lat):.0f}" if lat else "n/a",
            f"{sum(cost):.4f}" if cost else "n/a",
            f"{sum(cost) / n * 1000:.3f}" if cost else "n/a",
            f"{statistics.mean(tin):.0f}" if tin else "n/a",
            f"{statistics.mean(tout):.0f}" if tout else "n/a",
        ])
    out.append("PER MODEL x CONDITION")
    out.append(_table(rows, ["model", "cond", "n", "metric acc", "exact 8/8", "parse ok",
                             "med ms", "$ total", "$/1k rep", "tok in", "tok out"]))
    out.append("")

    # per model x condition x severity
    agg2 = defaultdict(list)
    for r in ok:
        agg2[(r["model"], r["condition"], r["severity"])].append(r)
    rows = []
    for (model, cond, sev), rs in sorted(agg2.items()):
        rows.append([model, cond, sev, len(rs),
                     _pct(sum(r["n_correct"] for r in rs), 8 * len(rs)),
                     _pct(sum(1 for r in rs if r["n_correct"] == 8), len(rs))])
    out.append("PER SEVERITY")
    out.append(_table(rows, ["model", "cond", "severity", "n", "metric acc", "exact 8/8"]))
    out.append("")

    # which metric each model gets wrong
    agg3 = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in ok:
        for m, hit in (r.get("per_metric") or {}).items():
            agg3[(r["model"], r["condition"])][m][1] += 1
            if hit:
                agg3[(r["model"], r["condition"])][m][0] += 1
    rows = []
    for (model, cond), per in sorted(agg3.items()):
        rows.append([model, cond] + [_pct(*per[m]) for m in cvss.METRIC_ORDER])
    out.append("PER METRIC")
    out.append(_table(rows, ["model", "cond"] + cvss.METRIC_ORDER))
    out.append("")

    # run-to-run stability: same report+condition+model across runs
    agg4 = defaultdict(set)
    for r in ok:
        agg4[(r["model"], r["condition"], r["ghsa"])].add(r.get("answer_vector"))
    rows = []
    stab = defaultdict(lambda: [0, 0])
    for (model, cond, _), vecs in agg4.items():
        stab[(model, cond)][1] += 1
        if len(vecs) == 1:
            stab[(model, cond)][0] += 1
    for (model, cond), (same, tot) in sorted(stab.items()):
        rows.append([model, cond, _pct(same, tot)])
    out.append("RUN-TO-RUN STABILITY (identical vector across all runs)")
    out.append(_table(rows, ["model", "cond", "stable"]))

    if errs:
        out.append("\nERRORS")
        seen = defaultdict(int)
        for r in errs:
            seen[(r["model"], str(r["error"])[:120])] += 1
        out.append(_table([[m, n, e] for (m, e), n in sorted(seen.items())], ["model", "n", "error"]))

    return "\n".join(out)


def to_csv(recs, path):
    import csv
    cols = ["ghsa", "severity", "condition", "model", "model_slug", "kind", "run",
            "expected", "answer_vector", "parse_ok", "n_correct", "latency_ms",
            "prompt_tokens", "completion_tokens", "cached_tokens", "cost_usd",
            "cost_source", "http_status", "error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols + cvss.METRIC_ORDER)
        for r in sorted(recs, key=lambda x: (x["model"], x["condition"], x["ghsa"], x["run"])):
            per = r.get("per_metric") or {}
            w.writerow([r.get(c) for c in cols] + [per.get(m) for m in cvss.METRIC_ORDER])


def main(argv=None):
    import argparse
    argparse.ArgumentParser(prog="bench.score", description=__doc__.split("\n")[0]).parse_args(argv)
    if not os.path.isfile(config.RESULTS):
        raise SystemExit(f"no results yet at {config.RESULTS} - run `python -m bench.run` first")
    recs = load(config.RESULTS)
    print(summarize(recs))
    csv_path = os.path.join("results", "calls.csv")
    to_csv(recs, csv_path)
    print(f"\ncsv -> {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

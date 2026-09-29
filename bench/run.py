"""Run the benchmark: every report, both conditions, every model, N runs.

    python -m bench.run                      everything
    python -m bench.run --dry-run            show the matrix and stop
    python -m bench.run --models jev sonnet-5  just those
    python -m bench.run --limit 2            2 reports per severity, for a smoke test

Re-running is safe and cheap: completed calls are skipped, failed ones are retried.
"""
import argparse
import concurrent.futures as cf
import json
import os
import sys
import threading
import time

from . import config, cvss, dataset, prompts

_lock = threading.Lock()


def _key(rec):
    return f"{rec['ghsa']}|{rec['condition']}|{rec['model']}|{rec['run']}"


def _done(path):
    """Keys already completed. Errored calls are left out so they are retried."""
    out = set()
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not rec.get("error"):
                    out.add(_key(rec))
    return out


def _append(path, rec):
    with _lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _call(report, condition, label, model, run_idx):
    started = time.time()
    try:
        res, err = model.run(report.stripped, condition), None
        err = res.error
    except Exception as exc:
        res, err = None, f"{type(exc).__name__}: {exc}"

    rec = {"ts": started, "ghsa": report.ghsa, "severity": report.severity,
           "condition": condition, "model": label, "model_slug": getattr(model, "slug", label),
           "kind": model.kind, "run": run_idx, "expected": report.expected, "error": err}
    if res is not None:
        n_correct, per_metric = (None, None)
        if not err:
            n_correct, per_metric = cvss.score_answer(report.expected, res.metrics)
        rec.update({"answer_vector": res.raw_answer, "answer_metrics": res.metrics,
                    "parse_ok": res.parse_ok, "n_correct": n_correct, "per_metric": per_metric,
                    "latency_ms": round(res.latency_ms, 1), "prompt_tokens": res.prompt_tokens,
                    "completion_tokens": res.completion_tokens, "cached_tokens": res.cached_tokens,
                    "cost_usd": res.cost_usd, "cost_source": res.cost_source,
                    "http_status": res.http_status, "extra": res.extra,
                    "raw_response": res.raw_response})
    return rec


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bench.run", description=__doc__.split("\n")[0])
    ap.add_argument("--models", nargs="+", help="model labels; default is all of them")
    ap.add_argument("--limit", type=int, help="reports per severity, for a smoke test")
    ap.add_argument("--dry-run", action="store_true", help="show the matrix and stop")
    args = ap.parse_args(argv)

    config.load_dotenv()
    out = config.RESULTS
    os.makedirs(os.path.dirname(out), exist_ok=True)

    reports = dataset.load(limit_per_severity=args.limit)
    if not reports:
        sys.exit("no reports found under reports/<severity>/<GHSA>/{stripped.md,expected.txt}")
    problems = dataset.validate(reports)
    if problems:
        print(f"! {len(problems)} corpus problem(s):", file=sys.stderr)
        for p in problems[:40]:
            print("  -", p, file=sys.stderr)
        if not args.dry_run:
            sys.exit("refusing to run against a corpus that still leaks the answer")

    models = config.build(only=args.models)
    jobs = [(r, c, lbl, m, i) for r in reports for c in prompts.CONDITIONS
            for lbl, m in models.items() for i in range(1, config.RUNS + 1)]
    done = _done(out)
    todo = [j for j in jobs if f"{j[0].ghsa}|{j[1]}|{j[2]}|{j[4]}" not in done]

    by_sev = {}
    for r in reports:
        by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
    print(f"reports: {len(reports)} ({', '.join(f'{k}={v}' for k, v in sorted(by_sev.items()))})")
    print(f"models:  {', '.join(sorted(models))}")
    print(f"calls:   {len(jobs)} total, {len(done)} done, {len(todo)} to run")
    if args.dry_run:
        return 0

    missing = [lbl for lbl, m in models.items() if not getattr(m, "api_key", None)]
    if missing:
        sys.exit(f"missing API key for: {', '.join(missing)} "
                 "(set OPENROUTER_API_KEY / TYPESAFE_API_KEY in .env)")

    errors = 0
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=config.CONCURRENCY) as pool:
        futs = [pool.submit(_call, *j) for j in todo]
        for n, fut in enumerate(cf.as_completed(futs), 1):
            rec = fut.result()
            _append(out, rec)
            errors += bool(rec.get("error"))
            flag = "ERR" if rec.get("error") else f"{rec.get('n_correct')}/8"
            print(f"[{n}/{len(todo)}] {rec['model']:<17} {rec['condition']:<4} "
                  f"{rec['ghsa']:<24} run{rec['run']} {flag}", flush=True)

    print(f"\n{len(todo) - errors} ok, {errors} errored in {time.time() - t0:.0f}s -> {out}")
    if errors:
        print("re-run the same command to retry just the failures")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

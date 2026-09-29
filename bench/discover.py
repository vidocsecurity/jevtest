"""Check the models are reachable and the slugs still exist.

    python -m bench.discover            one real call per model
    python -m bench.discover gemini     search the OpenRouter catalogue
"""
import argparse
import json
import os
import sys

import httpx

from . import config, providers


def list_models():
    r = httpx.get("https://openrouter.ai/api/v1/models", timeout=60)
    r.raise_for_status()
    return r.json()["data"]


def cmd_slugs(terms):
    models = list_models()
    terms = [t.lower() for t in terms] or [""]
    seen = set()
    rows = []
    for m in models:
        mid = m["id"]
        if mid in seen or not any(t in mid.lower() or t in (m.get("name") or "").lower() for t in terms):
            continue
        seen.add(mid)
        p = m.get("pricing") or {}
        rows.append((mid, m.get("context_length"),
                     p.get("prompt"), p.get("completion"), m.get("name")))
    rows.sort()
    print(f"{len(rows)} match(es)\n")
    for mid, ctx, pin, pout, name in rows:
        print(f"{mid}\n    ctx={ctx}  $in/tok={pin}  $out/tok={pout}  {name}")
    return 0


def cmd_preflight(labels):
    config.load_dotenv()
    models = config.build(only=labels or None)
    body = ("A web application exposes an unauthenticated HTTP endpoint that reads an "
            "attacker-supplied file path and returns its contents, allowing any remote "
            "user to read arbitrary files readable by the service account.")
    bad = 0
    for label, m in models.items():
        if not getattr(m, "api_key", None):
            print(f"{label:<16} SKIP  no API key")
            bad += 1
            continue
        try:
            res = m.run(body, "spec")
        except Exception as exc:
            print(f"{label:<16} FAIL  {type(exc).__name__}: {exc}")
            bad += 1
            continue
        if res.error:
            print(f"{label:<16} FAIL  http={res.http_status} {str(res.error)[:160]}")
            bad += 1
            continue
        print(f"{label:<16} OK    {res.raw_answer}  parse_ok={res.parse_ok}  "
              f"{res.latency_ms:.0f}ms  in={res.prompt_tokens} out={res.completion_tokens} "
              f"cost={res.cost_usd} ({res.cost_source})")
        if m.kind == "jev":
            raw = res.raw_response or {}
            print("  jev model   :", raw.get("model"))
            print("  jev usage   :", json.dumps(raw.get("usage"), default=str))
            print("  jev keys    :", sorted(raw.keys()))
    print("\nall good" if not bad else f"\n{bad} model(s) need attention")
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bench.discover", description=__doc__.split("\n")[0])
    ap.add_argument("terms", nargs="*", help="search the catalogue instead of calling models")
    args = ap.parse_args(argv)
    return cmd_slugs(args.terms) if args.terms else cmd_preflight(None)


if __name__ == "__main__":
    raise SystemExit(main())

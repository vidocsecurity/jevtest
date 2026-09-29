"""Render the exact payloads that go on the wire, for review.

    python -m bench.show                  all four payloads, with a sample report
    python -m bench.show jev spec         just one
    python -m bench.show --ghsa GHSA-...  use a real report from the corpus
"""
import argparse
import json
from . import config, dataset, prompts, providers

SAMPLE = """# Example advisory

## Summary

An unauthenticated HTTP endpoint reads a caller-supplied `path` parameter and returns the
file contents, so any remote user can read files readable by the service account.

## Details

`src/server/files.go:88` joins the parameter onto the storage root without normalising it.

[... report body continues; truncated here for display ...]"""


def render(model_kind, condition, report_text):
    if model_kind == "llm":
        body = {
            "model": "<openrouter-slug>",
            "messages": [{"role": "user", "content": prompts.llm_prompt(report_text, condition)}],
            "temperature": 0.0,
            "max_tokens": 200,
        }
        return f"POST {providers.OPENROUTER_URL}", body
    body = {
        "model": providers.JEV_MODEL,
        "state": prompts.jev_state(report_text, condition),
        "questions": prompts.jev_questions(condition),
    }
    return f"POST {providers.TYPESAFE_URL}", body


def as_text(model_kind, condition, report_text, source):
    url, body = render(model_kind, condition, report_text)
    name = "Jev" if model_kind == "jev" else "LLM"
    out = [f"### {name}, {condition} condition (report: {source})", "",
           url, "Authorization: Bearer <key>", "Content-Type: application/json", "",
           json.dumps(body, indent=2, ensure_ascii=False)]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bench.show", description=__doc__.split("\n")[0])
    ap.add_argument("model", nargs="?", choices=["llm", "jev"], help="default: both")
    ap.add_argument("condition", nargs="?", choices=prompts.CONDITIONS, help="default: both")
    ap.add_argument("--ghsa", help="use a real report from the corpus")
    args = ap.parse_args(argv)

    problems = prompts.validate_all()
    if problems:
        for p in problems:
            print("!", p)
        return 1

    report_text, source = SAMPLE, "a short synthetic sample"
    if args.ghsa:
        hit = [r for r in dataset.load() if r.ghsa == args.ghsa]
        if not hit:
            raise SystemExit(f"no report {args.ghsa} in the corpus")
        report_text, source = hit[0].stripped, f"`{args.ghsa}` stripped.md"

    kinds = [args.model] if args.model else ["llm", "jev"]
    conds = [args.condition] if args.condition else prompts.CONDITIONS

    for k in kinds:
        for c in conds:
            print(as_text(k, c, report_text, source))
            print("\n" + "=" * 100 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

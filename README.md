# CVSS benchmark

Scores vulnerability writeups with CVSS v3.1 base metrics across Jev and a set of LLMs,
and compares accuracy, latency and cost.

## Setup

    cp .env.example .env     # fill in OPENROUTER_API_KEY and TYPESAFE_API_KEY
    pip install httpx

## Run

    python -m bench.run --dry-run     # how many calls this will make
    python -m bench.run               # run it
    python -m bench.score             # tables, plus results/calls.csv

Re-running is safe: finished calls are skipped, failed ones retried.

Options, all optional: `--models jev sonnet-5` to pick models, `--limit 2` for a smoke test
over two reports per severity.

## Other commands

    python -m bench.discover          # one real call per model, checks the wiring
    python -m bench.show              # the exact request payloads
    python tests/test_suite.py        # offline self-check, makes no API calls

## Corpus

    reports/<severity>/<GHSA-ID>/
        original.md    the source advisory, with its CVSS data. Not used.
        stripped.md    the advisory with the CVSS hints removed. This is what models see.
        expected.txt   the ground-truth CVSS v3.1 base vector.

`bench.run` refuses to start if a `stripped.md` still contains a vector, a base score or a
severity label.

## Prompts

Everything a model sees is in `prompts/`, sent as written. `prompts/llm.md` and
`prompts/jev.md` are the templates; `prompts/cvss/<METRIC>.md` holds each base metric's
definition, scoring guidance and worked examples, quoted from FIRST.

"""Models under test.

OpenRouter slugs are placeholders until the key is available and
`python -m bench.run models --discover` can confirm the exact ids.
Anything with verified=False is skipped by default; pass --include-unverified to run it.
"""
import os

from .providers import JevModel, OpenRouterModel

# slug, short label, verified-against-OpenRouter
# slug, label, supports `reasoning`, supports `temperature`
# Capabilities read from the OpenRouter catalogue's supported_parameters on 2026-09-28
# and re-checked by `python -m bench.discover caps`.
OPENROUTER_MODELS = [
    ("anthropic/claude-sonnet-5",     "sonnet-5",         True,  False),
    ("openai/gpt-5.6-sol",            "gpt-5.6-sol",      True,  False),
    ("openai/gpt-5.6-luna",           "gpt-5.6-luna",     True,  False),
    ("google/gemini-3.1-pro-preview", "gemini-3.1-pro",   True,  True),
    ("google/gemini-3.8-flash",       "gemini-3.8-flash", True,  True),
    ("z-ai/glm-5.3",                  "glm-5.3",          True,  True),
    ("moonshotai/kimi-k3",            "kimi-k3",          True,  True),
]

# Uniform across every model that accepts it, so the runs stay comparable.
REASONING = {"effort": "low", "exclude": True}
MAX_TOKENS = 16000
TEMPERATURE = 0.0
RUNS = 3
CONCURRENCY = 4
RESULTS = "results/raw/results.jsonl"


def build(only=None, temperature=TEMPERATURE):
    models = {}
    for slug, label, can_reason, can_temp in OPENROUTER_MODELS:
        m = OpenRouterModel(
            slug,
            temperature=temperature if can_temp else None,
            max_tokens=MAX_TOKENS,
            reasoning=REASONING if can_reason else None,
        )
        m.name = label
        models[label] = m
    jev = JevModel()
    jev.name = "jev"
    models["jev"] = jev
    if only:
        missing = set(only) - set(models)
        if missing:
            raise SystemExit(f"unknown model label(s): {sorted(missing)}. available: {sorted(models)}")
        models = {k: v for k, v in models.items() if k in only}
    return models


def load_dotenv(path=".env"):
    if not os.path.isfile(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

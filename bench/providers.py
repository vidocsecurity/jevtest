"""Model backends. Each returns a uniform Result."""
import json
import os
import random
import time
from dataclasses import dataclass, field

import httpx

from . import cvss, prompts

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# TypeSafe's own API, not the Vercel AI Gateway.
TYPESAFE_URL = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-latest"
JEV_PRICE_PER_INPUT_TOKEN = 0.042 / 1_000_000   # $/token; output tokens are free
# Context budget: 64k total across state + all questions, 32k for state + longest question.
JEV_CONTEXT_TOKENS = 64_000
JEV_STATE_CONTEXT_TOKENS = 32_000
RETRY_STATUSES = (429, 500, 502, 503, 504, 520, 529)
# OpenRouter also reports upstream rate limits and timeouts as HTTP 200 with an error in
# the body, so the status code alone is not enough to decide whether to retry.
RETRY_BODY_MARKERS = ("rate-limit", "rate limit", "temporarily", "timeout", "overloaded",
                      "capacity", "try again")


@dataclass
class Result:
    metrics: dict                 # {"AV": "N", ...}, None where not answered
    parse_ok: bool
    raw_answer: str               # vector string as returned / reconstructed
    latency_ms: float
    prompt_tokens: int = None
    completion_tokens: int = None
    cached_tokens: int = None
    cost_usd: float = None
    cost_source: str = None       # "api" or "computed"
    http_status: int = None
    error: str = None
    extra: dict = field(default_factory=dict)   # probabilities, confidence, ...
    raw_response: dict = None


def _client(timeout):
    return httpx.Client(timeout=httpx.Timeout(timeout, connect=15.0))


def _retryable_body_error(data):
    """True when a 200 response carries a transient upstream error."""
    err = (data or {}).get("error")
    if not err:
        return False
    code = err.get("code") if isinstance(err, dict) else None
    if code in RETRY_STATUSES:
        return True
    msg = str(err).lower()
    return any(k in msg for k in RETRY_BODY_MARKERS)


def _post_with_retry(url, body, headers, timeout, max_retries):
    """POST with exponential backoff on 429/5xx. Returns (response, total_latency_ms).

    Latency is the full wall clock including retries, which is what a caller actually pays
    in time; single-attempt latency is available as `attempt_ms` on the response object.
    """
    t0 = time.perf_counter()
    resp = None
    for attempt in range(max_retries + 1):
        a0 = time.perf_counter()
        with _client(timeout) as c:
            resp = c.post(url, json=body, headers=headers)
        resp.attempt_ms = (time.perf_counter() - a0) * 1000
        resp.attempts = attempt + 1
        retry = resp.status_code in RETRY_STATUSES
        if not retry and resp.status_code == 200:
            try:
                retry = _retryable_body_error(resp.json())
            except ValueError:
                retry = False
        if not retry or attempt == max_retries:
            break
        retry_after = resp.headers.get("retry-after")
        try:
            delay = float(retry_after)
        except (TypeError, ValueError):
            delay = (2 ** attempt) + random.random()
        time.sleep(min(delay, 60.0))
    return resp, (time.perf_counter() - t0) * 1000


class OpenRouterModel:
    """One chat completion per report. Must return only the vector string."""
    kind = "llm"

    def __init__(self, slug, api_key=None, temperature=0.0, max_tokens=16000,
                 timeout=180.0, provider_order=None, extra_body=None, max_retries=6,
                 reasoning=None):
        self.slug = slug
        self.name = slug
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.provider_order = provider_order
        self.extra_body = extra_body or {}
        self.max_retries = max_retries
        self.reasoning = reasoning

    def calls_per_report(self):
        return 1

    def run(self, report_text, condition):
        prompt = prompts.llm_prompt(report_text, condition)
        body = {
            "model": self.slug,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.max_tokens,
        }
        # sent only where the model accepts them; see bench/config.py
        if self.temperature is not None:
            body["temperature"] = self.temperature
        if self.reasoning:
            body["reasoning"] = dict(self.reasoning)
        if self.provider_order:
            # pin the serving provider so latency and price are comparable across runs
            body["provider"] = {"order": self.provider_order, "allow_fallbacks": False}
        body.update(self.extra_body)

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        resp, latency_ms = _post_with_retry(OPENROUTER_URL, body, headers, self.timeout, self.max_retries)

        if resp.status_code != 200:
            return Result({m: None for m in cvss.METRIC_ORDER}, False, "", latency_ms,
                          http_status=resp.status_code, error=resp.text[:2000])
        data = resp.json()
        if data.get("error"):
            return Result({m: None for m in cvss.METRIC_ORDER}, False, "", latency_ms,
                          http_status=200, error=str(data["error"])[:2000], raw_response=data)

        choice = data["choices"][0]
        text = (choice["message"].get("content") or "").strip()
        metrics, parse_ok = cvss.parse_vector(text)
        usage = data.get("usage") or {}
        reasoning_tokens = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
        # reasoning shares the max_tokens budget: if it ate all of it the reply is empty and
        # must not be scored as a wrong answer
        visible = (usage.get("completion_tokens") or 0) - (reasoning_tokens or 0)
        truncated = choice.get("finish_reason") == "length" and not parse_ok
        return Result(
            metrics=metrics,
            parse_ok=parse_ok,
            raw_answer=text,
            latency_ms=latency_ms,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            cached_tokens=(usage.get("prompt_tokens_details") or {}).get("cached_tokens"),
            cost_usd=usage.get("cost"),
            cost_source="api" if usage.get("cost") is not None else None,
            http_status=200,
            error=("reasoning exhausted the token budget: finish_reason=length, "
                   f"completion={usage.get('completion_tokens')} reasoning={reasoning_tokens}"
                   if truncated else None),
            extra={"finish_reason": choice.get("finish_reason"),
                   "generation_id": data.get("id"),
                   "reasoning_tokens": reasoning_tokens,
                   "visible_tokens": visible,
                   "truncated": truncated,
                   "attempts": getattr(resp, "attempts", 1),
                   "attempt_ms": round(getattr(resp, "attempt_ms", latency_ms), 1)},
            raw_response=data,
        )


class JevModel:
    """One /v1/systemone call per report, carrying all 8 base metrics as choice questions."""
    kind = "jev"
    name = "jev"

    def __init__(self, api_key=None, timeout=180.0, model=JEV_MODEL, max_retries=4):
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY")
        self.timeout = timeout
        self.slug = model
        self.max_retries = max_retries

    def calls_per_report(self):
        return 1

    def budget(self, report_text, condition):
        """(total_tokens, state_plus_longest_question) estimated against Jev's two limits."""
        state = prompts.jev_state(report_text, condition)
        questions = prompts.jev_questions(condition)
        s_tok = estimate_tokens(json.dumps(state) if isinstance(state, dict) else state)
        q_tok = [estimate_tokens(json.dumps(q)) for q in questions.values()]
        return s_tok + sum(q_tok), s_tok + (max(q_tok) if q_tok else 0)

    def run(self, report_text, condition):
        state = prompts.jev_state(report_text, condition)
        questions = prompts.jev_questions(condition)
        total, state_longest = self.budget(report_text, condition)
        if total > JEV_CONTEXT_TOKENS or state_longest > JEV_STATE_CONTEXT_TOKENS:
            return Result({m: None for m in cvss.METRIC_ORDER}, False, "", 0.0,
                          prompt_tokens=total,
                          error=(f"over Jev context budget: total~{total} (limit {JEV_CONTEXT_TOKENS}), "
                                 f"state+longest question~{state_longest} (limit {JEV_STATE_CONTEXT_TOKENS})"))
        body = {"model": self.slug, "state": state, "questions": questions}
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        resp, latency_ms = _post_with_retry(TYPESAFE_URL, body, headers, self.timeout, self.max_retries)

        if resp.status_code != 200:
            return Result({m: None for m in cvss.METRIC_ORDER}, False, "", latency_ms,
                          http_status=resp.status_code, error=resp.text[:2000])
        data = resp.json()
        answers = data.get("answers") or {}
        metrics, probabilities, confidence = {}, {}, {}
        for m in cvss.METRIC_ORDER:
            a = answers.get(m) or {}
            metrics[m] = cvss.label_to_code(m, a.get("choice"))
            if a.get("probabilities"):
                probabilities[m] = a["probabilities"]
            if a.get("confidence") is not None:
                confidence[m] = a["confidence"]
        parse_ok = all(metrics[m] is not None for m in cvss.METRIC_ORDER)

        usage = data.get("usage") or {}
        prompt_tokens = usage.get("input_tokens")
        completion_tokens = usage.get("output_tokens")
        if prompt_tokens is None:
            prompt_tokens = estimate_tokens(json.dumps(body))
            cost_source = "estimated"
        else:
            # Tokens are reported, the price is not - compute cost from the published rate.
            cost_source = "computed"
        cost = prompt_tokens * JEV_PRICE_PER_INPUT_TOKEN   # output tokens are free

        return Result(
            metrics=metrics,
            parse_ok=parse_ok,
            raw_answer=cvss.format_vector(metrics),
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cached_tokens=None,
            cost_usd=cost,
            cost_source=cost_source,
            http_status=200,
            extra={"probabilities": probabilities,
                   "confidence": confidence,
                   "model_version": data.get("model"),
                   "attempts": getattr(resp, "attempts", 1),
                   "attempt_ms": round(getattr(resp, "attempt_ms", latency_ms), 1)},
            raw_response=data,
        )


def estimate_tokens(text):
    """Rough fallback only, used when a provider reports no token count."""
    return max(1, len(text) // 4)

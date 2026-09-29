"""Stand-in for OpenRouter + AI Gateway. Used to exercise the suite without spending money."""
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bench import cvss  # noqa: E402
from http.server import BaseHTTPRequestHandler, HTTPServer

TRUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
# Jev echoes the choice key back, and the key carries the metric name. Derived from the
# real metric files so the mock cannot drift from the prompts.
_WANT, _ = cvss.parse_vector(TRUTH)
LABELS = {m: f"{cvss.metric_name(m)}: {dict((c, l) for c, l, _ in cvss.values(m))[_WANT[m]]}"
          for m in cvss.METRIC_ORDER}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    calls = {}

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        Handler.calls[self.path] = Handler.calls.get(self.path, 0) + 1
        body = json.dumps(req)
        if "RATELIMIT" in body and Handler.calls[self.path] % 2 == 1:
            return self._json(429, {"error": "slow down"})
        if not (self.headers.get("Authorization") or "").startswith("Bearer "):
            return self._json(401, {"error": "no key"})

        if self.path.endswith("/chat/completions"):
            prompt = req["messages"][0]["content"]
            if "BROKEN" in prompt:                 # unparseable answer path
                text = "I think this is a critical issue."
            elif "PARTIAL" in prompt:              # one metric missing
                text = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H"
            elif "WRONG" in prompt:
                text = "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N"
            else:
                text = TRUTH
            return self._json(200, {
                "id": "gen-mock", "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1234, "completion_tokens": 21,
                          "prompt_tokens_details": {"cached_tokens": 0}, "cost": 0.00321},
            })

        if self.path.endswith("/systemone"):
            qs = req["questions"]
            assert set(qs) == set(LABELS), f"unexpected questions: {sorted(qs)}"
            for m, q in qs.items():
                assert q["type"] == "choice" and q["criteria"], m
                # the model only ever answers with a key it was given
                assert LABELS[m] in q["criteria"], (m, sorted(q["criteria"]))
            assert req.get("model") == "jev-latest", req.get("model")
            answers = {m: {"type": "choice", "choice": LABELS[m],
                           "probabilities": {LABELS[m]: 0.91}, "confidence": 0.9} for m in qs}
            if "BROKEN" in req["state"]:
                answers["S"]["choice"] = "Scope: Nonsense"  # unmappable on purpose
            payload = {"model": "jev-1.13.0", "answers": answers}
            if "NOUSAGE" not in req["state"]:
                payload["usage"] = {"input_tokens": 2048, "output_tokens": 34}
            return self._json(200, payload)

        return self._json(404, {"error": "no route"})


def start():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"

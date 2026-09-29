# NLTK: Uncontrolled recursion in nltk.featstruct.FeatStructReader causes unhandled RecursionError (DoS) via deeply nested feature-structure input

- GHSA: GHSA-cw6x-m8jw-qmrh
- CVE: CVE-2026-81724
- Published: 2026-09-02T14:33:22Z
- GHSA severity: medium
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3)
- CWE: CWE-674
- Packages: pip:nltk
- Source: https://github.com/advisories/GHSA-cw6x-m8jw-qmrh

---

### Summary

`nltk.featstruct.FeatStructReader` (used by `FeatStruct(str)` and by `FeatureGrammar.fromstring()`) parses feature-structure strings such as `[a=1]` with a recursive-descent parser that has no nesting-depth limit. A small, trivially-crafted input (~700 bytes) with deeply nested brackets drives the parser past Python's recursion limit and raises an **unhandled `RecursionError`** instead of the library's normal, catchable `ValueError`/`LogicalExpressionException`. Any application that parses user-supplied feature-structure or feature-grammar text (e.g. NLP teaching tools, grammar "playgrounds", unification-grammar-based NLU pipelines) can be crashed by an unauthenticated input with no special privileges. This is a Denial of Service issue (CWE-674, Uncontrolled Recursion), not a memory-safety or code-execution issue.

This appears to be the same bug class as two issues already fixed elsewhere in the codebase — `nltk/jsontags.py` (`JSONTaggedDecoder.decode_obj`, guarded by `MAX_DECODE_DEPTH = 200`) and `nltk/sem/logic.py` (`LogicParser`, guarded by `MAX_PARSE_DEPTH = 200`) — but `nltk/featstruct.py` does not have an equivalent guard.

### Details

The recursive call chain (current `develop` branch, `nltk/featstruct.py`):

1. `FeatStructReader.fromstring()` ([`featstruct.py:2184`](nltk/featstruct.py#L2184)) calls `read_partial()` → `_read_partial()` ([`featstruct.py:2250`](nltk/featstruct.py#L2250)).
2. `_read_partial()` dispatches to `_read_partial_featdict()`, which calls `_read_value()` ([`featstruct.py:2436`](nltk/featstruct.py#L2436)) for each feature's value.
3. `_read_value()` calls `read_value()` ([`featstruct.py:2442`](nltk/featstruct.py#L2442)), which matches the value against `VALUE_HANDLERS` ([`featstruct.py:2478`](nltk/featstruct.py#L2478)).
4. If the value itself starts with `[` (a nested feature structure), the matched handler is `read_fstruct_value` ([`featstruct.py:2479`](nltk/featstruct.py#L2479), defined at [`featstruct.py:2495`](nltk/featstruct.py#L2495)):
   ```python
   def read_fstruct_value(self, s, position, reentrances, match):
       return self.read_partial(s, position, reentrances)
   ```
   This calls `read_partial()` again, which re-enters `_read_partial()` — the same function from step 1.

This closes a recursive cycle (`_read_partial → _read_value → read_value → read_fstruct_value → read_partial → _read_partial → ...`) with **no depth counter, no `MAX_*_DEPTH` constant, and no `try/except RecursionError`** anywhere in the class. Each additional `[` in the input adds one more full cycle of Python stack frames. Once the input nests deeply enough, Python's own recursion-limit protection fires and raises `RecursionError`, which is not a subclass of `ValueError` (the exception type this parser's own `_error()` helper raises for normal, well-formed parse errors) and therefore propagates uncaught through this API.

For comparison, `nltk/sem/logic.py`'s `LogicParser` was hardened against exactly this class of issue:
```python
#: Maximum expression-nesting depth the recursive-descent parser will
#: descend to. Deeply nested input would otherwise recurse until Python
#: raises an uncaught RecursionError and crashes the caller
#: (uncontrolled recursion, CWE-674); past this depth a normal
#: LogicalExpressionException is raised instead. Configurable.
MAX_PARSE_DEPTH = 200
```
(`nltk/sem/logic.py:102-107`), and `nltk/jsontags.py`'s `JSONTaggedDecoder` similarly has `MAX_DECODE_DEPTH = 200` with an explicit depth check. `nltk/featstruct.py` has no analogous protection.

`FeatureGrammar.fromstring()` (`nltk/grammar.py`) parses feature structures embedded in FCFG grammar rules via the same `FeatStructReader`, so the same crash is reachable through grammar-string parsing as well as through `FeatStruct()` directly.

### PoC

Verified against the current `develop` branch in a clean virtualenv (Python 3.12, NLTK installed from this checkout via `pip install -e .`):

```python
from nltk.featstruct import FeatStruct

depth = 167
payload = "[a=" * depth + "1" + "]" * depth   # 669 bytes
FeatStruct(payload)
```

Result:
```
Traceback (most recent call last):
  ...
  File ".../nltk/featstruct.py", line 2310, in _read_partial_featdict
    value, position = self._read_value(name, s, position, reentrances)
  File ".../nltk/featstruct.py", line 2440, in _read_value
    return self.read_value(s, position, reentrances)
  File ".../nltk/featstruct.py", line 2446, in read_value
    return handler_func(s, position, reentrances, match)
  [... repeats ~167 times ...]
RecursionError: maximum recursion depth exceeded
```

- Crash threshold: nesting depth 167 (binary-searched between 50 and 200).
- Payload size: 669 bytes — fits trivially in a single HTTP request body/query parameter.
- Time to crash: <2ms — no resource exhaustion is needed, only recursion depth.

Minimal reproduction (no server required):
```bash
python3 -c "
from nltk.featstruct import FeatStruct
FeatStruct('[a=' * 200 + '1' + ']' * 200)
"
```

Illustrative server-side context (not part of NLTK itself, but representative of how the bug becomes reachable):
```python
from flask import Flask, request
from nltk.featstruct import FeatStruct

app = Flask(__name__)

@app.route("/parse", methods=["POST"])
def parse_grammar():
    return {"result": str(FeatStruct(request.json["grammar"]))}
```
A POST of `{"grammar": "[a=" * 200 + "1" + "]" * 200}` to this endpoint raises the uncaught `RecursionError` inside the request handler.

### Impact

**Vulnerability type:** Denial of Service via uncontrolled recursion (CWE-674). This is not a memory-corruption bug and does not lead to code execution or data disclosure — Python's own recursion-limit safety net converts what would be a C-level stack overflow into a catchable (but here, uncaught) `RecursionError`.

**Who is affected:** Any application that passes externally-supplied text into `nltk.featstruct.FeatStruct()` or `nltk.grammar.FeatureGrammar.fromstring()` — for example, NLP/computational-linguistics teaching tools, unification-grammar demo services, or NLU pipelines that accept user-authored feature grammars. This is a narrower slice of NLTK's user base than, e.g., tokenization or POS tagging, since feature-structure/unification-grammar parsing is a more specialized part of the library.

**Practical severity depends on deployment:**
- In typical WSGI-style web frameworks (Flask/Django/FastAPI behind gunicorn/uwsgi), an uncaught exception inside a request handler is caught at the framework/server boundary: the single request fails (HTTP 500), the worker process itself survives, and unaffected requests are unimpacted.
- In single-threaded or per-task-unprotected contexts (e.g. a queue-consuming worker without per-task exception isolation), the uncaught `RecursionError` can terminate the entire process; without a process supervisor that auto-restarts it, this is a persistent outage until manually restarted. An attacker who repeats the payload can keep such a worker in a crash loop for as long as the attack continues.

**Suggested fix:** Add a depth counter and a `MAX_PARSE_DEPTH`-style constant to `FeatStructReader`, mirroring the existing fix in `nltk/sem/logic.py`, and raise the library's normal `ValueError`-based parse error once the limit is exceeded instead of letting `RecursionError` propagate.

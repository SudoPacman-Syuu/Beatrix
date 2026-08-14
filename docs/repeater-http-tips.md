# Repeater "HTTP Tips" — coverage & roadmap

An opt-in learning aid in the Repeater tab. When **HTTP Tips** is toggled **on**
(button at the top-right of the Repeater toolbar), hovering a token in the
request or response pops a small bubble explaining what it is — and, where
relevant, what to look at when hunting for bugs.

The goal: help a human quickly understand what they're looking at and manually
spot issues. We start with the common, high-value stuff and grow the knowledge
base over time. **This file is the running ledger of what's covered and what's
next — update it whenever tips are added.**

---

## How it works (architecture)

- The syntax highlighter already wraps meaningful tokens in `<span>`s. For the
  tip-bearing ones it also stamps a `data-tip="<prefix>:<key>"` attribute:
  - `h:<header-name>` — request/response header names
  - `m:<method>` — request methods
  - `s:<status-code>` — response status codes (falls back to the class, e.g. `4xx`)
  - `t:<tag>` — HTML/XML tag names in a body
  - `cookie:<attr>` / `cookie:samesite-<val>` — Set-Cookie / Cookie attributes
  - `csp:<directive>` / `csp:kw-<source>` / `csp:star` — CSP value tokens
  - `cc:<directive>` — Cache-Control directives
  - `hsts:<token>` — Strict-Transport-Security tokens
  - `ct:<mime>` — Content-Type media types
  - `auth:<scheme>` — Authorization schemes
  - `attr:<name>` / `attr:on` — security-relevant HTML attributes
  - `jwt:<token>` — a detected JWT; decoded **live** (see below), not a static entry
- Header **values** are tokenized by `hlHeaderValue()` → `hlTokens()`, which wraps
  matched sub-tokens in tip spans while emitting the gaps verbatim, so every
  character is preserved and the request overlay stays aligned.
- The knowledge base is `HTTP_TIPS` in the embedded page JS (`beatrix/cli/suite.py`),
  keyed by those prefixes. Each entry is `{ title, desc, sec? }` where `sec` is an
  optional security note.
- `lookupTip(key)` resolves a `data-tip` value to an entry. **JWTs are dynamic**:
  `jwt:<token>` is decoded on hover by `decodeJwtTip()` (base64url header + payload)
  and flags `alg=none`, HMAC secret-guessing, and RS↔HS alg-confusion.
- Hover detection uses `document.elementsFromPoint()` so it works even in the
  request pane, where an editable textarea sits on top of the highlighted layer.
- The toggle state persists in `localStorage` (`beatrix.rep.tips`). When on,
  hoverable tokens get a faint dotted underline as an affordance.

**To add a tip:** add an entry to the right `HTTP_TIPS` sub-object, make sure the
highlighter stamps a matching `data-tip` key for that token type (a new header
value type usually means a new `case` in `hlHeaderValue`), then tick it off below.

---

## Covered

**~370 static tips across 12 categories, plus live JWT decoding.**

### Request methods (`m:`)
GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT,
PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, REPORT, SEARCH (WebDAV),
PURGE, TRACK, DEBUG

### Status codes (`s:`)
100, 101, 200, 201, 202, 203, 204, 205, 206, 226,
300, 301, 302, 303, 304, 305, 307, 308,
400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451,
500, 501, 502, 503, 504, 505, 507, 508, 510, 511 —
plus class fallbacks (`1xx`/`2xx`/`3xx`/`4xx`/`5xx`)

### Header names (`h:`)
host, user-agent, accept, accept-encoding, accept-language, referer, origin,
authorization, cookie, set-cookie, content-type, content-length,
content-encoding, transfer-encoding, connection, cache-control, pragma, date,
expires, etag, last-modified, location, server, x-powered-by, vary,
www-authenticate, content-disposition, content-language, content-md5, link,
accept-ranges, range, content-range, if-match, if-none-match, if-modified-since,
if-unmodified-since, if-range, te, expect, upgrade, keep-alive, max-forwards, dnt.
**Security headers:** x-frame-options, content-security-policy,
content-security-policy-report-only, x-content-security-policy (legacy),
x-webkit-csp (legacy), strict-transport-security, x-content-type-options,
x-xss-protection, referrer-policy, permissions-policy, feature-policy,
cross-origin-opener-policy, cross-origin-embedder-policy,
cross-origin-resource-policy, clear-site-data, timing-allow-origin, nel,
x-permitted-cross-domain-policies, x-dns-prefetch-control, x-download-options.
**CORS:** access-control-allow-origin, access-control-allow-credentials,
access-control-allow-methods, access-control-allow-headers,
access-control-expose-headers, access-control-max-age,
access-control-request-method, access-control-request-headers.
**Proxy / forwarding:** x-forwarded-for, x-forwarded-host, x-forwarded-proto,
x-forwarded-port, x-forwarded-server, forwarded, x-real-ip, x-host, via,
proxy-authorization, proxy-authenticate, x-original-url, x-rewrite-url,
x-http-method-override.
**Fetch metadata / client hints:** sec-fetch-site, sec-fetch-mode,
sec-fetch-dest, sec-fetch-user, sec-ch-ua, sec-ch-ua-platform, sec-ch-ua-mobile.
**Caching / rate-limit / tracing:** age, x-cache, cf-cache-status, retry-after,
allow, server-timing, report-to, reporting-endpoints, x-request-id,
x-correlation-id, x-amzn-trace-id, x-ratelimit-limit, x-ratelimit-remaining,
x-ratelimit-reset

### HTML/XML tags (`t:`)
html, head, title, meta, link, script, style, iframe, form, input, button,
textarea, a, img, svg, object, embed, base, `<!DOCTYPE>`,
body, video, audio, source, template, noscript, noembed, math, annotation-xml,
foreignObject, frame, frameset, applet, select, option, label, details,
marquee, dialog, portal, table, xml

### Cookie attributes (`cookie:`) — on the Set-Cookie / Cookie **value**
HttpOnly, Secure, SameSite (+ Strict/Lax/None values), Domain, Path, Max-Age,
Expires, Partitioned, and the `__Host-` / `__Secure-` name prefixes

### CSP tokens (`csp:`) — on the Content-Security-Policy **value**
default-src, script-src, script-src-elem, script-src-attr, style-src,
style-src-elem, style-src-attr, img-src, connect-src, font-src, object-src,
frame-src, child-src, worker-src, manifest-src, media-src, prefetch-src,
frame-ancestors, base-uri, form-action, navigate-to, report-uri, report-to,
trusted-types, require-trusted-types-for, webrtc, upgrade-insecure-requests,
block-all-mixed-content, sandbox;
sources `'unsafe-inline'`, `'unsafe-eval'`, `'wasm-unsafe-eval'`,
`'unsafe-hashes'`, `'self'`, `'none'`, `'strict-dynamic'`, `'report-sample'`,
`'inline-speculation-rules'`, `data:`, `blob:`, `https:`, `*`

### Cache-Control directives (`cc:`)
no-store, no-cache, private, public, max-age, s-maxage, must-revalidate,
proxy-revalidate, immutable, stale-while-revalidate, stale-if-error,
only-if-cached, max-stale, min-fresh, must-understand, no-transform

### HSTS tokens (`hsts:`)
max-age, includeSubDomains, preload

### Content-Type media types (`ct:`)
application/json, x-www-form-urlencoded, multipart/form-data, multipart/mixed,
application/xml, text/xml, application/soap+xml, application/xhtml+xml,
image/svg+xml, text/html, text/plain, octet-stream, application/javascript,
application/graphql, text/csv, application/ld+json, application/vnd.api+json,
application/hal+json, application/jwt, application/x-yaml, text/yaml,
application/pdf, application/zip, application/wasm, text/event-stream,
application/x-ndjson, application/x-protobuf, application/x-amf,
application/dns-message

### Authorization schemes (`auth:`)
Basic, Bearer, Digest, Negotiate, NTLM, AWS4-HMAC-SHA256 (AWS SigV4), Hawk,
Signature (HTTP Message Signatures)

### HTML attributes (`attr:`)
on* (event handlers), src, href, action, formaction, srcdoc, sandbox, rel,
target, type, http-equiv, content, integrity, nonce, style, autocomplete, name,
method, value, enctype, formmethod, formenctype, crossorigin, referrerpolicy,
ping, download, allow, loading

### JWT (`jwt:`) — dynamic
Any `eyJ….eyJ….` token (in Authorization, Cookie, or a body) is decoded live:
alg + typ, the first claims, and warnings for `alg=none`, HMAC secret-guessing,
and RS↔HS algorithm confusion.

---

## TODO / roadmap (not yet covered)

Ordered roughly by value for manual hunting.

- [ ] **Request smuggling / desync** — an explicit callout when both
      Content-Length *and* Transfer-Encoding are present on the same message.
- [ ] **CORS correlation** — flag ACAO reflecting the request Origin, or ACAO
      `*`/`null` combined with Allow-Credentials `true` (needs cross-line logic).
- [x] **More response headers** — Retry-After, Allow, Age, Via, X-Cache,
      Permissions-Policy, Cross-Origin-* (COOP/COEP/CORP), Timing-Allow-Origin,
      X-Request-Id, Server-Timing, Report-To/Reporting-Endpoints — *plus* the
      full forwarding/proxy set (X-Forwarded-*, Forwarded, X-Original-URL, …),
      Fetch-metadata/client hints (Sec-Fetch-*, Sec-CH-UA-*), the complete CORS
      family, conditional/range validators, and rate-limit headers. Done.
- [x] **Broader methods / status / content-types** — WebDAV methods
      (PROPFIND…UNLOCK, plus PURGE/TRACK/DEBUG), the remaining 1xx–5xx status
      codes (incl. 421/425/431/451/511), and many more media types
      (image/svg+xml, SOAP/XHTML, YAML, protobuf, AMF, …). Done.
- [ ] **JSON structure tips** — hovering a key path; flag likely secrets/IDs and
      IDOR-ish fields (id, uuid, role, isAdmin, token).
- [ ] **URL / query params** — hover a query key; note commonly injectable params.
- [ ] **GraphQL / API shapes** — `query`/`mutation`, `__schema`, introspection.
- [ ] **Encodings** — recognize base64 / URL-encoding / hex blobs and offer a
      decode hint (same dynamic pattern as JWT).
- [ ] **Basic-auth decode** — like JWT, decode `Basic <base64>` inline to `user:pass`.
- [ ] **Server/version → CVE hint** — when Server/X-Powered-By carries a version.
- [ ] **Per-value depth for more headers** — Vary tokens, Content-Disposition
      filename, WWW-Authenticate params, Referrer-Policy values.

## Ideas for later (beyond hover)

- A "why is this interesting?" severity dot on tokens that commonly indicate
  misconfig (e.g. `Server: Apache/2.2.3`, `ACAO: *`).
- Click-through: hover shows the gist, click opens a fuller reference panel.
- Per-token "send this to a scanner" action.

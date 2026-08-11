---
title: "Panel sessions"
nav_order: 190
summary: "signing in to the panel with a read key, and why the cookie cannot write"
status: accepted
---

# Design: signing in to the panel, without inventing a user model

**Status:** accepted · **Implemented in:** 0.11.0 · **Component:** collector

## The problem

The read-only dashboard **refuses to mount** on a collector that requires API keys,
and the refusal is correct: it is a browser page whose panels fetch `/stats`, and a
browser has nowhere to put a bearer token, so every panel would load empty. A
capability that cannot work must not look present.

The result is that the panel exists only in the evaluation mode nobody should
deploy — which makes it a demo rather than a feature.

## The decision: sign in with a read key, keep it in an httpOnly cookie

There are no users in this collector and inventing them here would mean a password
store, a reset flow and a session table before anything renders. There is already
a credential that names exactly one project and one scope: the **read-scoped API
key**.

```
POST   /session   { "token": "gdn_…" }   → 204, sets `guardana_session`
DELETE /session                          → 204, clears it
```

The cookie is `HttpOnly` (script cannot read it), `SameSite=Strict` (a third-party
page cannot cause it to be sent), and `Secure` whenever the request arrived over
HTTPS. It carries the token itself rather than a session id, because a session id
needs a table, an expiry sweeper and a revocation path — and the token already has
all three: `key revoke` ends the session, and an expired key ends it on its own.

## The rule that makes this safe

**The cookie authenticates reads and nothing else.** `POST /findings` accepts a
bearer header only. Without that rule a page on another origin could make a
signed-in operator's browser submit findings — and while `SameSite=Strict` already
prevents the request, a control that depends on one browser flag is a control that
fails the day somebody adds an exception for a proxy.

So the cookie is only consulted by the guard for `read`-scoped routes. It is a
property of *which dependency reads it*, not of what the browser sends, and a test
holds it: presenting a session cookie to ingest is refused exactly as if nothing
had been presented.

## What the panel gets, and what it does not

Signing in gives the browser exactly what the key gives: **one project**, and the
environment the key is pinned to when it is pinned. The panel shows that project
and cannot widen it — the scope on every storage call is the same one the ingest
path uses, so a signed-in browser cannot reach further than a `curl` with the same
key.

There is no "remember me", no refresh, and no idle timeout. The cookie is a
session cookie: closing the browser ends it. Anything longer needs the key's own
expiry, which is where a lifetime belongs.

## What this deliberately does not include

- **No user accounts, no passwords, no OIDC.** Those arrive with RBAC in the
  team-platform milestone, and they replace this rather than extend it.
- **No CSRF token.** Every route the cookie can reach is a `GET` that changes
  nothing, and `SameSite=Strict` covers the rest. The moment a cookie-reachable
  route changes state, this paragraph stops being true and a token is required —
  which is exactly why the read-only rule above is enforced in code rather than
  written down as guidance.
- **No sign-in page styling beyond the panel's own.** It is one form.

# hns-relay

A standards-compliant Nostr relay that knows about Handshake names.

Run by HNS.ONE at **`wss://relay.14898.hns.one`**. The code is here so anyone
can run one for their own Handshake TLD.

## What it is, in order of importance

**1. An ordinary Nostr relay.** It speaks NIP-01 and nothing exotic. Any
client reads from and writes to it, and the events it stores are plain events
that work everywhere else. If that stopped being true the project would have
built an island, which is the opposite of the point.

**2. Handshake-aware.** It can restrict writes to people who control a
Handshake name, verified over NIP-05 against that name's **own zone**. This is
**off by default** and stays off until there is adoption worth protecting: a
relay nobody can post to is a relay nobody joins.

## Running it

    go build -o hns-relay .
    ./hns-relay

It listens on `127.0.0.1:7447` and stores events in `./relay-db` (badger, pure
Go — the binary is static, no cgo, no system libraries).

| Variable | Default | Meaning |
|---|---|---|
| `HNS_RELAY_ADDR` | `127.0.0.1:7447` | listen address |
| `HNS_RELAY_DB` | `./relay-db` | event store directory |
| `HNS_RELAY_NAME` | `hns.one relay` | NIP-11 name |
| `HNS_RELAY_CONTACT` | `hello@hns.one` | NIP-11 contact |
| `HNS_RELAY_PUBKEY` | — | NIP-11 operator pubkey |
| `HNS_RELAY_MAX_CONTENT` | `65536` | reject larger events |
| `HNS_RELAY_REQUIRE_NAME` | `false` | **admission control, see below** |
| `HNS_RELAY_SUFFIX` | — | e.g. `.hns.one`, when admission is on |
| `HNS_RELAY_CACHE_MINUTES` | `60` | how long an admitted key stays admitted |

Put it behind a TLS terminator that passes websockets through. The one thing
worth saying about that config: raise `proxy_read_timeout`. A relay
subscription is a long-lived socket that is idle most of the time, and nginx's
default 60s closes it mid-conversation — which every client reports as the
relay dropping them.

## Admission control

> **DO NOT TURN THIS ON YET (2026-08-21).** The suffix test is a substring
> match on the built URL, so `{"hns":"127.0.0.1:38222/?x=.hns.one"}` both
> passes admission and makes the relay fetch loopback — an SSRF with an
> attacker-chosen target, one request per event. Validate that the claim is
> purely a hostname before building any URL from it; the browser's
> `verificationHost` in `browser/src/nostr/social-core.js` is the shape to
> copy. Until then this section describes the intent, not the behaviour.

With `HNS_RELAY_REQUIRE_NAME=true`, an event is accepted only if its author
controls a Handshake name under `HNS_RELAY_SUFFIX`. The check is:

1. read the name the author claims — the `nip05`/`hns` field of their `kind:0`,
   or a `nip05` tag;
2. fetch `https://<name>/.well-known/nostr.json?name=_`, following **no**
   redirects;
3. accept only if the document maps `_` to exactly that pubkey.

The claim in the event is worthless on its own, which is precisely why it is
safe to read it from the event: the name's own zone is what decides. A registry
index that could answer for every name would be a registry that could mint any
identity it liked, so the lookup deliberately goes to the name, not to us.

Affirmative answers are cached for `HNS_RELAY_CACHE_MINUTES`. Negative answers
are **not** cached — somebody who claims a name should be able to post seconds
later.

Rejections use the NIP-01 `restricted:` prefix, which clients render as "you
are not allowed" rather than "your event was malformed".

## Limits that apply either way

Even fully open, the relay refuses events over `HNS_RELAY_MAX_CONTENT` and
events dated more than 15 minutes in the future. The second one is not
theoretical: a future-dated event sorts to the top of every client's feed and
stays there.

## Running one for your own TLD

Nothing here is specific to `hns.one`. Set `HNS_RELAY_SUFFIX` to your TLD's
suffix, serve `/.well-known/nostr.json` from your names, and the relay admits
your holders. That is the whole integration.

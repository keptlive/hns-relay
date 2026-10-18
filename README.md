# hns-relay

A Nostr relay (NIP-01, NIP-11) that can limit writes to people who control a
name under a given domain suffix, checked with NIP-05 against the name's own
host. It is built on [khatru](https://github.com/fiatjaf/khatru) and stores
events in [badger](https://github.com/dgraph-io/badger).

hns.one runs an instance at `wss://social.hns.one`.

## Build and run

Requires Go 1.25 or later.

    CGO_ENABLED=0 go build -o hns-relay .
    ./hns-relay

The relay listens on `127.0.0.1:7447` and stores events in `./relay-db`. Put it
behind a TLS proxy that passes websockets through, and raise the proxy's read
timeout: subscriptions are long-lived and mostly idle, and nginx's default of
60 seconds closes them.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `HNS_RELAY_ADDR` | `127.0.0.1:7447` | listen address |
| `HNS_RELAY_DB` | `./relay-db` | event store directory |
| `HNS_RELAY_NAME` | `hns.one relay` | NIP-11 name |
| `HNS_RELAY_DESCRIPTION` | see `main.go` | NIP-11 description |
| `HNS_RELAY_CONTACT` | `hello@hns.one` | NIP-11 contact |
| `HNS_RELAY_PUBKEY` | none | NIP-11 operator pubkey |
| `HNS_RELAY_MAX_CONTENT` | `65536` | largest accepted event content, in bytes |
| `HNS_RELAY_REQUIRE_NAME` | `false` | turn on name admission |
| `HNS_RELAY_SUFFIX` | none | suffix admitted names must have, e.g. `.hns.one` |
| `HNS_RELAY_CACHE_MINUTES` | `60` | how long an admitted pubkey stays admitted |
| `HNS_RELAY_NEGATIVE_CACHE_MINUTES` | `5` | how long a name's lookup answer is reused |
| `HNS_RELAY_CACHE_SIZE` | `10000` | most entries in each admission cache |
| `HNS_RELAY_LOOKUPS_PER_MINUTE` | `120` | NIP-05 lookups per minute in all, `0` for no limit |
| `HNS_RELAY_IP_LOOKUPS_PER_MINUTE` | `10` | NIP-05 lookups per minute for one client address, `0` for no limit |

Whatever the admission setting, the relay rejects events whose content is
larger than `HNS_RELAY_MAX_CONTENT` and events dated more than 15 minutes in
the future.

## Name admission

Off by default. With `HNS_RELAY_REQUIRE_NAME=true`, an event is accepted only
if all of these hold:

1. It claims a name: the `hns` or `nip05` field of a kind 0 event, or a
   `nip05` tag on any other event. A leading `_@` is ignored.
2. The name is a plain DNS hostname under `HNS_RELAY_SUFFIX`: letters, digits
   and hyphens, with no port, path, user part or IP address. With no suffix
   set, any hostname passes this step.
3. `https://<name>/.well-known/nostr.json?name=_` answers 200 without a
   redirect, and its `names._` entry is the event's pubkey.

The lookup connects only to public IP addresses and reads at most 64 KiB.
Rejections carry the NIP-01 `restricted:` prefix.

Each lookup is an outbound request that anyone can cause by posting, so the
relay bounds them:

- An admitted pubkey stays admitted for `HNS_RELAY_CACHE_MINUTES`, and its
  later events need no claim.
- A name's answer, match or not, is reused for
  `HNS_RELAY_NEGATIVE_CACHE_MINUTES`. Someone who has just fixed their
  `nostr.json` may wait that long.
- Events that claim the same name at the same time share one lookup.
- The relay makes at most `HNS_RELAY_LOOKUPS_PER_MINUTE` lookups a minute, and
  `HNS_RELAY_IP_LOOKUPS_PER_MINUTE` for any one client address. An event that
  needs a lookup past either limit is rejected with the `rate-limited:` prefix.
- Each cache holds at most `HNS_RELAY_CACHE_SIZE` entries and drops the least
  recently used first.

The client address is the connection's peer, with IPv6 grouped by /64. When
the peer is a loopback or private address, the relay takes it to be its own
proxy and uses the last `X-Forwarded-For` entry instead, so the proxy should
set that header. In nginx:

    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

Without it, all clients share one address and the per-address limit acts as a
second overall limit.

To admit the holders of your own TLD, set `HNS_RELAY_SUFFIX` to it and serve
`/.well-known/nostr.json` from each name.

## Test

    go test ./...

## License

MIT. See [LICENSE](LICENSE).

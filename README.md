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
Admitted pubkeys are cached for `HNS_RELAY_CACHE_MINUTES`. Rejections are not
cached, so every rejected event costs one outbound request. Rejections carry
the NIP-01 `restricted:` prefix.

To admit the holders of your own TLD, set `HNS_RELAY_SUFFIX` to it and serve
`/.well-known/nostr.json` from each name.

## Test

    go test ./...

## License

MIT. See [LICENSE](LICENSE).

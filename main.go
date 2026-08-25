// hns-relay — a standards-compliant Nostr relay that knows about Handshake.
//
// TWO THINGS THIS IS, IN ORDER OF IMPORTANCE:
//
//  1. An ordinary Nostr relay. It speaks NIP-01 and nothing exotic. Any
//     client can read from and write to it, and the events it stores are
//     plain events that work everywhere else. If this stopped being true the
//     project would have built an island, which is the opposite of the point.
//
//  2. Handshake-aware. It can restrict writes to people who control a
//     Handshake name, verified by NIP-05 against that name's OWN zone. That
//     is switched OFF by default and stays off until there is adoption worth
//     protecting: a relay nobody can post to is a relay nobody joins.
//
// Anyone can run this for their own TLD — set HNS_RELAY_SUFFIX and turn
// HNS_RELAY_REQUIRE_NAME on, and the relay admits that TLD's holders.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fiatjaf/eventstore/badger"
	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v, err := strconv.ParseBool(env(key, ""))
	if err != nil {
		return fallback
	}
	return v
}

// ---------------------------------------------------------------- NIP-05

type nip05Doc struct {
	Names map[string]string `json:"names"`
}

// nameChecker answers "does this pubkey control a name under our suffix?",
// with a cache, because the answer costs a network round trip and a relay is
// asked it on every single event.
type nameChecker struct {
	suffix  string
	ttl     time.Duration
	client  *http.Client
	mu      sync.Mutex
	cache   map[string]cacheEntry
}

type cacheEntry struct {
	name string
	when time.Time
}

func newNameChecker(suffix string, ttl time.Duration) *nameChecker {
	return &nameChecker{
		suffix: suffix,
		ttl:    ttl,
		client: &http.Client{
			Timeout: 6 * time.Second,
			// NIP-05 forbids following redirects on this lookup: a redirect
			// means some other host is answering for the name, which is
			// exactly the substitution the check exists to prevent.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		cache: map[string]cacheEntry{},
	}
}

// verify fetches the name's own NIP-05 document and reports whether it names
// this pubkey. The lookup goes to the NAME's zone, never to a registry index:
// a registry that could answer for every name is a registry that could mint
// any identity it liked.
func (n *nameChecker) verify(ctx context.Context, name, pubkey string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if n.suffix != "" && !strings.HasSuffix(name, n.suffix) {
		return false
	}
	url := fmt.Sprintf("https://%s/.well-known/nostr.json?name=_", name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	res, err := n.client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return false
	}
	var doc nip05Doc
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return false
	}
	return strings.EqualFold(doc.Names["_"], pubkey)
}

// admits reports whether a pubkey may write, caching the affirmative answer.
// A negative is NOT cached: someone who claims a name should be able to post
// seconds later, and re-asking costs one request against an empty relay.
func (n *nameChecker) admits(ctx context.Context, event *nostr.Event) bool {
	n.mu.Lock()
	entry, ok := n.cache[event.PubKey]
	n.mu.Unlock()
	if ok && time.Since(entry.when) < n.ttl {
		return true
	}
	// The name comes from the author's own kind:0, then is CHECKED against
	// that name's zone. Taking it from the event is fine precisely because
	// the claim is worthless until the zone agrees.
	name := claimedName(event)
	if name == "" {
		return false
	}
	if !n.verify(ctx, name, event.PubKey) {
		return false
	}
	n.mu.Lock()
	n.cache[event.PubKey] = cacheEntry{name: name, when: time.Now()}
	n.mu.Unlock()
	return true
}

// claimedName reads a name out of an event: the `nip05`/`hns` fields of a
// kind:0, or a `nip05` tag on anything else.
func claimedName(event *nostr.Event) string {
	if event.Kind == 0 {
		var meta struct {
			Nip05 string `json:"nip05"`
			HNS   string `json:"hns"`
		}
		if err := json.Unmarshal([]byte(event.Content), &meta); err == nil {
			if meta.HNS != "" {
				return strings.TrimPrefix(meta.HNS, "_@")
			}
			if meta.Nip05 != "" {
				return strings.TrimPrefix(meta.Nip05, "_@")
			}
		}
	}
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "nip05" {
			return strings.TrimPrefix(tag[1], "_@")
		}
	}
	return ""
}

// ---------------------------------------------------------------- main

func main() {
	relay := khatru.NewRelay()
	relay.Info.Name = env("HNS_RELAY_NAME", "hns.one relay")
	relay.Info.Description = env("HNS_RELAY_DESCRIPTION",
		"An ordinary Nostr relay, run by hns.one, that also understands Handshake names.")
	relay.Info.PubKey = os.Getenv("HNS_RELAY_PUBKEY")
	relay.Info.Contact = env("HNS_RELAY_CONTACT", "hello@hns.one")
	relay.Info.Software = "https://github.com/hnsone/hns-relay"
	relay.Info.SupportedNIPs = []any{1, 11, 42, 70}

	dbPath := env("HNS_RELAY_DB", "./relay-db")
	db := badger.BadgerBackend{Path: dbPath}
	if err := db.Init(); err != nil {
		log.Fatalf("cannot open %s: %v", dbPath, err)
	}
	defer db.Close()

	relay.StoreEvent = append(relay.StoreEvent, db.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, db.QueryEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, db.DeleteEvent)
	relay.CountEvents = append(relay.CountEvents, db.CountEvents)
	relay.ReplaceEvent = append(relay.ReplaceEvent, db.ReplaceEvent)

	// Size limits apply whatever the admission policy is. An open relay with
	// no ceiling is a free disk for whoever finds it first.
	maxContent, _ := strconv.Atoi(env("HNS_RELAY_MAX_CONTENT", "65536"))
	relay.RejectEvent = append(relay.RejectEvent,
		func(ctx context.Context, event *nostr.Event) (bool, string) {
			if len(event.Content) > maxContent {
				return true, fmt.Sprintf("invalid: content over %d bytes", maxContent)
			}
			// Refuse events dated far in the future: they sort to the top of
			// every client's feed and stay there.
			if event.CreatedAt.Time().After(time.Now().Add(15 * time.Minute)) {
				return true, "invalid: created_at is in the future"
			}
			return false, ""
		})

	// HNS admission. OFF by default, on purpose: until there is adoption to
	// protect, a relay that turns strangers away is a relay that never gets
	// any. The code is here, tested and ready, for the day that flips.
	if envBool("HNS_RELAY_REQUIRE_NAME", false) {
		suffix := env("HNS_RELAY_SUFFIX", "")
		ttl := time.Duration(mustInt(env("HNS_RELAY_CACHE_MINUTES", "60"))) * time.Minute
		checker := newNameChecker(suffix, ttl)
		relay.RejectEvent = append(relay.RejectEvent,
			func(ctx context.Context, event *nostr.Event) (bool, string) {
				if checker.admits(ctx, event) {
					return false, ""
				}
				// "restricted:" is the NIP-01 prefix clients understand as
				// "you are not allowed", as opposed to "your event is bad".
				// Say what is actually required. "Publish a kind:0 first" was
				// the obvious wording and it is wrong: the kind:0 is checked
				// by the same rule, so the missing piece is never the event --
				// it is the name's own NIP-05 document.
				return true, "restricted: this relay serves Handshake name holders. " +
					"Set your nip05 to a name whose /.well-known/nostr.json " +
					"resolves to your pubkey, then try again"
			})
		log.Printf("admission: Handshake names only (suffix %q)", suffix)
	} else {
		log.Printf("admission: OPEN — anyone may publish")
	}

	addr := env("HNS_RELAY_ADDR", "127.0.0.1:7447")
	log.Printf("hns-relay listening on %s, store %s", addr, dbPath)
	if err := http.ListenAndServe(addr, relay); err != nil {
		log.Fatal(err)
	}
}

func mustInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 60
	}
	return n
}

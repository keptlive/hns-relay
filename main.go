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
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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

	// Name admission is off by default; see admission.go.
	if envBool("HNS_RELAY_REQUIRE_NAME", false) {
		suffix := env("HNS_RELAY_SUFFIX", "")
		if !validSuffix(suffix) {
			log.Fatalf("HNS_RELAY_SUFFIX %q is not a DNS suffix", suffix)
		}
		ttl := time.Duration(mustInt(env("HNS_RELAY_CACHE_MINUTES", "60"))) * time.Minute
		checker := newNameChecker(suffix, ttl)
		relay.RejectEvent = append(relay.RejectEvent,
			func(ctx context.Context, event *nostr.Event) (bool, string) {
				if checker.admits(ctx, event) {
					return false, ""
				}
				// "restricted:" is the NIP-01 prefix for "not allowed", as
				// opposed to "invalid:" for a malformed event. The kind:0 is
				// checked by the same rule, so the fix is always the name's
				// NIP-05 document, not another event.
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

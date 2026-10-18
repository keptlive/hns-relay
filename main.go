// hns-relay is a Nostr relay (NIP-01, NIP-11) that can limit writes to
// holders of names under a domain suffix, checked with NIP-05 against each
// name's own host. The check is off by default; see admission.go.
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

// envInt reads a non-negative integer, falling back when the variable is
// unset or malformed.
func envInt(key string, fallback int) int {
	n, err := strconv.Atoi(env(key, ""))
	if err != nil || n < 0 {
		return fallback
	}
	return n
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
	relay.Info.Software = "https://github.com/keptlive/hns-relay"
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

	// These limits apply whatever the admission policy is.
	relay.RejectEvent = append(relay.RejectEvent,
		eventLimits(envInt("HNS_RELAY_MAX_CONTENT", 65536)))

	// Name admission is off by default; see admission.go.
	if envBool("HNS_RELAY_REQUIRE_NAME", false) {
		suffix := env("HNS_RELAY_SUFFIX", "")
		if !validSuffix(suffix) {
			log.Fatalf("HNS_RELAY_SUFFIX %q is not a DNS suffix", suffix)
		}
		ttl := time.Duration(envInt("HNS_RELAY_CACHE_MINUTES", 60)) * time.Minute
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
		log.Printf("admission: open to anyone")
	}

	addr := env("HNS_RELAY_ADDR", "127.0.0.1:7447")
	log.Printf("hns-relay listening on %s, store %s", addr, dbPath)
	if err := http.ListenAndServe(addr, relay); err != nil {
		log.Fatal(err)
	}
}

// eventLimits rejects events whose content is over maxContent bytes, and
// events dated more than 15 minutes ahead, which would otherwise sit at the
// top of every client's feed.
func eventLimits(maxContent int) func(context.Context, *nostr.Event) (bool, string) {
	return func(_ context.Context, event *nostr.Event) (bool, string) {
		if len(event.Content) > maxContent {
			return true, fmt.Sprintf("invalid: content over %d bytes", maxContent)
		}
		if event.CreatedAt.Time().After(time.Now().Add(15 * time.Minute)) {
			return true, "invalid: created_at is in the future"
		}
		return false, ""
	}
}

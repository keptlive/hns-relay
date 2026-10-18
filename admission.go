package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

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

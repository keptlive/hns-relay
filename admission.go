package main

// Name admission. When HNS_RELAY_REQUIRE_NAME is on, an event is accepted
// only if its author claims a name under HNS_RELAY_SUFFIX and that name's
// own /.well-known/nostr.json maps "_" to the author's pubkey.
//
// The claimed name comes from a stranger's event and ends up in a URL, so it
// must be a bare DNS hostname before anything is fetched, and the HTTP client
// connects only to public addresses.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// maxNIP05Body bounds how much of a NIP-05 document is read.
const maxNIP05Body = 64 << 10

type nip05Doc struct {
	Names map[string]string `json:"names"`
}

// nameChecker answers "does this pubkey control a name under our suffix?",
// caching positive answers because the relay asks on every event.
type nameChecker struct {
	suffix string // "" (any name) or a lower-case suffix with a leading dot
	ttl    time.Duration
	client *http.Client
	mu     sync.Mutex
	cache  map[string]cacheEntry
}

type cacheEntry struct {
	name string
	when time.Time
}

func newNameChecker(suffix string, ttl time.Duration) *nameChecker {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: publicOnly}
	return &nameChecker{
		suffix: normalizeSuffix(suffix),
		ttl:    ttl,
		client: &http.Client{
			Timeout: 6 * time.Second,
			// No proxy: the dialer's address check must see the real target.
			Transport: &http.Transport{
				DialContext:            dialer.DialContext,
				TLSHandshakeTimeout:    5 * time.Second,
				MaxResponseHeaderBytes: 16 << 10,
			},
			// NIP-05 forbids following redirects on this lookup: a redirect
			// means another host is answering for the name.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		cache: map[string]cacheEntry{},
	}
}

// normalizeSuffix turns "hns.one", ".hns.one" or "HNS.ONE." into ".hns.one",
// so the suffix test always falls on a label boundary.
func normalizeSuffix(s string) string {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
	if s == "" {
		return ""
	}
	return "." + s
}

// validSuffix reports whether a configured suffix is made of DNS labels.
func validSuffix(s string) bool {
	s = strings.TrimPrefix(normalizeSuffix(s), ".")
	if s == "" {
		return true
	}
	for _, label := range strings.Split(s, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

// hostname returns claim as a lower-case DNS hostname, or "" if it is
// anything else. Accepted: two or more letter-digit-hyphen labels of 1-63
// bytes, 253 bytes in all, one optional trailing dot. Rejected: ports,
// paths, queries, fragments, userinfo, IP literals, non-ASCII, single labels.
func hostname(claim string) string {
	name := strings.TrimSuffix(strings.TrimSpace(claim), ".")
	if name == "" || len(name) > 253 {
		return ""
	}
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return ""
		}
	}
	name = strings.ToLower(name)
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, label := range labels {
		if !validLabel(label) {
			return ""
		}
	}
	// An all-digit last label makes the name an IPv4 address, not a host.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return ""
	}
	return name
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// publicOnly is a net.Dialer Control hook. It runs after DNS resolution, on
// the address actually being dialled, so a name that resolves to loopback or
// a private network is refused as well as a literal one.
func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if !isPublic(ip) {
		return fmt.Errorf("refusing to connect to non-public address %s", ip)
	}
	return nil
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10") // RFC 6598

// isPublic reports whether ip is a globally routable unicast address.
func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !sharedAddressSpace.Contains(ip)
}

var errNotHostname = errors.New("claimed name is not a hostname under the suffix")

// nip05URL returns the NIP-05 lookup URL for a claimed name, or an error if
// the claim is not a hostname under the configured suffix.
func (n *nameChecker) nip05URL(claim string) (string, error) {
	host := hostname(claim)
	if host == "" || (n.suffix != "" && !strings.HasSuffix(host, n.suffix)) {
		return "", errNotHostname
	}
	u := url.URL{Scheme: "https", Host: host, Path: "/.well-known/nostr.json", RawQuery: "name=_"}
	return u.String(), nil
}

// verify fetches the name's own NIP-05 document and reports whether it maps
// "_" to this pubkey. The lookup goes to the name's host, never to a
// registry index.
func (n *nameChecker) verify(ctx context.Context, claim, pubkey string) bool {
	target, err := n.nip05URL(claim)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	res, err := n.client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false
	}
	var doc nip05Doc
	if err := json.NewDecoder(io.LimitReader(res.Body, maxNIP05Body)).Decode(&doc); err != nil {
		return false
	}
	return strings.EqualFold(doc.Names["_"], pubkey)
}

// admits reports whether a pubkey may write, caching the affirmative answer.
// A negative is not cached, so someone who has just set up their name can
// post straight away.
func (n *nameChecker) admits(ctx context.Context, event *nostr.Event) bool {
	n.mu.Lock()
	entry, ok := n.cache[event.PubKey]
	n.mu.Unlock()
	if ok && time.Since(entry.when) < n.ttl {
		return true
	}
	// The claim is read from the event and is worth nothing until the
	// name's own NIP-05 document agrees with it.
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

// claimedName reads a name out of an event: the `hns` or `nip05` field of a
// kind:0, or a `nip05` tag on anything else. A leading "_@" is dropped.
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

package main

// Name admission. When HNS_RELAY_REQUIRE_NAME is on, an event is accepted
// only if its author claims a name under HNS_RELAY_SUFFIX and that name's
// own /.well-known/nostr.json maps "_" to the author's pubkey.
//
// The claimed name comes from a stranger's event and ends up in a URL, so it
// must be a bare DNS hostname before anything is fetched, and the HTTP client
// connects only to public addresses.
//
// Every lookup is an outbound request a stranger can cause, so lookups are
// shared, remembered and rationed: events that claim the same name at the
// same time wait for one fetch, a name's answer is reused for a few minutes,
// and fetches per minute are capped in all and per client address.

import (
	"container/list"
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

// checkerConfig holds the admission settings. A lookup limit of 0 means no
// limit.
type checkerConfig struct {
	ttl          time.Duration // how long an admitted pubkey stays admitted
	negativeTTL  time.Duration // how long a name's lookup answer is reused
	cacheSize    int           // most entries in each cache
	lookups      int           // outbound lookups per minute, in all
	lookupsPerIP int           // outbound lookups per minute for one client address
}

// nameChecker answers "does this pubkey control a name under our suffix?".
type nameChecker struct {
	suffix string // "" (any name) or a lower-case suffix with a leading dot
	client *http.Client
	now    func() time.Time

	mu       sync.Mutex
	admitted *lru               // pubkey -> the name it was admitted with
	answers  *lru               // lookup URL -> the pubkey it named, "" if the lookup failed
	inflight map[string]*lookup // lookups being fetched, by URL
	limit    lookupLimit
}

// lookup is one NIP-05 fetch in progress.
type lookup struct {
	done  chan struct{}
	owner string // set before done is closed
}

func newNameChecker(suffix string, cfg checkerConfig) *nameChecker {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: publicOnly}
	return &nameChecker{
		suffix: normalizeSuffix(suffix),
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
		now:      time.Now,
		admitted: newLRU(cfg.cacheSize, cfg.ttl),
		answers:  newLRU(cfg.cacheSize, cfg.negativeTTL),
		inflight: map[string]*lookup{},
		limit:    lookupLimit{total: cfg.lookups, perIP: cfg.lookupsPerIP},
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

var (
	errNotAdmitted = errors.New("no verified name under the suffix")
	errRateLimited = errors.New("too many name lookups")
)

// admits reports whether an event's author may write: nil if so,
// errRateLimited if deciding needs a lookup that is over the limit, and
// errNotAdmitted otherwise. ip is the client address the event came from.
func (n *nameChecker) admits(ctx context.Context, ip string, event *nostr.Event) error {
	n.mu.Lock()
	_, ok := n.admitted.get(event.PubKey, n.now())
	n.mu.Unlock()
	if ok {
		return nil
	}
	// The claim is read from the event and is worth nothing until the
	// name's own NIP-05 document agrees with it.
	target, err := n.nip05URL(claimedName(event))
	if err != nil {
		return errNotAdmitted
	}
	owner, err := n.owner(ctx, ip, target)
	if err != nil {
		return err
	}
	if owner == "" || !strings.EqualFold(owner, event.PubKey) {
		return errNotAdmitted
	}
	n.mu.Lock()
	n.admitted.put(event.PubKey, target, n.now())
	n.mu.Unlock()
	return nil
}

// owner returns the pubkey that target maps "_" to, or "" if the lookup
// fails. A recent answer is reused, an event that arrives while the same
// lookup is running waits for it, and only a new fetch counts against the
// limits.
func (n *nameChecker) owner(ctx context.Context, ip, target string) (string, error) {
	n.mu.Lock()
	if owner, ok := n.answers.get(target, n.now()); ok {
		n.mu.Unlock()
		return owner, nil
	}
	if l, ok := n.inflight[target]; ok {
		n.mu.Unlock()
		<-l.done // the client timeout bounds the wait
		return l.owner, nil
	}
	if !n.limit.allow(ip, n.now()) {
		n.mu.Unlock()
		return "", errRateLimited
	}
	l := &lookup{done: make(chan struct{})}
	n.inflight[target] = l
	n.mu.Unlock()

	// The fetch is not cancelled with the event that started it: others
	// may be waiting for it, and one client hanging up must not record a
	// failed lookup against someone else's name.
	l.owner = n.fetch(context.WithoutCancel(ctx), target)

	n.mu.Lock()
	n.answers.put(target, l.owner, n.now())
	delete(n.inflight, target)
	n.mu.Unlock()
	close(l.done)
	return l.owner, nil
}

// fetch reads a name's own NIP-05 document and returns the pubkey it maps
// "_" to, or "" if it cannot. The lookup goes to the name's host, never to
// a registry index.
func (n *nameChecker) fetch(ctx context.Context, target string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ""
	}
	res, err := n.client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	var doc nip05Doc
	if err := json.NewDecoder(io.LimitReader(res.Body, maxNIP05Body)).Decode(&doc); err != nil {
		return ""
	}
	return doc.Names["_"]
}

// lookupLimit counts outbound lookups in the current minute, in all and per
// client address. A limit of 0 means no limit. Callers hold nameChecker.mu.
type lookupLimit struct {
	total, perIP int
	window       time.Time
	count        int
	byIP         map[string]int
}

// allow reports whether one more lookup fits in this minute, and counts it
// if so. An address gets an entry only when a lookup is allowed, so with a
// total limit the map never holds more than that many addresses.
func (l *lookupLimit) allow(ip string, now time.Time) bool {
	if now.Sub(l.window) >= time.Minute {
		l.window, l.count, l.byIP = now, 0, map[string]int{}
	}
	if l.total > 0 && l.count >= l.total || l.perIP > 0 && l.byIP[ip] >= l.perIP {
		return false
	}
	l.count++
	if l.perIP > 0 {
		l.byIP[ip]++
	}
	return true
}

// clientAddress returns the address an event's connection came from, as a
// key for the per-address lookup limit. A connection from a loopback or
// private address is taken to be the relay's own proxy, and the client is
// the last X-Forwarded-For entry, the one that proxy added; earlier entries
// were sent by the client and prove nothing. IPv6 addresses are grouped by
// /64, the usual size of one customer's network.
func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if peer, err := netip.ParseAddr(host); err == nil && (peer.IsLoopback() || peer.Unmap().IsPrivate()) {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			entries := strings.Split(xff[len(xff)-1], ",")
			if last := strings.TrimSpace(entries[len(entries)-1]); last != "" {
				host = last
			}
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() && !ip.Is4In6() {
		prefix, _ := ip.Prefix(64)
		return prefix.String()
	}
	return host
}

// lru is a map from string to string with a size bound and an expiry. When
// it is full the least recently used entry is dropped. Callers hold
// nameChecker.mu.
type lru struct {
	max   int
	ttl   time.Duration
	order *list.List               // most recently used first; values are *lruEntry
	items map[string]*list.Element // by key
}

type lruEntry struct {
	key, value string
	expires    time.Time
}

func newLRU(max int, ttl time.Duration) *lru {
	return &lru{max: max, ttl: ttl, order: list.New(), items: map[string]*list.Element{}}
}

func (c *lru) get(key string, now time.Time) (string, bool) {
	el, ok := c.items[key]
	if !ok {
		return "", false
	}
	entry := el.Value.(*lruEntry)
	if !now.Before(entry.expires) {
		c.order.Remove(el)
		delete(c.items, key)
		return "", false
	}
	c.order.MoveToFront(el)
	return entry.value, true
}

func (c *lru) put(key, value string, now time.Time) {
	if el, ok := c.items[key]; ok {
		el.Value = &lruEntry{key, value, now.Add(c.ttl)}
		c.order.MoveToFront(el)
	} else {
		c.items[key] = c.order.PushFront(&lruEntry{key, value, now.Add(c.ttl)})
	}
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*lruEntry).key)
	}
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

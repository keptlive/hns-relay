package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

const testPubkey = "c3b1f2e8a1d4b5c6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e"

// testConfig caches but sets no lookup limits.
var testConfig = checkerConfig{ttl: time.Hour, negativeTTL: 5 * time.Minute, cacheSize: 100}

func TestHostnameAccepts(t *testing.T) {
	for claim, want := range map[string]string{
		"alice.hns.one":                  "alice.hns.one",
		"Alice.HNS.One":                  "alice.hns.one",
		"alice.hns.one.":                 "alice.hns.one",
		" alice.hns.one ":                "alice.hns.one",
		"a-b.c1.hns.one":                 "a-b.c1.hns.one",
		"xn--bcher-kva.hns.one":          "xn--bcher-kva.hns.one",
		"1.2.3.hns.one":                  "1.2.3.hns.one",
		"alice.wildroot":                 "alice.wildroot",
		strings.Repeat("a", 63) + ".one": strings.Repeat("a", 63) + ".one",
	} {
		if got := hostname(claim); got != want {
			t.Errorf("hostname(%q) = %q, want %q", claim, got, want)
		}
	}
}

func TestHostnameRejects(t *testing.T) {
	long := strings.Repeat(strings.Repeat("a", 63)+".", 4) + "one" // 259 bytes
	for _, claim := range []string{
		"",
		".",
		"localhost",
		"hns",
		"evil.com#.hns.one",
		"evil.com/.hns.one",
		"evil.com?.hns.one",
		"evil.com\\.hns.one",
		"127.0.0.1:38222/?x=.hns.one",
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"0x7f.0.0.1",
		"[::1]",
		"::1",
		"a.b.hns.one:8080",
		"user@x.hns.one",
		"_@alice.hns.one",
		"https://alice.hns.one",
		"alice..hns.one",
		".alice.hns.one",
		"alice.hns.one..",
		"-alice.hns.one",
		"alice-.hns.one",
		"al_ice.hns.one",
		"al ice.hns.one",
		"alice.hns\n.one",
		"alice.hns.one%00",
		"alice\x00.hns.one",
		"Kelvin.hns.one", // KELVIN SIGN lower-cases to ASCII "k"
		"bücher.hns.one",
		strings.Repeat("a", 64) + ".one",
		long,
	} {
		if got := hostname(claim); got != "" {
			t.Errorf("hostname(%q) = %q, want rejection", claim, got)
		}
	}
}

func TestSuffix(t *testing.T) {
	for in, want := range map[string]string{
		"":         "",
		"hns.one":  ".hns.one",
		".hns.one": ".hns.one",
		"HNS.ONE.": ".hns.one",
		" .14898 ": ".14898",
	} {
		if got := normalizeSuffix(in); got != want {
			t.Errorf("normalizeSuffix(%q) = %q, want %q", in, got, want)
		}
	}
	for _, s := range []string{"", ".hns.one", "hns.one", "14898"} {
		if !validSuffix(s) {
			t.Errorf("validSuffix(%q) = false", s)
		}
	}
	for _, s := range []string{".hns.one:443", "hns.one/x", "a..b", "-x.one"} {
		if validSuffix(s) {
			t.Errorf("validSuffix(%q) = true", s)
		}
	}
}

func TestNIP05URL(t *testing.T) {
	n := newNameChecker(".hns.one", testConfig)
	got, err := n.nip05URL("Alice.HNS.one.")
	if err != nil || got != "https://alice.hns.one/.well-known/nostr.json?name=_" {
		t.Fatalf("nip05URL = %q, %v", got, err)
	}
	for _, claim := range []string{
		"alice.example.com", // outside the suffix
		"evilhns.one",       // suffix match must fall on a label boundary
		"hns.one",           // the suffix itself is not a name under it
		"alice.hns.one.evil.com",
		"127.0.0.1:38222/?x=.hns.one",
		"evil.com#.hns.one",
	} {
		if got, err := n.nip05URL(claim); err == nil {
			t.Errorf("nip05URL(%q) = %q, want error", claim, got)
		}
	}

	// A suffix configured without its leading dot behaves the same.
	if _, err := newNameChecker("hns.one", testConfig).nip05URL("evilhns.one"); err == nil {
		t.Error(`suffix "hns.one" admitted "evilhns.one"`)
	}

	// With no suffix any hostname is looked up, but still only a hostname.
	open := newNameChecker("", testConfig)
	if _, err := open.nip05URL("alice.example.com"); err != nil {
		t.Errorf("no suffix: %v", err)
	}
	if _, err := open.nip05URL("127.0.0.1"); err == nil {
		t.Error("no suffix: accepted an IP literal")
	}
}

func TestIsPublic(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "255.255.255.255",
		"224.0.0.1", "::", "::1", "fe80::1", "fc00::1", "fd12::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "ff02::1",
	} {
		if isPublic(netip.MustParseAddr(s)) {
			t.Errorf("isPublic(%s) = true", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "93.184.215.14", "2606:4700:4700::1111", "::ffff:1.1.1.1"} {
		if !isPublic(netip.MustParseAddr(s)) {
			t.Errorf("isPublic(%s) = false", s)
		}
	}
}

// The real client refuses to connect to a loopback server even when asked
// for it directly, so a name whose DNS points inward is refused too.
func TestClientRefusesLoopback(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	n := newNameChecker("", testConfig)
	n.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	_, err := n.client.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("want a non-public refusal, got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("server saw %d requests", n)
	}
}

// nip05Server is a TLS server that the checker reaches whatever host it
// asks for. It records each dialled address and each request.
type nip05Server struct {
	*httptest.Server
	mu       sync.Mutex
	dials    []string
	requests []string
}

func newNIP05Server(t *testing.T, handler http.HandlerFunc) (*nip05Server, *nameChecker) {
	return newNIP05ServerWith(t, testConfig, handler)
}

func newNIP05ServerWith(t *testing.T, cfg checkerConfig, handler http.HandlerFunc) (*nip05Server, *nameChecker) {
	t.Helper()
	s := &nip05Server{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Host+r.URL.RequestURI())
		s.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	n := newNameChecker(".hns.one", cfg)
	tr := n.client.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		s.mu.Lock()
		s.dials = append(s.dials, addr)
		s.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, s.Listener.Addr().String())
	}
	return s, n
}

func (s *nip05Server) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.dials), len(s.requests)
}

func serveNames(pubkey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"names":{"_":"`+pubkey+`"}}`)
	}
}

// claim returns a kind:1 event from pubkey with name in a nip05 tag.
func claim(pubkey, name string) *nostr.Event {
	return &nostr.Event{PubKey: pubkey, Kind: 1, Tags: nostr.Tags{{"nip05", name}}}
}

func TestAdmitsFetchesOnlyTheNamedHost(t *testing.T) {
	s, n := newNIP05Server(t, serveNames(testPubkey))
	if err := n.admits(context.Background(), "", claim(testPubkey, "Alice.hns.one")); err != nil {
		t.Fatalf("rejected a matching document: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.dials) != 1 || s.dials[0] != "alice.hns.one:443" {
		t.Fatalf("dials = %v", s.dials)
	}
	if len(s.requests) != 1 || s.requests[0] != "alice.hns.one/.well-known/nostr.json?name=_" {
		t.Fatalf("requests = %v", s.requests)
	}
}

func TestAdmitsRejects(t *testing.T) {
	ctx := context.Background()
	for what, handler := range map[string]http.HandlerFunc{
		"a document naming another pubkey": serveNames(strings.Repeat("0", 64)),
		"a redirect": func(w http.ResponseWriter, r *http.Request) {
			if r.Host == "alice.hns.one" {
				http.Redirect(w, r, "https://elsewhere.hns.one/.well-known/nostr.json?name=_", http.StatusFound)
				return
			}
			serveNames(testPubkey)(w, r)
		},
		"a non-200 response": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			serveNames(testPubkey)(w, r)
		},
		"a document past the body limit": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strings.Repeat(" ", maxNIP05Body))
			serveNames(testPubkey)(w, r)
		},
	} {
		_, n := newNIP05Server(t, handler)
		if err := n.admits(ctx, "", claim(testPubkey, "alice.hns.one")); err != errNotAdmitted {
			t.Errorf("%s: admits = %v, want errNotAdmitted", what, err)
		}
	}

	// A document with no "_" entry does not admit an event with no pubkey.
	_, n := newNIP05Server(t, serveNames(""))
	if err := n.admits(ctx, "", claim("", "alice.hns.one")); err != errNotAdmitted {
		t.Errorf("empty pubkey: admits = %v, want errNotAdmitted", err)
	}
}

func TestAdmitsMakesNoRequestForBadClaims(t *testing.T) {
	s, n := newNIP05Server(t, serveNames(testPubkey))
	for _, name := range []string{
		"127.0.0.1:38222/?x=.hns.one",
		"evil.com#.hns.one",
		"evil.com/.hns.one",
		"user@evil.com/.hns.one",
		"a.b.hns.one:8080",
		"alice.example.com",
		"evilhns.one",
	} {
		if err := n.admits(context.Background(), "", claim(testPubkey, name)); err != errNotAdmitted {
			t.Errorf("claim %q: admits = %v, want errNotAdmitted", name, err)
		}
	}
	if dials, reqs := s.counts(); dials != 0 || reqs != 0 {
		t.Fatalf("bad claims caused %d dials and %d requests", dials, reqs)
	}
}

func TestAdmitsReusesAnswers(t *testing.T) {
	var mu sync.Mutex
	owner := strings.Repeat("0", 64)
	s, n := newNIP05Server(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pk := owner
		mu.Unlock()
		serveNames(pk)(w, r)
	})
	clock := time.Now()
	n.now = func() time.Time { return clock }
	ctx := context.Background()
	other := strings.Repeat("1", 64)
	requests := func(want int) {
		t.Helper()
		if _, reqs := s.counts(); reqs != want {
			t.Fatalf("%d requests, want %d", reqs, want)
		}
	}

	// A rejection is remembered for the name, whoever claims it next.
	for _, pk := range []string{testPubkey, testPubkey, other} {
		if n.admits(ctx, "", claim(pk, "_@alice.hns.one")) == nil {
			t.Fatal("admitted a key the document does not name")
		}
	}
	requests(1)

	// The owner fixes the document. The old answer stands until it expires.
	mu.Lock()
	owner = testPubkey
	mu.Unlock()
	clock = clock.Add(testConfig.negativeTTL - time.Second)
	if n.admits(ctx, "", claim(testPubkey, "alice.hns.one")) == nil {
		t.Fatal("looked up again before the answer expired")
	}
	clock = clock.Add(time.Second)
	if err := n.admits(ctx, "", claim(testPubkey, "alice.hns.one")); err != nil {
		t.Fatalf("not admitted once the answer expired: %v", err)
	}
	requests(2)

	// An admitted key needs no claim and no lookup until its own TTL ends.
	noClaim := &nostr.Event{PubKey: testPubkey, Kind: 1}
	clock = clock.Add(testConfig.ttl - time.Second)
	if err := n.admits(ctx, "", noClaim); err != nil {
		t.Fatalf("admitted key rejected within its TTL: %v", err)
	}
	clock = clock.Add(time.Second)
	if n.admits(ctx, "", noClaim) == nil {
		t.Fatal("still admitted after the TTL")
	}
	if n.admits(ctx, "", &nostr.Event{PubKey: other, Kind: 1}) == nil {
		t.Fatal("admitted an event with no claim")
	}
	requests(2)
}

func TestAdmitsSharesOneLookup(t *testing.T) {
	entered := make(chan struct{}, 100)
	release := make(chan struct{})
	cfg := testConfig
	cfg.lookups = 1 // a shared lookup counts once against the limit
	s, n := newNIP05ServerWith(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		serveNames(strings.Repeat("0", 64))(w, r)
	})
	var once sync.Once
	releaseAll := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseAll) // runs before the server's Close, which waits for handlers

	const events = 20
	errs := make(chan error, events)
	for i := 0; i < events; i++ {
		go func() { errs <- n.admits(context.Background(), "", claim(testPubkey, "alice.hns.one")) }()
	}
	<-entered
	// Give the other events time to arrive. Without sharing, each would
	// make its own request or be refused by the limit.
	time.Sleep(100 * time.Millisecond)
	releaseAll()
	for i := 0; i < events; i++ {
		if err := <-errs; err != errNotAdmitted {
			t.Errorf("admits = %v, want errNotAdmitted", err)
		}
	}
	if _, reqs := s.counts(); reqs != 1 {
		t.Fatalf("%d events made %d requests, want 1", events, reqs)
	}
}

func TestAdmitsLimitsLookups(t *testing.T) {
	cfg := testConfig
	cfg.lookups, cfg.lookupsPerIP = 3, 2
	s, n := newNIP05ServerWith(t, cfg, serveNames(strings.Repeat("0", 64)))
	clock := time.Now()
	n.now = func() time.Time { return clock }
	try := func(ip, label string) error {
		return n.admits(context.Background(), ip, claim(testPubkey, label+".hns.one"))
	}
	for _, step := range []struct {
		ip, label string
		want      error
	}{
		{"192.0.2.1", "a", errNotAdmitted},
		{"192.0.2.1", "b", errNotAdmitted},
		{"192.0.2.1", "c", errRateLimited}, // over the per-address limit
		{"192.0.2.1", "a", errNotAdmitted}, // a remembered answer costs no lookup
		{"192.0.2.2", "c", errNotAdmitted},
		{"192.0.2.3", "d", errRateLimited}, // over the total
	} {
		if err := try(step.ip, step.label); err != step.want {
			t.Errorf("%s claiming %s: admits = %v, want %v", step.ip, step.label, err, step.want)
		}
	}
	if _, reqs := s.counts(); reqs != 3 {
		t.Fatalf("%d requests, want 3", reqs)
	}
	clock = clock.Add(time.Minute)
	if err := try("192.0.2.3", "d"); err != errNotAdmitted {
		t.Errorf("next minute: admits = %v, want errNotAdmitted", err)
	}
}

// A client that hangs up mid-lookup must not leave a failed answer behind
// for the name.
func TestAdmitsLookupOutlivesItsEvent(t *testing.T) {
	_, n := newNIP05Server(t, serveNames(testPubkey))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := n.admits(ctx, "", claim(testPubkey, "alice.hns.one")); err != nil {
		t.Fatalf("admits with a cancelled context = %v, want nil", err)
	}
}

func TestLookupLimitWithoutLimits(t *testing.T) {
	var l lookupLimit
	now := time.Now()
	for i := 0; i < 1000; i++ {
		if !l.allow("192.0.2.1", now) {
			t.Fatalf("refused lookup %d with no limits set", i)
		}
	}
	if len(l.byIP) != 0 {
		t.Errorf("tracked %d addresses with no per-address limit", len(l.byIP))
	}
}

func TestLRU(t *testing.T) {
	now := time.Now()
	c := newLRU(2, time.Minute)
	c.put("a", "1", now)
	c.put("b", "2", now)
	c.get("a", now) // a is now the most recently used
	c.put("c", "3", now)
	if _, ok := c.get("b", now); ok {
		t.Error("kept the least recently used entry")
	}
	for key, want := range map[string]string{"a": "1", "c": "3"} {
		if got, ok := c.get(key, now); !ok || got != want {
			t.Errorf("get(%q) = %q, %v, want %q", key, got, ok, want)
		}
	}
	c.put("a", "4", now)
	if got, _ := c.get("a", now); got != "4" || c.order.Len() != 2 {
		t.Errorf("update: get(a) = %q with %d entries", got, c.order.Len())
	}
	if _, ok := c.get("c", now.Add(time.Minute)); ok {
		t.Error("returned an expired entry")
	}
	if c.order.Len() != 1 || len(c.items) != 1 {
		t.Errorf("expired entry not dropped: %d, %d", c.order.Len(), len(c.items))
	}

	off := newLRU(0, time.Minute)
	off.put("a", "1", now)
	if _, ok := off.get("a", now); ok {
		t.Error("a cache of size 0 kept an entry")
	}
}

func TestClientAddress(t *testing.T) {
	for _, tc := range []struct{ remote, xff, want string }{
		{"203.0.113.5:4000", "", "203.0.113.5"},
		{"203.0.113.5:4000", "198.51.100.1", "203.0.113.5"}, // a public peer's header proves nothing
		{"127.0.0.1:4000", "", "127.0.0.1"},
		{"127.0.0.1:4000", "198.51.100.1", "198.51.100.1"},
		{"127.0.0.1:4000", "192.0.2.66, 198.51.100.1", "198.51.100.1"}, // the client's own entry is ignored
		{"10.77.0.1:4000", "198.51.100.1", "198.51.100.1"},             // a proxy over a private network
		{"[::1]:4000", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"[2001:db8::1]:4000", "", "2001:db8::/64"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := clientAddress(r); got != tc.want {
			t.Errorf("clientAddress(%s, X-Forwarded-For %q) = %q, want %q", tc.remote, tc.xff, got, tc.want)
		}
	}
}

func TestClaimedName(t *testing.T) {
	for _, tc := range []struct {
		event nostr.Event
		want  string
	}{
		{nostr.Event{Kind: 0, Content: `{"hns":"_@alice.hns.one","nip05":"bob.hns.one"}`}, "alice.hns.one"},
		{nostr.Event{Kind: 0, Content: `{"nip05":"_@bob.hns.one"}`}, "bob.hns.one"},
		{nostr.Event{Kind: 0, Content: `{"nip05":"carol@bob.hns.one"}`}, "carol@bob.hns.one"},
		{nostr.Event{Kind: 0, Content: `not json`, Tags: nostr.Tags{{"nip05", "_@tag.hns.one"}}}, "tag.hns.one"},
		{nostr.Event{Kind: 1, Content: `{"hns":"ignored.hns.one"}`, Tags: nostr.Tags{{"nip05", "dave.hns.one"}}}, "dave.hns.one"},
		{nostr.Event{Kind: 1, Tags: nostr.Tags{{"nip05"}}}, ""},
		{nostr.Event{Kind: 1}, ""},
	} {
		if got := claimedName(&tc.event); got != tc.want {
			t.Errorf("claimedName(kind %d, %q) = %q, want %q", tc.event.Kind, tc.event.Content, got, tc.want)
		}
	}
}

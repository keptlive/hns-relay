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
	n := newNameChecker(".hns.one", time.Hour)
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
	if _, err := newNameChecker("hns.one", time.Hour).nip05URL("evilhns.one"); err == nil {
		t.Error(`suffix "hns.one" admitted "evilhns.one"`)
	}

	// With no suffix any hostname is looked up, but still only a hostname.
	open := newNameChecker("", time.Hour)
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
	n := newNameChecker("", time.Hour)
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
	t.Helper()
	s := &nip05Server{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Host+r.URL.RequestURI())
		s.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	n := newNameChecker(".hns.one", time.Hour)
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

func TestVerifyFetchesOnlyTheNamedHost(t *testing.T) {
	s, n := newNIP05Server(t, serveNames(testPubkey))
	if !n.verify(context.Background(), "Alice.hns.one", testPubkey) {
		t.Fatal("verify rejected a matching document")
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

func TestVerifyRejects(t *testing.T) {
	ctx := context.Background()

	_, n := newNIP05Server(t, serveNames(strings.Repeat("0", 64)))
	if n.verify(ctx, "alice.hns.one", testPubkey) {
		t.Error("accepted a document naming another pubkey")
	}

	_, n = newNIP05Server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "alice.hns.one" {
			http.Redirect(w, r, "https://elsewhere.hns.one/.well-known/nostr.json?name=_", http.StatusFound)
			return
		}
		serveNames(testPubkey)(w, r)
	})
	if n.verify(ctx, "alice.hns.one", testPubkey) {
		t.Error("followed a redirect")
	}

	_, n = newNIP05Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		serveNames(testPubkey)(w, r)
	})
	if n.verify(ctx, "alice.hns.one", testPubkey) {
		t.Error("accepted a non-200 response")
	}

	_, n = newNIP05Server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat(" ", maxNIP05Body))
		serveNames(testPubkey)(w, r)
	})
	if n.verify(ctx, "alice.hns.one", testPubkey) {
		t.Error("read past the body limit")
	}
}

func TestVerifyMakesNoRequestForBadClaims(t *testing.T) {
	s, n := newNIP05Server(t, serveNames(testPubkey))
	for _, claim := range []string{
		"127.0.0.1:38222/?x=.hns.one",
		"evil.com#.hns.one",
		"evil.com/.hns.one",
		"user@evil.com/.hns.one",
		"a.b.hns.one:8080",
		"alice.example.com",
		"evilhns.one",
	} {
		if n.verify(context.Background(), claim, testPubkey) {
			t.Errorf("verify(%q) = true", claim)
		}
	}
	if dials, reqs := s.counts(); dials != 0 || reqs != 0 {
		t.Fatalf("bad claims caused %d dials and %d requests", dials, reqs)
	}
}

func TestAdmitsCachesOnlyPositives(t *testing.T) {
	var mu sync.Mutex
	owner := strings.Repeat("0", 64)
	s, n := newNIP05Server(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pk := owner
		mu.Unlock()
		serveNames(pk)(w, r)
	})
	ctx := context.Background()
	ev := &nostr.Event{PubKey: testPubkey, Kind: 1, Tags: nostr.Tags{{"nip05", "_@alice.hns.one"}}}

	if n.admits(ctx, ev) || n.admits(ctx, ev) {
		t.Fatal("admitted before the document named the key")
	}
	if _, reqs := s.counts(); reqs != 2 {
		t.Fatalf("negative answers: %d requests, want 2 (not cached)", reqs)
	}

	mu.Lock()
	owner = testPubkey
	mu.Unlock()
	if !n.admits(ctx, ev) || !n.admits(ctx, ev) {
		t.Fatal("did not admit once the document named the key")
	}
	if _, reqs := s.counts(); reqs != 3 {
		t.Fatalf("positive answer: %d requests in total, want 3 (cached)", reqs)
	}

	if n.admits(ctx, &nostr.Event{PubKey: strings.Repeat("1", 64), Kind: 1}) {
		t.Error("admitted an event with no claim")
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

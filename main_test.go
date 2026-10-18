package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func TestEnvInt(t *testing.T) {
	for value, want := range map[string]int{"": 7, "12": 12, "0": 0, "abc": 7, "-3": 7} {
		t.Setenv("HNS_RELAY_TEST_INT", value)
		if got := envInt("HNS_RELAY_TEST_INT", 7); got != want {
			t.Errorf("envInt(%q) = %d, want %d", value, got, want)
		}
	}
}

func TestEventLimits(t *testing.T) {
	check := eventLimits(10)
	now := nostr.Timestamp(time.Now().Unix())
	for _, tc := range []struct {
		event  nostr.Event
		reject bool
	}{
		{nostr.Event{Content: "hello", CreatedAt: now}, false},
		{nostr.Event{Content: strings.Repeat("x", 10), CreatedAt: now}, false},
		{nostr.Event{Content: strings.Repeat("x", 11), CreatedAt: now}, true},
		{nostr.Event{CreatedAt: now + 10*60}, false},
		{nostr.Event{CreatedAt: now + 60*60}, true},
		{nostr.Event{CreatedAt: now - 365*24*60*60}, false},
	} {
		reject, msg := check(context.Background(), &tc.event)
		if reject != tc.reject {
			t.Errorf("content %d bytes, created_at %+ds: reject = %v (%q), want %v",
				len(tc.event.Content), int64(tc.event.CreatedAt-now), reject, msg, tc.reject)
		}
		if reject && !strings.HasPrefix(msg, "invalid: ") {
			t.Errorf("rejection %q lacks the NIP-01 invalid: prefix", msg)
		}
	}
}

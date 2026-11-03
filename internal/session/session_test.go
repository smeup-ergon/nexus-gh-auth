package session

import (
	"strings"
	"testing"
	"time"
)

type payload struct {
	User string `json:"u"`
}

func TestRoundTrip(t *testing.T) {
	s := NewSigner([]byte(strings.Repeat("k", 32)), "session")
	v, err := s.Seal(payload{User: "gh-alice"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var got payload
	if err := s.Open(v, &got); err != nil || got.User != "gh-alice" {
		t.Fatalf("Open = %v, %+v", err, got)
	}
}

func TestRejects(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	s := NewSigner(secret, "session")
	v, _ := s.Seal(payload{User: "gh-alice"}, time.Hour)
	p, sig, _ := strings.Cut(v, ".")

	other, _ := NewSigner([]byte(strings.Repeat("x", 32)), "session").Seal(payload{User: "gh-alice"}, time.Hour)
	otherPurpose, _ := NewSigner(secret, "local").Seal(payload{User: "gh-alice"}, time.Hour)
	forged, _ := NewSigner(secret, "session").Seal(payload{User: "admin"}, time.Hour)
	fp, _, _ := strings.Cut(forged, ".")

	cases := map[string]string{
		"empty":          "",
		"no dot":         p,
		"bad sig":        p + ".AAAA",
		"swapped body":   fp + "." + sig,
		"other key":      other,
		"other purpose":  otherPurpose,
		"garbage base64": "!!!." + sig,
	}
	for name, val := range cases {
		var got payload
		if err := s.Open(val, &got); err != ErrInvalid {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestExpiry(t *testing.T) {
	s := NewSigner([]byte(strings.Repeat("k", 32)), "session")
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }
	v, _ := s.Seal(payload{User: "a"}, time.Hour)

	var got payload
	now = now.Add(59 * time.Minute)
	if err := s.Open(v, &got); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	now = now.Add(time.Minute)
	if err := s.Open(v, &got); err != ErrInvalid {
		t.Fatalf("at expiry: want ErrInvalid, got %v", err)
	}
}

func TestRandomString(t *testing.T) {
	a, b := RandomString(32), RandomString(32)
	if a == b || len(a) != 43 {
		t.Fatalf("RandomString: %q %q", a, b)
	}
}

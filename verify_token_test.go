package apxchallenge

import (
	"testing"
	"time"
)

const vtSecret = "test-secret-verify"

func TestVerifyChallengeRoundTrip(t *testing.T) {
	tok := IssueVerifyChallenge(vtSecret, "203.0.113.7", 12, time.Now().Add(time.Minute))
	p, err := CheckVerifyChallenge(vtSecret, tok, "203.0.113.9") // same /24
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Diff != 12 {
		t.Fatalf("difficulty not carried: got %d", p.Diff)
	}
}

func TestVerifyChallengeRejectsOtherPrefix(t *testing.T) {
	tok := IssueVerifyChallenge(vtSecret, "203.0.113.7", 12, time.Now().Add(time.Minute))
	if _, err := CheckVerifyChallenge(vtSecret, tok, "198.51.100.7"); err == nil {
		t.Fatal("expected prefix mismatch rejection")
	}
}

func TestVerifyChallengeRejectsExpired(t *testing.T) {
	tok := IssueVerifyChallenge(vtSecret, "203.0.113.7", 12, time.Now().Add(-time.Second))
	if _, err := CheckVerifyChallenge(vtSecret, tok, "203.0.113.7"); err == nil {
		t.Fatal("expected expiry rejection")
	}
}

func TestVerifyTokenRoundTripAndHostBinding(t *testing.T) {
	tok := IssueVerifyToken(vtSecret, "203.0.113.7", "shop.example.com", "n1", time.Now().Add(time.Minute))
	if _, err := CheckVerifyToken(vtSecret, tok, "203.0.113.7", "shop.example.com"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := CheckVerifyToken(vtSecret, tok, "203.0.113.7", "evil.example.com"); err == nil {
		t.Fatal("expected host mismatch rejection")
	}
}

func TestVerifyTokenDomainSeparation(t *testing.T) {
	// A challenge token must NOT validate as a verify token and vice versa.
	ch := IssueVerifyChallenge(vtSecret, "203.0.113.7", 12, time.Now().Add(time.Minute))
	if _, err := CheckVerifyToken(vtSecret, ch, "203.0.113.7", "shop.example.com"); err == nil {
		t.Fatal("challenge token validated as verify token")
	}
}

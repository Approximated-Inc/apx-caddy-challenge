package apxchallenge

import "testing"

func TestNonceLRUFirstSeenThenReplay(t *testing.T) {
	l := NewNonceLRU(4)
	if l.Seen("a") {
		t.Fatal("first sighting must be false")
	}
	if !l.Seen("a") {
		t.Fatal("second sighting must be true (replay)")
	}
}

func TestNonceLRUEvictsOldest(t *testing.T) {
	l := NewNonceLRU(2)
	l.Seen("a")
	l.Seen("b")
	l.Seen("c") // evicts "a"
	if l.Seen("a") {
		t.Fatal("evicted nonce should read as first-seen again")
	}
}

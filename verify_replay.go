package apxchallenge

import (
	"container/list"
	"sync"
)

// NonceLRU is a bounded, concurrency-safe set of recently-seen token nonces
// for best-effort per-machine single-use. Not shared across the cluster.
type NonceLRU struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[string]*list.Element
}

func NewNonceLRU(max int) *NonceLRU {
	if max <= 0 {
		max = 1
	}
	// Map grows lazily; eviction in Seen bounds it to max entries.
	return &NonceLRU{max: max, ll: list.New(), m: make(map[string]*list.Element)}
}

// Seen records nonce and reports whether it was already present (a replay).
func (l *NonceLRU) Seen(nonce string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.m[nonce]; ok {
		l.ll.MoveToFront(el)
		return true
	}
	l.m[nonce] = l.ll.PushFront(nonce)
	for l.ll.Len() > l.max {
		back := l.ll.Back()
		if back == nil {
			break
		}
		l.ll.Remove(back)
		delete(l.m, back.Value.(string))
	}
	return false
}

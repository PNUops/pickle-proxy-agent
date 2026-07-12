package server

import (
	"sync"
	"time"
)

// limiter is a per-key token bucket. It bounds calls per key (FQDN for /apply,
// source IP otherwise) so a leaked token inside vmbr1 cannot hammer the agent.
// A zero perMin disables limiting (tests).
type limiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMin int) *limiter {
	perSec := float64(perMin) / 60.0
	burst := float64(perMin)
	if burst < 1 {
		burst = 1
	}
	return &limiter{
		perSec:  perSec,
		burst:   burst,
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// allow reports whether a call for key may proceed, consuming one token.
func (l *limiter) allow(key string) bool {
	if l.perSec <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.perSec
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

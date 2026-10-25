// Package ratelimit implements keyed, in-memory token-bucket rate limiting.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	last     time.Time
	rps      float64
	burst    float64
	lastSeen time.Time
}

// Limiter holds one token bucket per key. Buckets are created on first use
// and can be evicted with Sweep. A Limiter is safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

// New returns an empty Limiter using the wall clock.
func New() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, now: time.Now}
}

// NewWithClock returns a Limiter that reads time from now; useful in tests.
func NewWithClock(now func() time.Time) *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, now: now}
}

// Allow takes one token from the bucket for key, creating it with the given
// rate (tokens/second) and burst if needed. When the bucket is empty it
// returns false and the wait until a token is available. If the rate or
// burst for an existing key changes, the bucket adopts the new values.
func (l *Limiter) Allow(key string, rps float64, burst int) (bool, time.Duration) {
	if rps <= 0 || burst <= 0 {
		return true, 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(burst), last: now}
		l.buckets[key] = b
	}
	b.rps, b.burst, b.lastSeen = rps, float64(burst), now
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(b.burst, b.tokens+elapsed*b.rps)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / b.rps * float64(time.Second))
	return false, wait
}

// Sweep removes buckets not used for at least idle and returns how many
// were removed. When idle is at least burst/rps an idle bucket has refilled
// completely, so evicting it does not change limiting behaviour.
func (l *Limiter) Sweep(idle time.Duration) int {
	cutoff := l.now().Add(-idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
			n++
		}
	}
	return n
}

// Len returns the number of live buckets.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

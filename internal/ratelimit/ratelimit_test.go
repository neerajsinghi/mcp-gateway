package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestAllow(t *testing.T) {
	type step struct {
		advance time.Duration
		want    bool
	}
	tests := []struct {
		name  string
		rps   float64
		burst int
		steps []step
	}{
		{"burst then deny", 1, 3, []step{{0, true}, {0, true}, {0, true}, {0, false}}},
		{"refills over time", 2, 1, []step{{0, true}, {0, false}, {250 * time.Millisecond, false}, {250 * time.Millisecond, true}}},
		{"caps at burst", 10, 2, []step{{time.Hour, true}, {0, true}, {0, false}}},
		{"disabled when zero", 0, 0, []step{{0, true}, {0, true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{t: time.Unix(0, 0)}
			l := NewWithClock(c.now)
			for i, s := range tt.steps {
				c.add(s.advance)
				got, wait := l.Allow("k", tt.rps, tt.burst)
				if got != s.want {
					t.Fatalf("step %d: got %v, want %v", i, got, s.want)
				}
				if !got && wait <= 0 {
					t.Fatalf("step %d: denied without positive wait", i)
				}
			}
		})
	}
}

func TestKeysIndependentAndSweep(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := NewWithClock(c.now)
	if ok, _ := l.Allow("a", 1, 1); !ok {
		t.Fatal("a first")
	}
	if ok, _ := l.Allow("a", 1, 1); ok {
		t.Fatal("a second should be denied")
	}
	if ok, _ := l.Allow("b", 1, 1); !ok {
		t.Fatal("b is independent")
	}
	c.add(time.Minute)
	l.Allow("b", 1, 1)
	if n := l.Sweep(30 * time.Second); n != 1 || l.Len() != 1 {
		t.Fatalf("sweep removed %d, len %d", n, l.Len())
	}
}

func TestConcurrent(t *testing.T) {
	l := New()
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := l.Allow("k", 0.0001, 10); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 10 {
		t.Fatalf("allowed %d, want 10", allowed)
	}
}

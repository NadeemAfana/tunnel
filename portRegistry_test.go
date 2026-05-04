package main

import (
	"errors"
	"sync"
	"testing"
)

func TestPortRegistry_AllocateAndCount(t *testing.T) {
	r := newPortRegistry(10000, 10004, 30)

	port, err := r.allocate("alice", protoTCP)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if port < 10000 || port > 10004 {
		t.Fatalf("allocated port %d outside range [10000, 10004]", port)
	}
	if got := r.count("alice"); got != 1 {
		t.Fatalf("count(alice) = %d, want 1", got)
	}
	if owner := r.ownerOf(port, protoTCP); owner != "alice" {
		t.Fatalf("ownerOf(%d, tcp) = %q, want %q", port, owner, "alice")
	}
}

func TestPortRegistry_ReserveExplicitPort(t *testing.T) {
	r := newPortRegistry(10000, 10999, 30)

	if err := r.reserve(10042, "alice", protoTCP); err != nil {
		t.Fatalf("reserve in range: %v", err)
	}
	if r.ownerOf(10042, protoTCP) != "alice" {
		t.Fatalf("expected alice to own 10042/tcp")
	}

	// Same proto+port again, by anyone, must fail with errPortAlreadyInUse.
	if err := r.reserve(10042, "bob", protoTCP); !errors.Is(err, errPortAlreadyInUse) {
		t.Fatalf("expected errPortAlreadyInUse, got %v", err)
	}

	// Out-of-range rejected.
	if err := r.reserve(80, "alice", protoTCP); !errors.Is(err, errPortOutOfRange) {
		t.Fatalf("expected errPortOutOfRange for low port, got %v", err)
	}
	if err := r.reserve(70000, "alice", protoTCP); !errors.Is(err, errPortOutOfRange) {
		t.Fatalf("expected errPortOutOfRange for high port, got %v", err)
	}
}

// TCP/X and UDP/X are independent kernel listeners; the registry must allow
// the same port number to be held simultaneously for different protocols.
func TestPortRegistry_TCPAndUDPSamePortAllowed(t *testing.T) {
	r := newPortRegistry(10000, 10999, 30)

	if err := r.reserve(10042, "alice", protoTCP); err != nil {
		t.Fatalf("reserve tcp/10042: %v", err)
	}
	// Same number, UDP, same user: must succeed.
	if err := r.reserve(10042, "alice", protoUDP); err != nil {
		t.Fatalf("reserve udp/10042 for same user should succeed, got %v", err)
	}
	// Same number, UDP, different user: also fine; the OS allows independent
	// listeners on different protocols.
	if err := r.reserve(10043, "alice", protoTCP); err != nil {
		t.Fatalf("reserve tcp/10043: %v", err)
	}
	if err := r.reserve(10043, "bob", protoUDP); err != nil {
		t.Fatalf("reserve udp/10043 for different user should succeed, got %v", err)
	}

	// Combined count: alice has 3 (10042/tcp, 10042/udp, 10043/tcp).
	if got := r.count("alice"); got != 3 {
		t.Fatalf("alice combined count = %d, want 3", got)
	}
	if got := r.count("bob"); got != 1 {
		t.Fatalf("bob combined count = %d, want 1", got)
	}
}

func TestPortRegistry_PerUserLimitIsCombined(t *testing.T) {
	// limit 3, alice mixes TCP and UDP: 2 TCP + 1 UDP = 3 hits the cap.
	r := newPortRegistry(10000, 19999, 3)

	if _, err := r.allocate("alice", protoTCP); err != nil {
		t.Fatalf("alloc tcp 1: %v", err)
	}
	if _, err := r.allocate("alice", protoTCP); err != nil {
		t.Fatalf("alloc tcp 2: %v", err)
	}
	if _, err := r.allocate("alice", protoUDP); err != nil {
		t.Fatalf("alloc udp 1: %v", err)
	}
	// 4th must hit the limit regardless of protocol.
	if _, err := r.allocate("alice", protoUDP); !errors.Is(err, errUserPortLimit) {
		t.Fatalf("expected errUserPortLimit, got %v", err)
	}
	if err := r.reserve(15000, "alice", protoTCP); !errors.Is(err, errUserPortLimit) {
		t.Fatalf("expected errUserPortLimit on reserve over limit, got %v", err)
	}

	// Other users unaffected.
	if _, err := r.allocate("bob", protoTCP); err != nil {
		t.Fatalf("bob first allocate: %v", err)
	}
}

func TestPortRegistry_ReleaseAllowsReuse(t *testing.T) {
	r := newPortRegistry(10000, 10001, 30)

	p1, err := r.allocate("alice", protoTCP)
	if err != nil {
		t.Fatalf("allocate 1: %v", err)
	}
	p2, err := r.allocate("alice", protoTCP)
	if err != nil {
		t.Fatalf("allocate 2: %v", err)
	}
	if p1 == p2 {
		t.Fatalf("allocate returned duplicate %d", p1)
	}

	// TCP range full now (still 2 UDP slots though).
	if _, err := r.allocate("alice", protoTCP); !errors.Is(err, errPortRangeExhausted) {
		t.Fatalf("expected errPortRangeExhausted for tcp, got %v", err)
	}
	// UDP same number range, fresh slots, allocation works.
	if _, err := r.allocate("alice", protoUDP); err != nil {
		t.Fatalf("udp allocate after tcp full: %v", err)
	}

	r.release(p1, protoTCP)
	if r.count("alice") != 2 {
		t.Fatalf("count after release = %d, want 2", r.count("alice"))
	}
	if r.ownerOf(p1, protoTCP) != "" {
		t.Fatalf("ownerOf released port should be empty")
	}

	// Should now be able to allocate TCP again.
	if _, err := r.allocate("alice", protoTCP); err != nil {
		t.Fatalf("allocate tcp after release: %v", err)
	}
}

func TestPortRegistry_ReleaseUnknownPortIsNoop(t *testing.T) {
	r := newPortRegistry(10000, 10999, 30)
	r.release(99999, protoTCP)
	r.release(99999, protoUDP)
	if r.count("alice") != 0 {
		t.Fatalf("count(alice) should be 0")
	}
}

func TestPortRegistry_CountDropsToZeroDeletesEntry(t *testing.T) {
	// Internal-state check: byOwner[owner] is deleted (not left at 0) when
	// the user releases their last port. Otherwise the map grows unbounded
	// over the lifetime of the server.
	r := newPortRegistry(10000, 10999, 30)
	p, _ := r.allocate("alice", protoTCP)
	r.release(p, protoTCP)
	r.mu.RLock()
	_, present := r.byOwner["alice"]
	r.mu.RUnlock()
	if present {
		t.Fatalf("byOwner[alice] should be deleted, not 0")
	}
}

func TestPortRegistry_ConcurrentAllocate(t *testing.T) {
	// 100 workers each grabbing 1 port from a 1000-port range. No duplicates
	// across the 100 successful allocations.
	r := newPortRegistry(20000, 20999, 30)

	const N = 100
	var wg sync.WaitGroup
	ports := make(chan uint32, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			owner := "u" + string(rune('a'+idx%4))
			p, err := r.allocate(owner, protoTCP)
			if err == nil {
				ports <- p
			}
		}(i)
	}
	wg.Wait()
	close(ports)

	seen := make(map[uint32]bool)
	for p := range ports {
		if seen[p] {
			t.Fatalf("duplicate port %d allocated", p)
		}
		seen[p] = true
	}
	if len(seen) == 0 {
		t.Fatal("no successful allocations")
	}
}

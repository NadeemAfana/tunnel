package main

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
)

// netProto distinguishes TCP and UDP allocations so a user can hold the same
// port number on both protocols simultaneously (the OS treats them as
// independent listeners).
type netProto uint8

const (
	protoTCP netProto = iota
	protoUDP
)

func (p netProto) String() string {
	switch p {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	}
	return "unknown"
}

type portKey struct {
	proto netProto
	port  uint32
}

// portRegistry tracks which TCP/UDP forward ports are currently in use and by
// whom (the authenticated key name from authorized_keys.json). Used to enforce
// a per-user port quota and to hand out free ports without blind retry-bind
// loops.
//
// TCP and UDP are tracked independently so that a user with `tunnel.sh tcp X
// -p 5000` and `tunnel.sh udp Y -p 5000` is allowed (they target different
// kernel listeners). The per-user count is COMBINED across protocols, so 30
// TCP + 0 UDP and 15 TCP + 15 UDP both hit the same maxPerUser ceiling.
//
// Allocation strategy: pick a random port in [min, max] and linearly probe
// forward until a free port (for the requested protocol) is found. With the
// typical sparsity (a few dozen active forwards in a 50k-port range) this is
// O(1) on average.
//
// The registry is the source of truth for "which ports the tunnel server has
// handed out". Whether the kernel will actually accept the bind is a separate
// concern handled by the caller, since another process on the box may grab a
// port for an outbound connection between our reserve and listen calls. On
// bind failure the caller releases and tries again.
type portRegistry struct {
	mu         sync.RWMutex
	min        uint32
	max        uint32
	maxPerUser int
	inUse      map[portKey]string // (proto, port) → owner key name
	byOwner    map[string]int     // owner → count of ports held (TCP+UDP combined)
}

var (
	errPortRangeExhausted = errors.New("port range exhausted")
	errUserPortLimit      = errors.New("user has reached the per-user port limit")
	errPortAlreadyInUse   = errors.New("port already in use")
	errPortOutOfRange     = errors.New("port outside the configured range")
)

func newPortRegistry(minPort, maxPort uint32, maxPerUser int) *portRegistry {
	return &portRegistry{
		min:        minPort,
		max:        maxPort,
		maxPerUser: maxPerUser,
		inUse:      make(map[portKey]string),
		byOwner:    make(map[string]int),
	}
}

// allocate picks a free port for owner on the given protocol and records the
// reservation. The caller should attempt to bind the returned port; on bind
// failure call release(port, proto) and try allocate again (or surface the
// error).
func (r *portRegistry) allocate(owner string, proto netProto) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.byOwner[owner] >= r.maxPerUser {
		return 0, fmt.Errorf("%w: %q has %d ports, limit is %d",
			errUserPortLimit, owner, r.byOwner[owner], r.maxPerUser)
	}

	rangeSize := r.max - r.min + 1
	// Random start within the range, linear probe forward (with wraparound)
	// to find an unused port. The randomized start avoids two clients racing
	// for the same low ports when the registry is empty.
	start := r.min + uint32(rand.IntN(int(rangeSize)))
	for i := uint32(0); i < rangeSize; i++ {
		port := r.min + (start-r.min+i)%rangeSize
		k := portKey{proto: proto, port: port}
		if _, taken := r.inUse[k]; !taken {
			r.inUse[k] = owner
			r.byOwner[owner]++
			return port, nil
		}
	}
	return 0, errPortRangeExhausted
}

// reserve claims a specific port on the given protocol for owner. Used when
// the client passed -p N with an explicit port. Returns errPortOutOfRange,
// errPortAlreadyInUse, or errUserPortLimit if those preconditions fail.
func (r *portRegistry) reserve(port uint32, owner string, proto netProto) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if port < r.min || port > r.max {
		return fmt.Errorf("%w: %d not in [%d, %d]",
			errPortOutOfRange, port, r.min, r.max)
	}
	k := portKey{proto: proto, port: port}
	if existing, taken := r.inUse[k]; taken {
		return fmt.Errorf("%w: %s/%d held by %q", errPortAlreadyInUse, proto, port, existing)
	}
	if r.byOwner[owner] >= r.maxPerUser {
		return fmt.Errorf("%w: %q has %d ports, limit is %d",
			errUserPortLimit, owner, r.byOwner[owner], r.maxPerUser)
	}
	r.inUse[k] = owner
	r.byOwner[owner]++
	return nil
}

// release frees a previously reserved (port, proto) pair. No-op if the entry
// is not currently held. Safe to call from cleanup paths even when the
// underlying bind never succeeded.
func (r *portRegistry) release(port uint32, proto netProto) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := portKey{proto: proto, port: port}
	owner, ok := r.inUse[k]
	if !ok {
		return
	}
	delete(r.inUse, k)
	r.byOwner[owner]--
	if r.byOwner[owner] <= 0 {
		delete(r.byOwner, owner)
	}
}

// count returns the total number of ports owner currently holds across both
// protocols. Read-only, safe to call concurrently with other readers.
func (r *portRegistry) count(owner string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byOwner[owner]
}

// ownerOf returns the owner that currently holds (port, proto), or empty
// string if the slot is free. Read-only.
func (r *portRegistry) ownerOf(port uint32, proto netProto) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.inUse[portKey{proto: proto, port: port}]
}

// releasePortFromRegistry parses the port out of an "addr:port" string and
// releases it on the global ports registry, mapping the connectionType to the
// matching netProto. No-op for HTTP forwards (they don't reserve ports) and
// for malformed addrs. Used by cleanup paths in main.go and the cancel
// handler so they don't have to know about parsing or proto mapping.
func releasePortFromRegistry(addr string, c connectionType) {
	if ports == nil {
		return
	}
	var proto netProto
	switch c {
	case TCPConnectionType:
		proto = protoTCP
	case UDPConnectionType:
		proto = protoUDP
	default:
		return
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 0 || p > 65535 {
		return
	}
	ports.release(uint32(p), proto)
}

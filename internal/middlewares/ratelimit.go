package middlewares

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/the-bughex-code/backend/internal/apperrors"
	"github.com/the-bughex-code/backend/internal/dto/response"
)

// visitor is one client's token bucket plus the time we last saw them.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiter holds one token bucket per client IP.
//
// # How a token bucket works
//
// The bucket holds at most `burst` tokens and refills at `rps` tokens per
// second. Each request removes one token. An empty bucket means the request is
// rejected. This allows a short burst of activity — a mobile app fanning out
// six requests on screen load — while capping the sustained rate.
//
// A fixed window ("100 requests per minute") would let a client send 100 at
// 11:59:59 and 100 more at 12:00:00: 200 requests in one second, within limits.
type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rps      rate.Limit
	burst    int
}

// # Limitations you must understand before relying on this
//
//  1. The counters live in ONE process's memory. Run three replicas behind a
//     load balancer and each permits the full rate, so the real limit is 3x.
//     For a true global limit you need shared state — Redis, or your load
//     balancer's own limiter.
//
//  2. Restarting the process forgets every bucket.
//
//  3. It keys on IP. Everyone behind one corporate NAT shares a bucket, and
//     an attacker with a botnet has one bucket per node. IP is a proxy for
//     "client", not a definition of it. Rate-limit sensitive endpoints by
//     account as well.
//
// It is still worth having: it stops a single misbehaving client, a runaway
// retry loop, and casual credential-stuffing, and it costs one map lookup.
func newRateLimiter(rps float64, burst int) *rateLimiter {
	return &rateLimiter{
		visitors: make(map[string]*visitor),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

// allow reports whether this IP may proceed, and consumes a token if so.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, ok := rl.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.visitors[ip] = v
	}
	v.lastSeen = time.Now()

	return v.limiter.Allow()
}

// cleanup evicts idle visitors until ctx is cancelled.
//
// Without this the map grows once per unique IP, forever. A crawler sweeping
// your API from a /16 adds 65,536 entries that are never removed. That is a
// memory leak, and an unbounded map is a denial of service you built yourself.
func (rl *rateLimiter) cleanup(ctx context.Context, every, idleFor time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// The server is shutting down. Returning here lets the goroutine
			// die instead of outliving the process's usefulness.
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-idleFor)
			for ip, v := range rl.visitors {
				if v.lastSeen.Before(cutoff) {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// RateLimit throttles requests per client IP.
//
// It takes rps and burst explicitly rather than a whole config struct, because
// the router mounts it twice with different numbers: a permissive global limit,
// and a strict one on the authentication routes. A middleware that could only
// read one field of one config could not do that.
//
// ctx controls the lifetime of the background cleanup goroutine; pass the
// application context so it stops when the server does.
//
// Mount it BEFORE Authenticate. Otherwise an attacker floods /auth/login and
// forces the server to run bcrypt — 300ms of CPU — for every guess, before the
// limiter ever sees the request. That is a denial of service with a free
// password-cracking oracle attached.
func RateLimit(ctx context.Context, enabled bool, rps float64, burst int) func(http.Handler) http.Handler {
	if !enabled {
		// A pass-through. Returning a no-op middleware keeps the chain in
		// routes.go identical in every environment, so what you test is what
		// you run.
		return func(next http.Handler) http.Handler { return next }
	}

	rl := newRateLimiter(rps, burst)
	go rl.cleanup(ctx, time.Minute, 3*time.Minute)

	// Precomputed so it is not recalculated on every rejected request.
	retryAfter := strconv.Itoa(int(1/rps) + 1)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.allow(clientIP(r)) {
				// Retry-After tells a well-behaved client when to come back,
				// instead of leaving it to hammer you in a tight loop.
				w.Header().Set("Retry-After", retryAfter)

				response.Error(w, r, apperrors.RateLimited(
					"Too many requests. Please slow down and try again shortly."))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

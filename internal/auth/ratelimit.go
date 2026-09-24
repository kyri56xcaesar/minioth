package auth

/* Per-client-IP rate limiting for credential-sensitive endpoints (register,
* login, password change/reset — see registerAuthRoutes). A lightweight
* in-memory token bucket per IP via golang.org/x/time/rate: the standard
* Go answer for this that doesn't need a full middleware framework or an
* external store (Redis etc.) for a single-process tool like this one.
* Caveat that comes with that: it resets on restart and doesn't share
* state across multiple instances behind a load balancer — a distributed
* rate limiter is a different, bigger piece of infrastructure this
* project's scope doesn't call for (see README). */

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/kyri56xcaesar/minioth/internal/config"
)

// visitorTTL is how long an IP's bucket is kept idle before it's eligible
// for cleanup — bounds the limiters map's growth under many distinct
// clients over a long-running process without needing a background
// goroutine (see ipRateLimiter.allow).
const visitorTTL = 10 * time.Minute

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*visitor
	rps      rate.Limit
	burst    int
}

func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		limiters: make(map[string]*visitor),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	v, ok := l.limiters[ip]
	if !ok {
		// Opportunistic cleanup instead of a background goroutine+ticker:
		// only worth scanning when a genuinely new IP shows up, which is
		// exactly when the map would otherwise keep growing.
		for k, existing := range l.limiters {
			if now.Sub(existing.lastSeen) > visitorTTL {
				delete(l.limiters, k)
			}
		}
		v = &visitor{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.limiters[ip] = v
	}
	v.lastSeen = now
	return v.limiter.Allow()
}

// RateLimitMiddleware returns Gin middleware that rejects a client IP's
// request with 429 once it exceeds cfg.RateLimitRPS/RateLimitBurst. One
// limiter instance (and so one shared per-IP budget) is meant to be
// reused across every route it's attached to — construct it once and pass
// the same gin.HandlerFunc to each rg.POST(...) call, not once per route,
// or an attacker can just spread requests across routes to dodge the
// limit.
func RateLimitMiddleware(cfg *config.EnvConfig) gin.HandlerFunc {
	limiter := newIPRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
	return func(c *gin.Context) {
		if !limiter.allow(c.ClientIP()) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many requests, slow down"})
			c.Abort()
			return
		}
		c.Next()
	}
}

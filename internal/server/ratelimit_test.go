package server

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRateLimitBlocksAfterBurst(t *testing.T) {
	// A low, sustained-rate-effectively-zero limit so the test doesn't
	// need to wait on real wall-clock refill — only the burst allowance
	// is being exercised here.
	h := newTestHarness(t, map[string]string{
		"RATE_LIMIT_RPS":   "0.001",
		"RATE_LIMIT_BURST": "3",
	})

	body := gin.H{"username": "nobody", "password": "wrong"}
	var codes []int
	for range 6 {
		rec := h.do(t, http.MethodPost, "/v1/login", body, nil)
		codes = append(codes, rec.Code)
	}

	for i, code := range codes[:3] {
		if code == http.StatusTooManyRequests {
			t.Errorf("request %d: got 429 within the burst allowance (codes: %v)", i+1, codes)
		}
	}
	for i, code := range codes[3:] {
		if code != http.StatusTooManyRequests {
			t.Errorf("request %d: expected 429 once the burst is exhausted, got %d (codes: %v)", i+4, code, codes)
		}
	}
}

func TestRateLimitIsSharedAcrossRoutes(t *testing.T) {
	// Confirms one IP's budget is shared across every rate-limited route
	// (see RateLimitMiddleware's doc comment) — burning it on /register
	// must also throttle /login for the same client, not give each route
	// its own independent allowance.
	h := newTestHarness(t, map[string]string{
		"RATE_LIMIT_RPS":   "0.001",
		"RATE_LIMIT_BURST": "2",
	})

	for range 2 {
		h.do(t, http.MethodPost, "/v1/register", gin.H{
			"user": gin.H{"username": "whoever", "password": gin.H{"hashpass": "whoeverpass1"}},
		}, nil)
	}

	rec := h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "whoever", "password": "whoeverpass1"}, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected /login to be throttled after /register exhausted the shared budget, got %d", rec.Code)
	}
}

func TestRateLimitDoesNotAffectUnlimitedRoutes(t *testing.T) {
	h := newTestHarness(t, map[string]string{
		"RATE_LIMIT_RPS":   "0.001",
		"RATE_LIMIT_BURST": "1",
	})

	// Exhaust the shared budget on a limited route.
	h.do(t, http.MethodPost, "/v1/login", gin.H{"username": "nobody", "password": "wrong"}, nil)

	// /user/token isn't rate-limited (see registerAuthRoutes) — it should
	// still just do its own thing (401 for a missing token, not 429).
	rec := h.do(t, http.MethodGet, "/v1/user/token", nil, nil)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("expected an unlimited route to be unaffected by the exhausted budget on limited routes")
	}
}

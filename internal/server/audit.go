package server

/* Audit logging: a structured, grep-able log line for every privileged
* admin action, so there's one record of who did what — see Known
* weaknesses ("audit logging") for why this is log lines rather than a
* queryable store: the PlainHandler backend has no query surface, so
* persisting audit events only for -backend=db would make the two
* backends behave asymmetrically. */

import (
	"log"

	"github.com/gin-gonic/gin"
)

// auditActor extracts the calling identity AuthMiddleware attached to the
// context — either the authenticated username (bearer-token admin) or the
// service name (X-Service-Secret bypass).
func auditActor(c *gin.Context) string {
	if u := c.GetString("username"); u != "" {
		return u
	}
	if s := c.GetString("service"); s != "" {
		return "service:" + s
	}
	return "unknown"
}

// audit logs one line for a privileged admin action: who (actor), what
// (action), on whom/what (target), and the outcome (result). Called from
// every AdminHandler method that mutates state, on both the success and
// failure paths — a failed attempt is exactly the kind of thing audit
// logging exists to catch.
func audit(c *gin.Context, action, target, result string) {
	log.Printf("[AUDIT] actor=%q action=%q target=%q result=%q", auditActor(c), action, target, result)
}

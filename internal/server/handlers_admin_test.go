package server

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAdminRoutesRequireAdminAuth(t *testing.T) {
	h := newTestHarness(t)
	h.registerUser(t, "plainuser", "plainpass123", "")
	nonAdminToken := h.loginUser(t, "plainuser", "plainpass123")

	if rec := h.do(t, http.MethodGet, "/v1/admin/users", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d", rec.Code)
	}
	if rec := h.do(t, http.MethodGet, "/v1/admin/users", nil, bearer(nonAdminToken)); rec.Code != http.StatusUnauthorized {
		t.Errorf("non-admin token: expected 401, got %d", rec.Code)
	}
	if rec := h.do(t, http.MethodGet, "/v1/admin/users", nil, bearer(h.rootToken(t))); rec.Code != http.StatusOK {
		t.Errorf("root (admin) token: expected 200, got %d", rec.Code)
	}
}

func TestAdminServiceSecretBypass(t *testing.T) {
	h := newTestHarness(t)

	rec := h.do(t, http.MethodGet, "/v1/admin/users", nil, map[string]string{"X-Service-Secret": "testsvcsecret"})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the configured service secret to grant access, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodGet, "/v1/admin/users", nil, map[string]string{"X-Service-Secret": "wrong-secret"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected an unrecognized service secret to be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUserAddAndDuplicateRejected(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))

	rec := h.do(t, http.MethodPost, "/v1/admin/useradd", gin.H{
		"user": gin.H{"username": "newadminuser", "password": gin.H{"hashpass": "newpass123"}},
	}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("useradd = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodPost, "/v1/admin/useradd", gin.H{
		"user": gin.H{"username": "newadminuser", "password": gin.H{"hashpass": "different12"}},
	}, root)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on duplicate /admin/useradd, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUserDel(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))
	uid := h.registerUser(t, "todelete", "todeletepass1", "")

	rec := h.do(t, http.MethodDelete, "/v1/admin/userdel?uid="+strconv.Itoa(uid), nil, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("userdel = %d, body %s", rec.Code, rec.Body.String())
	}

	// Root itself (uid 0) must be protected.
	rec = h.do(t, http.MethodDelete, "/v1/admin/userdel?uid=0", nil, root)
	if rec.Code == http.StatusOK {
		t.Error("expected deleting root (uid 0) to be rejected")
	}

	rec = h.do(t, http.MethodDelete, "/v1/admin/userdel?uid=999999", nil, root)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 deleting a nonexistent uid, got %d", rec.Code)
	}
}

func TestAdminUserPatch(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))
	uid := h.registerUser(t, "topatch", "topatchpass1", "")

	rec := h.do(t, http.MethodPatch, "/v1/admin/userpatch", gin.H{
		"uid": strconv.Itoa(uid), "info": "patched info",
	}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("userpatch = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodGet, "/v1/admin/users?uid="+strconv.Itoa(uid), nil, root)
	var listing struct {
		Content []struct {
			Info string `json:"info"`
		} `json:"content"`
	}
	decode(t, rec, &listing)
	if len(listing.Content) != 1 || listing.Content[0].Info != "patched info" {
		t.Errorf("expected patched info to stick, got %+v", listing.Content)
	}

	// Patching root (uid "0") must be rejected.
	rec = h.do(t, http.MethodPatch, "/v1/admin/userpatch", gin.H{"uid": "0", "info": "hijacked"}, root)
	if rec.Code == http.StatusOK {
		t.Error("expected patching root (uid 0) to be rejected")
	}
}

func TestAdminUserMod(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))
	h.registerUser(t, "tomod", "tomodpass123", "")

	rec := h.do(t, http.MethodPut, "/v1/admin/usermod", gin.H{
		"user": gin.H{"username": "tomod", "info": "modded", "password": gin.H{"hashpass": "tomodpass123"}},
	}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("usermod = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestAdminGroupCRUD(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))

	rec := h.do(t, http.MethodPost, "/v1/admin/groupadd", gin.H{"groupname": "engineering"}, root)
	if rec.Code != http.StatusCreated {
		t.Fatalf("groupadd = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodGet, "/v1/admin/groups", nil, root)
	var listing struct {
		Content []struct {
			Groupname string `json:"groupname"`
			Gid       int    `json:"gid"`
		} `json:"content"`
	}
	decode(t, rec, &listing)
	var gid int
	found := false
	for _, g := range listing.Content {
		if g.Groupname == "engineering" {
			gid, found = g.Gid, true
		}
	}
	if !found {
		t.Fatalf("expected \"engineering\" among groups, got %+v", listing.Content)
	}
	gidStr := strconv.Itoa(gid)

	rec = h.do(t, http.MethodPatch, "/v1/admin/grouppatch", gin.H{
		"gid": gidStr, "fields": gin.H{"groupname": "platform-engineering"},
	}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("grouppatch = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodPut, "/v1/admin/groupmod", gin.H{"groupname": "platform-eng", "gid": gid}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("groupmod = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodDelete, "/v1/admin/groupdel?gid="+gidStr, nil, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("groupdel = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestAdminPromote(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))
	uid := h.registerUser(t, "futureadmin", "futureadminpass1", "")

	// Not an admin yet.
	futureAdminToken := h.loginUser(t, "futureadmin", "futureadminpass1")
	if rec := h.do(t, http.MethodGet, "/v1/admin/users", nil, bearer(futureAdminToken)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 before promotion, got %d", rec.Code)
	}

	rec := h.do(t, http.MethodPost, "/v1/admin/promote", gin.H{"uid": strconv.Itoa(uid)}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("promote = %d, body %s", rec.Code, rec.Body.String())
	}

	// A fresh login picks up the new group membership in the token's
	// groups claim.
	promotedToken := h.loginUser(t, "futureadmin", "futureadminpass1")
	if rec := h.do(t, http.MethodGet, "/v1/admin/users", nil, bearer(promotedToken)); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after promotion, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminVerifyPassword(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))
	h.registerUser(t, "verifyme", "verifymepass1", "")

	rec := h.do(t, http.MethodPost, "/v1/admin/verify-password", gin.H{"username": "verifyme", "password": "verifymepass1"}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-password (correct) = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodPost, "/v1/admin/verify-password", gin.H{"username": "verifyme", "password": "wrong-pass"}, root)
	if rec.Code == http.StatusOK {
		t.Error("expected verify-password with the wrong password to fail")
	}
}

func TestAdminHasher(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))

	rec := h.do(t, http.MethodPost, "/v1/admin/hasher", gin.H{"text": "hash-me-please", "hashcost": 4}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("hasher (hash) = %d, body %s", rec.Code, rec.Body.String())
	}
	var hashResp struct {
		Result string `json:"result"`
	}
	decode(t, rec, &hashResp)
	if hashResp.Result == "" {
		t.Fatal("expected a non-empty hash result")
	}

	rec = h.do(t, http.MethodPost, "/v1/admin/hasher", gin.H{"text": "hash-me-please", "hash": hashResp.Result}, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("hasher (verify) = %d, body %s", rec.Code, rec.Body.String())
	}
	var verifyResp struct {
		Result string `json:"result"`
	}
	decode(t, rec, &verifyResp)
	if verifyResp.Result != "true" {
		t.Errorf("expected the hasher to confirm its own hash, got %q", verifyResp.Result)
	}
}

func TestAdminAuditLogsNotQueryable(t *testing.T) {
	h := newTestHarness(t)
	root := bearer(h.rootToken(t))

	rec := h.do(t, http.MethodGet, "/v1/admin/audit/logs", nil, root)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rec.Code, rec.Body.String())
	}
}

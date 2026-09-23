package auth

import "testing"

func TestMatchServiceSecret(t *testing.T) {
	secrets := map[string][]byte{
		"billing": []byte("s3cret-1"),
		"search":  []byte("s3cret-2"),
	}

	svc, ok := matchServiceSecret(secrets, "s3cret-2")
	if !ok || svc != "search" {
		t.Errorf("expected match on search, got svc=%q ok=%v", svc, ok)
	}
	if _, ok := matchServiceSecret(secrets, "wrong"); ok {
		t.Error("expected no match for an unknown secret")
	}
	if _, ok := matchServiceSecret(secrets, ""); ok {
		t.Error("expected no match for an empty secret")
	}
}

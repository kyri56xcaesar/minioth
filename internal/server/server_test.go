package server

import "testing"

func TestOffLimitsCaseInsensitive(t *testing.T) {
	blocked := []string{"root", "Root", "ROOT", "kubernetes", "K8S", "k8S"}
	for _, name := range blocked {
		if !offLimits(name) {
			t.Errorf("expected %q to be off limits", name)
		}
	}
	if offLimits("alice") {
		t.Error("expected alice to be allowed")
	}
}

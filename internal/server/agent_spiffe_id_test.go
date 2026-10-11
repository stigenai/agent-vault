package server

import "testing"

func TestValidateAgentSPIFFEID(t *testing.T) {
	ok := []string{
		"",
		"spiffe://example.org/ns/a/sa/b",
		"spiffe://substrate-actor.local/actor/factory/f-run-1",
		"spiffe://substrate-actor.local/actor/factory/*",
	}
	for _, raw := range ok {
		if err := validateAgentSPIFFEID(raw); err != nil {
			t.Errorf("validateAgentSPIFFEID(%q) = %v; want nil", raw, err)
		}
	}
	bad := []string{
		"spiffe://example.org/*",
		"spiffe://substrate-actor.local/actor/*",
		"spiffe://substrate-actor.local/actor/factory/*/*",
		"spiffe://substrate-actor.local/actor/factory/x/*",
		"spiffe://substrate-actor.local/other/factory/*",
		"spiffe://substrate-actor.local/actor/fac*/x",
		"spiffe://substrate-actor.local/actor/*/x",
		"spiffe://substrate-actor.local/actor/factory/f*",
		"spiffe://*/actor/factory/x",
		"spiffe://substrate-actor.local/actor/factory/**",
		"spiffe://substrate-actor.local/actor//*",
		"spiffe://substrate-actor.local/actor/factory/*/",
		"not-a-spiffe-id",
	}
	for _, raw := range bad {
		if err := validateAgentSPIFFEID(raw); err == nil {
			t.Errorf("validateAgentSPIFFEID(%q) = nil; want error", raw)
		}
	}
}

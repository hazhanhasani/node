package xray

import (
	"slices"
	"testing"

	"github.com/pasarguard/node/common"
)

func TestExpandTorUserKeepsOneIdentityAcrossLocations(t *testing.T) {
	x := &Xray{torInbounds: map[string]map[string]struct{}{
		"vless-main": {
			"bluepanel-tor-in-de-a1": {},
			"bluepanel-tor-in-nl-b2": {},
		},
	}}
	user := &common.User{Email: "42", Inbounds: []string{"vless-main"}}

	expanded := x.expandTorUser(user)
	if expanded == user {
		t.Fatal("expected a copy so the canonical user payload is not mutated")
	}
	if user.GetInbounds()[0] != "vless-main" || len(user.GetInbounds()) != 1 {
		t.Fatalf("canonical payload was mutated: %#v", user.GetInbounds())
	}
	for _, tag := range []string{"vless-main", "bluepanel-tor-in-de-a1", "bluepanel-tor-in-nl-b2"} {
		if !slices.Contains(expanded.GetInbounds(), tag) {
			t.Fatalf("expanded user missing %q: %#v", tag, expanded.GetInbounds())
		}
	}
	if expanded.GetEmail() != "42" {
		t.Fatalf("user identity changed: %q", expanded.GetEmail())
	}
}

func TestExpandTorUserDisabledUserGetsNoLocation(t *testing.T) {
	x := &Xray{torInbounds: map[string]map[string]struct{}{
		"vless-main": {"bluepanel-tor-in-de-a1": {}},
	}}
	user := &common.User{Email: "42"}
	if got := x.expandTorUser(user); len(got.GetInbounds()) != 0 {
		t.Fatalf("disabled/expired user must not gain Tor inbounds: %#v", got.GetInbounds())
	}
}

func TestExpandTorInboundTagsDeduplicates(t *testing.T) {
	x := &Xray{torInbounds: map[string]map[string]struct{}{
		"vless-main": {"tor-de": {}},
	}}
	got := x.expandTorInboundTags([]string{"vless-main", "tor-de", "vless-main"})
	if len(got) != 2 {
		t.Fatalf("expected two unique tags, got %#v", got)
	}
}

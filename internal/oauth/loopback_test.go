package oauth

import "testing"

func TestLoopbackCallbackURL(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		"http://127.0.0.1:19443",
		"http://localhost:19443",
		"http://[::1]:19443",
	} {
		origin := origin
		t.Run(origin, func(t *testing.T) {
			t.Parallel()
			got, err := LoopbackCallbackURL(origin)
			if err != nil {
				t.Fatalf("LoopbackCallbackURL(%q): %v", origin, err)
			}
			want := origin + "/v1/oauth/callback"
			if got != want {
				t.Fatalf("callback = %q, want %q", got, want)
			}
			gotOrigin, err := LoopbackOriginFromCallbackURL(got)
			if err != nil || gotOrigin != origin {
				t.Fatalf("round trip = %q, %v; want %q", gotOrigin, err, origin)
			}
		})
	}
}

func TestLoopbackCallbackURLRejectsUnsafeOrigins(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		"https://127.0.0.1:19443",
		"http://127.0.0.1",
		"http://127.0.0.1:0",
		"http://127.0.0.1:65536",
		"http://127.0.0.1:19443/",
		"http://127.0.0.1:19443/path",
		"http://127.0.0.1:19443?code=secret",
		"http://127.0.0.1:19443#fragment",
		"http://user@127.0.0.1:19443",
		"http://127.0.0.2:19443",
		"http://localhost.example:19443",
		"http://LOCALHOST:19443",
		"http://2130706433:19443",
		"http://0177.0.0.1:19443",
		"http://[::ffff:127.0.0.1]:19443",
	} {
		origin := origin
		t.Run(origin, func(t *testing.T) {
			t.Parallel()
			if got, err := LoopbackCallbackURL(origin); err == nil {
				t.Fatalf("LoopbackCallbackURL(%q) = %q, want rejection", origin, got)
			}
		})
	}
}

func TestLoopbackOriginFromCallbackURLRejectsOtherPaths(t *testing.T) {
	t.Parallel()

	for _, callback := range []string{
		"http://127.0.0.1:19443/oauth/complete",
		"http://127.0.0.1:19443/v1/oauth/callback?code=secret",
		"https://127.0.0.1:19443/v1/oauth/callback",
	} {
		if origin, err := LoopbackOriginFromCallbackURL(callback); err == nil {
			t.Fatalf("LoopbackOriginFromCallbackURL(%q) = %q, want rejection", callback, origin)
		}
	}
}

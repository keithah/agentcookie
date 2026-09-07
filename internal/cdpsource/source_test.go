package cdpsource

import (
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestValidateEndpointAcceptsLoopbackHTTP(t *testing.T) {
	for _, endpoint := range []string{
		"http://127.0.0.1:9230",
		"http://localhost:9230",
		"http://[::1]:9230",
	} {
		if err := ValidateEndpoint(endpoint); err != nil {
			t.Fatalf("ValidateEndpoint(%q): %v", endpoint, err)
		}
	}
}

func TestValidateEndpointRejectsNonLoopbackOrUnsafeURLs(t *testing.T) {
	for _, endpoint := range []string{
		"",
		"https://127.0.0.1:9230",
		"http://100.91.16.115:9230",
		"http://example.com:9230",
		"http://127.0.0.1:9230/json/version",
		"http://127.0.0.1:9230?token=secret",
	} {
		if err := ValidateEndpoint(endpoint); err == nil {
			t.Errorf("ValidateEndpoint(%q) succeeded, want error", endpoint)
		}
	}
}

func TestConvertCookiePreservesCDPFields(t *testing.T) {
	in := &network.Cookie{
		Domain:       ".example.com",
		Name:         "session",
		Value:        "value",
		Path:         "/account",
		Expires:      42,
		Secure:       true,
		HTTPOnly:     true,
		Priority:     network.CookiePriorityHigh,
		SameSite:     network.CookieSameSiteStrict,
		SourceScheme: network.CookieSourceSchemeSecure,
		SourcePort:   443,
		Session:      false,
	}

	got := convertCookie(in)
	if got.HostKey != ".example.com" || got.Name != "session" || got.Value != "value" || got.Path != "/account" {
		t.Fatalf("identity fields = %#v", got)
	}
	if got.IsSecure != 1 || got.IsHTTPOnly != 1 || got.Priority != 2 || got.SameSite != 2 || got.SourceScheme != 2 || got.SourcePort != 443 {
		t.Fatalf("cookie attributes = %#v", got)
	}
	if got.ExpiresUTC == 0 || got.HasExpires != 1 || got.IsPersistent != 1 {
		t.Fatalf("expiry fields = %#v", got)
	}
}

func TestConvertCookieKeepsSessionCookieNonPersistent(t *testing.T) {
	got := convertCookie(&network.Cookie{Domain: "example.com", Name: "session", Value: "v", Path: "/", Session: true})
	if got.ExpiresUTC != 0 || got.HasExpires != 0 || got.IsPersistent != 0 {
		t.Fatalf("session cookie fields = %#v", got)
	}
}

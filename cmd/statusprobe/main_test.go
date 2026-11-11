package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(server *httptest.Server) *http.Client {
	client := server.Client()
	client.Timeout = time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

func TestCollectLockdownAndCatalog(t *testing.T) {
	var redirected atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/protected":
			w.WriteHeader(http.StatusForbidden)
		case "/redirect":
			http.Redirect(w, r, "/destination", http.StatusFound)
		case "/destination":
			redirected.Store(true)
			w.WriteHeader(http.StatusForbidden)
		case "/catalog":
			fmt.Fprint(w, `{"items":[{},{}]}`)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer server.Close()
	client := testClient(server)
	out := collect(client, []string{server.URL + "/protected", server.URL + "/redirect"}, server.URL, server.URL+"/catalog")
	if out.Lockdown.State != "BREACH" || len(out.Lockdown.FailingRoutes) != 1 || out.Lockdown.FailingRoutes[0] != server.URL+"/redirect" {
		t.Fatalf("unexpected lockdown: %+v", out.Lockdown)
	}
	if redirected.Load() || out.Lockdown.Routes[1].Status != http.StatusFound {
		t.Fatal("redirect was followed or status was not recorded")
	}
	if out.Storefront.State != "UP" || out.Storefront.TLS == "none" || out.Catalog.Count == nil || *out.Catalog.Count != 2 {
		t.Fatalf("unexpected public results: %+v %+v", out.Storefront, out.Catalog)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	catalog := decoded["catalog"].(map[string]any)
	if catalog["url"] != server.URL+"/catalog" || catalog["count"] != float64(2) || catalog["status"] != float64(200) {
		t.Fatalf("missing JSON fields: %s", encoded)
	}
	if !strings.Contains(markdown(out), "**Catalog count:** 2") {
		t.Fatal("missing count in markdown")
	}
	holding := collect(client, []string{server.URL + "/protected"}, server.URL, server.URL+"/catalog")
	if holding.Lockdown.State != "HOLDING" || len(holding.Lockdown.FailingRoutes) != 0 {
		t.Fatalf("expected holding: %+v", holding.Lockdown)
	}
}

func TestCatalogCount(t *testing.T) {
	tests := []struct {
		body string
		want int
		ok   bool
	}{
		{`[]`, 0, true},
		{`[1,2,3]`, 3, true},
		{`{"items":[1]}`, 1, true},
		{`{"items":null,"products":[1,2]}`, 2, true},
		{`{"products":[]}`, 0, true},
		{`{"items":{},"products":[1]}`, 0, false},
		{`{"items":null}`, 0, false},
		{`null`, 0, false},
		{`not json`, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			got, err := catalogCount([]byte(tt.body))
			if (err == nil) != tt.ok || (tt.ok && (got == nil || *got != tt.want)) || (!tt.ok && got != nil) {
				t.Fatalf("got count %v, error %v", got, err)
			}
		})
	}
}

func TestUnavailableCatalog(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"http error", `[]`, http.StatusForbidden},
		{"redirect", `[]`, http.StatusFound},
		{"invalid JSON", `{`, http.StatusOK},
		{"missing array", `{}`, http.StatusOK},
		{"oversize", strings.Repeat("x", maxCatalogBytes+1), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			out := collect(testClient(server), []string{server.URL}, server.URL, server.URL)
			if out.Catalog.Count != nil || out.Catalog.CountError == "" || !strings.Contains(markdown(out), "Catalog count:** Unavailable") {
				t.Fatalf("expected unavailable catalog: %+v", out.Catalog)
			}
			data, err := json.Marshal(out.Catalog)
			if err != nil || !strings.Contains(string(data), `"count":null`) {
				t.Fatalf("expected JSON null count: %s (%v)", data, err)
			}
		})
	}
}

func TestTimeoutIsBreach(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	client := testClient(server)
	client.Timeout = 10 * time.Millisecond
	out := collect(client, []string{server.URL}, server.URL, server.URL)
	if out.Lockdown.State != "BREACH" || len(out.Lockdown.FailingRoutes) != 1 || out.Lockdown.Routes[0].Error == "" || out.Catalog.Count != nil {
		t.Fatalf("timeout must report breach and unavailable count: %+v", out)
	}
}

func TestClientRefusesRedirect(t *testing.T) {
	if err := newClient(time.Second).CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy: %v", err)
	}
}

func TestConfiguredURL(t *testing.T) {
	for _, name := range []string{"STOREFRONT_URL", "CATALOG_URL"} {
		for _, tc := range []struct {
			name, value, want string
			valid             bool
		}{
			{"empty uses default", "", "https://default.example/", true},
			{"absolute", "https://example.com:8443/path?q=1", "https://example.com:8443/path?q=1", true},
			{"ipv6", "https://[::1]:8443/", "https://[::1]:8443/", true},
			{"http", "http://example.com/", "", false},
			{"relative", "/path", "", false},
			{"scheme relative", "//example.com/path", "", false},
			{"opaque", "https:example.com", "", false},
			{"missing host", "https:///path", "", false},
			{"missing hostname", "https://:443/path", "", false},
			{"userinfo", "https://user@example.com/", "", false},
			{"user and password", "https://user" + ":" + "pass@example.com/", "", false},
			{"empty userinfo", "https://@example.com/", "", false},
			{"bad port", "https://example.com:bad/", "", false},
			{"malformed", "https://[::1", "", false},
			{"whitespace", " https://example.com/", "", false},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				t.Setenv(name, tc.value)
				got, err := configuredURL(name, "https://default.example/")
				if got != tc.want || (err == nil) != tc.valid {
					t.Fatalf("got %q, error %v", got, err)
				}
				if err != nil && (!strings.Contains(err.Error(), name) || strings.Contains(err.Error(), tc.value)) {
					t.Fatalf("unsafe or unclear error: %v", err)
				}
			})
		}
	}
}

func TestDefaultPublicEndpoints(t *testing.T) {
	t.Setenv("STOREFRONT_URL", "")
	t.Setenv("CATALOG_URL", "")
	for _, tc := range []struct{ name, fallback, want string }{
		{"STOREFRONT_URL", storefrontURL, "https://vegasdiscountdepot.com/"},
		{"CATALOG_URL", catalogURL, "https://vegasdiscountdepot.com/catalog.json"},
	} {
		got, err := configuredURL(tc.name, tc.fallback)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %q, error %v", tc.name, got, err)
		}
	}
}

func TestConfiguredPublicEndpoints(t *testing.T) {
	var redirected atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/store":
			http.Redirect(w, r, "/destination", http.StatusFound)
		case "/destination":
			redirected.Store(true)
		case "/inventory":
			fmt.Fprint(w, `[{},{}]`)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	t.Setenv("STOREFRONT_URL", server.URL+"/store")
	t.Setenv("CATALOG_URL", server.URL+"/inventory")
	site, err := configuredURL("STOREFRONT_URL", storefrontURL)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := configuredURL("CATALOG_URL", catalogURL)
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(time.Second)
	client.Transport = server.Client().Transport
	out := collect(client, []string{server.URL + "/protected"}, site, catalog)
	if redirected.Load() || out.Storefront.URL != site || out.Storefront.Status != http.StatusFound {
		t.Fatalf("unexpected storefront result or followed redirect: %+v", out.Storefront)
	}
	if out.Catalog.URL != catalog || out.Catalog.Count == nil || *out.Catalog.Count != 2 {
		t.Fatalf("unexpected catalog result: %+v", out.Catalog)
	}
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	for _, name := range []string{"STOREFRONT_URL", "CATALOG_URL"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("STOREFRONT_URL", "")
			t.Setenv("CATALOG_URL", "")
			t.Setenv(name, "http://example.com/")
			flag.CommandLine = flag.NewFlagSet("statusprobe", flag.ContinueOnError)
			os.Args = []string{"statusprobe"}
			if err := run(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("expected configuration error for %s, got %v", name, err)
			}
		})
	}
}

func TestLockdownRoutesUnchanged(t *testing.T) {
	want := []string{
		"https://hub.mateflowlabs.com/god-mode-admin/GodModeAdmin.html",
		"https://mateflowlabs.com/god-mode-admin/GodModeAdmin.html",
		"https://vegasdiscountdepot.com/god-mode-admin/GodModeAdmin.html",
		"https://yard.mateflowlabs.com/god-mode-admin/GodModeAdmin.html",
		"https://dashboard.mateflowlabs.com/god-mode-admin/GodModeAdmin.html",
		"https://mateflowlabs.com/api/v1/credentials",
		"https://vegasdiscountdepot.com/api/v1/credentials",
		"https://yard.mateflowlabs.com/api/v1/credentials",
	}
	if !reflect.DeepEqual(lockdownURLs, want) {
		t.Fatalf("lockdown routes changed: %v", lockdownURLs)
	}
}

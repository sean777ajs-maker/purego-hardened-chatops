// Command statusprobe checks the public storefront and protected routes.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxCatalogBytes = 2 * 1024 * 1024

var lockdownURLs = []string{
	"https://hub.mateflowlabs.com/god-mode-admin/GodModeAdmin.html",
	"https://mateflowlabs.com/god-mode-admin/GodModeAdmin.html",
	"https://vegasdiscountdepot.com/god-mode-admin/GodModeAdmin.html",
	"https://yard.mateflowlabs.com/god-mode-admin/GodModeAdmin.html",
	"https://dashboard.mateflowlabs.com/god-mode-admin/GodModeAdmin.html",
	"https://mateflowlabs.com/api/v1/credentials",
	"https://vegasdiscountdepot.com/api/v1/credentials",
	"https://yard.mateflowlabs.com/api/v1/credentials",
}

const (
	storefrontURL = "https://vegasdiscountdepot.com/"
	catalogURL    = "https://vegasdiscountdepot.com/catalog.json"
)

type result struct {
	URL       string `json:"url"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	TLS       string `json:"tls"`
	Error     string `json:"error,omitempty"`
}

type publicResult struct {
	result
	State string `json:"state"`
}

type catalogResult struct {
	publicResult
	Count      *int   `json:"count"`
	CountError string `json:"count_error,omitempty"`
}

type report struct {
	Timestamp time.Time `json:"timestamp"`
	Lockdown  struct {
		State         string   `json:"state"`
		Routes        []result `json:"routes"`
		FailingRoutes []string `json:"failing_routes"`
	} `json:"lockdown"`
	Storefront publicResult  `json:"storefront"`
	Catalog    catalogResult `json:"catalog"`
}

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func tlsVersion(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func probe(client *http.Client, url string, readBody bool) (r result, body []byte) {
	r.URL, r.TLS = url, "none"
	start := time.Now()
	defer func() { r.LatencyMS = time.Since(start).Milliseconds() }()
	resp, err := client.Get(url)
	if err != nil {
		r.Error = err.Error()
		return
	}
	defer resp.Body.Close()
	r.Status = resp.StatusCode
	if resp.TLS != nil {
		r.TLS = tlsVersion(resp.TLS.Version)
	}
	if readBody {
		body, err = io.ReadAll(io.LimitReader(resp.Body, maxCatalogBytes+1))
		if err != nil {
			r.Error = err.Error()
			body = nil
		} else if len(body) > maxCatalogBytes {
			r.Error = "response too large"
			body = nil
		}
	}
	return
}

func publicState(r result) string {
	if r.Error == "" && r.Status >= 200 && r.Status < 400 {
		return "UP"
	}
	return "DOWN"
}

func catalogCount(body []byte) (*int, error) {
	var value json.RawMessage
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, errors.New("invalid JSON")
	}
	var items []json.RawMessage
	switch {
	case len(value) > 0 && value[0] == '[':
		if err := json.Unmarshal(value, &items); err != nil {
			return nil, errors.New("invalid catalog array")
		}
	case len(value) > 0 && value[0] == '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(value, &object); err != nil {
			return nil, errors.New("invalid catalog object")
		}
		raw := object["items"]
		if len(raw) == 0 || string(raw) == "null" {
			raw = object["products"]
		}
		if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
			return nil, errors.New("catalog items unavailable")
		}
	default:
		return nil, errors.New("catalog items unavailable")
	}
	count := len(items)
	return &count, nil
}

func collect(client *http.Client, routes []string, siteURL, catalogURL string) report {
	var out report
	out.Lockdown.Routes = make([]result, len(routes))
	out.Lockdown.FailingRoutes = []string{}
	var wg sync.WaitGroup
	for i, url := range routes {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			out.Lockdown.Routes[i], _ = probe(client, url, false)
		}(i, url)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, _ := probe(client, siteURL, false)
		out.Storefront = publicResult{result: r, State: publicState(r)}
	}()
	go func() {
		defer wg.Done()
		r, body := probe(client, catalogURL, true)
		out.Catalog.publicResult = publicResult{result: r, State: publicState(r)}
		switch {
		case r.Error != "":
			out.Catalog.CountError = r.Error
		case r.Status < 200 || r.Status >= 300:
			out.Catalog.CountError = fmt.Sprintf("HTTP %d", r.Status)
		default:
			var err error
			out.Catalog.Count, err = catalogCount(body)
			if err != nil {
				out.Catalog.CountError = err.Error()
			}
		}
	}()
	wg.Wait()
	out.Lockdown.State = "HOLDING"
	for _, r := range out.Lockdown.Routes {
		if r.Status != http.StatusForbidden || r.Error != "" {
			out.Lockdown.State = "BREACH"
			out.Lockdown.FailingRoutes = append(out.Lockdown.FailingRoutes, r.URL)
		}
	}
	out.Timestamp = time.Now().UTC()
	return out
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\r", " ")
}

func markdown(out report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Server status\n\n- **Timestamp:** %s\n- **Lockdown:** %s\n\n", out.Timestamp.Format(time.RFC3339), out.Lockdown.State)
	b.WriteString("## Lockdown routes\n\n| Route | HTTP | Latency | TLS | Result |\n|---|---:|---:|---|---|\n")
	for _, r := range out.Lockdown.Routes {
		state := "HOLDING"
		if r.Status != http.StatusForbidden || r.Error != "" {
			state = "BREACH"
		}
		if r.Error != "" {
			state += ": " + cell(r.Error)
		}
		fmt.Fprintf(&b, "| %s | %d | %d ms | %s | %s |\n", cell(r.URL), r.Status, r.LatencyMS, r.TLS, state)
	}
	b.WriteString("\n## Public endpoints\n\n| Route | HTTP | Latency | TLS | State |\n|---|---:|---:|---|---|\n")
	for _, r := range []publicResult{out.Storefront, out.Catalog.publicResult} {
		state := r.State
		if r.Error != "" {
			state += ": " + cell(r.Error)
		}
		fmt.Fprintf(&b, "| %s | %d | %d ms | %s | %s |\n", cell(r.URL), r.Status, r.LatencyMS, r.TLS, state)
	}
	if out.Catalog.Count == nil {
		fmt.Fprintf(&b, "\n**Catalog count:** Unavailable (%s)\n", cell(out.Catalog.CountError))
	} else {
		fmt.Fprintf(&b, "\n**Catalog count:** %d\n", *out.Catalog.Count)
	}
	return b.String()
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func configuredURL(name, fallback string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil {
		return "", fmt.Errorf("%s must be an absolute HTTPS URL without userinfo", name)
	}
	return value, nil
}

func run() error {
	jsonPath := flag.String("json", "", "also write JSON report to this path")
	markdownPath := flag.String("markdown", "", "write Markdown snapshot to this path")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	flag.Parse()
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if *jsonPath != "" && *jsonPath == *markdownPath {
		return errors.New("JSON and Markdown paths must differ")
	}
	site, err := configuredURL("STOREFRONT_URL", storefrontURL)
	if err != nil {
		return err
	}
	catalog, err := configuredURL("CATALOG_URL", catalogURL)
	if err != nil {
		return err
	}
	out := collect(newClient(*timeout), lockdownURLs, site, catalog)
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *jsonPath != "" {
		if err := writeFile(*jsonPath, data); err != nil {
			return fmt.Errorf("write JSON: %w", err)
		}
	}
	if *markdownPath != "" {
		if err := writeFile(*markdownPath, []byte(markdown(out))); err != nil {
			return fmt.Errorf("write Markdown: %w", err)
		}
	}
	_, err = os.Stdout.Write(data)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

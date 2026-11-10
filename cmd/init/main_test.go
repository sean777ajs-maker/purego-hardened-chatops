//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	server := httptest.NewServer(healthHandler())
	defer server.Close()
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"GET", "/health", 200, "{\"status\":\"ok\"}\n"},
		{"HEAD", "/health", 200, ""},
		{"POST", "/health", 405, "method not allowed\n"},
		{"GET", "/other", 404, "404 page not found\n"},
	} {
		req, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != tc.status || string(body) != tc.body {
			t.Errorf("%s %s: status=%d body=%q err=%v", tc.method, tc.path, resp.StatusCode, body, err)
		}
	}
}

func TestTLS13(t *testing.T) {
	cfg, err := newTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("unexpected key: %T", cert.PublicKey)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatal(err)
	}
	other, err := newTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.Certificates[0].Certificate[0]) == string(other.Certificates[0].Certificate[0]) {
		t.Fatal("expected a fresh certificate")
	}
	server := httptest.NewUnstartedServer(healthHandler())
	server.TLS = cfg
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	resp, err := client.Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.TLS.Version != tls.VersionTLS13 || resp.StatusCode != http.StatusOK {
		t.Fatalf("version=%x status=%d", resp.TLS.Version, resp.StatusCode)
	}
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true,
	}}}
	if resp, err := old.Get(server.URL + "/health"); err == nil {
		resp.Body.Close()
		t.Fatal("TLS 1.2 unexpectedly succeeded")
	}
}

func TestModuleOrder(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".modules-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "modules.dep")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("kernel/virtio_net.ko: kernel/net_failover.ko kernel/failover.ko\nkernel/net_failover.ko: kernel/failover.ko\nkernel/failover.ko:\n")
	got, err := moduleOrder(dir, "virtio_net")
	want := []string{filepath.Join(dir, "kernel/failover.ko"), filepath.Join(dir, "kernel/net_failover.ko"), filepath.Join(dir, "kernel/virtio_net.ko")}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v; want %v", got, err, want)
	}
	write("kernel/virtio_net.ko: kernel/missing.ko\n")
	if _, err := moduleOrder(dir, "virtio_net"); err == nil || !strings.Contains(err.Error(), "missing dependency") {
		t.Fatalf("expected missing dependency error, got %v", err)
	}
	write("kernel/virtio_net.ko: kernel/a.ko\nkernel/a.ko: kernel/virtio_net.ko\n")
	if _, err := moduleOrder(dir, "virtio_net"); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

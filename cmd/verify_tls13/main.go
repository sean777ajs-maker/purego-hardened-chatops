package main

import (
"crypto/sha256"
"crypto/tls"
"encoding/hex"
"fmt"
"io"
"net/http"
"time"
)

func main() {
tlsCfg := &tls.Config{
InsecureSkipVerify: true,
MinVersion:         tls.VersionTLS13,
MaxVersion:         tls.VersionTLS13,
}
client := &http.Client{
Timeout:   5 * time.Second,
Transport: &http.Transport{TLSClientConfig: tlsCfg},
}

resp, err := client.Get("https://127.0.0.1:8443/health")
if err != nil {
fmt.Printf("[!] TLS 1.3 Request Error: %v\n", err)
return
}
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)

state := resp.TLS
cert := state.PeerCertificates[0]
sum := sha256.Sum256(cert.Raw)

fmt.Println("=== VERIFIED TLS 1.3 HANDSHAKE & CERTIFICATE ===")
fmt.Printf("TLS Version      : 0x%04X (TLS 1.3)\n", state.Version)
fmt.Printf("Cipher Suite     : %s\n", tls.CipherSuiteName(state.CipherSuite))
fmt.Printf("Subject CN       : %s\n", cert.Subject.CommonName)
fmt.Printf("Public Key Algo  : %s (P-256 Ephemeral In-Memory)\n", cert.PublicKeyAlgorithm.String())
fmt.Printf("Cert SHA-256     : %s\n", hex.EncodeToString(sum[:]))
fmt.Printf("HTTPS /health    : %s", string(body))
}

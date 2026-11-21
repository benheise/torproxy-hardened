// healthcheck verifies that the local Arti SOCKS5 port carries traffic over
// Tor. It replaces curl in the Docker HEALTHCHECK of a shell-less image.
//
// It fetches HEALTHCHECK_URL (default: the check.torproject.org API) through
// HEALTHCHECK_PROXY (default socks5h://127.0.0.1:9050, i.e. DNS resolved by
// Tor) and, for the default URL, requires IsTor=true. Exit 0 healthy, 1 not.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultURL   = "https://check.torproject.org/api/ip"
	defaultProxy = "socks5h://127.0.0.1:9050"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}
	ok, msg := check(envOr("HEALTHCHECK_URL", defaultURL), envOr("HEALTHCHECK_PROXY", defaultProxy))
	fmt.Println(msg)
	if !ok {
		os.Exit(1)
	}
}

func check(target, proxyURL string) (bool, string) {
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return false, "unhealthy: bad HEALTHCHECK_PROXY: " + err.Error()
	}
	u, err := url.Parse(target)
	if err != nil {
		return false, "unhealthy: bad HEALTHCHECK_URL: " + err.Error()
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), TLSHandshakeTimeout: 15 * time.Second}
	// A v3 onion address is the service's public key, so the address itself
	// authenticates the endpoint; onion HTTPS certificates are often self-signed.
	if strings.HasSuffix(u.Hostname(), ".onion") {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return false, "unhealthy: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return evaluate(target, resp.StatusCode, body)
}

// evaluate decides health from a response. For the default URL the body
// must report IsTor=true; otherwise any 2xx/3xx status is healthy.
func evaluate(target string, status int, body []byte) (bool, string) {
	if status < 200 || status >= 400 {
		return false, fmt.Sprintf("unhealthy: %s returned HTTP %d", target, status)
	}
	if target != defaultURL {
		return true, fmt.Sprintf("healthy: %s returned HTTP %d", target, status)
	}
	var r struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(body, &r); err != nil || !r.IsTor {
		return false, "unhealthy: traffic is not exiting via Tor (" + strings.TrimSpace(string(body)) + ")"
	}
	return true, "healthy: exiting via Tor (" + r.IP + ")"
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

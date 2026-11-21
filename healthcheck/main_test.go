package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvaluate(t *testing.T) {
	cases := []struct {
		target string
		status int
		body   string
		ok     bool
	}{
		{defaultURL, 200, `{"IsTor":true,"IP":"192.0.2.1"}`, true},
		{defaultURL, 200, `{"IsTor":false,"IP":"198.51.100.7"}`, false},
		{defaultURL, 200, `not json`, false},
		{defaultURL, 503, `{"IsTor":true}`, false},
		{"https://example.org/", 204, ``, true},
		{"https://example.org/", 302, ``, true},
		{"https://example.org/", 404, ``, false},
	}
	for _, c := range cases {
		ok, msg := evaluate(c.target, c.status, []byte(c.body))
		if ok != c.ok {
			t.Errorf("evaluate(%s, %d, %q) = %v (%s), want %v", c.target, c.status, c.body, ok, msg, c.ok)
		}
	}
}

func TestCheckProxyUnreachable(t *testing.T) {
	// Grab a free port, then close it so the proxy is refused.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	ok, msg := check("https://example.org/", "socks5h://"+addr)
	if ok || !strings.HasPrefix(msg, "unhealthy:") {
		t.Fatalf("want unhealthy, got %v %q", ok, msg)
	}
}

func TestCheckThroughHTTPProxy(t *testing.T) {
	// The proxy path is scheme-agnostic: an HTTP proxy that answers directly
	// exercises the request/response handling end to end.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	ok, msg := check("http://target.invalid/", srv.URL)
	if !ok {
		t.Fatalf("want healthy, got %q", msg)
	}
}

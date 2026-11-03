package bridge

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// forwardedHeaders are removed by httputil.ReverseProxy before Rewrite runs.
// The external reverse proxy sets them and Nexus needs them to build absolute
// URLs, so they are restored unchanged.
var forwardedHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}

// newProxy returns a reverse proxy to upstream. The incoming Host header is
// preserved. decide may set the trusted user header on the outbound request;
// it runs after the header and the bridge cookies have been stripped.
func (b *Bridge) newProxy(upstream *url.URL, decide func(in, out *http.Request)) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host
			for _, h := range forwardedHeaders {
				if v := pr.In.Header.Values(h); len(v) > 0 {
					pr.Out.Header[h] = v
				}
			}
			b.stripUserHeader(pr.Out.Header)
			stripBridgeCookies(pr.Out.Header)
			if decide != nil {
				decide(pr.In, pr.Out)
			}
		},
		Transport: b.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			b.log.Warn("upstream error", "upstream", upstream.Host, "method", r.Method, "path", r.URL.Path, "err", err)
			http.Error(w, "Nexus is not reachable", http.StatusBadGateway)
		},
	}
}

// stripUserHeader removes every spelling of the trusted header, including
// underscore variants that some servers treat as equivalent.
func (b *Bridge) stripUserHeader(h http.Header) {
	for name := range h {
		if strings.EqualFold(strings.ReplaceAll(name, "_", "-"), b.userHeader) {
			delete(h, name)
		}
	}
}

func newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil, // never route Nexus traffic through HTTP(S)_PROXY
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		// Pass Content-Encoding through untouched.
		DisableCompression: true,
	}
}

// isBrowserNavigation reports whether r looks like a top-level page load.
func isBrowserNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// isNexusSignOut matches the request the Nexus UI sends for "Sign out".
func isNexusSignOut(r *http.Request) bool {
	return r.Method == http.MethodDelete && strings.TrimRight(r.URL.Path, "/") == "/service/rapture/session"
}

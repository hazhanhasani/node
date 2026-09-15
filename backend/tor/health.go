package tor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ExitObservation is produced only from an HTTP request that traversed the
// location-specific Tor SOCKS listener.
type ExitObservation struct {
	IP        string
	Country   string
	LatencyMS int64
}

// ExitVerifier abstracts external IP/GeoIP services and makes health checks
// deterministic in tests.
type ExitVerifier interface {
	Verify(ctx context.Context, socksPort int) (ExitObservation, error)
}

type geoEndpoint struct {
	URL        string
	IPField    string
	CountryKey string
}

// HTTPExitVerifier uses independent providers with fallback. Hostname
// resolution is handed to SOCKS5 by passing the hostname untouched to the Tor
// proxy; the Node never resolves a provider hostname before entering Tor.
type HTTPExitVerifier struct {
	Timeout   time.Duration
	Endpoints []geoEndpoint
}

func NewHTTPExitVerifier(timeout time.Duration) *HTTPExitVerifier {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	return &HTTPExitVerifier{
		Timeout: timeout,
		Endpoints: []geoEndpoint{
			{URL: "https://api.country.is/", IPField: "ip", CountryKey: "country"},
			{URL: "https://ipapi.co/json/", IPField: "ip", CountryKey: "country_code"},
		},
	}
}

func (v *HTTPExitVerifier) client(socksPort int) (*http.Client, error) {
	if socksPort < 1 || socksPort > 65535 {
		return nil, fmt.Errorf("invalid SOCKS port %d", socksPort)
	}
	base := &net.Dialer{Timeout: v.Timeout, KeepAlive: 15 * time.Second}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, base)
	if err != nil {
		return nil, fmt.Errorf("create Tor SOCKS dialer: %w", err)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   v.Timeout,
		ResponseHeaderTimeout: v.Timeout,
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		},
	}
	return &http.Client{Transport: transport, Timeout: v.Timeout}, nil
}

func (v *HTTPExitVerifier) Verify(ctx context.Context, socksPort int) (ExitObservation, error) {
	client, err := v.client(socksPort)
	if err != nil {
		return ExitObservation{}, err
	}
	defer client.CloseIdleConnections()

	endpoints := v.Endpoints
	if len(endpoints) == 0 {
		return ExitObservation{}, errors.New("no exit verification providers configured")
	}

	var failures []string
	for _, endpoint := range endpoints {
		started := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL, nil)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "BluePanel-Node/TorHealth")
		resp, err := client.Do(req)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", endpoint.URL, err))
			continue
		}
		var body map[string]any
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			failures = append(failures, fmt.Sprintf("%s: HTTP %d", endpoint.URL, resp.StatusCode))
			continue
		}
		if decodeErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", endpoint.URL, decodeErr))
			continue
		}

		ip, _ := body[endpoint.IPField].(string)
		country, _ := body[endpoint.CountryKey].(string)
		ip = strings.TrimSpace(ip)
		country, err = NormalizeCountry(country)
		if err != nil || net.ParseIP(ip) == nil {
			failures = append(failures, fmt.Sprintf("%s: invalid IP/country response", endpoint.URL))
			continue
		}
		return ExitObservation{IP: ip, Country: country, LatencyMS: time.Since(started).Milliseconds()}, nil
	}
	return ExitObservation{}, fmt.Errorf("all exit verification providers failed: %s", strings.Join(failures, "; "))
}

func checkTCPPort(ctx context.Context, port int, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	return conn.Close()
}

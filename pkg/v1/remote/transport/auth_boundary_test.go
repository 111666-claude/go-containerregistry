// Copyright 2026 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// authRecordingTransport is a scripted RoundTripper that records every request
// it sees, separately tracking the requests that carried an Authorization
// header in AuthRequests. It is used to assert, without a live server, exactly
// which hosts receive credentials and how a transport reacts to a 401.
type authRecordingTransport struct {
	// responses are returned, in order, to successive RoundTrip calls. When the
	// slice is exhausted, the last response is reused.
	responses []*http.Response
	// errs are returned, in order, mirroring responses. Entries may be nil.
	errs []error

	Requests     []*http.Request
	AuthRequests []*http.Request
	calls        int
}

func (t *authRecordingTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	t.Requests = append(t.Requests, in)
	if a := in.Header.Get("Authorization"); a != "" {
		t.AuthRequests = append(t.AuthRequests, in)
	}

	idx := t.calls
	if idx >= len(t.responses) {
		idx = len(t.responses) - 1
	}
	t.calls++

	var resp *http.Response
	if idx >= 0 && idx < len(t.responses) {
		resp = t.responses[idx]
	}
	var err error
	if idx < len(t.errs) {
		err = t.errs[idx]
	}
	return resp, err
}

func challenge401(wwwAuthenticate string) *http.Response {
	h := http.Header{}
	h.Set("WWW-Authenticate", wwwAuthenticate)
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     http.StatusText(http.StatusUnauthorized),
		Header:     h,
		Body:       io.NopCloser(strings.NewReader("")),
	}
}

func okResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     http.StatusText(http.StatusOK),
		Body:       io.NopCloser(strings.NewReader("")),
	}
}

// reentrantScriptTransport simulates a single client.Do that encounters
// several successive 401 challenges. When the bearer transport's internal
// retry reaches the inner transport with another 401, the script re-enters the
// outer bearer RoundTripper so the next challenge is handled (and the per-request
// refresh counter on the transport advances), exactly as a registry answering
// 401 on the re-sent request would. It records one entry per simulated registry
// request, along with that request's Authorization header.
type reentrantScriptTransport struct {
	responses []*http.Response
	outer     http.RoundTripper

	Requests []*http.Request
	AuthHdrs []string
	calls    int
}

// reenterKey marks a request that is already a bearer-internal retry, so the
// scripted transport delivers a response instead of re-entering again.
type reenterKey struct{}

func (c *reentrantScriptTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	if in.Context().Value(reenterKey{}) == nil && c.outer != nil && c.calls > 0 {
		// This is an internal retry of an in-flight request: loop back through
		// the bearer transport to process the next challenge.
		ctx := context.WithValue(in.Context(), reenterKey{}, struct{}{})
		return c.outer.RoundTrip(in.WithContext(ctx))
	}

	c.Requests = append(c.Requests, in)
	c.AuthHdrs = append(c.AuthHdrs, in.Header.Get("Authorization"))

	idx := c.calls
	if idx >= len(c.responses) {
		idx = len(c.responses) - 1
	}
	c.calls++
	return c.responses[idx], nil
}

// TestBasicTransportHostCanonicalization verifies that basic credentials are
// attached using canonical host:port matching (default ports and IPv6 literals
// are normalized), so a local registry reached with or without an explicit
// default port still receives its Basic header, while a genuinely different
// host never does.
func TestBasicTransportHostCanonicalization(t *testing.T) {
	basic := &authn.Basic{Username: "user", Password: "pass"}

	cases := []struct {
		name     string
		target   string
		scheme   string
		reqURL   string
		wantAuth bool
	}{
		{
			name:     "https default port omitted matches explicit :443 target",
			target:   "registry.example.com:443",
			scheme:   "https",
			reqURL:   "https://registry.example.com/v2/",
			wantAuth: true,
		},
		{
			name:     "http default port omitted matches explicit :80 target",
			target:   "registry.example.com:80",
			scheme:   "http",
			reqURL:   "http://registry.example.com/v2/",
			wantAuth: true,
		},
		{
			name:     "local registry without port matches target with port",
			target:   "localhost:5000",
			scheme:   "http",
			reqURL:   "http://localhost:5000/v2/",
			wantAuth: true,
		},
		{
			name:     "different host does not receive credentials",
			target:   "registry.example.com",
			scheme:   "https",
			reqURL:   "https://evil.example.com/v2/",
			wantAuth: false,
		},
		{
			name:     "same host different port does not receive credentials",
			target:   "registry.example.com:5000",
			scheme:   "http",
			reqURL:   "http://registry.example.com:9000/v2/",
			wantAuth: false,
		},
		{
			name:     "ipv6 literal matches bracketed target",
			target:   "[::1]:5000",
			scheme:   "http",
			reqURL:   "http://[::1]:5000/v2/",
			wantAuth: true,
		},
		{
			name:     "ipv6 default port omitted matches explicit target port",
			target:   "[::1]:443",
			scheme:   "https",
			reqURL:   "https://[::1]/v2/",
			wantAuth: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &authRecordingTransport{responses: []*http.Response{okResponse()}}
			bt := &basicTransport{
				inner:  rec,
				auth:   basic,
				target: tc.target,
				scheme: tc.scheme,
			}

			req, err := http.NewRequest(http.MethodGet, tc.reqURL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := bt.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}

			gotAuth := len(rec.AuthRequests) == 1
			if gotAuth != tc.wantAuth {
				t.Errorf("Authorization attached = %v, want %v (auth requests: %d)", gotAuth, tc.wantAuth, len(rec.AuthRequests))
				return
			}
			if tc.wantAuth {
				if hdr := rec.AuthRequests[0].Header.Get("Authorization"); !strings.HasPrefix(hdr, "Basic ") {
					t.Errorf("Authorization = %q, want Basic prefix", hdr)
				}
			}
		})
	}
}

// TestBasicTransportNoCredentialsOnRedirect simulates an http.Client following
// a cross-host redirect: after the redirect, in.URL.Host is the new host while
// in.Host may be empty. The Basic credential for the original registry must
// not be re-attached to the redirected request.
func TestBasicTransportNoCredentialsOnRedirect(t *testing.T) {
	rec := &authRecordingTransport{responses: []*http.Response{okResponse()}}
	bt := &basicTransport{
		inner:  rec,
		auth:   &authn.Basic{Username: "user", Password: "pass"},
		target: "registry.example.com",
		scheme: "https",
	}

	// First request targets the registry: credentials must be attached.
	orig, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/blob", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bt.RoundTrip(orig); err != nil {
		t.Fatalf("first RoundTrip: %v", err)
	}

	// The redirected request (as produced by http.Client) carries the new host
	// in its URL and an empty Host.
	redir, err := http.NewRequest(http.MethodGet, "https://cdn.attacker.example.com/blob", nil)
	if err != nil {
		t.Fatal(err)
	}
	redir.Host = ""
	if _, err := bt.RoundTrip(redir); err != nil {
		t.Fatalf("redirected RoundTrip: %v", err)
	}

	if got, want := len(rec.Requests), 2; got != want {
		t.Fatalf("requests = %d, want %d", got, want)
	}
	if got, want := len(rec.AuthRequests), 1; got != want {
		t.Fatalf("authenticated requests = %d, want %d: Basic credential leaked cross-host", got, want)
	}
	if rec.AuthRequests[0].URL.Host != "registry.example.com" {
		t.Errorf("credential sent to %q, want registry.example.com", rec.AuthRequests[0].URL.Host)
	}
}

// TestBearerRefreshBoundaryOnce verifies the token-refresh boundary: when the
// registry keeps answering same-host requests with a 401 Bearer challenge that
// adds no new scope, the transport exchanges a token exactly once and then
// returns the subsequent response instead of looping on refresh() forever.
func TestBearerRefreshBoundaryOnce(t *testing.T) {
	registry, err := name.NewRegistry("registry.example.com", name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}

	// The inner transport always returns a 401 challenge carrying a scope the
	// transport already requested. A naive loop would refresh and resend
	// indefinitely; the no-progress guard must stop after one refresh.
	rec := &authRecordingTransport{
		responses: []*http.Response{
			challenge401(`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:pull"`),
			challenge401(`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:pull"`),
			challenge401(`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:pull"`),
		},
	}

	var refreshCalls int
	bt := &bearerTransport{
		inner:    rec,
		registry: registry,
		realm:    "https://registry.example.com/token",
		service:  "registry",
		scopes:   []string{"repo:foo:pull"},
		scheme:   "https",
		// The counting authenticator wraps authn.Bearer, whose refresh()
		// short-circuits by setting the token from the credential with no network
		// call, so the refresh count is observable without a real token server.
		basic: &countingAuthenticator{inner: &authn.Bearer{Token: "fresh-token"}, onAuth: func() { refreshCalls++ }},
	}

	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/foo/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := bt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	// First attempt + one retry after the single refresh.
	if got, want := len(rec.Requests), 2; got != want {
		t.Errorf("registry requests = %d, want %d (no unbounded retry loop)", got, want)
	}
	if refreshCalls != 1 {
		t.Errorf("token refresh authentications = %d, want 1", refreshCalls)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("final status = %d, want 401 surfaced to caller", resp.StatusCode)
	}
}

// TestBearerRetryStillSucceedsOnSecondAttempt confirms the boundary guard does
// not break the normal happy path: one 401 followed by a 200 with the refreshed
// token results in a successful response and exactly one refresh.
func TestBearerRetryStillSucceedsOnSecondAttempt(t *testing.T) {
	registry, err := name.NewRegistry("registry.example.com", name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}

	rec := &authRecordingTransport{
		responses: []*http.Response{
			challenge401(`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:pull"`),
			okResponse(),
		},
	}

	bt := &bearerTransport{
		inner:    rec,
		registry: registry,
		realm:    "https://registry.example.com/token",
		service:  "registry",
		scopes:   []string{"repo:foo:pull"},
		scheme:   "https",
		basic:    &authn.Bearer{Token: "fresh-token"},
	}

	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/foo/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := bt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200", resp.StatusCode)
	}
	if got, want := len(rec.Requests), 2; got != want {
		t.Errorf("registry requests = %d, want %d", got, want)
	}
	// Both attempts target the same host and therefore carry a Bearer header.
	if got, want := len(rec.AuthRequests), 2; got != want {
		t.Errorf("authenticated requests = %d, want %d", got, want)
	}
}

// TestBearerDoesNotAttachTokenCrossHost uses the recording transport to assert
// that a request whose host differs from the authenticated registry is sent
// without an Authorization header (the header-stripping half of redirect
// safety), while same-host requests keep their Bearer token.
func TestBearerDoesNotAttachTokenCrossHost(t *testing.T) {
	registry, err := name.NewRegistry("registry.example.com", name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	rec := &authRecordingTransport{responses: []*http.Response{okResponse(), okResponse()}}
	bt := &bearerTransport{
		inner:    rec,
		registry: registry,
		bearer:   authn.AuthConfig{RegistryToken: "the-token"},
		scheme:   "https",
	}

	same, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bt.RoundTrip(same); err != nil {
		t.Fatalf("same-host RoundTrip: %v", err)
	}

	cross, err := http.NewRequest(http.MethodGet, "https://blobstore.example.com/v2/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bt.RoundTrip(cross); err != nil {
		t.Fatalf("cross-host RoundTrip: %v", err)
	}

	if got, want := len(rec.AuthRequests), 1; got != want {
		t.Fatalf("authenticated requests = %d, want %d", got, want)
	}
	if rec.AuthRequests[0].URL.Host != "registry.example.com" {
		t.Errorf("token attached to %q, want registry.example.com", rec.AuthRequests[0].URL.Host)
	}
}

// TestRetryTransportWrapsBearerAndRetries composes the retry transport around
// the bearer transport to prove a temporary network error is retried and the
// eventual success is returned while the bearer token is attached to every
// same-host attempt.
func TestRetryTransportWrapsBearerAndRetries(t *testing.T) {
	registry, err := name.NewRegistry("registry.example.com", name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}

	tempErr := &temporaryNetError{}
	rec := &authRecordingTransport{
		responses: []*http.Response{nil, okResponse()},
		errs:      []error{tempErr, nil},
	}
	bt := &bearerTransport{
		inner:    rec,
		registry: registry,
		bearer:   authn.AuthConfig{RegistryToken: "the-token"},
		scheme:   "https",
	}

	tr := NewRetry(bt, WithRetryBackoff(noBackoff()))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example.com/v2/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got, want := len(rec.Requests), 2; got != want {
		t.Errorf("attempts = %d, want 2", got)
	}
	// The failed attempt still had its token attached before hitting the network.
	if got, want := len(rec.AuthRequests), 2; got != want {
		t.Errorf("authenticated attempts = %d, want %d", got, want)
	}
}

// TestBearerRefreshAllowsScopeEscalation verifies that a registry may demand
// additional scopes across successive 401 challenges within one request: each
// challenge that introduces a genuinely new scope triggers another refresh, and
// once the registry answers 200 the request succeeds. This must not be mistaken
// for the no-progress loop.
func TestBearerRefreshAllowsScopeEscalation(t *testing.T) {
	registry, err := name.NewRegistry("registry.example.com", name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}

	rec := &reentrantScriptTransport{
		responses: []*http.Response{
			challenge401(`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:pull"`),
			challenge401(`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:push"`),
			okResponse(),
		},
	}

	var refreshCalls int
	bt := &bearerTransport{
		inner:    rec,
		registry: registry,
		realm:    "https://registry.example.com/token",
		service:  "registry",
		// Start holding no scopes; each challenge adds a new one.
		scopes: []string{},
		scheme: "https",
		basic:  &countingAuthenticator{inner: &authn.Bearer{Token: "t"}, onAuth: func() { refreshCalls++ }},
	}
	rec.outer = bt

	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/foo/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := bt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200", resp.StatusCode)
	}
	// Initial attempt + two scope-driven refreshes + final success attempt.
	if got, want := len(rec.Requests), 3; got != want {
		t.Errorf("registry requests = %d, want %d", got, want)
	}
	if refreshCalls != 2 {
		t.Errorf("token refreshes = %d, want 2 (one per new scope)", refreshCalls)
	}
}

// TestBearerRefreshHardCeiling verifies the absolute cap: a registry that
// issues a never-ending series of distinct-scope challenges cannot force more
// than maxSameHostRefreshes token exchanges for a single request.
func TestBearerRefreshHardCeiling(t *testing.T) {
	registry, err := name.NewRegistry("registry.example.com", name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}

	// Each challenge advertises a distinct scope so the no-progress check never
	// fires; only the hard ceiling should stop the loop.
	resps := make([]*http.Response, 0, maxSameHostRefreshes+3)
	for i := 0; i < maxSameHostRefreshes+3; i++ {
		resps = append(resps, challenge401(
			`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:scope`+
				string(rune('a'+i))+`"`))
	}
	rec := &reentrantScriptTransport{responses: resps}

	var refreshCalls int
	bt := &bearerTransport{
		inner:    rec,
		registry: registry,
		realm:    "https://registry.example.com/token",
		service:  "registry",
		scopes:   []string{},
		scheme:   "https",
		basic:    &countingAuthenticator{inner: &authn.Bearer{Token: "t"}, onAuth: func() { refreshCalls++ }},
	}
	rec.outer = bt

	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/foo/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := bt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	// The first refresh is unconditional; afterwards the ceiling of
	// maxSameHostRefreshes attempts blocks the (maxSameHostRefreshes+1)-th token
	// exchange, so the request performs maxSameHostRefreshes-1 actual refreshes and
	// maxSameHostRefreshes registry requests (initial + one per completed refresh).
	wantRefreshes := maxSameHostRefreshes - 1
	if refreshCalls != wantRefreshes {
		t.Errorf("token refreshes = %d, want %d", refreshCalls, wantRefreshes)
	}
	if got, want := len(rec.Requests), maxSameHostRefreshes; got != want {
		t.Errorf("registry requests = %d, want %d", got, want)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("final status = %d, want 401 once the ceiling is reached", resp.StatusCode)
	}
}

// TestBearerRefreshCountersArePerRequest drives many concurrent requests
// through one bearerTransport. Each independent request gets its own refresh
// counter, and the per-request map is cleaned up so it does not grow without
// bound. A data race here would be caught by the race detector.
func TestBearerRefreshCountersArePerRequest(t *testing.T) {
	registry, err := name.NewRegistry("registry.example.com", name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}

	// Every request sees a repeated same-scope 401, so each performs exactly one
	// refresh before the no-progress guard returns the 401.
	rec := &authRecordingTransport{
		responses: []*http.Response{
			challenge401(`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:pull"`),
			challenge401(`Bearer realm="https://registry.example.com/token",service="registry",scope="repo:foo:pull"`),
		},
	}
	bt := &bearerTransport{
		inner:    rec,
		registry: registry,
		realm:    "https://registry.example.com/token",
		service:  "registry",
		scopes:   []string{"repo:foo:pull"},
		scheme:   "https",
		basic:    &authn.Bearer{Token: "t"},
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/foo", nil)
			if err != nil {
				t.Errorf("NewRequest: %v", err)
				return
			}
			resp, err := bt.RoundTrip(req)
			if err != nil {
				t.Errorf("RoundTrip: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()

	bt.mx.RLock()
	leftover := len(bt.refreshAttempts)
	bt.mx.RUnlock()
	if leftover != 0 {
		t.Errorf("per-request refresh map not cleaned up: %d stale entries", leftover)
	}
}

// countingAuthenticator wraps an authenticator and counts Authorization calls.
type countingAuthenticator struct {
	inner  authn.Authenticator
	onAuth func()
}

func (c *countingAuthenticator) Authorization() (*authn.AuthConfig, error) {
	if c.onAuth != nil {
		c.onAuth()
	}
	return c.inner.Authorization()
}

// temporaryNetError implements the temporary-error interface used by the retry
// predicate.
type temporaryNetError struct{}

func (*temporaryNetError) Error() string   { return "temporary network error" }
func (*temporaryNetError) Timeout() bool   { return false }
func (*temporaryNetError) Temporary() bool { return true }

// noBackoff returns a backoff that retries immediately so the test is fast and
// deterministic.
func noBackoff() Backoff {
	return Backoff{Steps: 3}
}

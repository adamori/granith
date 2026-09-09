package client

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testRawToken = "grnth_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))

const testAuthToken = "grnth_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

const testRequestID = "11111111-2222-3333-4444-555555555555"

func send202(w http.ResponseWriter) {
	w.Header().Set("X-Granith-Approval-Request", testRequestID)
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status":"pending","request_id":"` + testRequestID + `","expires_at":"` +
		time.Now().Add(time.Minute).UTC().Format(time.RFC3339) + `"}`))
}

func TestFetchBundleAwaitingApproval_ApprovedFlow(t *testing.T) {
	var polls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testAuthToken {
			t.Errorf("authorization includes unexpected token material: %q", got)
		}
		got := r.Header.Get("X-Granith-Approval-Request")
		if got == "" {
			send202(w)
			return
		}
		if got != testRequestID {
			t.Errorf("poll sent wrong request id %q", got)
		}
		polls++
		if polls == 1 {
			send202(w)
			return
		}
		w.Header().Set("ETag", `"abc"`)
		w.Write([]byte(`{"secrets":[]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, testRawToken)
	resp, err := c.FetchBundleAwaitingApproval(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 || string(resp.Body) != `{"secrets":[]}` {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if polls != 2 {
		t.Fatalf("expected 2 polls, got %d", polls)
	}
}

func TestFetchBundleAwaitingApproval_TerminalStates(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{http.StatusForbidden, ErrAccessDenied},
		{http.StatusGone, ErrAccessExpired},
		{http.StatusConflict, ErrAlreadyDelivered},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Granith-Approval-Request") == "" {
				send202(w)
				return
			}
			w.WriteHeader(tc.status)
		}))
		c := New(srv.URL, testRawToken)
		_, err := c.FetchBundleAwaitingApproval(nil)
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d: got %v, want %v", tc.status, err, tc.want)
		}
		srv.Close()
	}
}

func TestFetchBundle_NoWaitOn202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		send202(w)
	}))
	defer srv.Close()

	c := New(srv.URL, testRawToken)
	_, err := c.FetchBundle()
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("got %v, want ErrApprovalRequired", err)
	}
}

func TestRequestsOnlySendLookupID(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if got := r.Header.Get("Authorization"); got != "Bearer "+testAuthToken {
					t.Errorf("unexpected authorization: %q", got)
				}
				if r.Method != method || r.RequestURI != "/api/v1/bundle" {
					t.Errorf("unexpected request: %s %s", r.Method, r.RequestURI)
				}
				if requests == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.Write([]byte(`{"secrets":[]}`))
			}))
			defer srv.Close()

			c := New(srv.URL, testRawToken)
			defer c.Close()
			c.httpClient.Transport.(*retryTransport).baseDelay = time.Millisecond
			var err error
			if method == http.MethodHead {
				err = c.Ping()
			} else {
				_, err = c.FetchBundle()
			}
			if err != nil {
				t.Fatal(err)
			}
			if requests != 2 {
				t.Fatalf("expected two requests including retry, got %d", requests)
			}
		})
	}
}

func TestInvalidTokensNeverReachServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid token reached server")
	}))
	defer srv.Close()

	for _, raw := range []string{
		"",
		testAuthToken,
		testRawToken + ".extra",
		strings.TrimPrefix(testRawToken, "grnth_"),
		testAuthToken + ".short",
		"grnth_short." + strings.Repeat("A", 43),
	} {
		c := New(srv.URL, raw)
		if _, err := c.FetchBundle(); err == nil {
			t.Errorf("FetchBundle accepted invalid token %q", raw)
		}
		if err := c.Ping(); err == nil {
			t.Errorf("Ping accepted invalid token %q", raw)
		}
		c.Close()
	}
}

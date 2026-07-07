package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

	c := New(srv.URL, "grnth_x.y")
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
		c := New(srv.URL, "grnth_x.y")
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

	c := New(srv.URL, "grnth_x.y")
	_, err := c.FetchBundle()
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("got %v, want ErrApprovalRequired", err)
	}
}

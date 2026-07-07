package client

import (
	"net/http"
	"time"
)

type retryTransport struct {
	base       http.RoundTripper
	maxRetries int
	baseDelay  time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := range t.maxRetries {
		resp, err = t.base.RoundTrip(req)
		// <500 includes 202 (approval pending) — must pass through, never retry here
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		if attempt < t.maxRetries-1 {
			time.Sleep(t.baseDelay * time.Duration(1<<attempt))
		}
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

package client

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"time"
)

var (
	ErrAccessDenied     = errors.New("access denied by project owner")
	ErrAccessExpired    = errors.New("approval request expired")
	ErrAlreadyDelivered = errors.New("approval already used for a delivery")
	ErrApprovalTimeout  = errors.New("timed out waiting for owner approval")
	ErrApprovalRequired = errors.New("project requires owner approval for bundle access")
)

type Client struct {
	baseURL    string
	rawToken   []byte
	httpClient *http.Client
	etag       string
}

type Option func(*Client)

func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

func New(baseURL, rawToken string, opts ...Option) *Client {
	c := &Client{
		baseURL:  baseURL,
		rawToken: []byte(rawToken),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &retryTransport{
				base: &http.Transport{
					TLSClientConfig: &tls.Config{
						MinVersion: tls.VersionTLS13,
					},
					MaxIdleConns:       10,
					IdleConnTimeout:    90 * time.Second,
					DisableCompression: true,
				},
				maxRetries: 3,
				baseDelay:  500 * time.Millisecond,
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type BundleResponse struct {
	Body       []byte
	ETag       string
	StatusCode int
	// Set on 202 (approval pending):
	RequestID  string
	RetryAfter time.Duration
	ExpiresAt  time.Time
}

func (c *Client) doFetch(requestID string) (*BundleResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/v1/bundle", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+string(c.rawToken))
	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}
	if requestID != "" {
		req.Header.Set("X-Granith-Approval-Request", requestID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		etag := resp.Header.Get("ETag")
		c.etag = etag
		return &BundleResponse{Body: body, ETag: etag, StatusCode: 200}, nil

	case http.StatusNotModified:
		return &BundleResponse{StatusCode: 304, ETag: c.etag}, nil

	case http.StatusAccepted:
		out := &BundleResponse{
			StatusCode: 202,
			RequestID:  resp.Header.Get("X-Granith-Approval-Request"),
			RetryAfter: 5 * time.Second,
		}
		if s := resp.Header.Get("Retry-After"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				out.RetryAfter = time.Duration(n) * time.Second
			}
		}
		var pending struct {
			RequestID string    `json:"request_id"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if body, err := io.ReadAll(resp.Body); err == nil {
			if json.Unmarshal(body, &pending) == nil {
				if out.RequestID == "" {
					out.RequestID = pending.RequestID
				}
				out.ExpiresAt = pending.ExpiresAt
			}
		}
		if out.RequestID == "" {
			return nil, fmt.Errorf("server sent 202 without an approval request id")
		}
		return out, nil

	case http.StatusForbidden:
		if requestID != "" {
			return nil, ErrAccessDenied
		}
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bundle request failed: %d %s", resp.StatusCode, string(body))

	case http.StatusGone:
		return nil, ErrAccessExpired

	case http.StatusConflict:
		return nil, ErrAlreadyDelivered

	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bundle request failed: %d %s", resp.StatusCode, string(body))
	}
}

// FetchBundle fails fast with ErrApprovalRequired when the project gates access;
// use FetchBundleAwaitingApproval to wait for the owner's decision.
func (c *Client) FetchBundle() (*BundleResponse, error) {
	resp, err := c.doFetch("")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusAccepted {
		return nil, ErrApprovalRequired
	}
	return resp, nil
}

type StatusFunc func(msg string)

// FetchBundleAwaitingApproval polls the same approval request until the owner
// decides. The deadline tracks the server-side expiry so the authoritative
// denied/expired outcome is surfaced rather than a local timeout.
func (c *Client) FetchBundleAwaitingApproval(status StatusFunc) (*BundleResponse, error) {
	resp, err := c.doFetch("")
	if err != nil || resp.StatusCode != http.StatusAccepted {
		return resp, err
	}

	if status != nil {
		status("waiting for owner approval (request " + resp.RequestID + ")")
	}

	deadline := time.Now().Add(6 * time.Minute)
	if !resp.ExpiresAt.IsZero() {
		deadline = resp.ExpiresAt.Add(30 * time.Second)
	}
	interval := resp.RetryAfter
	requestID := resp.RequestID

	for time.Now().Before(deadline) {
		time.Sleep(interval)
		next, err := c.doFetch(requestID)
		if err != nil {
			return nil, err
		}
		if next.StatusCode != http.StatusAccepted {
			return next, nil
		}
		if next.RetryAfter > 0 {
			interval = next.RetryAfter
		}
	}
	return nil, ErrApprovalTimeout
}

func (c *Client) Close() {
	for i := range c.rawToken {
		c.rawToken[i] = 0
	}
	runtime.KeepAlive(c.rawToken)
}

func (c *Client) Ping() error {
	req, err := http.NewRequest("HEAD", c.baseURL+"/api/v1/bundle", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+string(c.rawToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		return fmt.Errorf("ping failed: status %d", resp.StatusCode)
	}
	return nil
}

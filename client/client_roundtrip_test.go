package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// fakeTransport is a controllable http.RoundTripper for tests.
type fakeTransport struct {
	// handler handles the request and returns a response
	handler func(req *http.Request) (*http.Response, error)
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if f.handler != nil {
		return f.handler(req)
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func TestConfig_GetPrivateKeyPEM_FileAndString(t *testing.T) {
	// Direct string case
	cfg := Config{PrivateKey: "c29tZS1wZW0="}
	got, err := cfg.GetPrivateKey()
	if err != nil {
		t.Fatalf("GetPrivateKey (string) error: %v", err)
	}
	if got != "c29tZS1wZW0=" {
		t.Fatalf("unexpected value: %s", got)
	}

	// File case
	tmp, err := os.CreateTemp(t.TempDir(), "pem-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	wantBytes := []byte("-----BEGIN EC PRIVATE KEY-----\nXXX\n-----END EC PRIVATE KEY-----\n")
	if _, err := tmp.Write(wantBytes); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	tmp.Close()

	cfg = Config{PrivateKeyFile: tmp.Name()}
	got, err = cfg.GetPrivateKey()
	if err != nil {
		t.Fatalf("GetPrivateKey (file) error: %v", err)
	}
	wantB64 := string(wantBytes)
	if got != wantB64 {
		t.Fatalf("unexpected file-based value: %s", got)
	}
}

func TestRoundTrip_MissingAuthorization(t *testing.T) {
	// Build a signer
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// Fake transport should not be called because auth is missing
	ft := &fakeTransport{handler: func(req *http.Request) (*http.Response, error) {
		t.Fatalf("underlying transport should not be called when auth is missing")
		return nil, nil
	}}

	rt := &eCDSARoundTripper{Transport: ft, signer: signer, ChunkSize: 4096, ValidatorUrlResolver: StaticValidatorUrlResolver("")}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    mustURL(t, "http://example.com/bucket/object"),
		Header: make(http.Header),
		Body:   nil,
	}

	_, err = rt.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "missing authorization header") {
		t.Fatalf("expected missing authorization error, got %v", err)
	}
}

func TestRoundTrip_NoOriginalContentType_FallbackToJSON(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	ft := &fakeTransport{handler: func(req *http.Request) (*http.Response, error) {
		ext := map[string]any{
			"originalS3Response": "DATA",
			"validatorSendData":  map[string]any{"k": "v"},
		}
		b, _ := json.Marshal(ext)
		hdr := make(http.Header)
		hdr.Set("Content-Type", "application/json")
		return &http.Response{StatusCode: 200, Header: hdr, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: req}, nil
	}}

	rt := &eCDSARoundTripper{Transport: ft, signer: signer, ChunkSize: 4096, ValidatorUrlResolver: StaticValidatorUrlResolver("http://validator.local/events")}
	req := &http.Request{Method: http.MethodGet, URL: mustURL(t, "http://example.com/bucket/object"), Header: make(http.Header)}
	req.Header.Set("Authorization", "Bearer abc")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected fallback Content-Type application/json, got %q", ct)
	}
}

func TestRoundTrip_NoValidatorURL_NoPost(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	var sawEvents bool
	ft := &fakeTransport{handler: func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/events") {
			sawEvents = true
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: req}, nil
		}
		// normal response (non-extended) so pass-through
		h := make(http.Header)
		h.Set("Content-Type", "text/plain")
		b := []byte("hello")
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: req}, nil
	}}

	rt := &eCDSARoundTripper{Transport: ft, signer: signer, ChunkSize: 1024, ValidatorUrlResolver: StaticValidatorUrlResolver("")}
	req := &http.Request{Method: http.MethodGet, URL: mustURL(t, "http://example.com/bucket/object"), Header: make(http.Header)}
	req.Header.Set("Authorization", "Bearer abc")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}
	if sawEvents {
		t.Fatalf("validator events should not be posted when ValidatorURL is empty")
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "hello" {
		t.Fatalf("unexpected body: %q", string(b))
	}
}

func TestRoundTrip_JSONPassthroughWhenNotExtended(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	ft := &fakeTransport{handler: func(req *http.Request) (*http.Response, error) {
		b := []byte(`{"foo":"bar"}`)
		h := make(http.Header)
		h.Set("Content-Type", "application/json")
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: req}, nil
	}}

	rt := &eCDSARoundTripper{Transport: ft, signer: signer, ChunkSize: 1024, ValidatorUrlResolver: StaticValidatorUrlResolver("http://validator.local/events")}
	req := &http.Request{Method: http.MethodGet, URL: mustURL(t, "http://example.com/bucket/object"), Header: make(http.Header)}
	req.Header.Set("Authorization", "Bearer abc")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != `{"foo":"bar"}` {
		t.Fatalf("body should pass through, got %q", string(b))
	}
}

func TestRoundTrip_NonJSONPassthrough(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	ft := &fakeTransport{handler: func(req *http.Request) (*http.Response, error) {
		h := make(http.Header)
		h.Set("Content-Type", "text/plain")
		b := []byte("plain")
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: req}, nil
	}}

	rt := &eCDSARoundTripper{Transport: ft, signer: signer, ChunkSize: 1024, ValidatorUrlResolver: StaticValidatorUrlResolver("http://validator.local/events")}
	req := &http.Request{Method: http.MethodGet, URL: mustURL(t, "http://example.com/bucket/object"), Header: make(http.Header)}
	req.Header.Set("Authorization", "Bearer abc")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "plain" {
		t.Fatalf("unexpected body: %q", string(b))
	}
}

package client

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// helper to build a minimal presigned-style URL with X-Amz-Signature
func makePresignedURL(sig string) string {
	base := "https://s3.example.com/bucket/key"
	v := url.Values{}
	v.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	v.Set("X-Amz-Credential", "dummy/20250101/us-east-1/s3/aws4_request")
	v.Set("X-Amz-Date", "20250101T000000Z")
	v.Set("X-Amz-Expires", "900")
	v.Set("X-Amz-SignedHeaders", "host")
	v.Set("X-Amz-Signature", sig)
	return base + "?" + v.Encode()
}

func TestAppendLimeWireNetworkParamsToPresignedURL_SignsAndAppends(t *testing.T) {
	// Arrange a deterministic private key
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cfg := Config{PrivateKey: b64pem}

	// A dummy AWS presigned URL carrying the signature value we will sign with
	awsSig := "deadbeefcafebabefeedface"
	inputURL := makePresignedURL(awsSig)

	// Act
	outURL, err := AddLimeWireNetworkParamsToPresignedURL(cfg, inputURL, 1)
	if err != nil {
		t.Fatalf("AddLimeWireNetworkParamsToPresignedURL error: %v", err)
	}

	// Assert
	u, _ := url.Parse(outURL)
	q := u.Query()
	reqID := q.Get(QueryParamRequestID)
	if reqID == "" {
		t.Fatalf("%s not found in output URL", QueryParamRequestID)
	}
	bnSig := q.Get(QueryParamSignature)
	if bnSig == "" {
		t.Fatalf("%s not found in output URL", QueryParamSignature)
	}
	// Ensure original AWS signature remains unchanged
	gotAwsSig := q.Get("X-Amz-Signature")
	if gotAwsSig != awsSig {
		t.Fatalf("X-Amz-Signature changed: want %q, got %q", awsSig, gotAwsSig)
	}

	// Verify the compact signature was produced by our private key over SHA256(reqID + maxRequestCount + awsSig)
	bnSigDecoded, err := url.QueryUnescape(bnSig)
	if err != nil {
		t.Fatalf("failed to unescape bnSig: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(bnSigDecoded)
	if err != nil {
		t.Fatalf("bnSig is not base64: %v", err)
	}
	maxCount := q.Get(QueryParamMaxRequestCount)
	h := sha256.Sum256([]byte(reqID + maxCount + awsSig))

	recoveredPub, ok, err := btcecdsa.RecoverCompact(sigBytes, h[:])
	if err != nil {
		t.Fatalf("RecoverCompact error: %v", err)
	}
	if !ok {
		t.Fatalf("signature verification failed")
	}

	// Compare recovered public key with the expected one from our private key
	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("failed to recreate signer: %v", err)
	}
	if !signer.privateKey.PubKey().IsEqual(recoveredPub) {
		t.Fatalf("recovered public key does not match expected")
	}
}

func TestAppendLimeWireNetworkParamsToPresignedURL_Errors(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cfg := Config{PrivateKey: b64pem}

	// Empty URL
	if _, err := AddLimeWireNetworkParamsToPresignedURL(cfg, "", 1); err == nil {
		t.Fatalf("expected error for empty URL")
	}

	// Missing X-Amz-Signature in URL
	u := "https://s3.example.com/bucket/key?X-Amz-Date=20250101T000000Z"
	if _, err := AddLimeWireNetworkParamsToPresignedURL(cfg, u, 1); err == nil || !strings.Contains(err.Error(), "X-Amz-Signature") {
		t.Fatalf("expected error about missing X-Amz-Signature, got %v", err)
	}
}

func TestExtractPresignedParams_Success(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cfg := Config{PrivateKey: b64pem}

	awsSig := "feedface"
	inputURL := makePresignedURL(awsSig)

	signedURL, err := AddLimeWireNetworkParamsToPresignedURL(cfg, inputURL, 1)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	info, err := ExtractPresignedParams(signedURL)
	if err != nil {
		t.Fatalf("ExtractPresignedParams error: %v", err)
	}

	if info.RequestID == "" || info.LimeWireNetworkSignature == "" {
		t.Fatalf("expected non-empty reqID and bnSig")
	}
	if info.AwsSignature != awsSig {
		t.Fatalf("awsSig mismatch: want %q got %q", awsSig, info.AwsSignature)
	}
}

func TestExtractPresignedParams_Errors(t *testing.T) {
	// Empty URL
	if _, err := ExtractPresignedParams(""); err == nil {
		t.Fatalf("expected error for empty URL")
	}

	// Missing x-lmwrntwrk-request-id
	u := makePresignedURL("abc")
	if _, err := ExtractPresignedParams(u); err == nil || !strings.Contains(err.Error(), QueryParamRequestID) {
		t.Fatalf("expected error mentioning %s, got %v", QueryParamRequestID, err)
	}

	// Missing x-lmwrntwrk-signature
	uu, _ := url.Parse(u)
	q := uu.Query()
	q.Set(QueryParamRequestID, "01HZXZ7W1YJ7R8ZQSVQSJ1VQAF")
	uu.RawQuery = q.Encode()
	if _, err := ExtractPresignedParams(uu.String()); err == nil || !strings.Contains(err.Error(), QueryParamSignature) {
		t.Fatalf("expected error mentioning %s, got %v", QueryParamSignature, err)
	}

	// Missing X-Amz-Signature
	q.Set(QueryParamSignature, "ZmFrZS1zaWc=")
	q.Del("X-Amz-Signature")
	uu.RawQuery = q.Encode()
	if _, err := ExtractPresignedParams(uu.String()); err == nil || !strings.Contains(err.Error(), "X-Amz-Signature") {
		t.Fatalf("expected error mentioning X-Amz-Signature, got %v", err)
	}
}

func mustURLLocal(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func TestRemoveLimeWireNetworkQueryParamsFromRequest_RemovesOnlyLimeWireNetworkParams(t *testing.T) {
	// Original request with LimeWireNetwork params and others
	orig := &http.Request{Method: http.MethodGet}
	orig.URL = mustURLLocal(t, "https://example.com/path?x-lmwrntwrk-request-id=RID123&x-lmwrntwrk-signature=S1G&X-Amz-Signature=aws&foo=bar")
	orig.Header = http.Header{"X-Test": []string{"v"}}

	clean, err := RemoveLimeWireNetworkQueryParamsFromRequest(orig)
	if err != nil {
		t.Fatalf("RemoveLimeWireNetworkQueryParamsFromRequest error: %v", err)
	}

	if clean == orig {
		t.Fatalf("expected a different (cloned) request, got same pointer")
	}
	if clean.URL.String() == orig.URL.String() {
		t.Fatalf("expected URL to change after removal")
	}

	// Ensure LimeWireNetwork params are removed
	q := clean.URL.Query()
	if q.Get(QueryParamRequestID) != "" {
		t.Fatalf("%s should be removed", QueryParamRequestID)
	}
	if q.Get(QueryParamSignature) != "" {
		t.Fatalf("%s should be removed", QueryParamSignature)
	}

	// Ensure other params remain intact
	if q.Get("X-Amz-Signature") != "aws" {
		t.Fatalf("X-Amz-Signature should remain unchanged")
	}
	if q.Get("foo") != "bar" {
		t.Fatalf("foo should remain unchanged")
	}

	// Ensure original request not mutated
	origQ := orig.URL.Query()
	if origQ.Get(QueryParamRequestID) == "" || origQ.Get(QueryParamSignature) == "" {
		t.Fatalf("original request query mutated; expected LimeWireNetwork params still present")
	}
}

func TestRemoveLimeWireNetworkQueryParamsFromRequest_IdempotentWhenAbsent(t *testing.T) {
	orig := &http.Request{Method: http.MethodGet}
	orig.URL = mustURL(t, "https://example.com/path?a=1&b=2")

	clean, err := RemoveLimeWireNetworkQueryParamsFromRequest(orig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clean.URL.String() != orig.URL.String() {
		t.Fatalf("expected URL unchanged when no LimeWireNetwork params present")
	}
}

func TestRemoveLimeWireNetworkQueryParamsFromRequest_MultipleOccurrences(t *testing.T) {
	orig := &http.Request{Method: http.MethodGet}
	// duplicate keys included
	orig.URL = mustURL(t, "https://example.com/path?x-lmwrntwrk-request-id=RID1&x-lmwrntwrk-request-id=RID2&x-lmwrntwrk-signature=S1&x-lmwrntwrk-signature=S2&keep=1")

	clean, err := RemoveLimeWireNetworkQueryParamsFromRequest(orig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q := clean.URL.Query()
	if _, ok := q[QueryParamRequestID]; ok {
		t.Fatalf("%s should have been fully removed", QueryParamRequestID)
	}
	if _, ok := q[QueryParamSignature]; ok {
		t.Fatalf("%s should have been fully removed", QueryParamSignature)
	}
	if q.Get("keep") != "1" {
		t.Fatalf("expected to keep other params")
	}
}

func TestRemoveLimeWireNetworkQueryParamsFromRequest_Errors(t *testing.T) {
	if _, err := RemoveLimeWireNetworkQueryParamsFromRequest(nil); err == nil {
		t.Fatalf("expected error for nil request")
	}

	req := &http.Request{}
	if _, err := RemoveLimeWireNetworkQueryParamsFromRequest(req); err == nil || !strings.Contains(err.Error(), "URL") {
		t.Fatalf("expected error mentioning URL is nil, got %v", err)
	}
}

func TestAppendLimeWireNetworkParamsToPresignedURL_AllowsMax4h(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cfg := Config{PrivateKey: b64pem}

	awsSig := "facefeed"
	u := makePresignedURL(awsSig)
	// Set X-Amz-Expires to boundary value 14400 (4 hours)
	uu, _ := url.Parse(u)
	q := uu.Query()
	q.Set("X-Amz-Expires", "14400")
	uu.RawQuery = q.Encode()

	if _, err := AddLimeWireNetworkParamsToPresignedURL(cfg, uu.String(), 1); err != nil {
		t.Fatalf("expected success for X-Amz-Expires=14400, got error: %v", err)
	}
}

func TestAppendLimeWireNetworkParamsToPresignedURL_RejectsExpiresOver4h(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cfg := Config{PrivateKey: b64pem}

	awsSig := "c0ffee"
	u := makePresignedURL(awsSig)
	// Set X-Amz-Expires to 14401 (> 4 hours)
	uu, _ := url.Parse(u)
	q := uu.Query()
	q.Set("X-Amz-Expires", "14401")
	uu.RawQuery = q.Encode()

	if _, err := AddLimeWireNetworkParamsToPresignedURL(cfg, uu.String(), 1); err == nil || !strings.Contains(err.Error(), "X-Amz-Expires") {
		t.Fatalf("expected error about X-Amz-Expires exceeding maximum, got %v", err)
	}
}

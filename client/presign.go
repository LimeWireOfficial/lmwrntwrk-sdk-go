package client

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/oklog/ulid/v2"
)

// Query parameter names used to carry LimeWireNetwork request metadata when using presigned URLs.
const (
	QueryParamRequestID                = "x-lmwrntwrk-request-id"
	QueryParamSignature                = "x-lmwrntwrk-signature"
	QueryParamMaxRequestCount          = "x-max-request-count"
	MaxAllowedPresignedRequestDuration = 4 * time.Hour // max allowed duration of presigned requests on the LimeWireNetwork network
	signatureHeaderName                = "X-Amz-Signature"
)

// AddLimeWireNetworkParamsToPresignedURL appends LimeWireNetwork request metadata as query parameters
// to an existing AWS S3 presigned URL and returns the resulting URL string.
//
// The signature is computed over:
//
//	message = requestId + maxRequestCount + X-Amz-Signature
//
// It adds query parameters:
//   - x-lmwrntwrk-request-id: ULID request id
//   - x-lmwrntwrk-signature: base64-encoded compact ECDSA(secp256k1) signature over SHA-256(message)
//   - x-max-request-count: how many times is presigned request allowed to be performed, >0
func AddLimeWireNetworkParamsToPresignedURL(cfg Config, presignedURL string, maxRequestCount int) (string, error) {
	if presignedURL == "" {
		return "", fmt.Errorf("presignedURL is empty")
	}

	if maxRequestCount <= 0 {
		return "", fmt.Errorf("maxRequestCount must be > 0")
	}
	maxRequestCountStr := strconv.Itoa(maxRequestCount)

	u, err := url.Parse(presignedURL)
	if err != nil {
		return "", fmt.Errorf("parse presigned url: %w", err)
	}

	// Extract only the value of the chosen signature header from query params
	q := u.Query()

	// Enforce maximum allowed presign expiry if present: X-Amz-Expires <= 4h
	if expStr := q.Get("X-Amz-Expires"); expStr != "" {
		exp, err := strconv.Atoi(expStr)
		if err != nil {
			return "", fmt.Errorf("invalid X-Amz-Expires value: %v", err)
		}
		expDuration := time.Duration(exp) * time.Second
		if expDuration > MaxAllowedPresignedRequestDuration {
			return "", fmt.Errorf("X-Amz-Expires exceeds maximum of %v allowed on the LimeWireNetwork", MaxAllowedPresignedRequestDuration)
		}
	}

	authValue := q.Get(signatureHeaderName)
	if authValue == "" {
		return "", fmt.Errorf("query parameter %q not found in presigned URL", signatureHeaderName)
	}

	pemB64, err := cfg.GetPrivateKey()
	if err != nil {
		return "", fmt.Errorf("get private key: %w", err)
	}
	signer, err := newECDSASigner(pemB64)
	if err != nil {
		return "", fmt.Errorf("init signer: %w", err)
	}

	rid, err := ulid.New(ulid.Timestamp(time.Now()), requestIDEntropy)
	if err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	reqID := rid.String()

	sig, err := signer.signStringCompact(reqID + maxRequestCountStr + authValue)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// Append LimeWireNetwork params
	q.Set(QueryParamRequestID, reqID)
	q.Set(QueryParamSignature, url.QueryEscape(sig))
	q.Set(QueryParamMaxRequestCount, maxRequestCountStr)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// LimeWireNetworkPresignInfo captures the relevant parameters extracted from a presigned URL
// that has been augmented with LimeWireNetwork metadata.
//
// Fields:
//   - RequestID: value of x-lmwrntwrk-request-id
//   - LimeWireNetworkSignature: value of x-lmwrntwrk-signature
//   - AwsSignature: value of X-Amz-Signature (the AWS presign signature)
//   - MaxRequestCount: optional value of x-max-request-count
type LimeWireNetworkPresignInfo struct {
	RequestID                string
	LimeWireNetworkSignature string
	AwsSignature             string
	MaxRequestCount          int
}

// ExtractPresignedParams parses the provided URL string and extracts LimeWireNetworkPresignInfo.
// Returns an error if the URL is invalid or any of the required parameters are missing.
func ExtractPresignedParams(presignedURL string) (LimeWireNetworkPresignInfo, error) {
	var info LimeWireNetworkPresignInfo
	if presignedURL == "" {
		return info, fmt.Errorf("presignedURL is empty")
	}

	u, parseErr := url.Parse(presignedURL)
	if parseErr != nil {
		return info, fmt.Errorf("parse presigned url: %w", parseErr)
	}

	q := u.Query()
	info.RequestID = q.Get(QueryParamRequestID)
	if info.RequestID == "" {
		return info, fmt.Errorf("query parameter %q not found in URL", QueryParamRequestID)
	}

	info.LimeWireNetworkSignature = q.Get(QueryParamSignature)
	if info.LimeWireNetworkSignature == "" {
		return info, fmt.Errorf("query parameter %q not found in URL", QueryParamSignature)
	}
	escapedSig, err := url.QueryUnescape(info.LimeWireNetworkSignature)
	if err != nil {
		return info, fmt.Errorf("unescape signature: %w", err)
	}
	info.LimeWireNetworkSignature = escapedSig

	info.AwsSignature = q.Get(signatureHeaderName)
	if info.AwsSignature == "" {
		return info, fmt.Errorf("query parameter %q not found in URL", signatureHeaderName)
	}

	if maxStr := q.Get(QueryParamMaxRequestCount); maxStr == "" {
		return info, fmt.Errorf("query parameter %q not found in URL", QueryParamMaxRequestCount)
	} else {
		maxReqCount, err := strconv.Atoi(maxStr)
		if err != nil {
			return info, fmt.Errorf("invalid %s value: %v", QueryParamMaxRequestCount, err)
		}
		if maxReqCount < 0 {
			return info, fmt.Errorf("%s must be >= 0", QueryParamMaxRequestCount)
		}
		info.MaxRequestCount = maxReqCount
	}

	return info, nil
}

// RemoveLimeWireNetworkQueryParamsFromRequest returns a copy of the request whose URL has
// all LimeWireNetwork query parameters removed. It removes the following keys from the URL query:
//   - x-lmwrntwrk-request-id (QueryParamRequestID)
//   - x-lmwrntwrk-signature (QueryParamSignature)
//   - x-max-request-count (QueryParamMaxRequestCount)
//
// The original request is not mutated. All other parts of the request (method, headers,
// body, path, fragment, and non-LimeWireNetwork query parameters) are preserved.
func RemoveLimeWireNetworkQueryParamsFromRequest(req *http.Request) (*http.Request, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if req.URL == nil {
		return nil, fmt.Errorf("request URL is nil")
	}

	// Clone copies the request with the same context and a deep copy of the URL.
	cloned := req.Clone(req.Context())

	// Make a copy of the URL struct before mutating to avoid touching the original.
	u := *cloned.URL
	q := u.Query()
	q.Del(QueryParamRequestID)
	q.Del(QueryParamSignature)
	q.Del(QueryParamMaxRequestCount)
	u.RawQuery = q.Encode()
	cloned.URL = &u
	return cloned, nil
}

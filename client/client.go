package client

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/allowlist"
	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/graph"
	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/internal/shared"
	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/internal/version"
	"github.com/oklog/ulid/v2"
)

// SignatureHeader is the HTTP response/request header that carries the request signature.
// Value format: base64-encoded compact ECDSA (secp256k1) signature over SHA-256(message), where:
//
//	message = requestId + authorization
//
// with both parts concatenated as UTF-8 bytes with NO delimiter.
// - requestId is the value of RequestIdHeader (a ULID string generated per request)
// - authorization is the exact value of the Authorization header sent on the request
// The server MUST reconstruct the same message bytes and verify the signature using the caller's public key.
const SignatureHeader = "X-Lmwrntwrk-Signature"

// RequestIdHeader is the HTTP header that carries a unique per-request identifier used in signing.
// The same value is used when constructing the message to sign (see SignatureHeader).
const RequestIdHeader = "x-Lmwrntwrk-Request-Id"

// ChunkSize is the HTTP header that carries the size of chunks used for building the hash list in the footer.
const ChunkSize = "x-Lmwrntwrk-Chunk-Size"

// FooterLength is the HTTP header that carries the size of the footer at the end of the request body.
const FooterLength = "X-Lmwrntwrk-Footer-Length"

// OriginalContentLengthHeader is the HTTP header that carries the original content length
// when transport or middleware may alter the body.
const OriginalContentLengthHeader = "Original-Content-Length"

// OriginalContentTypeHeader is the HTTP header that carries the original content type
// when transport or middleware may alter the body.
const OriginalContentTypeHeader = "Original-Content-Type"

// Canonical header keys used internally.
const contentTypeHeader = "Content-Type"
const contentLengthHeader = "Content-Length"
const contentTypeApplicationJson = "application/json"

// package-level ULID entropy, initialized once for requestId
var requestIDEntropy = ulid.Monotonic(rand.New(rand.NewSource(time.Now().UnixNano())), 0)

type ValidatorUrlResolver func() (string, error)

// Config holds the configuration for the LimeWireNetwork client
type Config struct {
	PrivateKey           string // private key, encoded in either hex, pem, or base64_pem
	PrivateKeyFile       string // path to a private key file in any supported format
	ChunkSize            int    // size of chunks for building a hash list in the footer, default: 4096
	ValidatorUrlResolver ValidatorUrlResolver
	GraphQLURL           string
	GraphQLBearer        string
}

func StaticValidatorUrlResolver(urls ...string) ValidatorUrlResolver {
	if len(urls) == 0 {
		panic("no validator url provided")
	}

	return func() (string, error) {
		randomIndex := rand.Intn(len(urls))
		return urls[randomIndex], nil
	}
}

func DefaultValidatorUrlResolver(client graph.ValidatorEndpointsGetter, ttl time.Duration) ValidatorUrlResolver {
	return NewCachingValidatorResolver(client, ttl)
}

type eCDSARoundTripper struct {
	Transport            http.RoundTripper
	signer               *ecdsaSigner
	ChunkSize            int // size of chunks for a building hash list in the footer
	ValidatorUrlResolver ValidatorUrlResolver
	sdkUserAgent         string
}

func (cfg *Config) GetPrivateKey() (string, error) {
	if cfg.PrivateKeyFile != "" {
		data, err := os.ReadFile(cfg.PrivateKeyFile)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	if cfg.PrivateKey != "" {
		return cfg.PrivateKey, nil
	}

	return "", nil
}

// NewHTTPClient creates a new http client that supports LimeWireNetwork authentication and data validation.
//
// LimeWireNetwork authentication uses ECDSA signature in request headers.
// LimeWireNetwork data validation uses a footer with a hash list and signature at the end of the body.
func NewHTTPClient(cfg Config) (*http.Client, error) {
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = shared.DefaultChunkSize
	}
	rt, err := newECDSARoundTripper(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: rt}, nil
}

func newECDSARoundTripper(cfg Config) (*eCDSARoundTripper, error) {
	privateKey, err := cfg.GetPrivateKey()
	if err != nil {
		return nil, err
	}
	signer, err := newECDSASigner(privateKey)
	if err != nil {
		return nil, err
	}

	validatorUrlResolver := cfg.ValidatorUrlResolver
	if validatorUrlResolver == nil {
		graphQLClient := graph.NewGraphQLClient(cfg.GraphQLURL, cfg.GraphQLBearer, nil)
		validatorUrlResolver = DefaultValidatorUrlResolver(graphQLClient, 1*time.Minute)
	}

	return &eCDSARoundTripper{
		Transport:            http.DefaultTransport,
		signer:               signer,
		ChunkSize:            cfg.ChunkSize,
		ValidatorUrlResolver: validatorUrlResolver,
		sdkUserAgent:         version.UserAgent(),
	}, nil
}

// RoundTrip implements the signing and footer-appending transport.
func (rt *eCDSARoundTripper) RoundTrip(incomingReq *http.Request) (*http.Response, error) {
	slog.Debug("Intercepting request", "method", incomingReq.Method, "url", incomingReq.URL, "content-type", incomingReq.Header.Get("Content-Type"))

	for key, value := range incomingReq.Header {
		slog.Debug("Request Header", "key", key, "value", value)
	}

	s3Action := allowlist.GetS3ActionFromRequest(incomingReq)
	if !allowlist.IsActionAllowed(s3Action) {
		return nil, fmt.Errorf("request not allowed")
	}

	auth := incomingReq.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	requestId, err := ulid.New(ulid.Timestamp(time.Now()), requestIDEntropy)
	if err != nil {
		return nil, fmt.Errorf("generate request id: %w", err)
	}
	requestIdString := requestId.String()

	sig, err := rt.signer.signStringCompact(requestIdString + auth)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	incomingReq.Header.Set(SignatureHeader, sig)
	incomingReq.Header.Set(RequestIdHeader, requestIdString)

	userAgent := incomingReq.Header.Get("User-Agent")
	if userAgent != "" {
		userAgent = fmt.Sprintf("%s %s", userAgent, rt.sdkUserAgent)
	} else {
		userAgent = rt.sdkUserAgent
	}
	incomingReq.Header.Set("User-Agent", userAgent)

	isRequestRecordingNeeded := s3Action == "s3:CompleteMultipartUpload" || s3Action == "s3:PutObjectTagging"

	wrappedRequestBody := NewMaybeBufferingReader(incomingReq.Body, isRequestRecordingNeeded)
	footerAppendingReader, err := FooterAppendingReader(wrappedRequestBody, FooterOptions{
		ChunkSize:   rt.ChunkSize,
		EcdsaSigner: rt.signer,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create FooterAppendingReader: %w", err)
	}

	if incomingReq.Body != nil {
		incomingReq.Body = footerAppendingReader

		incomingReq.Header.Set(FooterLength, "109")
		incomingReq.Header.Set(ChunkSize, strconv.Itoa(rt.ChunkSize))

		updatedContentLength := incomingReq.ContentLength + 109
		incomingReq.ContentLength = updatedContentLength
		incomingReq.Header.Set("Content-Length", strconv.FormatInt(updatedContentLength, 10))
	}

	response, err := rt.Transport.RoundTrip(incomingReq)
	if err != nil {
		return nil, fmt.Errorf("round trip: %w", err)
	}

	if allowlist.IsValidatorActionAllowed(s3Action) {
		if validatorPayload := generatePayload(incomingReq, response, wrappedRequestBody.GetBufferedData(), footerAppendingReader.validatorPayload, s3Action); validatorPayload != nil {
			validatorUrl, err := rt.ValidatorUrlResolver()
			if err != nil {
				slog.Error("Failed to resolve validator url, not sending event", "error", err)
			}

			sendDataToValidator(incomingReq.Context(), validatorPayload, validatorUrl, rt)
		}
	}

	return response, nil
}

package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/graph"
	"github.com/jellydator/ttlcache/v3"
)

// mockBSCClient implements only GetBucketDetails for testing
type mockBSCClient struct {
	details *graph.BucketDetails
	err     error
	calls   int
}

func (m *mockBSCClient) GetBucketDetails(ctx context.Context, bucket string) (*graph.BucketDetails, error) {
	m.calls++
	return m.details, m.err
}

func (m *mockBSCClient) GetStorageProvider(ctx context.Context, providerID uint32) (*graph.StorageProvider, error) {
	return nil, nil // Not used in tests
}

func TestResolveEndpoint_Success(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{
		details: &graph.BucketDetails{
			StorageProviderEndpointUrl: "https://example.com/path",
		},
	}, 0)
	scheme, host, err := r.ResolveEndpoint("bucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "https" || host != "example.com" {
		t.Errorf("expected https/example.com, got %s/%s", scheme, host)
	}
}

func TestResolveEndpoint_Success_HostWitPort(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{
		details: &graph.BucketDetails{
			StorageProviderEndpointUrl: "https://example.com:8080/path",
		},
	}, 0)
	scheme, host, err := r.ResolveEndpoint("bucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "https" || host != "example.com:8080" {
		t.Errorf("expected https/example.com:8080, got %s/%s", scheme, host)
	}
}

func TestResolveEndpoint_NoScheme(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{
		details: &graph.BucketDetails{
			StorageProviderEndpointUrl: "example.com",
		},
	}, 0)
	scheme, host, err := r.ResolveEndpoint("bucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "https" || host != "example.com" {
		t.Errorf("expected https/example.com, got %s/%s", scheme, host)
	}
}

func TestResolveEndpoint_Error(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{err: errors.New("fail")}, 0)
	scheme, host, err := r.ResolveEndpoint("bucket")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if scheme != "" || host != "" {
		t.Errorf("expected empty result on error, got %s/%s", scheme, host)
	}
}

func TestResolveEndpoint_NilClient(t *testing.T) {
	r := NewStorageProviderResolver(nil, 0)
	scheme, host, err := r.ResolveEndpoint("bucket")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if scheme != "" || host != "" {
		t.Errorf("expected empty result for nil client, got %s/%s", scheme, host)
	}
}

func TestResolveEndpoint_EmptyEndpoint(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{
		details: &graph.BucketDetails{StorageProviderEndpointUrl: ""},
	}, 0)
	scheme, host, err := r.ResolveEndpoint("bucket")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if scheme != "" || host != "" {
		t.Errorf("expected empty result for empty endpoint, got %s/%s", scheme, host)
	}
}

func TestResolveEndpoint_EmptyBucket(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{
		details: &graph.BucketDetails{StorageProviderEndpointUrl: "https://example.com"},
	}, 0)
	if _, _, err := r.ResolveEndpoint(""); err == nil {
		t.Fatalf("expected error for empty bucket, got nil")
	}
}

func TestResolveEndpoint_WhitespaceBucket(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{
		details: &graph.BucketDetails{StorageProviderEndpointUrl: "https://example.com"},
	}, 0)
	if _, _, err := r.ResolveEndpoint("   "); err == nil {
		t.Fatalf("expected error for whitespace bucket, got nil")
	}
}

func TestResolveEndpoint_InvalidURL(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{
		details: &graph.BucketDetails{StorageProviderEndpointUrl: "://bad"},
	}, 0)
	_, _, err := r.ResolveEndpoint("bucket")
	if err == nil {
		t.Fatalf("expected error for invalid URL, got nil")
	}
}

func TestResolveEndpoint_MissingHostAfterParse(t *testing.T) {
	r := NewStorageProviderResolver(&mockBSCClient{
		// path-only URL becomes https:// with empty host after prefixing
		details: &graph.BucketDetails{StorageProviderEndpointUrl: "/just-path"},
	}, 0)
	_, _, err := r.ResolveEndpoint("bucket")
	if err == nil {
		t.Fatalf("expected error for URL with empty host, got nil")
	}
}

func TestResolveEndpoint_CacheCorruptionGuard(t *testing.T) {
	mock := &mockBSCClient{details: &graph.BucketDetails{StorageProviderEndpointUrl: "https://good.example"}}
	impl := NewStorageProviderResolver(mock, time.Minute).(*storageProviderResolver)

	// Manually insert a bad cache entry to simulate corruption
	impl.cache.Set("bucket", endpoint{scheme: "", host: ""}, ttlcache.DefaultTTL)

	// Should not return cached bad value; should call backend once and then cache good value
	scheme, host, err := impl.ResolveEndpoint("bucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "https" || host != "good.example" {
		t.Fatalf("expected https/good.example, got %s/%s", scheme, host)
	}
	if mock.calls != 1 {
		t.Fatalf("expected backend call after evicting bad cache entry, got %d", mock.calls)
	}
}

func TestResolveEndpoint_Caching(t *testing.T) {
	mock := &mockBSCClient{details: &graph.BucketDetails{StorageProviderEndpointUrl: "https://cached.example"}}
	r := NewStorageProviderResolver(mock, 200*time.Millisecond)

	// first call hits client
	_, _, _ = r.ResolveEndpoint("bucket")
	// second call within TTL should hit cache
	_, _, _ = r.ResolveEndpoint("bucket")
	if mock.calls != 1 {
		t.Fatalf("expected 1 blockchain call within TTL, got %d", mock.calls)
	}

	// wait for expiry and call again
	time.Sleep(250 * time.Millisecond)
	_, _, _ = r.ResolveEndpoint("bucket")
	if mock.calls != 2 {
		t.Fatalf("expected second blockchain call after TTL expiry, got %d", mock.calls)
	}
}

func TestResolveEndpoint_PreserveStaleOnError(t *testing.T) {
	mock := &mockBSCClient{details: &graph.BucketDetails{StorageProviderEndpointUrl: "https://stale.example"}}
	// Use a small TTL so the fresh entry expires quickly but the item remains for stale usage
	ttl := 80 * time.Millisecond
	r := NewStorageProviderResolver(mock, ttl)

	// First call: success populates cache
	s1, h1, err := r.ResolveEndpoint("bucket")
	if err != nil {
		t.Fatalf("unexpected error on initial resolve: %v", err)
	}
	if s1 != "https" || h1 != "stale.example" {
		t.Fatalf("expected https/stale.example on first resolve, got %s/%s", s1, h1)
	}
	if mock.calls != 1 {
		t.Fatalf("expected 1 backend call after first resolve, got %d", mock.calls)
	}

	// Wait for fresh TTL to elapse so cache no longer returns a fresh hit
	time.Sleep(100 * time.Millisecond)

	// Simulate upstream failure
	mock.err = errors.New("upstream down")
	mock.details = nil

	// Second call: should serve stale from cache and NOT return error
	s2, h2, err := r.ResolveEndpoint("bucket")
	if err != nil {
		t.Fatalf("expected stale cache to be served on error, got error: %v", err)
	}
	if s2 != "https" || h2 != "stale.example" {
		t.Fatalf("expected stale https/stale.example on error, got %s/%s", s2, h2)
	}
	if mock.calls != 2 {
		t.Fatalf("expected backend to be called once more and then stale served, got calls=%d", mock.calls)
	}

	// Sleep less than grace TTL and verify stale is still served on subsequent error
	time.Sleep(60 * time.Millisecond)
	s3, h3, err := r.ResolveEndpoint("bucket")
	if err != nil {
		t.Fatalf("expected stale cache to be served again on error, got error: %v", err)
	}
	if s3 != "https" || h3 != "stale.example" {
		t.Fatalf("expected stale https/stale.example again, got %s/%s", s3, h3)
	}
	if mock.calls != 3 {
		t.Fatalf("expected a third backend call due to no fresh hit, got calls=%d", mock.calls)
	}
}

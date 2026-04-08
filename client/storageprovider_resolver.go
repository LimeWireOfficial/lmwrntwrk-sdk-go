package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/graph"
	"github.com/jellydator/ttlcache/v3"
)

// StorageProviderResolver is the public interface for resolving endpoints based on the bucket name.
type StorageProviderResolver interface {
	// ResolveEndpoint returns the tuple (scheme, host) for a given bucket name.
	ResolveEndpoint(bucket string) (string, string, error)
}

// storageProviderResolver is the unexported concrete implementation of StorageProviderResolver.
type storageProviderResolver struct {
	Client   graph.BucketDetailsGetter
	CacheTTL time.Duration
	// Grace period to keep stale entries when origin fetch fails (no global flags).
	StaleGraceTTL time.Duration

	cache *ttlcache.Cache[string, endpoint]
}

// an endpoint is a struct stored in the cache.
type endpoint struct {
	scheme  string
	host    string
	addedAt time.Time
}

func (e endpoint) valid() bool { return e.scheme != "" && e.host != "" }

// NewStorageProviderResolver creates a resolver with a pre-initialized cache.
// If client is nil, a default GraphQLClient is used.
// If ttl <= 0, a default of 1 minute is used.
func NewStorageProviderResolver(client graph.BucketDetailsGetter, ttl time.Duration) StorageProviderResolver {
	if client == nil {
		client = graph.DefaultGraphQLClient()
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	r := &storageProviderResolver{
		Client:        client,
		CacheTTL:      ttl,
		StaleGraceTTL: ttl, // default: extend for one more TTL on failures
	}
	r.cache = ttlcache.New[string, endpoint](ttlcache.WithTTL[string, endpoint](ttl))
	return r
}

func DefaultProviderResolver() StorageProviderResolver {
	return NewStorageProviderResolver(nil, 0)
}

// ResolveEndpoint returns the tuple (scheme, host, error) based on the bucket name using blockchain.
func (r *storageProviderResolver) ResolveEndpoint(bucket string) (string, string, error) {
	if r == nil {
		return "", "", errors.New("resolver is nil")
	}
	if r.Client == nil {
		return "", "", errors.New("blockchain client is nil")
	}
	if r.cache == nil {
		return "", "", errors.New("resolver cache is nil")
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return "", "", errors.New("bucket is empty")
	}

	// 1) Try cache first
	if scheme, host, ok := r.getFromCache(bucket); ok {
		return scheme, host, nil
	}

	// 2) Fetch fresh
	ctx := context.Background() // Using Background because this is invoked during client setup/init, not within a request lifecycle.
	details, err := r.Client.GetBucketDetails(ctx, bucket)
	if err != nil || details == nil {
		return r.staleOrError(bucket, fmt.Errorf("get bucket details: %w", err))
	}

	endpointURL := strings.TrimSpace(details.StorageProviderEndpointUrl)
	if !strings.Contains(endpointURL, "://") {
		endpointURL = "https://" + endpointURL
	}
	u, err := url.Parse(endpointURL)
	if err != nil {
		return r.staleOrError(bucket, fmt.Errorf("parse endpoint URL %q: %w", endpointURL, err))
	}
	ep := endpoint{scheme: u.Scheme, host: u.Host}
	if !ep.valid() {
		return r.staleOrError(bucket, fmt.Errorf("invalid endpoint URL %q", endpointURL))
	}

	scheme, host := ep.scheme, ep.host

	// success: update the cache with extended TTL so stale can be served on failures
	// TTLs are validated during initialization; no need for runtime <=0 checks here
	totalTTL := r.CacheTTL + r.StaleGraceTTL
	// Keep item in cache for CacheTTL + StaleGraceTTL, but serve as hit only within CacheTTL
	r.cache.Set(bucket, endpoint{scheme: scheme, host: host, addedAt: time.Now()}, totalTTL)
	return scheme, host, nil
}

// getFromCache retrieves an endpoint from cache if present.
// It also guards against corrupted entries by evicting invalid values.
func (r *storageProviderResolver) getFromCache(bucket string) (string, string, bool) {
	if it := r.cache.Get(bucket); it != nil {
		ce := it.Value()
		if !ce.valid() {
			// cache corruption guard; evict
			r.cache.Delete(bucket)
			return "", "", false
		}
		// Only serve from cache if within fresh TTL; keep item for potential stale use
		// TTLs are validated on initialization; just compare against CacheTTL
		if !ce.addedAt.IsZero() {
			if time.Since(ce.addedAt) > r.CacheTTL {
				return "", "", false
			}
		}
		return ce.scheme, ce.host, true
	}
	return "", "", false
}

// extendStaleIfPresent extends an existing cached value with a grace TTL and returns it.
// Note: getFromCache() already evicts invalid (corrupted) entries, so we don't
// re-validate here; we simply extend the existing cached value if present.
func (r *storageProviderResolver) extendStaleIfPresent(bucket string) (string, string, bool) {
	if it := r.cache.Get(bucket); it != nil {
		ce := it.Value()
		// refresh stale TTL to give another grace window
		r.cache.Set(bucket, ce, r.StaleGraceTTL)
		return ce.scheme, ce.host, true
	}
	return "", "", false
}

// staleOrError tries to return a stale cached endpoint if present; otherwise returns the provided error.
func (r *storageProviderResolver) staleOrError(bucket string, err error) (string, string, error) {
	if scheme, host, ok := r.extendStaleIfPresent(bucket); ok {
		return scheme, host, nil
	}
	return "", "", err
}

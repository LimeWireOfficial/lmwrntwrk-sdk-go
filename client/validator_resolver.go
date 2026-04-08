package client

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/graph"
	"github.com/jellydator/ttlcache/v3"
)

type cachingValidatorResolver struct {
	Client   graph.ValidatorEndpointsGetter
	CacheTTL time.Duration
	cache    *ttlcache.Cache[string, []string]
}

const validatorCacheKey = "enabled_endpoints"

// NewCachingValidatorResolver creates a ValidatorUrlResolver that caches endpoints from the graph.
// If ttl <= 0, a default of 10 minutes is used.
func NewCachingValidatorResolver(client graph.ValidatorEndpointsGetter, ttl time.Duration) ValidatorUrlResolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	r := &cachingValidatorResolver{
		Client:   client,
		CacheTTL: ttl,
	}
	r.cache = ttlcache.New[string, []string](ttlcache.WithTTL[string, []string](ttl))
	go r.cache.Start()

	return func() (string, error) {
		return r.resolve()
	}
}

func (r *cachingValidatorResolver) resolve() (string, error) {
	if r.Client == nil {
		return "", errors.New("validator endpoints getter is nil")
	}

	var endpoints []string
	if item := r.cache.Get(validatorCacheKey); item != nil {
		endpoints = item.Value()
	}

	if len(endpoints) == 0 {
		var err error
		endpoints, err = r.Client.ListEnabledValidatorEndpoints(context.Background())
		if err != nil {
			return "", err
		}
		if len(endpoints) == 0 {
			return "", errors.New("no enabled validator endpoints found")
		}
		r.cache.Set(validatorCacheKey, endpoints, r.CacheTTL)
	}

	randomIndex := rand.Intn(len(endpoints))
	return endpoints[randomIndex], nil
}

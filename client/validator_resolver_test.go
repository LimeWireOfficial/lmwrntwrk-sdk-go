package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockValidatorEndpointsGetter struct {
	endpoints []string
	err       error
	calls     int32
}

func (m *mockValidatorEndpointsGetter) ListEnabledValidatorEndpoints(ctx context.Context) ([]string, error) {
	atomic.AddInt32(&m.calls, 1)
	return m.endpoints, m.err
}

func TestCachingValidatorResolver(t *testing.T) {
	t.Run("success caching", func(t *testing.T) {
		mock := &mockValidatorEndpointsGetter{
			endpoints: []string{"http://v1.com", "http://v2.com"},
		}
		resolver := NewCachingValidatorResolver(mock, 100*time.Millisecond)

		// First call - should fetch
		url1, err := resolver()
		assert.NoError(t, err)
		assert.Contains(t, mock.endpoints, url1)
		assert.Equal(t, int32(1), atomic.LoadInt32(&mock.calls))

		// Second call - should use cache
		url2, err := resolver()
		assert.NoError(t, err)
		assert.Contains(t, mock.endpoints, url2)
		assert.Equal(t, int32(1), atomic.LoadInt32(&mock.calls))

		// Wait for cache to expire
		time.Sleep(150 * time.Millisecond)

		// Third call - should fetch again
		url3, err := resolver()
		assert.NoError(t, err)
		assert.Contains(t, mock.endpoints, url3)
		assert.Equal(t, int32(2), atomic.LoadInt32(&mock.calls))
	})

	t.Run("error fetching", func(t *testing.T) {
		mock := &mockValidatorEndpointsGetter{
			err: errors.New("network error"),
		}
		resolver := NewCachingValidatorResolver(mock, 10*time.Minute)

		url, err := resolver()
		assert.Error(t, err)
		assert.Equal(t, "", url)
		assert.Equal(t, int32(1), atomic.LoadInt32(&mock.calls))

		// Second call - should try again since it's not cached
		_, err = resolver()
		assert.Error(t, err)
		assert.Equal(t, int32(2), atomic.LoadInt32(&mock.calls))
	})

	t.Run("empty endpoints", func(t *testing.T) {
		mock := &mockValidatorEndpointsGetter{
			endpoints: []string{},
		}
		resolver := NewCachingValidatorResolver(mock, 10*time.Minute)

		url, err := resolver()
		assert.Error(t, err)
		assert.Equal(t, "no enabled validator endpoints found", err.Error())
		assert.Equal(t, "", url)
	})
}

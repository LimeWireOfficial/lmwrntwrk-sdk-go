package graph

import (
	"context"
	"math/big"
)

// StorageProvider represents a storage provider's details.
type StorageProvider struct {
	ID          uint32
	EndpointUrl string
}

// BucketDetails represents the decoded bucket details.
type BucketDetails struct {
	Visibility                 uint8
	AccountID                  uint32
	Status                     uint8
	CreatedDate                *big.Int
	PrimaryStorageProviderID   uint32
	StorageProviderEndpointUrl string
}

type BucketDetailsGetter interface {
	GetBucketDetails(ctx context.Context, bucket string) (*BucketDetails, error)
}

// ValidatorEndpointsGetter is the interface for getting validator endpoints.
type ValidatorEndpointsGetter interface {
	ListEnabledValidatorEndpoints(ctx context.Context) ([]string, error)
}

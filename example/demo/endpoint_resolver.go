package main

import (
	"context"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/client"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
)

type EndpointResolver struct {
	base                    s3.EndpointResolverV2
	limeWireNetworkResolver client.StorageProviderResolver
}

// NewEndpointResolver creates a new EndpointResolver that uses the provided base resolver and a LimeWireNetwork resolver.
// It first resolves the endpoint using the base resolver, then checks if a specific endpoint for the bucket is available
// using the LimeWireNetwork resolver. If a specific endpoint is found, it overrides the scheme and host of the resolved endpoint.
func NewEndpointResolver(base s3.EndpointResolverV2, limeWireNetworkResolver client.StorageProviderResolver) *EndpointResolver {
	return &EndpointResolver{
		base:                    base,
		limeWireNetworkResolver: limeWireNetworkResolver,
	}
}

func (c *EndpointResolver) ResolveEndpoint(ctx context.Context, params s3.EndpointParameters) (smithyendpoints.Endpoint, error) {
	ep, err := c.base.ResolveEndpoint(ctx, params)
	if err != nil {
		return ep, err
	}

	bucketName := ""
	if params.Bucket != nil {
		bucketName = *params.Bucket

		scheme, host, err := c.limeWireNetworkResolver.ResolveEndpoint(bucketName)
		if err != nil {
			return ep, err
		}
		if scheme != "" && host != "" {
			ep.URI.Scheme = scheme
			ep.URI.Host = host
			// log.Printf("Resolved endpoint for bucket '%s': %s://%s", bucketName, scheme, host)
		} else {
			// log.Printf("No specific endpoint resolved for bucket '%s', using default: %s", bucketName, ep.URI.String())
		}
	}

	return ep, nil
}

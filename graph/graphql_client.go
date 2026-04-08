package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

const DefaultGraphEndpoint = "https://graph.limewire.network/subgraphs/name/lmwrntwrk-v1"

//const DefaultGraphEndpoint = "http://graph-node-admin.localhost:8000/subgraphs/name/bn-test-1"

// GraphQLRequest defines the request structure for the GraphQL endpoint.
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse defines the response structure from the GraphQL endpoint.
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

type gqlAccount struct {
	ID string `json:"id"`
}

type gqlStorageProvider struct {
	ID          string `json:"id"`
	EndpointUrl string `json:"endpointUrl"`
}

type gqlBucket struct {
	ID                     string             `json:"id"`
	Name                   string             `json:"name"`
	Visibility             int                `json:"visibility"`
	Account                gqlAccount         `json:"account"`
	Status                 int                `json:"status"`
	PrimaryStorageProvider gqlStorageProvider `json:"primaryStorageProvider"`
	CreatedDate            string             `json:"createdDate"`
}

type gqlValidator struct {
	ID          string `json:"id"`
	EndpointUrl string `json:"endpointUrl"`
}

// GraphQLClient is a client for the GraphQL endpoint.
type GraphQLClient struct {
	URL        string
	Bearer     string
	HTTPClient *http.Client
}

// NewGraphQLClient creates a new GraphQL client.
func NewGraphQLClient(url string, bearer string, httpClient *http.Client) *GraphQLClient {
	if url == "" {
		url = DefaultGraphEndpoint
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &GraphQLClient{
		URL:        url,
		Bearer:     bearer,
		HTTPClient: httpClient,
	}
}

// DefaultGraphQLClient creates a GraphQL client using the package defaults.
func DefaultGraphQLClient() *GraphQLClient {
	return NewGraphQLClient("", "", nil)
}

func (c *GraphQLClient) query(ctx context.Context, query string, variables map[string]interface{}, result any) error {
	reqBody := GraphQLRequest{
		Query:     query,
		Variables: variables,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GraphQL request failed (%d): %s", resp.StatusCode, string(body))
	}

	var gqlResp GraphQLResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return fmt.Errorf("GraphQL errors: %v", gqlResp.Errors)
	}

	if err := json.Unmarshal(gqlResp.Data, result); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// GetBucketDetails retrieves bucket details via GraphQL.
func (c *GraphQLClient) GetBucketDetails(ctx context.Context, bucketName string) (*BucketDetails, error) {
	query := `
		query GetBucketDetails($name: String!) {
			buckets(where: {name: $name}, first: 1) {
				id
				name
				visibility
				account { id }
				status
				createdDate
				primaryStorageProvider {
					id
					endpointUrl
				}
			}
		}
	`

	var result struct {
		Buckets []gqlBucket `json:"buckets"`
	}

	err := c.query(ctx, query, map[string]interface{}{"name": bucketName}, &result)
	if err != nil {
		return nil, err
	}

	if len(result.Buckets) == 0 {
		return nil, fmt.Errorf("bucket not found: %s", bucketName)
	}

	b := result.Buckets[0]
	accountID, _ := strconv.ParseUint(b.Account.ID, 10, 32)
	createdDate := new(big.Int)
	createdDate.SetString(b.CreatedDate, 10)
	spID, _ := strconv.ParseUint(b.PrimaryStorageProvider.ID, 10, 32)

	return &BucketDetails{
		Visibility:                 uint8(b.Visibility),
		AccountID:                  uint32(accountID),
		Status:                     uint8(b.Status),
		CreatedDate:                createdDate,
		PrimaryStorageProviderID:   uint32(spID),
		StorageProviderEndpointUrl: b.PrimaryStorageProvider.EndpointUrl,
	}, nil
}

// GetStorageProvider retrieves storage provider details via GraphQL.
func (c *GraphQLClient) GetStorageProvider(ctx context.Context, providerID uint32) (*StorageProvider, error) {
	query := `
		query GetStorageProvider($id: ID!) {
			storageProvider(id: $id) {
				id
				owner
				endpointUrl
				createdDate
			}
		}
	`

	var result struct {
		StorageProvider *gqlStorageProvider `json:"storageProvider"`
	}

	err := c.query(ctx, query, map[string]interface{}{"id": strconv.FormatUint(uint64(providerID), 10)}, &result)
	if err != nil {
		return nil, err
	}

	if result.StorageProvider == nil {
		return nil, fmt.Errorf("storage provider not found: %d", providerID)
	}

	sp := result.StorageProvider
	id, _ := strconv.ParseUint(sp.ID, 10, 32)

	return &StorageProvider{
		ID:          uint32(id),
		EndpointUrl: sp.EndpointUrl,
	}, nil
}

// GetEnabledValidatorEndpoints retrieves all enabled validator endpoints via GraphQL.
func (c *GraphQLClient) ListEnabledValidatorEndpoints(ctx context.Context) ([]string, error) {
	query := `
		query GetValidators {
			validators(first: 3, where: {status: ENABLED}) {
				endpointUrl
			}
		}
	`

	var result struct {
		Validators []gqlValidator `json:"validators"`
	}

	err := c.query(ctx, query, nil, &result)
	if err != nil {
		return nil, err
	}

	if len(result.Validators) == 0 {
		return nil, fmt.Errorf("no active validator found")
	}

	endpoints := make([]string, len(result.Validators))
	for i, validator := range result.Validators {
		endpoints[i] = validator.EndpointUrl
	}

	return endpoints, nil
}

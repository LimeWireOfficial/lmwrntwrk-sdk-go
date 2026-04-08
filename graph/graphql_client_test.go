package graph

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGraphQLGetBucketDetails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GraphQLResponse{
			Data: json.RawMessage(`{
				"buckets": [{
					"visibility": 1,
					"account": {"id": "42"},
					"status": 0,
					"createdDate": "1700000001",
					"primaryStorageProvider": {
						"id": "7",
						"endpointUrl": "https://sp-primary.example"
					}
				}]
			}`),
		}
		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}))
	defer ts.Close()

	client := NewGraphQLClient(ts.URL, "test-token", nil)
	got, err := client.GetBucketDetails(context.Background(), "dev-bucket")
	if err != nil {
		t.Fatalf("GetBucketDetails error: %v", err)
	}

	if got.Visibility != 1 || got.AccountID != 42 || got.Status != 0 || got.CreatedDate.Cmp(big.NewInt(1700000001)) != 0 || got.PrimaryStorageProviderID != 7 || got.StorageProviderEndpointUrl != "https://sp-primary.example" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestGraphQLGetStorageProvider(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GraphQLResponse{
			Data: json.RawMessage(`{
				"storageProvider": {
					"id": "1",
					"owner": "0x1111111111111111111111111111111111111111",
					"endpointUrl": "https://sp.example",
					"createdDate": "1700000000"
				}
			}`),
		}
		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}))
	defer ts.Close()

	client := NewGraphQLClient(ts.URL, "test-token", nil)
	got, err := client.GetStorageProvider(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetStorageProvider error: %v", err)
	}

	if got.ID != 1 || got.EndpointUrl != "https://sp.example" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestGraphQLListEnabledValidatorEndpoints(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GraphQLResponse{
			Data: json.RawMessage(`{
				"validators": [
					{"endpointUrl": "https://v1.example"},
					{"endpointUrl": "https://v2.example"}
				]
			}`),
		}
		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}))
	defer ts.Close()

	client := NewGraphQLClient(ts.URL, "test-token", nil)
	got, err := client.ListEnabledValidatorEndpoints(context.Background())
	if err != nil {
		t.Fatalf("ListEnabledValidatorEndpoints error: %v", err)
	}

	if len(got) != 2 || got[0] != "https://v1.example" || got[1] != "https://v2.example" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

func generatePayload(
	request *http.Request,
	response *http.Response,
	requestBody []byte,
	footerPayload *ValidatorPayload,
	s3Action string,
) []byte {
	spSignature := response.Header.Get("x-lmwrntwrk-sp-signature")
	if spSignature == "" {
		return nil
	}

	var footerValue *Footer = nil
	if footerPayload != nil {
		if spFooterSig := response.Header.Get("x-lmwrntwrk-sp-footer-signature"); spFooterSig != "" {
			footerValue = &Footer{
				ClientSignature:          base64.StdEncoding.EncodeToString(footerPayload.Signature),
				FileSize:                 int(footerPayload.TotalSize),
				Hashes:                   convert(footerPayload.Hashes),
				StorageProviderSignature: spFooterSig,
			}
		}
	}

	responseBody, err := readResponseIfNeeded(s3Action, response)
	if err != nil {
		slog.Error("Failed to read response body", "error", err)
		return nil
	}

	result := StoreEventRequestJson{
		StorageProviderS3Signature: spSignature,
		StorageProviderPayload:     response.Header.Get("x-lmwrntwrk-sp-payload"),
		Footer:                     footerValue,
		Request: Request{
			Body:    toPointer(string(requestBody)),
			Headers: convertHeaderToArray(request.Header, request.Host),
			Method:  request.Method,
			Url:     request.URL.RequestURI(),
		},
		Response: Response{
			Body:    toPointer(string(responseBody)),
			Headers: convertHeaderToArray(response.Header, ""),
		},
	}

	marshalled, err := json.Marshal(result)
	if err != nil {
		slog.Error("Failed to marshal validator payload", "error", err)
		return nil
	}

	return marshalled
}

func convert(hashes []HashWithLength) []HashTuple {
	var result []HashTuple
	for _, h := range hashes {
		result = append(result, HashTuple{
			base64.StdEncoding.EncodeToString(h.Hash), strconv.Itoa(h.Length),
		})
	}
	return result
}

func convertHeaderToArray(header http.Header, host string) map[string]string {
	result := make(map[string]string)
	for k, v := range header {
		lowerKey := strings.ToLower(k)
		if len(v) > 0 {
			result[lowerKey] = v[0] // Use the first value for simplicity
		} else {
			result[lowerKey] = "" // Handle empty values
		}
	}
	// Add a host header if not present
	if _, ok := result["host"]; !ok && host != "" {
		result["host"] = host
	}
	return result
}

func sendDataToValidator(context context.Context, validatorData []byte, validatorUrl string, rt *eCDSARoundTripper) {
	req, reqErr := http.NewRequestWithContext(context, http.MethodPost, validatorUrl, bytes.NewReader(validatorData))
	if reqErr != nil {
		slog.Error("Failed to create validator request", "error", reqErr)
	}

	client := &http.Client{Transport: rt.Transport}
	if _, err := client.Do(req); err != nil {
		slog.Warn("Failed to send validatorData", "error", err)
	} else {
		slog.Debug("Sent validatorData", "url", validatorUrl, "payload", string(validatorData))
	}
}

func readResponseIfNeeded(s3Action string, resp *http.Response) ([]byte, error) {
	if s3Action == "s3:GetObject" {
		return nil, nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if err := resp.Body.Close(); err != nil {
		slog.Warn("could not close response body", "error", err)
	}

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, nil
}

func toPointer[T any](v T) *T {
	return &v
}

package allowlist

import (
	"net/http"
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func newReq(method, rawURL string) *http.Request {
	return &http.Request{
		Method: method,
		URL:    mustURL(&testing.T{}, rawURL),
	}
}

func TestAllowedRequest_MappedActions(t *testing.T) {
	tests := []struct {
		name   string
		method string
		url    string
		allow  bool
	}{
		// Bucket-level
		{"GetBucketTagging", http.MethodGet, "https://s3.local/bucket?tagging", true},
		{"PutBucketTagging", http.MethodPut, "https://s3.local/bucket?tagging", true},
		{"DeleteBucketTagging", http.MethodDelete, "https://s3.local/bucket?tagging", true},
		{"GetBucketVersioning", http.MethodGet, "https://s3.local/bucket?versioning", true},
		{"GetBucketLocation", http.MethodGet, "https://s3.local/bucket?location", true},
		{"ListObjects", http.MethodGet, "https://s3.local/bucket?max-keys=100", true},
		{"ListObjectsV2", http.MethodGet, "https://s3.local/bucket?list-type=2", true},
		{"ListMultipartUploads", http.MethodGet, "https://s3.local/bucket?uploads", true},
		{"CreateSession", http.MethodGet, "https://s3.local/bucket?session", false},
		{"HeadBucket", http.MethodHead, "https://s3.local/bucket", true},

		// Object tagging
		{"GetObjectTagging", http.MethodGet, "https://s3.local/bucket/object?tagging", true},
		{"PutObjectTagging", http.MethodPut, "https://s3.local/bucket/object?tagging", true},
		{"DeleteObjectTagging", http.MethodDelete, "https://s3.local/bucket/object?tagging", true},

		// Object lock / legal hold / retention
		{"GetObjectLegalHold", http.MethodGet, "https://s3.local/bucket/object?legal-hold", true},
		{"PutObjectLegalHold", http.MethodPut, "https://s3.local/bucket/object?legal-hold", false},
		{"GetObjectRetention", http.MethodGet, "https://s3.local/bucket/object?retention", true},
		{"PutObjectRetention", http.MethodPut, "https://s3.local/bucket/object?retention", false},
		{"GetObjectLockConfiguration", http.MethodGet, "https://s3.local/bucket?object-lock", true},
		{"PutObjectLockConfiguration", http.MethodPut, "https://s3.local/bucket?object-lock", false},

		// Multipart
		{"CreateMultipartUpload", http.MethodPost, "https://s3.local/bucket/object?uploads", true},
		{"AbortMultipartUpload", http.MethodDelete, "https://s3.local/bucket/object?uploadId=abc", true},
		{"ListParts", http.MethodGet, "https://s3.local/bucket/object?uploadId=abc", true},
		{"ListMultipartUploads", http.MethodGet, "https://s3.local/bucket?uploads&delimiter=Delimiter", true},
		{"CompleteMultipartUpload", http.MethodPost, "https://s3.local/bucket/object?uploadId=abc", true},
		{"UploadPart", http.MethodPut, "https://s3.local/bucket/object?partNumber=1&uploadId=abc", true},

		// Objects
		{"HeadObject", http.MethodHead, "https://s3.local/bucket/object", true},
		{"GetObject", http.MethodGet, "https://s3.local/bucket/object", true},
		{"PutObject", http.MethodPut, "https://s3.local/bucket/object", true},
		{"DeleteObject", http.MethodDelete, "https://s3.local/bucket/object", true},
		{"DeleteObjects", http.MethodPost, "https://s3.local/bucket?delete", true},

		// GetObjectAttributes via attributes param
		{"GetObjectAttributes", http.MethodGet, "https://s3.local/bucket/object?attributes", true},

		// Unknown/Not allowed examples
		{"Create", http.MethodPut, "https://s3.local/bucket", false},
		{"DeleteBucket", http.MethodDelete, "https://s3.local/bucket", false},
		{"UnknownBucketPostUploads", http.MethodPost, "https://s3.local/bucket?uploads", false},
		{"UnknownServiceRoot", http.MethodGet, "https://s3.local/", false},
		{"UnknownBucketOp", http.MethodPost, "https://s3.local/bucket", false},
		{"UnknownObjectOp", http.MethodPatch, "https://s3.local/bucket/object", false},
		{"UnknownQuery", http.MethodGet, "https://s3.local/bucket?acl", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newReq(tc.method, tc.url)
			// action name check
			gotAction := GetS3ActionFromRequest(r)
			if gotAction != "" && gotAction != "s3:"+tc.name {
				t.Fatalf("getS3ActionFromRequest(%s %s) = %q, want %q", tc.method, tc.url, GetS3ActionFromRequest(r), tc.name)
			}

			// allowed check
			got := AllowedRequest(r)
			if got != tc.allow {
				t.Fatalf("AllowedRequest(%s %s) = %v, want %v", tc.method, tc.url, got, tc.allow)
			}
		})
	}
}

func TestGetS3ActionFromRequest_CopyObject(t *testing.T) {
	r := newReq(http.MethodPut, "https://s3.local/dst-bucket/dst-object")
	// ensure Header is initialized before setting
	r.Header = make(http.Header)
	r.Header.Set("x-amz-copy-source", "/src-bucket/src-object")

	action := GetS3ActionFromRequest(r)
	if action != "s3:CopyObject" {
		t.Fatalf("getS3ActionFromRequest did not map to CopyObject, got %q", action)
	}
	if !AllowedRequest(r) {
		t.Fatalf("AllowedRequest should allow CopyObject request")
	}
}

func TestGetS3ActionFromRequest_UploadPartCopy(t *testing.T) {
	r := newReq(http.MethodPut, "https://s3.local/dst-bucket/dst-object?partNumber=1&uploadId=abc")
	// ensure Header is initialized before setting
	r.Header = make(http.Header)
	r.Header.Set("x-amz-copy-source", "/src-bucket/src-object")

	action := GetS3ActionFromRequest(r)
	if action != "s3:UploadPartCopy" {
		t.Fatalf("getS3ActionFromRequest did not map to UploadPartCopy, got %q", action)
	}
	if !AllowedRequest(r) {
		t.Fatalf("AllowedRequest should allow UploadPartCopy request")
	}
}

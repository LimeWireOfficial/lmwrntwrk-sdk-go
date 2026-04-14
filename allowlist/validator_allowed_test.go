package allowlist

import (
	"net/http"
	"testing"
)

func TestIsValidatorActionAllowed(t *testing.T) {
	tests := []struct {
		action  string
		allowed bool
	}{
		// Whitelisted
		{"s3:AbortMultipartUpload", true},
		{"s3:CompleteMultipartUpload", true},
		{"s3:CopyObject", true},
		{"s3:CreateMultipartUpload", true},
		{"s3:DeleteObject", true},
		{"s3:DeleteObjects", true},
		{"s3:DeleteObjectTagging", true},
		{"s3:GetObject", true},
		{"s3:PutBucketTagging", true},
		{"s3:PutObject", true},
		{"s3:PutObjectTagging", true},
		{"s3:UploadPart", true},
		{"s3:UploadPartCopy", true},

		// Not Whitelisted (but might be in general allowlist)
		{"s3:GetBucketTagging", false},
		{"s3:GetBucketVersioning", false},
		{"s3:ListObjects", false},
		{"s3:ListObjectsV2", false},
		{"s3:HeadBucket", false},
		{"s3:HeadObject", false},
		{"s3:ListParts", false},
		{"s3:GetObjectAttributes", false},
		{"s3:GetObjectLegalHold", false},
		{"s3:GetObjectRetention", false},
		{"s3:GetObjectLockConfiguration", false},
		{"", false},
		{"random", false},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := IsValidatorActionAllowed(tc.action)
			if got != tc.allowed {
				t.Errorf("IsValidatorActionAllowed(%q) = %v, want %v", tc.action, got, tc.allowed)
			}
		})
	}
}

func TestValidatorAllowedRequest(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		url     string
		allowed bool
	}{
		{"PutObject", http.MethodPut, "https://s3.local/bucket/object", true},
		{"GetObject", http.MethodGet, "https://s3.local/bucket/object", true},
		{"ListObjects", http.MethodGet, "https://s3.local/bucket?max-keys=100", false},
		{"GetBucketTagging", http.MethodGet, "https://s3.local/bucket?tagging", false},
		{"PutBucketTagging", http.MethodPut, "https://s3.local/bucket?tagging", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newReq(tc.method, tc.url)
			action := GetS3ActionFromRequest(r)
			got := IsValidatorActionAllowed(action)
			if got != tc.allowed {
				t.Errorf("Validator allowed check for %s (%s %s) = %v, want %v (action: %s)", tc.name, tc.method, tc.url, got, tc.allowed, action)
			}
		})
	}
}

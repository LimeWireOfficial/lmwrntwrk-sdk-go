package allowlist

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
	"sync"
)

// provided by actions_embed.go
//   var actionsJSON []byte

// Package-level immutable data initialized once from embedded JSON.
var (
	once       sync.Once
	allowedSet map[string]struct{}
	initErr    error
)

// allowed reports whether the action is allowed by the embedded policy.
// It lazily initializes from the embedded actionsJSON once.
func allowed(action string) bool {
	initialize()
	if initErr != nil {
		// Fail closed if initialization failed.
		return false
	}
	_, ok := allowedSet[action]
	return ok
}

// AllowedRequest reports whether the embedded policy allows the given HTTP request.
func AllowedRequest(r *http.Request) bool {
	action := GetS3ActionFromRequest(r)
	return allowed(action)
}

func IsActionAllowed(action string) bool {
	return allowed(action)
}

// GetS3ActionFromRequest maps an HTTP request to the closest S3 action name.
// It supports virtual-hosted-style and path-style addressing and inspects query params
// to disambiguate operations. Unsupported/unknown requests map to an empty action.
func GetS3ActionFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	method := r.Method
	u := r.URL
	if u == nil {
		return ""
	}
	// Normalize path components.
	rawPath := u.EscapedPath()
	if rawPath == "" {
		rawPath = "/"
	}
	p := path.Clean(rawPath)
	if p == "." {
		p = "/"
	}

	// Extract top-level resource semantics.
	// Path may be:
	// - "/" => service-level (unused here)
	// - "/bucket" => bucket-level
	// - "/bucket/object" => object-level
	// Virtual-hosted-style like "bucket.s3.amazonaws.com/object" appears in Host; we focus on path for simplicity.

	// Parse query flags once.
	q := u.Query()
	has := func(k string) bool { _, ok := q[k]; return ok }
	get := func(k string) string { return q.Get(k) }

	// Helper: count path segments (excluding leading "/").
	segments := strings.Split(strings.TrimPrefix(p, "/"), "/")
	segCount := 0
	for _, s := range segments {
		if s != "" {
			segCount++
		}
	}
	isBucketPath := segCount == 1
	isObjectPath := segCount >= 2

	// Order matters: check most specific patterns first.

	// Multipart uploads related
	if isBucketPath && has("uploads") && method == http.MethodGet {
		return "s3:ListMultipartUploads"
	}
	if isObjectPath && has("uploadId") && method == http.MethodGet {
		return "s3:ListParts"
	}
	if isObjectPath && has("uploadId") && method == http.MethodDelete {
		return "s3:AbortMultipartUpload"
	}
	if isObjectPath && has("uploadId") && method == http.MethodPost {
		return "s3:CompleteMultipartUpload"
	}
	if isObjectPath && has("partNumber") && has("uploadId") && method == http.MethodPut {
		if r.Header.Get("x-amz-copy-source") != "" {
			return "s3:UploadPartCopy"
		}
		return "s3:UploadPart"
	}

	// Tagging
	if isBucketPath && has("tagging") {
		switch method {
		case http.MethodGet:
			return "s3:GetBucketTagging"
		case http.MethodDelete:
			return "s3:DeleteBucketTagging"
		case http.MethodPut:
			return "s3:PutBucketTagging"
		}
	}
	if isObjectPath && has("tagging") {
		switch method {
		case http.MethodGet:
			return "s3:GetObjectTagging"
		case http.MethodDelete:
			return "s3:DeleteObjectTagging"
		case http.MethodPut:
			return "s3:PutObjectTagging"
		}
	}

	// Object lock / legal hold / retention (object-level)
	if isObjectPath && has("legal-hold") {
		if method == http.MethodGet {
			return "s3:GetObjectLegalHold"
		}
		if method == http.MethodPut {
			return "s3:PutObjectLegalHold"
		}
	}
	if isObjectPath && has("retention") {
		if method == http.MethodGet {
			return "s3:GetObjectRetention"
		}
		if method == http.MethodPut {
			return "s3:PutObjectRetention"
		}
	}
	if isBucketPath && has("object-lock") {
		if method == http.MethodGet {
			return "s3:GetObjectLockConfiguration"
		}
		if method == http.MethodPut {
			return "s3:PutObjectLockConfiguration"
		}
	}

	// Bucket operations
	if isBucketPath && has("versioning") && method == http.MethodGet {
		return "s3:GetBucketVersioning"
	}
	if isBucketPath && has("location") && method == http.MethodGet {
		return "s3:GetBucketLocation"
	}
	if isBucketPath && has("session") && method == http.MethodGet {
		return "s3:CreateSession"
	}
	if isBucketPath && has("delete") && method == http.MethodPost {
		return "s3:DeleteObjects"
	}
	if isBucketPath && method == http.MethodHead {
		return "s3:HeadBucket"
	}

	// ListObject
	if isBucketPath && method == http.MethodGet {
		if get("list-type") == "2" {
			return "s3:ListObjectsV2"
		}
		// example ListObjects: GET /?delimiter=Delimiter&encoding-type=EncodingType&marker=Marker&max-keys=MaxKeys&prefix=Prefix HTTP/1.1
		if has("delimiter") || has("encoding-type") || has("marker") || has("max-keys") || has("prefix") {
			return "s3:ListObjects"
		}
	}

	// Object basic operations
	if isObjectPath {
		switch method {
		case http.MethodGet:
			if has("attributes") {
				return "s3:GetObjectAttributes"
			}
			return "s3:GetObject"
		case http.MethodPut:
			// Detect CopyObject via x-amz-copy-source header on PUT per AWS S3 API.
			if r.Header.Get("x-amz-copy-source") != "" {
				return "s3:CopyObject"
			}
			return "s3:PutObject"
		case http.MethodPost:
			if has("uploadId") {
				return "s3:CompleteMultipartUpload"
			}
			if has("uploads") {
				return "s3:CreateMultipartUpload"
			}
		case http.MethodDelete:
			return "s3:DeleteObject"
		case http.MethodHead:
			return "s3:HeadObject"
		}
	}

	return ""
}

// initialize parses the embedded actionsJSON exactly once.
func initialize() {
	once.Do(func() {
		var fs struct {
			Actions     []string `json:"actions"`
			Description string   `json:"description"`
		}
		dec := json.NewDecoder(strings.NewReader(string(actionsJSON)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fs); err != nil {
			initErr = err
			log.Printf("allowlist: failed to decode embedded actions.json: %v", err)
			return
		}
		m := make(map[string]struct{}, len(fs.Actions))
		for _, act := range fs.Actions {
			act = strings.TrimSpace(act)
			if act == "" {
				continue
			}
			m[act] = struct{}{}
		}
		if len(m) == 0 {
			initErr = fmt.Errorf("no valid actions in embedded actions.json")
			log.Printf("allowlist: no valid actions in embedded actions.json")
			return
		}
		allowedSet = m
	})
}

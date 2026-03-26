package client

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
)

type RecordedRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
}

type RequestSpy struct {
	Requests []RecordedRequest
}

func startMockServer(spy *RequestSpy) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		spy.Requests = append(spy.Requests, RecordedRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: r.Header.Clone(),
			Body:    body,
		})

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/bucket/simple-get":
			w.Header().Set("x-lmwrntwrk-sp-signature", "IGSNDfoL8HxqQL+uaaadnd0x8paLIkUivp+ksvei+G2nFgknlUwy+lezOCwYjMmTETDw5vmc7k/qeCVDkZCgGUE=")
			w.Header().Set("x-lmwrntwrk-sp-payload", `{"some-key": "some-value"}`)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "Hello, LimeWireNetwork!")

		case r.Method == http.MethodPost && r.URL.Path == "/bucket/multipart-key":
			w.Header().Set("x-lmwrntwrk-sp-signature", "H/vgsIJFXxaHCoIWGXvr3VHuSfp+J+UNDnKvi4phopjRc7j+4C5eNWskx78zMN3NgMErvh/r19mzRy4hXjJtjSY=")
			w.Header().Set("x-lmwrntwrk-sp-footer-signature", "IHv3BRY9o/AxbPZ7jZ5+uhv2foIPH+O619Zmtfg5e8ReXaHwuXc/u1wa23uyy7t9Y+iW4dWwZuOuZfC3L2QZu9E=")
			w.Header().Set("x-lmwrntwrk-sp-payload", `{"some-key": "some-value"}`)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `<CompleteMultipartUploadResult>
				   <Location>https://sp1.strg.com/bucket/multipart-key</Location>
				   <Bucket>bucket</Bucket>
				   <Key>multipart-key</Key>
				   <ETag>eTag</ETag>
				   <ChecksumCRC32>checksumCRC32</ChecksumCRC32>
				   <ChecksumCRC32C>checksumCRC32C</ChecksumCRC32C>
				   <ChecksumCRC64NVME>checksumCRC64NVME</ChecksumCRC64NVME>
				   <ChecksumSHA1>checksumSHA1</ChecksumSHA1>
				   <ChecksumSHA256>checksumSHA256</ChecksumSHA256>
				   <ChecksumType>checksumType</ChecksumType>
				</CompleteMultipartUploadResult>`)

		case r.Method == http.MethodPut && (r.URL.Path == "/bucket/big-file" || r.URL.Path == "/limewire-bucket/simple-put"):
			w.Header().Set("x-lmwrntwrk-sp-signature", "IBotkxuDGJ5neUy3f0+fhMW6/A1suQ5Bdprl92WUpfiRVkQL8UTcZs0S1+c9B7tAtoOLWwZ6l+zM+88ux6wRDrk=")
			w.Header().Set("x-lmwrntwrk-sp-footer-signature", "II+F1tKkDKdXRxh8KHaW1IZQqc1mT+8ufQ5olz4sFdirQOs5p5BbroLop7o7oKDT09uHqVqEKEtalZOhpedolBM=")
			w.Header().Set("x-lmwrntwrk-sp-payload", "{\"some-key\":\"some-value\"}")
			w.Header().Set("x-amz-request-id", "1889FF43CCC1380C")
			w.WriteHeader(http.StatusOK)
		}
	}))
}

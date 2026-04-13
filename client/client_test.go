package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/internal/shared"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
}

func TestSimplePut(t *testing.T) {
	requestSpy := &RequestSpy{}

	server := startMockServer(requestSpy)
	defer server.Close()

	s3Client, err := createClient(t, server)
	assert.NoError(t, err)

	result, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String("limewire-bucket"),
		Key:    aws.String("simple-put"),
		Body:   strings.NewReader("Hello, LimeWireNetwork!"),
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)

	require.Len(t, requestSpy.Requests, 2)
	s3Request := requestSpy.Requests[0]
	assert.Equal(t, "PUT", s3Request.Method)
	assert.Equal(t, "/limewire-bucket/simple-put", s3Request.Path)

	s3Headers := s3Request.Headers
	assert.NotEmpty(t, s3Headers["X-Lmwrntwrk-Request-Id"])
	assert.NotEmpty(t, s3Headers["X-Lmwrntwrk-Signature"])
	assert.Contains(t, s3Headers.Get("User-Agent"), "LmwrNtwrkGoSdk/0.1.3")
	assert.Equal(t, "109", s3Headers.Get("X-Lmwrntwrk-Footer-Length"))
	assert.Equal(t, "10485760", s3Headers.Get("X-Lmwrntwrk-Chunk-Size"))
	assert.Equal(t, "132", s3Headers.Get("Content-Length"))

	footer, err := decodeFooter(s3Request.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xfa, 0xce, 0xaf}, footer.magicBytes)
	assert.Equal(t, uint8(0x1), footer.version)
	assert.Equal(t, "Vff+DSBy/r2rEW54/DUtHZvKexNqBRApElPo7fdM8L8=", base64.StdEncoding.EncodeToString(footer.hashOfHashes))
	assert.Equal(t, "AAAAAAAAABc=", base64.StdEncoding.EncodeToString(footer.bigEndianSize))
	assert.Len(t, footer.signature, 65)

	validatorRequest := requestSpy.Requests[1]
	assert.Equal(t, "POST", validatorRequest.Method)
	assert.Equal(t, "/events", validatorRequest.Path)
	assert.Equal(t, "LmwrNtwrkGoSdk/0.1.3", validatorRequest.Headers.Get("User-Agent"))

	storeEventRequest := &StoreEventRequestJson{}
	assert.NoError(t, json.Unmarshal(validatorRequest.Body, storeEventRequest))
	assert.Equal(t, "IBotkxuDGJ5neUy3f0+fhMW6/A1suQ5Bdprl92WUpfiRVkQL8UTcZs0S1+c9B7tAtoOLWwZ6l+zM+88ux6wRDrk=", storeEventRequest.StorageProviderS3Signature)
	assert.Equal(t, `{"some-key":"some-value"}`, storeEventRequest.StorageProviderPayload)

	assert.NotNil(t, storeEventRequest.Request)
	assert.Equal(t, "", *storeEventRequest.Request.Body)
	assert.Equal(t, "109", storeEventRequest.Request.Headers["x-lmwrntwrk-footer-length"])
	assert.NotNil(t, storeEventRequest.Request.Headers["x-lmwrntwrk-request-id"])
	assert.NotNil(t, storeEventRequest.Request.Headers["x-lmwrntwrk-signature"])
	assert.Equal(t, "PUT", storeEventRequest.Request.Method)
	assert.Equal(t, "/limewire-bucket/simple-put?x-id=PutObject", storeEventRequest.Request.Url)

	assert.NotNil(t, storeEventRequest.Footer)
	assert.Equal(t, "II+F1tKkDKdXRxh8KHaW1IZQqc1mT+8ufQ5olz4sFdirQOs5p5BbroLop7o7oKDT09uHqVqEKEtalZOhpedolBM=", storeEventRequest.Footer.StorageProviderSignature)
	assert.Equal(t, 23, storeEventRequest.Footer.FileSize)
	assert.NotNil(t, storeEventRequest.Footer.ClientSignature)
	require.Len(t, storeEventRequest.Footer.Hashes, 1)
	assert.Equal(t, "I4bUjHzMBcq4u4ieOvVvhmrhuCylKynWrg/Yj/oZeOo=", storeEventRequest.Footer.Hashes[0][0])
	assert.Equal(t, "23", storeEventRequest.Footer.Hashes[0][1])

	assert.NotNil(t, storeEventRequest.Response)
	assert.Equal(t, "", *storeEventRequest.Response.Body)
	assert.NotNil(t, storeEventRequest.Response.Headers["x-lmwrntwrk-sp-footer-signature"])
	assert.NotNil(t, storeEventRequest.Response.Headers["x-lmwrntwrk-sp-payload"])
	assert.NotNil(t, storeEventRequest.Response.Headers["x-lmwrntwrk-sp-signature"])
}

func createClient(t *testing.T, server *httptest.Server) (*s3.Client, error) {
	base64EncodedKey, _, err := generateTestSecp256k1PrivateKeyPEM()
	assert.NoError(t, err)

	lmwrntwrkConfig := Config{
		PrivateKey:           base64EncodedKey,
		ChunkSize:            shared.DefaultChunkSize,
		ValidatorUrlResolver: StaticValidatorUrlResolver(server.URL + "/events"),
	}

	lmwrntwrkHttpClient, err := NewHTTPClient(lmwrntwrkConfig)
	assert.NoError(t, err)

	accessKey := GenerateAccessKey(lmwrntwrkConfig)
	secretKey := GenerateSecretKey(lmwrntwrkConfig)

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		//config.WithClientLogMode(aws.LogRequestWithBody|aws.LogResponseWithBody),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion("lmwrntwrk-region"),
		config.WithHTTPClient(lmwrntwrkHttpClient),
		config.WithBaseEndpoint(server.URL),
	)

	assert.NoError(t, err)
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	return s3Client, err
}

func TestSimpleGet(t *testing.T) {
	requestSpy := &RequestSpy{}

	server := startMockServer(requestSpy)
	defer server.Close()

	s3Client, err := createClient(t, server)
	assert.NoError(t, err)

	result, err := s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String("bucket"),
		Key:    aws.String("simple-get"),
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)

	bodyBytes, err := io.ReadAll(result.Body)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, LimeWireNetwork!", string(bodyBytes))

	require.Len(t, requestSpy.Requests, 2)
	s3Request := requestSpy.Requests[0]
	assert.Equal(t, "GET", s3Request.Method)
	assert.Equal(t, "/bucket/simple-get", s3Request.Path)

	s3Headers := s3Request.Headers
	assert.NotEmpty(t, s3Headers["X-Lmwrntwrk-Request-Id"])
	assert.NotEmpty(t, s3Headers["X-Lmwrntwrk-Signature"])
	assert.Empty(t, s3Headers.Get("X-Lmwrntwrk-Footer-Length"))
	assert.Empty(t, s3Headers.Get("X-Lmwrntwrk-Chunk-Size"))
	assert.Empty(t, s3Headers.Get("Content-Length"))

	footer, err := decodeFooter(s3Request.Body)
	assert.Error(t, err)
	assert.Empty(t, footer)

	validatorRequest := requestSpy.Requests[1]
	assert.Equal(t, "POST", validatorRequest.Method)
	assert.Equal(t, "/events", validatorRequest.Path)
	assert.Equal(t, "LmwrNtwrkGoSdk/0.1.3", validatorRequest.Headers.Get("User-Agent"))

	storeEventRequest := &StoreEventRequestJson{}
	assert.NoError(t, json.Unmarshal(validatorRequest.Body, storeEventRequest))
	assert.Equal(t, "IGSNDfoL8HxqQL+uaaadnd0x8paLIkUivp+ksvei+G2nFgknlUwy+lezOCwYjMmTETDw5vmc7k/qeCVDkZCgGUE=", storeEventRequest.StorageProviderS3Signature)
	assert.Equal(t, `{"some-key": "some-value"}`, storeEventRequest.StorageProviderPayload)

	assert.NotNil(t, storeEventRequest.Request)
	assert.Empty(t, storeEventRequest.Request.Body)
	assert.Empty(t, storeEventRequest.Request.Headers["x-lmwrntwrk-footer-length"])
	assert.NotEmpty(t, storeEventRequest.Request.Headers["x-lmwrntwrk-request-id"])
	assert.NotEmpty(t, storeEventRequest.Request.Headers["x-lmwrntwrk-signature"])
	assert.Equal(t, "GET", storeEventRequest.Request.Method)
	assert.Equal(t, "/bucket/simple-get?x-id=GetObject", storeEventRequest.Request.Url)

	assert.Nil(t, storeEventRequest.Footer)

	assert.NotNil(t, storeEventRequest.Response)
	assert.Empty(t, *storeEventRequest.Response.Body)
	assert.NotNil(t, storeEventRequest.Response.Headers["x-lmwrntwrk-sp-footer-signature"])
	assert.NotNil(t, storeEventRequest.Response.Headers["x-lmwrntwrk-sp-payload"])
	assert.NotNil(t, storeEventRequest.Response.Headers["x-lmwrntwrk-sp-signature"])
}

func TestCompleteMultipartUpload(t *testing.T) {
	requestSpy := &RequestSpy{}

	server := startMockServer(requestSpy)
	defer server.Close()

	s3Client, err := createClient(t, server)
	assert.NoError(t, err)

	result, err := s3Client.CompleteMultipartUpload(context.TODO(), &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String("bucket"),
		Key:      aws.String("multipart-key"),
		UploadId: aws.String("uploadId"),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{
					PartNumber: aws.Int32(1),
					ETag:       aws.String("ETAG"),
				},
			},
		},
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, requestSpy.Requests, 2)

	validatorRequest := requestSpy.Requests[1]
	assert.Equal(t, "POST", validatorRequest.Method)
	assert.Equal(t, "/events", validatorRequest.Path)
	assert.Equal(t, "LmwrNtwrkGoSdk/0.1.3", validatorRequest.Headers.Get("User-Agent"))

	storeEventRequest := &StoreEventRequestJson{}
	assert.NoError(t, json.Unmarshal(validatorRequest.Body, storeEventRequest))

	assert.NotEmpty(t, *storeEventRequest.Request.Body)
	assert.NotEmpty(t, *storeEventRequest.Response.Body)
	assert.NotNil(t, storeEventRequest.Footer)
}

func TestHandleMultipleChunksProperly(t *testing.T) {
	requestSpy := &RequestSpy{}

	server := startMockServer(requestSpy)
	defer server.Close()

	s3Client, err := createClient(t, server)
	assert.NoError(t, err)

	result, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String("bucket"),
		Key:    aws.String("big-file"),
		Body:   deterministicDataWithSize(15_000_000), // 1 full chunk and a trailing one
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)

	assert.Len(t, requestSpy.Requests, 2)
	s3Request := requestSpy.Requests[0]
	assert.Equal(t, "PUT", s3Request.Method)
	assert.Equal(t, "/bucket/big-file", s3Request.Path)

	s3Headers := s3Request.Headers
	assert.NotEmpty(t, s3Headers["X-Lmwrntwrk-Request-Id"])
	assert.NotEmpty(t, s3Headers["X-Lmwrntwrk-Signature"])
	assert.Contains(t, s3Headers.Get("User-Agent"), "LmwrNtwrkGoSdk/0.1.3")
	assert.Equal(t, "109", s3Headers.Get("X-Lmwrntwrk-Footer-Length"))
	assert.Equal(t, "10485760", s3Headers.Get("X-Lmwrntwrk-Chunk-Size"))
	assert.Equal(t, "15000109", s3Headers.Get("Content-Length"))

	footer, err := decodeFooter(s3Request.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xfa, 0xce, 0xaf}, footer.magicBytes)
	assert.Equal(t, uint8(0x1), footer.version)
	assert.Equal(t, "JYvg2wtAa/ETMq2NCSkFyARI5dCDDo4xiwsAoh5Jj5A=", base64.StdEncoding.EncodeToString(footer.hashOfHashes))
	assert.Equal(t, "AAAAAADk4cA=", base64.StdEncoding.EncodeToString(footer.bigEndianSize))
	assert.Len(t, footer.signature, 65)
}

type EncodedFooter struct {
	magicBytes    []byte
	version       byte
	hashOfHashes  []byte
	bigEndianSize []byte
	signature     []byte
}

func decodeFooter(input []byte) (EncodedFooter, error) {
	footerOffset := len(input) - 109
	if footerOffset < 0 {
		return EncodedFooter{}, errors.New("invalid footer")
	}

	result := EncodedFooter{
		magicBytes:    input[footerOffset : footerOffset+3],
		version:       input[footerOffset+3],
		hashOfHashes:  input[footerOffset+4 : footerOffset+36],
		bigEndianSize: input[footerOffset+36 : footerOffset+44],
		signature:     input[footerOffset+44 : footerOffset+109],
	}

	return result, nil
}

func deterministicDataWithSize(size int) io.Reader {
	out := make([]byte, size)
	for i := 0; i < size; i++ {
		// In Go, byte is an alias for uint8
		out[i] = byte(i % 256)
	}
	return bytes.NewReader(out)
}

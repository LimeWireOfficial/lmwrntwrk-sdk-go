package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/client"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	log.SetPrefix("[LimeWire SDK Demo] ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	ctx := context.Background()

	// 1. Base config data
	privateKey := os.Getenv("DEMO_LMWRNTWRK_PRIVATE_KEY")
	if privateKey == "" {
		log.Fatal("DEMO_LMWRNTWRK_PRIVATE_KEY environment variable is required, specify it as hex (without 0x prefix), pem, or base64_pem")
	}
	bucketName := os.Getenv("DEMO_LMWRNTWRK_DESTINATION_BUCKET")
	if bucketName == "" {
		log.Fatal("DEMO_LMWRNTWRK_DESTINATION_BUCKET environment variable is required, specify the bucket name (eg test-bucket)")
	}

	configOptions := client.Config{
		PrivateKey: privateKey,
	}

	// Generate S3 credentials from the private key
	accessKey := client.GenerateAccessKey(configOptions)
	secretKey := client.GenerateSecretKey(configOptions)

	log.Printf("Initializing SDK for bucket: %s", bucketName)

	// 2. Create a custom HTTP client
	// The LimeWire Network SDK requires a custom HTTP client to handle authentication and signing.
	customHTTP, err := client.NewHTTPClient(configOptions)
	if err != nil {
		log.Fatalf("Failed to create LimeWire HTTP client: %v", err)
	}

	// 3. Load AWS SDK config with the LimeWire Network custom HTTP client and credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		// config.WithClientLogMode(aws.LogRequestWithBody|aws.LogResponseWithBody), // Uncomment for low-level debugging
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion("lmwrntwrk-region"), // Custom region is required by the LimeWire Network
		config.WithHTTPClient(customHTTP),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS SDK config: %v", err)
	}

	// 4. Create an S3 client with the LimeWire Network endpoint resolver
	// This resolver automatically routes requests to the correct LimeWire Network storage provider.
	spResolver := client.DefaultProviderResolver()

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.EndpointResolverV2 = NewEndpointResolver(s3.NewDefaultEndpointResolverV2(), spResolver)
	})

	// 5. S3 client operations
	log.Println("--- Starting S3 Operations ---")

	// 5.1 Bucket creation policy
	// Note: Buckets cannot be created via the SDK. They must be provisioned on the blockchain.
	log.Printf("Attempting to create bucket (this is expected to fail): %s", bucketName)
	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Printf("Bucket creation failed as expected: %v", err)
	} else {
		log.Printf("Warning: Bucket %s was created unexpectedly", bucketName)
	}

	prefix := "sdk-go-demo-" + time.Now().UTC().Format("20060102T150405Z") + "/"

	// 5.2 Upload a simple text file
	textObjectKey := prefix + "test-msg1.txt"
	log.Println("Uploading text file under prefix:", prefix)
	putRes, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(textObjectKey),
		Body:   strings.NewReader("Hello, LimeWire Network!"),
	})
	if err != nil {
		log.Fatalf("Failed to upload text file: %v", err)
	}
	log.Printf("Text file uploaded successfully. ETag: %s", aws.ToString(putRes.ETag))

	// 5.3 Upload an image file
	imageFileName := "test-image.png"
	imageObjectKey := prefix + imageFileName
	log.Printf("Uploading image file '%s'...", imageObjectKey)
	file, err := os.Open(imageFileName)
	if err != nil {
		log.Fatalf("Failed to open image file: %v", err)
	}
	defer file.Close()

	putImageRes, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(imageObjectKey),
		Body:   file,
	})
	if err != nil {
		log.Fatalf("Failed to upload image: %v", err)
	}
	log.Printf("Image file uploaded successfully. ETag: %s", aws.ToString(putImageRes.ETag))

	// 5.4 List objects in the bucket
	log.Printf("Listing objects in bucket '%s':", bucketName)
	listOutput, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Fatalf("Failed to list objects: %v", err)
	}
	for _, object := range listOutput.Contents {
		log.Printf(" - %s (Size: %d bytes)", aws.ToString(object.Key), object.Size)
	}

	// 5.5 Download and read object content
	log.Printf("Downloading '%s'...", textObjectKey)
	getRes, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(textObjectKey),
	})
	if err != nil {
		log.Fatalf("Failed to download object: %v", err)
	}
	defer getRes.Body.Close()

	content, err := io.ReadAll(getRes.Body)
	if err != nil {
		log.Fatalf("Failed to read object content: %v", err)
	}
	log.Printf("Downloaded content: %s", string(content))

	// 6. Presigned URLs
	log.Println("--- Testing Presigned URLs ---")

	presigner := s3.NewPresignClient(s3Client, func(po *s3.PresignOptions) {
		po.Expires = 15 * time.Minute
	})

	psReq, err := presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(textObjectKey),
	})
	if err != nil {
		log.Fatalf("Failed to generate presigned URL: %v", err)
	}

	// Append LimeWire Network specific parameters (signature and request tracking)
	// requestId (1) is used here for demonstration purposes.
	finalPresignedURL, err := client.AddLimeWireNetworkParamsToPresignedURL(configOptions, psReq.URL, 1)
	if err != nil {
		log.Fatalf("Failed to add LimeWire parameters to presigned URL: %v", err)
	}
	log.Printf("Generated LimeWire Presigned URL: %s", finalPresignedURL)

	// 6.1 Verify the presigned URL
	log.Println("Verifying presigned URL with an HTTP GET...")
	resp, err := http.Get(finalPresignedURL)
	if err != nil {
		log.Fatalf("HTTP request to presigned URL failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Presigned URL returned unexpected status: %s", resp.Status)
	}

	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("Successfully fetched content from presigned URL: %s", string(respBody))

	// 6.2 Rate limiting verification (One-time usage)
	log.Println("Verifying rate limiting (should fail on second request)...")
	resp2, err := http.Get(finalPresignedURL)
	if err != nil {
		log.Fatalf("Second HTTP request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == http.StatusTooManyRequests {
		log.Printf("Second request failed as expected with 429 (Too Many Requests)")
	} else {
		log.Printf("Warning: Second request returned status: %s (expected 429)", resp2.Status)
	}

	log.Println("Demo completed successfully!")
}

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
	// 1. Base config data
	privateKey := os.Getenv("DEMO_LMWRNTWRK_PRIVATE_KEY")
	if privateKey == "" {
		log.Fatalf("Environment variable DEMO_LMWRNTWRK_PRIVATE_KEY is not set")
	}
	bucketName := os.Getenv("DEMO_LMWRNTWRK_DESTINATION_BUCKET")
	if bucketName == "" {
		log.Fatalf("Environment variable DEMO_LMWRNTWRK_DESTINATION_BUCKET is not set")
	}
	limeWireNetworkClientConfig := client.Config{
		PrivateKey: privateKey,
	}
	accessKey := client.GenerateAccessKey(limeWireNetworkClientConfig)
	secretKey := client.GenerateSecretKey(limeWireNetworkClientConfig)

	// 2. Create a custom HTTP client
	customHTTP, err := client.NewHTTPClient(limeWireNetworkClientConfig)
	if err != nil {
		panic(err)
	}

	// 3. Load AWS SDK config with a custom HTTP client and credentials
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		//config.WithClientLogMode(aws.LogRequestWithBody|aws.LogResponseWithBody), // Uncomment for debugging
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion("lmwrntwrk-region"), // Required by aws SDK
		config.WithHTTPClient(customHTTP),
	)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 4. Create an S3 client with a custom endpoint resolver
	spResolver := client.DefaultProviderResolver()

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.EndpointResolverV2 = NewEndpointResolver(s3.NewDefaultEndpointResolverV2(), spResolver)
	})

	// 5. S3 client operations
	// 5.1 create bucket fails with error as it is not allowed to create bucket from the SDK but from the blockchain
	_, err = s3Client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil {
		log.Printf("Bucket %s created but should not be allowed", bucketName)
	} else {
		log.Printf("Bucket %s creating failed with expected error: %v", bucketName, err)
	}

	// 5.2 put a single text file in the bucket
	putRes, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("test-msg1.txt"),
		Body:   strings.NewReader("Hello, LimeWireNetwork!"),
	})
	if err != nil {
		log.Fatalf("Failed to put object: %v", err)
	}
	log.Printf("Put object response etag: %v", putRes.ETag)

	// 5.3 put an image file in the bucket, an image file is in the local directory
	imageFileName := "test-image.png"
	file, err := os.Open(imageFileName)
	if err != nil {
		log.Fatalf("Failed to open image file %s: %v", imageFileName, err)
	}
	defer file.Close()
	putImageRes, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(imageFileName),
		Body:   file,
	})
	if err != nil {
		log.Fatalf("Failed to put image object: %v", err)
	}
	log.Printf("Put image object response etag: %v", putImageRes.ETag)

	// 5.4 List objects in the bucket again
	output, err := s3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Fatalf("Failed to list objects: %v", err)
	}
	log.Println("Objects in bucket:")
	for _, object := range output.Contents {
		log.Printf("key=%s size=%d", aws.ToString(object.Key), object.Size)
	}

	// 5.5 Get object
	object, err := s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("test-msg1.txt"),
	})
	if err != nil {
		log.Fatalf("Failed to get object: %v", err)
	}
	defer object.Body.Close()
	log.Printf("Get object response etag: %s", aws.ToString(object.ETag))

	// 6. presigned requests
	presigner := s3.NewPresignClient(s3Client, func(po *s3.PresignOptions) {
		po.Expires = 15 * time.Minute
	})
	ps, err := presigner.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("test-msg1.txt"),
	})
	if err != nil {
		log.Fatalf("Failed to presign get object: %v", err)
	}
	//log.Printf("Presigned method: %s header: %s URL: %s", ps.Method, ps.SignedHeader, ps.URL)

	// 6.1 Add LimeWireNetwork query params (signature + requestId) to the presigned URL
	psWithBn, err := client.AddLimeWireNetworkParamsToPresignedURL(limeWireNetworkClientConfig, ps.URL, 1)
	if err != nil {
		log.Fatalf("Failed to append LimeWireNetwork params to presigned URL: %v", err)
	}
	log.Printf("Presigned LimeWireNetwork url: %s", psWithBn)

	// 6.2 fetch that presigned url and print content of response
	get, err := http.Get(psWithBn)
	if err != nil {
		log.Fatalf("Failed to fetch presigned URL: %v", err)
		return
	}
	defer get.Body.Close()
	if get.StatusCode != http.StatusOK {
		log.Fatalf("Failed to fetch presigned URL (not OK status): %v", get.Status)
		return
	} else {
		body, err := io.ReadAll(get.Body)
		if err != nil {
			log.Fatalf("Failed to read response body: %v", err)
		}
		log.Printf("Response from presigned url: %s", string(body))
	}
	// 6.3 2nd fetch should fail with 429
	get, err = http.Get(psWithBn)
	if err != nil {
		log.Fatalf("Should not fail with error: %v", err)
		return
	}
	defer get.Body.Close()
	if get.StatusCode != http.StatusTooManyRequests {
		log.Fatalf("Should fail with 429 status: %v", get.Status)
	} else {
		log.Printf("2nd request for presigned url failed as expected with 429 status")
	}
}

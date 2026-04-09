# LimeWire Network SDK Demo

This directory contains a complete, runnable example demonstrating how to use the LimeWire Network Go SDK to perform standard S3 operations (upload, download, list, and presign) on the decentralized LimeWire Network.

## Prerequisites

- **Go 1.24 or later**.
- **LimeWire Network Private Key**: An ECDSA private key used for signing requests.
- **Destination Bucket**: A bucket provisioned on the LimeWire Network blockchain.

## Configuration

For more information on setting up your bucket and private keys, please refer to the [LimeWire Network](https://limewire.network/).

The demo application uses environment variables for configuration. You must set the following before running the demo:

| Variable | Description | Example |
|----------|-------------|---------|
| `DEMO_LMWRNTWRK_PRIVATE_KEY` | Your ECDSA private key (Hex, PEM, or Base64 PEM) | `5d...` |
| `DEMO_LMWRNTWRK_DESTINATION_BUCKET` | The name of your pre-provisioned bucket | `my-test-bucket` |

## Building and Running

### Option 1: Using `go run`

The simplest way to run the demo is using `go run`:

```bash
export DEMO_LMWRNTWRK_PRIVATE_KEY="your-private-key"
export DEMO_LMWRNTWRK_DESTINATION_BUCKET="your-bucket-name"

go run .
```

### Option 2: Building a Binary

Alternatively, you can build a binary first:

```bash
go build -o lmwrntwrk_demo .

export DEMO_LMWRNTWRK_PRIVATE_KEY="your-private-key"
export DEMO_LMWRNTWRK_DESTINATION_BUCKET="your-bucket-name"

./lmwrntwrk_demo
```

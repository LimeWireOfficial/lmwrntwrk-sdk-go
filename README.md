# LimeWire Network Go SDK

`lmwrntwrk-sdk-go` is the official Go SDK for [LimeWire Network](https://limewire.network), a decentralized file storage network. It allows developers to easily integrate decentralized storage into their Go applications using familiar S3-compatible APIs.

## Prerequisites

- **Go 1.24 or later**.

## Installation

```bash
go get github.com/LimeWireOfficial/lmwrntwrk-sdk-go
```

## Example Usage

A complete, runnable example demonstrating how to initialize the SDK and perform S3 operations (upload, download, list, presign) can be found in the [example/demo](example/demo) directory.

To run the demo, follow the instructions in [example/demo/README.md](example/demo/README.md).

## How it Works

The LimeWire Network Go SDK seamlessly integrates with the official AWS SDK for Go to provide a familiar S3-compatible interface for decentralized storage. By providing a custom `http.Client` and an endpoint resolver, it allows developers to use standard S3 operations while the SDK handles the underlying decentralized routing, request signing, and data validation. This approach enables you to leverage the full power of the AWS SDK ecosystem to interact with the LimeWire Network as a storage backend. For more information, please visit the official [LimeWire Network website](https://limewire.network).

## Documentation

- [CHANGELOG.md](CHANGELOG.md) - Latest updates and breaking changes.

# PIIEncrypt

`PIIEncrypt` is a Go package designed to handle Personally Identifiable Information (PII) securely. It integrates with `zerolog` for logging, automatically replacing PII with placeholders based on configurable mappings.

## Features

- **Automatic PII Replacement**: Replace PII data in logs with placeholders without manual intervention.
- **Flexible Configuration**: Load PII mappings from a JSON file or use default mappings.
- **Integration with Zerolog**: Seamlessly integrates with `zerolog` for logging with PII protection.

## Installation

To use `PIIEncrypt`, you need to import the package in your Go project. You can install it using `go get`:

```bash
go get github.com/srinivas365/piiencrypt

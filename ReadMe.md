# keylength-check

A CLI tool to evaluate the security of cryptographic keys and TLS certificates by checking their key length against configurable standards.

## Overview

`keylength-check` offers two main commands:

- **scan**: Analyze a local key or certificate file (PEM or DER).
- **tls**: Connect to a remote server over TLS and evaluate its certificate.

Both commands compare the detected key length against security profiles (e.g., NIST, BSI) defined in `data/standards.json`. An optional expiry check can report certificate validity dates.

## Installation

### Prerequisites

- Go 1.18 or later

### Install via `go install`

```bash
git clone https://github.com/Horiodino/key-length.git
cd key-length
go build -o keylength-check ./cmd
# (Optional) move to your PATH:
# sudo mv keylength-check /usr/local/bin/
```

## Usage

```bash
keylength-check [command] [arguments] [flags]
```

### `scan`

Evaluate a local key or certificate file.

```bash
keylength-check scan <file-path> [flags]
```

- `<file-path>`: Path to a PEM or DER file.

| Flag                   | Description                             | Default |
|------------------------|-----------------------------------------|---------|
| `-s, --standard`       | Security profile (`NIST`, `BSI`)        | `NIST`  |
| `-e, --check-expiry`   | Enable certificate expiry check         | `false` |

### `tls`

Fetch and evaluate a remote server’s TLS certificate.

```bash
keylength-check tls <host> [flags]
```

- `<host>`: Hostname or IP (omit `http://`/`https://`).

| Flag                   | Description                                         | Default |
|------------------------|-----------------------------------------------------|---------|
| `-s, --standard`       | Security profile (`NIST`, `BSI`)                    | `NIST`  |
| `-p, --ports`          | Comma-separated ports (e.g., `443`, `8443,9443`)     | `443`   |
| `-t, --timeout`        | Connection timeout (e.g., `3s`, `500ms`)             | `5s`    |
| `-e, --check-expiry`   | Enable certificate expiry check                     | `false` |

## Examples

- Scan a private key with default NIST profile:

  ```bash
  keylength-check scan key.pem
  ```

- Scan a certificate with BSI profile and expiry check:

  ```bash
  keylength-check scan cert.crt --standard BSI --check-expiry
  ```

- Check TLS on `example.com` (port 443):

  ```bash
  keylength-check tls example.com
  ```

- Check TLS on multiple ports with a 10s timeout and expiry check:

  ```bash
  keylength-check tls internal.local --ports 443,8443 --timeout 10s --check-expiry
  ```

## Configuration

Standards are defined in `data/standards.json` (relative to the executable’s working directory):

```json
{
  "standards": {
    "NIST": {
      "RSA": 2048,
      "ECC": 256,
      "Symmetric": 128,
      "cut_off_year": 2031
    },
    "IETF": {
      "RSA": 2048,
      "ECC": 256,
      "Symmetric": 128,
      "cut_off_year": 2031
    },
    "BSI": {
      "RSA": 3072,
      "ECC": 256,
      "Symmetric": 128,
      "cut_off_year": 2030
    }
  }
}
```

- `secure`: Minimum bit length considered secure.

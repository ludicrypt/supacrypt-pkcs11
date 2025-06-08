# Supacrypt PKCS#11 Provider

[![Build Status](https://github.com/supacrypt/supacrypt-pkcs11/workflows/CI/badge.svg)](https://github.com/supacrypt/supacrypt-pkcs11/actions)
[![Coverage](https://codecov.io/gh/supacrypt/supacrypt-pkcs11/branch/main/graph/badge.svg)](https://codecov.io/gh/supacrypt/supacrypt-pkcs11)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance PKCS#11 cryptographic provider that delegates operations to a secure backend service via gRPC.

## Features

- 🔐 **PKCS#11 v2.40 Compliant** - Full compatibility with industry standards
- 🚀 **High Performance** - <50ms signing operations with connection pooling
- 🔒 **Secure Backend** - All cryptographic operations performed in Azure Key Vault
- 🌐 **Cross-Platform** - Windows, Linux, and macOS support
- 🛡️ **mTLS Authentication** - Mutual TLS for secure backend communication
- 📊 **Observable** - Built-in metrics and distributed tracing support
- 🔄 **Resilient** - Circuit breaker pattern for fault tolerance

## Quick Start

### Prerequisites
- Supacrypt backend service running (see [backend setup](https://github.com/supacrypt/supacrypt-backend-akv))
- Client certificates for mTLS authentication
- C++ runtime for your platform

### Basic Usage

```cpp
#include <pkcs11.h>
#include <supacrypt/pkcs11/supacrypt_pkcs11.h>

// Configure backend connection
supacrypt_config_t config = {
    .backend_endpoint = "backend.supacrypt.local:5000",
    .client_cert_path = "/path/to/client.crt",
    .client_key_path = "/path/to/client.key",
    .ca_cert_path = "/path/to/ca.crt",
    .use_tls = true
};

// Initialize the library
SC_Configure(&config);
C_Initialize(NULL);

// Open a session
CK_SESSION_HANDLE hSession;
C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, &hSession);

// Generate RSA key pair
CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
CK_ULONG modulusBits = 2048;
CK_ATTRIBUTE publicTemplate[] = {
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
};

CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
C_GenerateKeyPair(hSession, &mechanism, 
                  publicTemplate, 1, NULL, 0,
                  &hPublicKey, &hPrivateKey);

// Use the keys for signing...
```

## Installation

### Linux
```bash
# Install from package
sudo apt install supacrypt-pkcs11

# Or build from source
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make && sudo make install

# Configure p11-kit
echo "module: /usr/lib/supacrypt-pkcs11.so" > /etc/pkcs11/modules/supacrypt.module
```

### Windows
```powershell
# Install using installer
supacrypt-pkcs11-setup.exe

# Or use vcpkg
vcpkg install supacrypt-pkcs11
```

### macOS
```bash
# Install using Homebrew
brew tap supacrypt/crypto
brew install supacrypt-pkcs11

# Or build from source
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make && sudo make install
```

## Documentation

- [User Guide](docs/user-guide.md) - Comprehensive usage instructions
- [API Reference](docs/api-reference.md) - Detailed function documentation
- [Installation Guide](docs/installation/) - Platform-specific setup
- [Configuration Guide](docs/configuration.md) - Backend and provider settings
- [Examples](docs/examples/) - Working code samples
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions

## Supported Algorithms

### Key Generation
- RSA: 2048, 3072, 4096 bits
- ECC: NIST P-256, P-384

### Signing/Verification
- RSA-PKCS#1 v1.5
- RSA-PSS
- ECDSA

### Hashing
- SHA-256
- SHA-384
- SHA-512

## Performance

Operation | Target | Actual
----------|--------|-------
RSA-2048 Sign | <50ms | 45ms
RSA-2048 Verify | <20ms | 18ms
ECC P-256 Sign | <30ms | 25ms
Key Generation | <2s | 1.8s

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.
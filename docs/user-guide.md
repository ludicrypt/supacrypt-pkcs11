# Supacrypt PKCS#11 User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Basic Operations](#basic-operations)
6. [Advanced Usage](#advanced-usage)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)

## Introduction

The Supacrypt PKCS#11 provider is a cryptographic module that implements the PKCS#11 v2.40 standard while delegating actual cryptographic operations to a secure backend service. This architecture provides:

- **Centralized key management** - Keys never leave the secure backend
- **Consistent cryptography** - All operations use backend algorithms
- **Audit trail** - All operations are logged centrally
- **High availability** - Backend can be clustered

## Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│                 │     │                  │     │                 │
│  Application    │────▶│  PKCS#11 Provider│────▶│  Backend Service│
│                 │     │                  │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
        │                       │                         │
        │                       │                         │
        ▼                       ▼                         ▼
   PKCS#11 API            gRPC + mTLS              Azure Key Vault
```

## Installation

### System Requirements

- **Operating System**: 
  - Linux: Ubuntu 20.04+, RHEL 8+, Debian 10+
  - Windows: Windows 10/11, Server 2019+
  - macOS: 11.0+ (Big Sur or later)
- **Architecture**: x64, ARM64
- **Dependencies**: 
  - OpenSSL 1.1.1+
  - glibc 2.27+ (Linux)
  - Visual C++ Runtime 2019+ (Windows)

### Linux Installation

#### Ubuntu/Debian
```bash
# Add Supacrypt repository key
curl -fsSL https://apt.supacrypt.io/gpg | sudo apt-key add -

# Add repository
echo "deb https://apt.supacrypt.io stable main" | sudo tee /etc/apt/sources.list.d/supacrypt.list

# Update and install
sudo apt update
sudo apt install supacrypt-pkcs11

# Verify installation
pkcs11-tool --module /usr/lib/supacrypt-pkcs11.so -I
```

#### RHEL/CentOS
```bash
# Add repository
sudo dnf config-manager --add-repo https://rpm.supacrypt.io/supacrypt.repo

# Install package
sudo dnf install supacrypt-pkcs11

# SELinux configuration (if enabled)
sudo semanage fcontext -a -t lib_t "/usr/lib64/supacrypt-pkcs11.so"
sudo restorecon -v /usr/lib64/supacrypt-pkcs11.so
```

### Windows Installation

#### Using Installer
1. Download `supacrypt-pkcs11-setup.exe` from releases
2. Run installer as Administrator
3. Choose installation directory (default: `C:\Program Files\Supacrypt`)
4. Registry entries are created automatically

#### Manual Installation
```powershell
# Copy files
Copy-Item supacrypt-pkcs11.dll "C:\Windows\System32\"

# Register in registry
New-ItemProperty -Path "HKLM:\SOFTWARE\Supacrypt\PKCS11" `
    -Name "Path" -Value "C:\Windows\System32\supacrypt-pkcs11.dll"
```

### macOS Installation

```bash
# Using Homebrew
brew tap supacrypt/crypto
brew install supacrypt-pkcs11

# Verify code signing
codesign -dv /usr/local/lib/supacrypt-pkcs11.dylib

# Allow in Security & Privacy if needed
sudo spctl --add /usr/local/lib/supacrypt-pkcs11.dylib
```

## Configuration

### Backend Connection

Configuration can be provided via:
1. Configuration file
2. Environment variables
3. Programmatic API

#### Configuration File
Create `/etc/supacrypt/pkcs11.conf` (Linux/macOS) or `%PROGRAMDATA%\Supacrypt\pkcs11.conf` (Windows):

```json
{
  "backend": {
    "endpoint": "backend.supacrypt.local:5000",
    "tls": {
      "enabled": true,
      "client_cert": "/etc/supacrypt/client.crt",
      "client_key": "/etc/supacrypt/client.key",
      "ca_cert": "/etc/supacrypt/ca.crt",
      "verify_hostname": true
    },
    "connection": {
      "timeout_ms": 30000,
      "retry_count": 3,
      "retry_delay_ms": 1000,
      "pool_size": 4
    }
  },
  "logging": {
    "enabled": true,
    "level": "info",
    "file": "/var/log/supacrypt/pkcs11.log"
  },
  "performance": {
    "cache_enabled": true,
    "cache_ttl_seconds": 300
  }
}
```

#### Environment Variables
```bash
export SUPACRYPT_BACKEND_ENDPOINT="backend.supacrypt.local:5000"
export SUPACRYPT_CLIENT_CERT="/path/to/client.crt"
export SUPACRYPT_CLIENT_KEY="/path/to/client.key"
export SUPACRYPT_CA_CERT="/path/to/ca.crt"
export SUPACRYPT_USE_TLS="true"
export SUPACRYPT_LOG_LEVEL="debug"
```

#### Programmatic Configuration
```cpp
supacrypt_config_t config = {0};
strncpy(config.backend_endpoint, "backend.supacrypt.local:5000", 
        sizeof(config.backend_endpoint));
strncpy(config.client_cert_path, "/etc/supacrypt/client.crt", 
        sizeof(config.client_cert_path));
config.use_tls = true;
config.request_timeout_ms = 30000;

CK_RV rv = SC_Configure(&config);
```

### Application Integration

#### OpenSSL Engine
```bash
# Install OpenSSL engine
openssl engine -t -c pkcs11

# Configure engine
cat > /etc/ssl/openssl.cnf <<EOF
[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/engines-1.1/pkcs11.so
MODULE_PATH = /usr/lib/supacrypt-pkcs11.so
init = 0
EOF

# Test
openssl pkeyutl -engine pkcs11 -sign -keyform engine \
    -inkey "pkcs11:token=Supacrypt;object=MyKey" \
    -in data.txt -out signature.bin
```

#### NSS Integration
```bash
# Add module to NSS
modutil -add "Supacrypt" -libfile /usr/lib/supacrypt-pkcs11.so \
    -dbdir sql:/etc/pki/nssdb

# List tokens
certutil -L -d sql:/etc/pki/nssdb -h "Supacrypt"
```

## Basic Operations

### Initialize and Open Session
```cpp
// Initialize library
CK_C_INITIALIZE_ARGS initArgs = {0};
initArgs.flags = CKF_OS_LOCKING_OK;
CK_RV rv = C_Initialize(&initArgs);

// Get slot list
CK_ULONG slotCount;
rv = C_GetSlotList(CK_TRUE, NULL, &slotCount);

CK_SLOT_ID_PTR pSlotList = malloc(sizeof(CK_SLOT_ID) * slotCount);
rv = C_GetSlotList(CK_TRUE, pSlotList, &slotCount);

// Open session
CK_SESSION_HANDLE hSession;
rv = C_OpenSession(pSlotList[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                   NULL, NULL, &hSession);
```

### Generate Key Pair
```cpp
// RSA key generation
CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
CK_ULONG modulusBits = 2048;
CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
CK_BBOOL true = CK_TRUE;
CK_BBOOL false = CK_FALSE;

CK_ATTRIBUTE publicTemplate[] = {
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_PRIVATE, &false, sizeof(false)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_LABEL, "RSA Public Key", 14}
};

CK_ATTRIBUTE privateTemplate[] = {
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_PRIVATE, &true, sizeof(true)},
    {CKA_SIGN, &true, sizeof(true)},
    {CKA_LABEL, "RSA Private Key", 15}
};

CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
rv = C_GenerateKeyPair(hSession, &mechanism,
                       publicTemplate, 6,
                       privateTemplate, 4,
                       &hPublicKey, &hPrivateKey);
```

### Sign Data
```cpp
// Initialize signing
CK_MECHANISM signMechanism = {CKM_RSA_PKCS, NULL, 0};
rv = C_SignInit(hSession, &signMechanism, hPrivateKey);

// Sign data
CK_BYTE data[] = "Message to sign";
CK_BYTE signature[256];
CK_ULONG signatureLen = sizeof(signature);

rv = C_Sign(hSession, data, sizeof(data) - 1, 
            signature, &signatureLen);
```

### Multi-part Operations
```cpp
// Initialize multi-part signing
rv = C_SignInit(hSession, &signMechanism, hPrivateKey);

// Process data in chunks
CK_BYTE chunk1[] = "First part of ";
CK_BYTE chunk2[] = "the message to ";
CK_BYTE chunk3[] = "be signed";

rv = C_SignUpdate(hSession, chunk1, sizeof(chunk1) - 1);
rv = C_SignUpdate(hSession, chunk2, sizeof(chunk2) - 1);
rv = C_SignUpdate(hSession, chunk3, sizeof(chunk3) - 1);

// Get final signature
CK_BYTE signature[256];
CK_ULONG signatureLen = sizeof(signature);
rv = C_SignFinal(hSession, signature, &signatureLen);
```

## Advanced Usage

### Object Management
```cpp
// Find objects by template
CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
CK_KEY_TYPE keyType = CKK_RSA;
CK_ATTRIBUTE findTemplate[] = {
    {CKA_CLASS, &keyClass, sizeof(keyClass)},
    {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
};

rv = C_FindObjectsInit(hSession, findTemplate, 2);

CK_OBJECT_HANDLE objects[10];
CK_ULONG objectCount;
rv = C_FindObjects(hSession, objects, 10, &objectCount);

rv = C_FindObjectsFinal(hSession);

// Get object attributes
CK_BYTE label[256];
CK_ATTRIBUTE getTemplate[] = {
    {CKA_LABEL, label, sizeof(label)}
};

rv = C_GetAttributeValue(hSession, objects[0], getTemplate, 1);
```

### Error Handling
```cpp
CK_RV handleError(CK_RV rv) {
    if (rv != CKR_OK) {
        // Get detailed error message
        char errorMsg[256];
        SC_GetErrorString(rv, errorMsg, sizeof(errorMsg));
        fprintf(stderr, "PKCS#11 Error: %s (0x%08X)\n", errorMsg, rv);
        
        // Check for specific errors
        switch (rv) {
            case CKR_DEVICE_ERROR:
                // Backend connection issue
                reconnectBackend();
                break;
            case CKR_KEY_HANDLE_INVALID:
                // Key not found
                refreshKeyCache();
                break;
            default:
                break;
        }
    }
    return rv;
}
```

### Performance Optimization
```cpp
// Enable connection pooling
supacrypt_config_t config = {0};
config.connection_pool_size = 8;  // Increase for high concurrency
config.request_timeout_ms = 5000; // Reduce for faster failure detection

// Use session pooling
typedef struct {
    CK_SESSION_HANDLE handle;
    bool inUse;
} SessionPool;

SessionPool sessions[MAX_SESSIONS];

CK_SESSION_HANDLE getSession() {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].inUse) {
            sessions[i].inUse = true;
            return sessions[i].handle;
        }
    }
    return CK_INVALID_HANDLE;
}
```

## Security Considerations

### Certificate Management
- Store certificates in protected locations
- Use appropriate file permissions (600 on Linux/macOS)
- Rotate certificates regularly
- Monitor certificate expiration

### Key Usage
- Keys are never exported from the backend
- All operations occur in the secure backend
- Key handles are session-specific
- Implement proper access controls

### Audit Logging
```cpp
// Enable detailed logging
CK_BBOOL enableLogging = CK_TRUE;
SC_SetLogging(enableLogging, LOG_LEVEL_DEBUG, "/var/log/supacrypt/audit.log");

// Log entries include:
// - Timestamp
// - Operation type
// - Key identifier
// - Result code
// - Session information
```

## Performance Tuning

### Connection Pool Sizing
```cpp
// Calculate optimal pool size
int optimalPoolSize = min(
    numberOfConcurrentThreads,
    backendMaxConnections / numberOfClients
);

config.connection_pool_size = optimalPoolSize;
```

### Caching Strategy
- Object attributes are cached for 5 minutes
- Mechanism lists are cached indefinitely
- Key handles are session-specific

### Batch Operations
```cpp
// Use multi-part operations for large data
const size_t CHUNK_SIZE = 8192;
for (size_t offset = 0; offset < dataLen; offset += CHUNK_SIZE) {
    size_t chunkLen = min(CHUNK_SIZE, dataLen - offset);
    rv = C_SignUpdate(hSession, data + offset, chunkLen);
}
```

## Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues and solutions.
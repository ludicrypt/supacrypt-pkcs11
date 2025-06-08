# Supacrypt PKCS#11 API Reference

## Overview

This document provides detailed information about all PKCS#11 functions implemented by the Supacrypt provider, including function signatures, parameters, return values, and usage examples.

## Function Categories

1. [General Purpose Functions](#general-purpose-functions)
2. [Slot and Token Management](#slot-and-token-management)
3. [Session Management](#session-management)
4. [Object Management](#object-management)
5. [Cryptographic Operations](#cryptographic-operations)
6. [Supacrypt Extensions](#supacrypt-extensions)

## General Purpose Functions

### C_Initialize

Initializes the PKCS#11 library.

```c
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
```

**Parameters:**
- `pInitArgs` - Pointer to CK_C_INITIALIZE_ARGS structure or NULL

**Returns:**
- `CKR_OK` - Success
- `CKR_CRYPTOKI_ALREADY_INITIALIZED` - Library already initialized
- `CKR_ARGUMENTS_BAD` - Invalid arguments
- `CKR_GENERAL_ERROR` - General failure

**Thread Safety:** This function is not thread-safe. Only one thread should call C_Initialize.

**Example:**
```c
CK_C_INITIALIZE_ARGS initArgs = {
    .CreateMutex = NULL,
    .DestroyMutex = NULL,
    .LockMutex = NULL,
    .UnlockMutex = NULL,
    .flags = CKF_OS_LOCKING_OK,
    .pReserved = NULL
};

CK_RV rv = C_Initialize(&initArgs);
if (rv != CKR_OK) {
    printf("Failed to initialize: 0x%08X\n", rv);
}
```

### C_Finalize

Finalizes the PKCS#11 library.

```c
CK_RV C_Finalize(CK_VOID_PTR pReserved);
```

**Parameters:**
- `pReserved` - Must be NULL

**Returns:**
- `CKR_OK` - Success
- `CKR_CRYPTOKI_NOT_INITIALIZED` - Library not initialized
- `CKR_ARGUMENTS_BAD` - pReserved is not NULL

**Notes:**
- Closes all sessions
- Releases all resources
- Disconnects from backend

### C_GetInfo

Gets general information about the PKCS#11 library.

```c
CK_RV C_GetInfo(CK_INFO_PTR pInfo);
```

**Parameters:**
- `pInfo` - Pointer to CK_INFO structure to receive information

**Returns:**
- `CKR_OK` - Success
- `CKR_CRYPTOKI_NOT_INITIALIZED` - Library not initialized
- `CKR_ARGUMENTS_BAD` - pInfo is NULL

**Info Structure:**
```c
typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;  // PKCS#11 version (2.40)
    CK_UTF8CHAR manufacturerID[32];  // "Supacrypt"
    CK_FLAGS flags;  // 0
    CK_UTF8CHAR libraryDescription[32];  // "Supacrypt PKCS#11"
    CK_VERSION libraryVersion;  // Provider version
} CK_INFO;
```

## Slot and Token Management

### C_GetSlotList

Gets list of available slots.

```c
CK_RV C_GetSlotList(
    CK_BBOOL tokenPresent,
    CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount
);
```

**Parameters:**
- `tokenPresent` - CK_TRUE to list only slots with tokens
- `pSlotList` - Array to receive slot IDs (can be NULL)
- `pulCount` - Pointer to number of slots

**Returns:**
- `CKR_OK` - Success
- `CKR_BUFFER_TOO_SMALL` - Provided buffer too small
- `CKR_CRYPTOKI_NOT_INITIALIZED` - Library not initialized

**Notes:**
- Supacrypt provides exactly one slot (ID = 1)
- Token is always present when backend is connected

### C_GetSlotInfo

Gets information about a specific slot.

```c
CK_RV C_GetSlotInfo(
    CK_SLOT_ID slotID,
    CK_SLOT_INFO_PTR pInfo
);
```

**Slot Info Structure:**
```c
typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];  // "Supacrypt Remote HSM Slot"
    CK_UTF8CHAR manufacturerID[32];   // "Supacrypt"
    CK_FLAGS flags;  // CKF_TOKEN_PRESENT | CKF_HW_SLOT
    CK_VERSION hardwareVersion;  // 1.0
    CK_VERSION firmwareVersion;  // 1.0
} CK_SLOT_INFO;
```

## Session Management

### C_OpenSession

Opens a session between an application and a token.

```c
CK_RV C_OpenSession(
    CK_SLOT_ID slotID,
    CK_FLAGS flags,
    CK_VOID_PTR pApplication,
    CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession
);
```

**Parameters:**
- `slotID` - ID of the token's slot
- `flags` - Session flags (must include CKF_SERIAL_SESSION)
- `pApplication` - Application-defined pointer (can be NULL)
- `Notify` - Callback function (can be NULL)
- `phSession` - Pointer to receive session handle

**Flags:**
- `CKF_SERIAL_SESSION` - Required
- `CKF_RW_SESSION` - Read/write session (optional)

**Returns:**
- `CKR_OK` - Success
- `CKR_SLOT_ID_INVALID` - Invalid slot ID
- `CKR_SESSION_PARALLEL_NOT_SUPPORTED` - Missing CKF_SERIAL_SESSION
- `CKR_DEVICE_ERROR` - Backend connection failed

**Example:**
```c
CK_SESSION_HANDLE hSession;
CK_RV rv = C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                         NULL, NULL, &hSession);
```

### C_CloseSession

Closes a session.

```c
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
```

**Notes:**
- Cancels any active operations
- Releases session resources
- Thread-safe

### C_GetSessionInfo

Gets information about a session.

```c
CK_RV C_GetSessionInfo(
    CK_SESSION_HANDLE hSession,
    CK_SESSION_INFO_PTR pInfo
);
```

**Session Info Structure:**
```c
typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;  // Always 1
    CK_STATE state;     // Session state
    CK_FLAGS flags;     // Session flags
    CK_ULONG ulDeviceError;  // Device-specific error code
} CK_SESSION_INFO;
```

## Object Management

### C_FindObjectsInit

Initializes object search.

```c
CK_RV C_FindObjectsInit(
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
);
```

**Search Examples:**
```c
// Find all RSA private keys
CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
CK_KEY_TYPE keyType = CKK_RSA;
CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &keyClass, sizeof(keyClass)},
    {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
};

rv = C_FindObjectsInit(hSession, template, 2);
```

### C_FindObjects

Continues object search.

```c
CK_RV C_FindObjects(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount
);
```

### C_FindObjectsFinal

Finishes object search.

```c
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
```

## Cryptographic Operations

### Key Generation

#### C_GenerateKeyPair

Generates a public/private key pair.

```c
CK_RV C_GenerateKeyPair(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey
);
```

**Supported Mechanisms:**
- `CKM_RSA_PKCS_KEY_PAIR_GEN` - RSA key generation
- `CKM_EC_KEY_PAIR_GEN` - ECC key generation

**RSA Example:**
```c
CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
CK_ULONG modulusBits = 2048;
CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};

CK_ATTRIBUTE publicTemplate[] = {
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
    {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
};

CK_ATTRIBUTE privateTemplate[] = {
    {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
    {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
    {CKA_SIGN, &ckTrue, sizeof(ckTrue)}
};
```

**ECC Example:**
```c
CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
CK_BYTE ecParams[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}; // P-256

CK_ATTRIBUTE publicTemplate[] = {
    {CKA_EC_PARAMS, ecParams, sizeof(ecParams)},
    {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
    {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
};
```

### Signing Operations

#### C_SignInit

Initializes a signature operation.

```c
CK_RV C_SignInit(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
);
```

**Supported Mechanisms:**
- `CKM_RSA_PKCS` - RSA PKCS#1 v1.5
- `CKM_RSA_PKCS_PSS` - RSA PSS
- `CKM_ECDSA` - ECDSA
- `CKM_ECDSA_SHA256` - ECDSA with SHA-256

#### C_Sign

Signs data in a single operation.

```c
CK_RV C_Sign(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
);
```

**Size Query:**
```c
// First call to get size
CK_ULONG signatureLen;
rv = C_Sign(hSession, data, dataLen, NULL, &signatureLen);

// Allocate buffer and sign
CK_BYTE_PTR signature = malloc(signatureLen);
rv = C_Sign(hSession, data, dataLen, signature, &signatureLen);
```

#### C_SignUpdate

Continues multi-part signature.

```c
CK_RV C_SignUpdate(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
);
```

#### C_SignFinal

Finishes multi-part signature.

```c
CK_RV C_SignFinal(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
);
```

### Verification Operations

#### C_VerifyInit

Initializes verification operation.

```c
CK_RV C_VerifyInit(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
);
```

#### C_Verify

Verifies a signature.

```c
CK_RV C_Verify(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen
);
```

**Returns:**
- `CKR_OK` - Signature valid
- `CKR_SIGNATURE_INVALID` - Signature invalid
- `CKR_SIGNATURE_LEN_RANGE` - Wrong signature length

## Supacrypt Extensions

### SC_Configure

Configures backend connection before initialization.

```c
CK_RV SC_Configure(const supacrypt_config_t* config);
```

**Configuration Structure:**
```c
typedef struct supacrypt_config {
    char backend_endpoint[256];
    char client_cert_path[256];
    char client_key_path[256];
    char ca_cert_path[256];
    CK_BBOOL use_tls;
    uint32_t request_timeout_ms;
    uint32_t retry_count;
    uint32_t connection_pool_size;
} supacrypt_config_t;
```

### SC_GetConfiguration

Gets current configuration.

```c
CK_RV SC_GetConfiguration(supacrypt_config_t* config);
```

### SC_GetErrorString

Gets human-readable error message.

```c
CK_RV SC_GetErrorString(
    CK_RV error_code,
    char* buffer,
    size_t buffer_size
);
```

**Example:**
```c
char errorMsg[256];
SC_GetErrorString(rv, errorMsg, sizeof(errorMsg));
printf("Error: %s\n", errorMsg);
```

### SC_SetLogging

Configures logging.

```c
CK_RV SC_SetLogging(
    CK_BBOOL enable,
    int log_level,
    const char* log_file
);
```

**Log Levels:**
- 0 - ERROR
- 1 - WARNING
- 2 - INFO
- 3 - DEBUG

### SC_GetStatistics

Gets performance statistics.

```c
CK_RV SC_GetStatistics(void* stats);
```

## Return Codes

### Standard PKCS#11 Return Codes

Code | Value | Description
-----|-------|------------
CKR_OK | 0x00000000 | Success
CKR_CANCEL | 0x00000001 | Operation cancelled
CKR_HOST_MEMORY | 0x00000002 | Memory allocation failed
CKR_SLOT_ID_INVALID | 0x00000003 | Invalid slot ID
CKR_GENERAL_ERROR | 0x00000005 | General error
CKR_FUNCTION_FAILED | 0x00000006 | Function failed
CKR_ARGUMENTS_BAD | 0x00000007 | Invalid arguments
CKR_ATTRIBUTE_TYPE_INVALID | 0x00000012 | Invalid attribute type
CKR_ATTRIBUTE_VALUE_INVALID | 0x00000013 | Invalid attribute value
CKR_DEVICE_ERROR | 0x00000030 | Device/backend error
CKR_DEVICE_MEMORY | 0x00000031 | Device memory error
CKR_DEVICE_REMOVED | 0x00000032 | Device disconnected
CKR_KEY_HANDLE_INVALID | 0x00000060 | Invalid key handle
CKR_KEY_SIZE_RANGE | 0x00000062 | Key size not supported
CKR_KEY_TYPE_INCONSISTENT | 0x00000063 | Key type mismatch
CKR_KEY_FUNCTION_NOT_PERMITTED | 0x00000068 | Operation not allowed
CKR_MECHANISM_INVALID | 0x00000070 | Invalid mechanism
CKR_MECHANISM_PARAM_INVALID | 0x00000071 | Invalid mechanism parameter
CKR_OBJECT_HANDLE_INVALID | 0x00000082 | Invalid object handle
CKR_OPERATION_ACTIVE | 0x00000090 | Another operation active
CKR_OPERATION_NOT_INITIALIZED | 0x00000091 | Operation not initialized
CKR_SESSION_CLOSED | 0x000000B0 | Session closed
CKR_SESSION_HANDLE_INVALID | 0x000000B3 | Invalid session handle
CKR_SIGNATURE_INVALID | 0x000000C0 | Invalid signature
CKR_SIGNATURE_LEN_RANGE | 0x000000C1 | Wrong signature length
CKR_BUFFER_TOO_SMALL | 0x00000150 | Output buffer too small
CKR_CRYPTOKI_NOT_INITIALIZED | 0x00000190 | Library not initialized
CKR_CRYPTOKI_ALREADY_INITIALIZED | 0x00000191 | Already initialized

### Backend-Specific Error Mappings

Backend Error | PKCS#11 Return Code | Description
--------------|-------------------|-------------
KEY_NOT_FOUND | CKR_KEY_HANDLE_INVALID | Key doesn't exist
PERMISSION_DENIED | CKR_KEY_FUNCTION_NOT_PERMITTED | Access denied
INVALID_KEY_SIZE | CKR_KEY_SIZE_RANGE | Unsupported size
UNSUPPORTED_ALGORITHM | CKR_MECHANISM_INVALID | Algorithm not supported
RATE_LIMITED | CKR_DEVICE_ERROR | Too many requests
NETWORK_ERROR | CKR_DEVICE_ERROR | Connection failed

## Thread Safety

### Thread-Safe Functions
- All functions except C_Initialize and C_Finalize
- Multiple threads can use different sessions
- Object handles are globally valid

### Thread-Unsafe Functions
- C_Initialize - Single thread only
- C_Finalize - Single thread only

### Best Practices
```c
// Use separate sessions per thread
void* worker_thread(void* arg) {
    CK_SESSION_HANDLE hSession;
    CK_RV rv = C_OpenSession(1, CKF_SERIAL_SESSION, 
                             NULL, NULL, &hSession);
    
    // Use session for operations...
    
    C_CloseSession(hSession);
    return NULL;
}
```

## Performance Characteristics

Operation | Typical Latency | Notes
----------|-----------------|-------
C_Initialize | 100-500ms | Backend connection
C_OpenSession | <1ms | Local operation
C_GenerateKeyPair | 1-2s | Backend operation
C_Sign (RSA-2048) | 40-50ms | Including network
C_Verify (RSA-2048) | 15-20ms | Including network
C_FindObjects | 10-50ms | Depends on count

## Migration Guide

### From SoftHSM
```c
// SoftHSM
C_Initialize(NULL);

// Supacrypt - configure first
supacrypt_config_t config = {0};
// ... set config ...
SC_Configure(&config);
C_Initialize(NULL);
```

### From OpenSC
- Replace module path in opensc.conf
- Update slot references (always use slot 1)
- No PIN required for Supacrypt

### From AWS CloudHSM
- Similar architecture (remote HSM)
- Update connection configuration
- Adjust for different mechanism support
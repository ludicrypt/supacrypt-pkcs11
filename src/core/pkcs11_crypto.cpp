/**
 * @file pkcs11_crypto.cpp
 * @brief PKCS#11 cryptographic operations
 */

#include "supacrypt/pkcs11/pkcs11.h"
#include "state_manager.h"
#include "session_state.h"
#include "object_cache.h"
#include "../utils/error_mapping.h"
#include "../utils/logging.h"
#include "supacrypt.grpc.pb.h"

#include <cstring>
#include <memory>
#include <string>

using namespace supacrypt::pkcs11;

namespace {

/**
 * @brief Key attributes parsed from PKCS#11 templates
 */
struct KeyAttributes {
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ULONG modulusBits = 2048;
    std::string ecParams;
    std::string label;
    CK_ULONG usage = 0;
    
    KeyAttributes() = default;
};

/**
 * @brief Parse key attributes from PKCS#11 templates
 */
KeyAttributes parseKeyAttributes(
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount) {
    
    KeyAttributes attrs;
    
    // Parse public key template
    for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; ++i) {
        switch (pPublicKeyTemplate[i].type) {
            case CKA_KEY_TYPE:
                if (pPublicKeyTemplate[i].pValue && pPublicKeyTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE)) {
                    attrs.keyType = *static_cast<CK_KEY_TYPE*>(pPublicKeyTemplate[i].pValue);
                }
                break;
            case CKA_MODULUS_BITS:
                if (pPublicKeyTemplate[i].pValue && pPublicKeyTemplate[i].ulValueLen == sizeof(CK_ULONG)) {
                    attrs.modulusBits = *static_cast<CK_ULONG*>(pPublicKeyTemplate[i].pValue);
                }
                break;
            case CKA_EC_PARAMS:
                if (pPublicKeyTemplate[i].pValue) {
                    attrs.ecParams = std::string(static_cast<char*>(pPublicKeyTemplate[i].pValue), 
                                                pPublicKeyTemplate[i].ulValueLen);
                }
                break;
            case CKA_LABEL:
                if (pPublicKeyTemplate[i].pValue) {
                    attrs.label = std::string(static_cast<char*>(pPublicKeyTemplate[i].pValue),
                                             pPublicKeyTemplate[i].ulValueLen);
                }
                break;
        }
    }
    
    // Parse private key template for additional attributes
    for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; ++i) {
        switch (pPrivateKeyTemplate[i].type) {
            case CKA_SIGN:
                if (pPrivateKeyTemplate[i].pValue && 
                    *static_cast<CK_BBOOL*>(pPrivateKeyTemplate[i].pValue) == CK_TRUE) {
                    attrs.usage |= (1 << 0); // Sign flag
                }
                break;
            case CKA_DECRYPT:
                if (pPrivateKeyTemplate[i].pValue && 
                    *static_cast<CK_BBOOL*>(pPrivateKeyTemplate[i].pValue) == CK_TRUE) {
                    attrs.usage |= (1 << 1); // Decrypt flag
                }
                break;
            case CKA_LABEL:
                if (pPrivateKeyTemplate[i].pValue && attrs.label.empty()) {
                    attrs.label = std::string(static_cast<char*>(pPrivateKeyTemplate[i].pValue),
                                             pPrivateKeyTemplate[i].ulValueLen);
                }
                break;
        }
    }
    
    return attrs;
}

/**
 * @brief Map usage flags to backend format
 */
uint32_t mapUsageFlags(CK_ULONG usage) {
    uint32_t backendUsage = 0;
    
    if (usage & (1 << 0)) { // Sign
        backendUsage |= static_cast<uint32_t>(supacrypt::v1::KeyUsage::KEY_USAGE_SIGN);
    }
    if (usage & (1 << 1)) { // Decrypt/Encrypt
        backendUsage |= static_cast<uint32_t>(supacrypt::v1::KeyUsage::KEY_USAGE_ENCRYPT);
        backendUsage |= static_cast<uint32_t>(supacrypt::v1::KeyUsage::KEY_USAGE_DECRYPT);
    }
    
    return backendUsage;
}

/**
 * @brief EC parameter constants
 */
const std::string EC_P256_PARAMS = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"; // secp256r1 OID
const std::string EC_P384_PARAMS = "\x06\x05\x2b\x81\x04\x00\x22"; // secp384r1 OID

} // anonymous namespace

// PKCS#11 Function Implementation

extern "C" {

CK_RV C_GenerateKeyPair(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey
) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (!pMechanism || !phPublicKey || !phPrivateKey) {
            return CKR_ARGUMENTS_BAD;
        }
        
        // Validate session
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) return rv;
        
        // Parse key attributes
        KeyAttributes attrs = parseKeyAttributes(pPublicKeyTemplate, 
                                               ulPublicKeyAttributeCount,
                                               pPrivateKeyTemplate,
                                               ulPrivateKeyAttributeCount);
        
        // Create GenerateKeyRequest
        supacrypt::v1::GenerateKeyRequest request;
        request.set_version(1);
        
        // Map key type and size
        switch (attrs.keyType) {
            case CKK_RSA:
                request.set_algorithm(supacrypt::v1::KeyAlgorithm::KEY_ALGORITHM_RSA);
                
                // Set RSA parameters
                auto* rsaParams = request.mutable_parameters()->mutable_rsa_params();
                if (attrs.modulusBits == 2048) {
                    rsaParams->set_key_size(supacrypt::v1::RSAKeySize::RSA_KEY_SIZE_2048);
                } else if (attrs.modulusBits == 3072) {
                    rsaParams->set_key_size(supacrypt::v1::RSAKeySize::RSA_KEY_SIZE_3072);
                } else if (attrs.modulusBits == 4096) {
                    rsaParams->set_key_size(supacrypt::v1::RSAKeySize::RSA_KEY_SIZE_4096);
                } else {
                    return CKR_KEY_SIZE_RANGE;
                }
                rsaParams->set_public_exponent(65537); // Standard public exponent
                break;
                
            case CKK_EC:
                request.set_algorithm(supacrypt::v1::KeyAlgorithm::KEY_ALGORITHM_ECC);
                
                // Set ECC parameters
                auto* eccParams = request.mutable_parameters()->mutable_ecc_params();
                if (attrs.ecParams == EC_P256_PARAMS) {
                    eccParams->set_curve(supacrypt::v1::ECCCurve::ECC_CURVE_P256);
                } else if (attrs.ecParams == EC_P384_PARAMS) {
                    eccParams->set_curve(supacrypt::v1::ECCCurve::ECC_CURVE_P384);
                } else {
                    return CKR_DOMAIN_PARAMS_INVALID;
                }
                break;
                
            default:
                return CKR_KEY_TYPE_INCONSISTENT;
        }
        
        // Set key name and operations
        if (!attrs.label.empty()) {
            request.set_name(attrs.label);
        } else {
            request.set_name("pkcs11-generated-key");
        }
        
        // Map operations
        if (attrs.usage & (1 << 0)) {
            request.add_operations("sign");
        }
        if (attrs.usage & (1 << 1)) {
            request.add_operations("decrypt");
            request.add_operations("encrypt");
        }
        
        // Execute RPC
        supacrypt::v1::GenerateKeyResponse response;
        auto& pool = StateManager::getInstance().getConnectionPool();
        
        rv = pool.executeRpc<supacrypt::v1::GenerateKeyRequest, 
                            supacrypt::v1::GenerateKeyResponse>(
            "GenerateKey",
            request,
            response,
            [](auto* stub, auto* ctx, const auto& req, auto* resp) {
                return stub->GenerateKey(ctx, req, resp);
            }
        );
        
        if (rv != CKR_OK) {
            logError("GenerateKey RPC failed");
            return rv;
        }
        
        // Check response
        if (!response.has_success()) {
            if (response.has_error()) {
                logError("GenerateKey backend error: " + response.error().message());
                return mapErrorCodeToPkcs11(response.error().code());
            }
            return CKR_FUNCTION_FAILED;
        }
        
        const auto& success = response.success();
        const auto& metadata = success.metadata();
        
        // Create object cache entries
        auto& cache = StateManager::getInstance().getObjectCache();
        
        // Add public key object
        *phPublicKey = cache.addObject(metadata.key_id(), CKO_PUBLIC_KEY);
        
        // Add private key object with same backend key ID
        *phPrivateKey = cache.addObject(metadata.key_id(), CKO_PRIVATE_KEY);
        
        // Set attributes for both objects
        // TODO: Implement proper attribute mapping from metadata
        
        logInfo("Generated key pair successfully: " + metadata.key_id());
        return CKR_OK;
        
    } catch (const std::exception& e) {
        logError("C_GenerateKeyPair exception: " + std::string(e.what()));
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_SignInit(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pMechanism == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) return rv;
        
        // Get key information from cache
        auto& cache = StateManager::getInstance().getObjectCache();
        ObjectEntry entry(0, "", CKO_DATA);
        if (!cache.getObject(hKey, entry)) {
            return CKR_KEY_HANDLE_INVALID;
        }
        
        // Validate key type for signing
        if (entry.objectClass != CKO_PRIVATE_KEY) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        
        // Initialize signing operation in session
        rv = session->beginOperation(OperationType::Sign, pMechanism, entry.backendKeyId);
        return rv;
        
    } catch (const std::exception& e) {
        logError("C_SignInit exception: " + std::string(e.what()));
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_Sign(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pulSignatureLen == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) return rv;
        
        // Get operation context
        const auto& context = session->getOperationContext();
        if (context.type != OperationType::Sign) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        
        // Handle size query
        const size_t expectedSize = 256; // TODO: Calculate based on key type and size
        if (pSignature == nullptr) {
            *pulSignatureLen = expectedSize;
            return CKR_OK;
        }
        
        if (*pulSignatureLen < expectedSize) {
            *pulSignatureLen = expectedSize;
            return CKR_BUFFER_TOO_SMALL;
        }
        
        // Create SignDataRequest
        supacrypt::v1::SignDataRequest request;
        request.set_version(1);
        request.set_key_id(context.keyId);
        
        if (pData && ulDataLen > 0) {
            request.set_data(pData, ulDataLen);
        }
        
        // Set signing parameters based on mechanism
        auto* params = request.mutable_parameters();
        switch (context.mechanism.mechanism) {
            case CKM_RSA_PKCS:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                params->mutable_rsa_params()->set_padding_scheme(supacrypt::v1::RSAPaddingScheme::RSA_PADDING_PKCS1);
                break;
            case CKM_RSA_PKCS_PSS:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                params->mutable_rsa_params()->set_padding_scheme(supacrypt::v1::RSAPaddingScheme::RSA_PADDING_PSS);
                break;
            case CKM_ECDSA:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                break;
            default:
                session->cancelOperation();
                return CKR_MECHANISM_INVALID;
        }
        
        // Execute RPC
        supacrypt::v1::SignDataResponse response;
        auto& pool = StateManager::getInstance().getConnectionPool();
        
        rv = pool.executeRpc<supacrypt::v1::SignDataRequest, 
                            supacrypt::v1::SignDataResponse>(
            "SignData",
            request,
            response,
            [](auto* stub, auto* ctx, const auto& req, auto* resp) {
                return stub->SignData(ctx, req, resp);
            }
        );
        
        if (rv != CKR_OK) {
            session->cancelOperation();
            return rv;
        }
        
        // Check response
        if (!response.has_success()) {
            session->cancelOperation();
            if (response.has_error()) {
                return mapErrorCodeToPkcs11(response.error().code());
            }
            return CKR_FUNCTION_FAILED;
        }
        
        const auto& success = response.success();
        
        // Copy signature to output
        if (success.signature().size() > *pulSignatureLen) {
            *pulSignatureLen = success.signature().size();
            session->cancelOperation();
            return CKR_BUFFER_TOO_SMALL;
        }
        
        std::memcpy(pSignature, success.signature().data(), success.signature().size());
        *pulSignatureLen = success.signature().size();
        
        // Clear operation state
        session->cancelOperation();
        
        return CKR_OK;
        
    } catch (const std::exception& e) {
        logError("C_Sign exception: " + std::string(e.what()));
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_VerifyInit(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pMechanism == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) return rv;
        
        // Get key information from cache
        auto& cache = StateManager::getInstance().getObjectCache();
        ObjectEntry entry(0, "", CKO_DATA);
        if (!cache.getObject(hKey, entry)) {
            return CKR_KEY_HANDLE_INVALID;
        }
        
        // Validate key type for verification (should be public key)
        if (entry.objectClass != CKO_PUBLIC_KEY) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        
        // Initialize verification operation in session
        rv = session->beginOperation(OperationType::Verify, pMechanism, entry.backendKeyId);
        return rv;
        
    } catch (const std::exception& e) {
        logError("C_VerifyInit exception: " + std::string(e.what()));
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_Verify(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen
) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (!pData || !pSignature || ulDataLen == 0 || ulSignatureLen == 0) {
            return CKR_ARGUMENTS_BAD;
        }
        
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) return rv;
        
        // Get operation context
        const auto& context = session->getOperationContext();
        if (context.type != OperationType::Verify) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        
        // Create VerifySignatureRequest
        supacrypt::v1::VerifySignatureRequest request;
        request.set_version(1);
        request.set_key_id(context.keyId);
        request.set_data(pData, ulDataLen);
        request.set_signature(pSignature, ulSignatureLen);
        
        // Set verification parameters based on mechanism
        auto* params = request.mutable_parameters();
        switch (context.mechanism.mechanism) {
            case CKM_RSA_PKCS:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                params->mutable_rsa_params()->set_padding_scheme(supacrypt::v1::RSAPaddingScheme::RSA_PADDING_PKCS1);
                break;
            case CKM_RSA_PKCS_PSS:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                params->mutable_rsa_params()->set_padding_scheme(supacrypt::v1::RSAPaddingScheme::RSA_PADDING_PSS);
                break;
            case CKM_ECDSA:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                break;
            default:
                session->cancelOperation();
                return CKR_MECHANISM_INVALID;
        }
        
        // Execute RPC
        supacrypt::v1::VerifySignatureResponse response;
        auto& pool = StateManager::getInstance().getConnectionPool();
        
        rv = pool.executeRpc<supacrypt::v1::VerifySignatureRequest, 
                            supacrypt::v1::VerifySignatureResponse>(
            "VerifySignature",
            request,
            response,
            [](auto* stub, auto* ctx, const auto& req, auto* resp) {
                return stub->VerifySignature(ctx, req, resp);
            }
        );
        
        if (rv != CKR_OK) {
            session->cancelOperation();
            return rv;
        }
        
        // Check response
        if (!response.has_success()) {
            session->cancelOperation();
            if (response.has_error()) {
                return mapErrorCodeToPkcs11(response.error().code());
            }
            return CKR_FUNCTION_FAILED;
        }
        
        const auto& success = response.success();
        
        // Check verification result
        if (!success.is_valid()) {
            session->cancelOperation();
            return CKR_SIGNATURE_INVALID;
        }
        
        session->cancelOperation();
        return CKR_OK;
        
    } catch (const std::exception& e) {
        logError("C_Verify exception: " + std::string(e.what()));
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_SignUpdate(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) return rv;
        
        // Update operation with more data
        rv = session->updateOperation(pPart, ulPartLen);
        return rv;
        
    } catch (const std::exception& e) {
        logError("C_SignUpdate exception: " + std::string(e.what()));
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_SignFinal(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pulSignatureLen == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) return rv;
        
        // Get operation context
        const auto& context = session->getOperationContext();
        if (context.type != OperationType::Sign) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        
        // Handle size query
        const size_t expectedSize = 256; // TODO: Calculate based on key type and size
        if (pSignature == nullptr) {
            *pulSignatureLen = expectedSize;
            return CKR_OK;
        }
        
        if (*pulSignatureLen < expectedSize) {
            *pulSignatureLen = expectedSize;
            return CKR_BUFFER_TOO_SMALL;
        }
        
        // Create SignDataRequest with accumulated data
        supacrypt::v1::SignDataRequest request;
        request.set_version(1);
        request.set_key_id(context.keyId);
        
        if (!context.accumulatedData.empty()) {
            request.set_data(context.accumulatedData.data(), context.accumulatedData.size());
        }
        
        // Set signing parameters based on mechanism
        auto* params = request.mutable_parameters();
        switch (context.mechanism.mechanism) {
            case CKM_RSA_PKCS:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                params->mutable_rsa_params()->set_padding_scheme(supacrypt::v1::RSAPaddingScheme::RSA_PADDING_PKCS1);
                break;
            case CKM_RSA_PKCS_PSS:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                params->mutable_rsa_params()->set_padding_scheme(supacrypt::v1::RSAPaddingScheme::RSA_PADDING_PSS);
                break;
            case CKM_ECDSA:
                params->set_hash_algorithm(supacrypt::v1::HASH_ALGORITHM_SHA256);
                break;
            default:
                session->cancelOperation();
                return CKR_MECHANISM_INVALID;
        }
        
        // Execute RPC
        supacrypt::v1::SignDataResponse response;
        auto& pool = StateManager::getInstance().getConnectionPool();
        
        rv = pool.executeRpc<supacrypt::v1::SignDataRequest, 
                            supacrypt::v1::SignDataResponse>(
            "SignData",
            request,
            response,
            [](auto* stub, auto* ctx, const auto& req, auto* resp) {
                return stub->SignData(ctx, req, resp);
            }
        );
        
        if (rv != CKR_OK) {
            session->cancelOperation();
            return rv;
        }
        
        // Check response
        if (!response.has_success()) {
            session->cancelOperation();
            if (response.has_error()) {
                return mapErrorCodeToPkcs11(response.error().code());
            }
            return CKR_FUNCTION_FAILED;
        }
        
        const auto& success = response.success();
        
        // Copy signature to output
        if (success.signature().size() > *pulSignatureLen) {
            *pulSignatureLen = success.signature().size();
            session->cancelOperation();
            return CKR_BUFFER_TOO_SMALL;
        }
        
        std::memcpy(pSignature, success.signature().data(), success.signature().size());
        *pulSignatureLen = success.signature().size();
        
        // Clear operation state
        session->cancelOperation();
        
        return CKR_OK;
        
    } catch (const std::exception& e) {
        logError("C_SignFinal exception: " + std::string(e.what()));
        return CKR_GENERAL_ERROR;
    }
}

} // extern "C"
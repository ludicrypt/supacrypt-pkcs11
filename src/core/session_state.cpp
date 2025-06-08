/**
 * @file session_state.cpp
 * @brief Implementation of session state management
 */

#include "session_state.h"
#include "supacrypt/pkcs11/pkcs11.h"
#include <algorithm>
#include <cstring>
#include <shared_mutex>

namespace supacrypt {
namespace pkcs11 {

SessionState::SessionState(CK_SESSION_HANDLE handle, CK_FLAGS flags)
    : handle_(handle), flags_(flags) {
}

SessionState::~SessionState() {
    cancelOperation();
}

CK_STATE SessionState::getState() const {
    // For simplicity, we only support R/W User sessions
    return CKS_RW_USER_FUNCTIONS;
}

CK_RV SessionState::beginOperation(OperationType type, CK_MECHANISM_PTR pMechanism, const std::string& keyId) {
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }

    if (keyId.empty()) {
        return CKR_KEY_HANDLE_INVALID;
    }

    std::unique_lock<std::shared_mutex> lock(mutex_);

    // Check if another operation is active
    if (activeOperation_.type != OperationType::None) {
        return CKR_OPERATION_ACTIVE;
    }

    // Validate mechanism for operation type
    CK_RV rv = validateMechanism(type, pMechanism);
    if (rv != CKR_OK) {
        return rv;
    }

    // Initialize operation context
    activeOperation_.type = type;
    activeOperation_.mechanism = *pMechanism;
    activeOperation_.keyId = keyId;
    activeOperation_.accumulatedData.clear();
    activeOperation_.isMultiPart = false;

    return CKR_OK;
}

CK_RV SessionState::updateOperation(CK_BYTE_PTR pData, CK_ULONG dataLen) {
    if (!pData && dataLen > 0) {
        return CKR_ARGUMENTS_BAD;
    }

    std::unique_lock<std::shared_mutex> lock(mutex_);

    if (activeOperation_.type == OperationType::None) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    // Mark as multi-part operation
    activeOperation_.isMultiPart = true;

    // Accumulate data
    if (dataLen > 0) {
        size_t currentSize = activeOperation_.accumulatedData.size();
        activeOperation_.accumulatedData.resize(currentSize + dataLen);
        std::memcpy(activeOperation_.accumulatedData.data() + currentSize, pData, dataLen);
    }

    return CKR_OK;
}

CK_RV SessionState::finalizeOperation(CK_BYTE_PTR pResult, CK_ULONG_PTR pResultLen) {
    if (!pResultLen) {
        return CKR_ARGUMENTS_BAD;
    }

    std::unique_lock<std::shared_mutex> lock(mutex_);

    if (activeOperation_.type == OperationType::None) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    // For now, just return a placeholder result size
    // The actual implementation will call the backend service
    CK_ULONG requiredSize = 256; // Placeholder signature size

    if (!pResult) {
        // Just return required size
        *pResultLen = requiredSize;
        return CKR_OK;
    }

    if (*pResultLen < requiredSize) {
        *pResultLen = requiredSize;
        return CKR_BUFFER_TOO_SMALL;
    }

    // TODO: Implement actual backend call here
    // For now, just fill with zeros
    std::memset(pResult, 0, requiredSize);
    *pResultLen = requiredSize;

    // Clear operation state
    activeOperation_.reset();

    return CKR_OK;
}

void SessionState::cancelOperation() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    activeOperation_.reset();
}

bool SessionState::hasActiveOperation(OperationType type) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return activeOperation_.type == type;
}

const OperationContext& SessionState::getOperationContext() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return activeOperation_;
}

CK_RV SessionState::validateMechanism(OperationType type, CK_MECHANISM_PTR pMechanism) const {
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }

    // Validate supported mechanisms based on operation type
    switch (type) {
        case OperationType::Sign:
        case OperationType::Verify:
            switch (pMechanism->mechanism) {
                case CKM_RSA_PKCS:
                case CKM_RSA_PKCS_PSS:
                case CKM_ECDSA:
                case CKM_ECDSA_SHA1:
                case CKM_ECDSA_SHA256:
                case CKM_ECDSA_SHA384:
                case CKM_ECDSA_SHA512:
                    return CKR_OK;
                default:
                    return CKR_MECHANISM_INVALID;
            }
            break;

        case OperationType::Encrypt:
        case OperationType::Decrypt:
            switch (pMechanism->mechanism) {
                case CKM_RSA_PKCS:
                case CKM_RSA_PKCS_OAEP:
                    return CKR_OK;
                default:
                    return CKR_MECHANISM_INVALID;
            }
            break;

        case OperationType::Digest:
            switch (pMechanism->mechanism) {
                case CKM_SHA_1:
                case CKM_SHA256:
                case CKM_SHA384:
                case CKM_SHA512:
                    return CKR_OK;
                default:
                    return CKR_MECHANISM_INVALID;
            }
            break;

        default:
            return CKR_OPERATION_NOT_INITIALIZED;
    }

    return CKR_OK;
}

} // namespace pkcs11
} // namespace supacrypt
/**
 * @file session_state.h
 * @brief Session state management for PKCS#11 operations
 */

#ifndef SUPACRYPT_PKCS11_SESSION_STATE_H
#define SUPACRYPT_PKCS11_SESSION_STATE_H

#include "supacrypt/pkcs11/pkcs11.h"
#include <shared_mutex>
#include <vector>
#include <string>
#include <memory>

namespace supacrypt {
namespace pkcs11 {

/**
 * @brief Operation types for session state tracking
 */
enum class OperationType {
    None,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Digest
};

/**
 * @brief Context for multi-part operations
 */
struct OperationContext {
    OperationType type = OperationType::None;
    CK_MECHANISM mechanism{};
    std::string keyId;
    std::vector<uint8_t> accumulatedData;
    bool isMultiPart = false;
    
    /**
     * @brief Reset the operation context
     */
    void reset() {
        type = OperationType::None;
        mechanism = CK_MECHANISM{};
        keyId.clear();
        accumulatedData.clear();
        isMultiPart = false;
    }
};

/**
 * @brief Thread-safe session state management
 * 
 * Manages the state of individual PKCS#11 sessions including
 * active operations and session properties.
 */
class SessionState {
public:
    /**
     * @brief Constructor
     * @param handle Session handle
     * @param flags Session flags
     */
    SessionState(CK_SESSION_HANDLE handle, CK_FLAGS flags);

    /**
     * @brief Destructor
     */
    ~SessionState();

    /**
     * @brief Get session handle
     * @return Session handle
     */
    CK_SESSION_HANDLE getHandle() const { return handle_; }

    /**
     * @brief Get session flags
     * @return Session flags
     */
    CK_FLAGS getFlags() const { return flags_; }

    /**
     * @brief Get session state
     * @return Session state
     */
    CK_STATE getState() const;

    /**
     * @brief Begin a cryptographic operation
     * @param type Operation type
     * @param pMechanism Mechanism pointer
     * @param keyId Backend key identifier
     * @return CK_RV Return code
     */
    CK_RV beginOperation(OperationType type, CK_MECHANISM_PTR pMechanism, const std::string& keyId);

    /**
     * @brief Update operation with more data (multi-part)
     * @param pData Data pointer
     * @param dataLen Data length
     * @return CK_RV Return code
     */
    CK_RV updateOperation(CK_BYTE_PTR pData, CK_ULONG dataLen);

    /**
     * @brief Finalize operation and get result
     * @param pResult Result buffer
     * @param pResultLen Result length pointer
     * @return CK_RV Return code
     */
    CK_RV finalizeOperation(CK_BYTE_PTR pResult, CK_ULONG_PTR pResultLen);

    /**
     * @brief Cancel active operation
     */
    void cancelOperation();

    /**
     * @brief Check if operation is active
     * @param type Operation type to check
     * @return true if operation is active
     */
    bool hasActiveOperation(OperationType type) const;

    /**
     * @brief Get active operation context (read-only)
     * @return Const reference to operation context
     */
    const OperationContext& getOperationContext() const;

private:
    const CK_SESSION_HANDLE handle_;
    const CK_FLAGS flags_;
    mutable std::shared_mutex mutex_;
    OperationContext activeOperation_;

    /**
     * @brief Validate mechanism for operation type
     * @param type Operation type
     * @param pMechanism Mechanism pointer
     * @return CK_RV Return code
     */
    CK_RV validateMechanism(OperationType type, CK_MECHANISM_PTR pMechanism) const;
};

} // namespace pkcs11
} // namespace supacrypt

#endif // SUPACRYPT_PKCS11_SESSION_STATE_H
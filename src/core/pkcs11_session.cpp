/**
 * @file pkcs11_session.cpp
 * @brief PKCS#11 session management functions
 */

#include "supacrypt/pkcs11/pkcs11.h"
#include "supacrypt/pkcs11/supacrypt_pkcs11.h"
#include "state_manager.h"
#include "../utils/error_mapping.h"
#include <cstring>

using namespace supacrypt::pkcs11;

extern "C" {

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (phSession == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        if (slotID != 1) {
            return CKR_SLOT_ID_INVALID;
        }
        
        // Validate flags
        if (!(flags & CKF_SERIAL_SESSION)) {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        
        CK_RV rv = StateManager::getInstance().createSession(flags, phSession);
        return rv;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        CK_RV rv = StateManager::getInstance().removeSession(hSession);
        return rv;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (slotID != 1) {
            return CKR_SLOT_ID_INVALID;
        }
        
        StateManager::getInstance().closeAllSessions();
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pInfo == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) {
            return rv;
        }
        
        std::memset(pInfo, 0, sizeof(CK_SESSION_INFO));
        pInfo->slotID = 1; // Our single slot ID
        pInfo->state = session->getState();
        pInfo->flags = session->getFlags();
        pInfo->ulDeviceError = 0;
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, 
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        // For simplicity, we don't require authentication in this implementation
        // In a production system, this would authenticate against the backend
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) {
            return rv;
        }
        
        // Accept any login attempt
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        SessionState* session = nullptr;
        CK_RV rv = StateManager::getInstance().getSession(hSession, &session);
        if (rv != CKR_OK) {
            return rv;
        }
        
        // Cancel any active operations
        session->cancelOperation();
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

} // extern "C"
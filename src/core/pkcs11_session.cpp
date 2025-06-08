/**
 * @file pkcs11_session.cpp
 * @brief PKCS#11 session management functions
 */

#include "supacrypt/pkcs11/pkcs11.h"
#include "supacrypt/pkcs11/supacrypt_pkcs11.h"
#include <unordered_map>
#include <mutex>
#include <cstring>

static std::mutex g_session_mutex;
static std::unordered_map<CK_SESSION_HANDLE, CK_SESSION_INFO> g_sessions;
static CK_SESSION_HANDLE g_next_session_handle = 1;

extern "C" {

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    if (pulCount == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    
    // For now, return a single slot
    if (pSlotList == nullptr) {
        *pulCount = 1;
        return CKR_OK;
    }
    
    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    
    pSlotList[0] = 0;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    if (pInfo == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    
    // TODO: Implement proper slot info
    std::memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    std::memcpy(pInfo->slotDescription, SUPACRYPT_SLOT_DESCRIPTION, 64);
    std::memcpy(pInfo->manufacturerID, SUPACRYPT_MANUFACTURER_ID, 32);
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    if (pInfo == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    
    // TODO: Implement proper token info
    std::memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    std::memcpy(pInfo->label, SUPACRYPT_TOKEN_LABEL, 32);
    std::memcpy(pInfo->manufacturerID, SUPACRYPT_MANUFACTURER_ID, 32);
    
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    if (phSession == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    
    std::lock_guard<std::mutex> lock(g_session_mutex);
    
    CK_SESSION_HANDLE handle = g_next_session_handle++;
    CK_SESSION_INFO session_info = {0};
    session_info.slotID = slotID;
    session_info.flags = flags;
    session_info.state = CKS_RO_PUBLIC_SESSION; // TODO: Implement proper state management
    
    g_sessions[handle] = session_info;
    *phSession = handle;
    
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    std::lock_guard<std::mutex> lock(g_session_mutex);
    
    auto it = g_sessions.find(hSession);
    if (it == g_sessions.end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    g_sessions.erase(it);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    
    std::lock_guard<std::mutex> lock(g_session_mutex);
    
    auto it = g_sessions.begin();
    while (it != g_sessions.end()) {
        if (it->second.slotID == slotID) {
            it = g_sessions.erase(it);
        } else {
            ++it;
        }
    }
    
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    if (pInfo == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    
    std::lock_guard<std::mutex> lock(g_session_mutex);
    
    auto it = g_sessions.find(hSession);
    if (it == g_sessions.end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    *pInfo = it->second;
    return CKR_OK;
}

} // extern "C"
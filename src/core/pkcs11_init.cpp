/**
 * @file pkcs11_init.cpp
 * @brief PKCS#11 initialization and finalization functions
 */

#include "supacrypt/pkcs11/pkcs11.h"
#include "supacrypt/pkcs11/supacrypt_pkcs11.h"
#include "state_manager.h"
#include "../utils/error_mapping.h"
#include <cstring>
#include <mutex>

using namespace supacrypt::pkcs11;

// Global configuration storage for SC_Configure calls before initialization
static std::mutex g_config_mutex;
static supacrypt_config_t g_pre_init_config = {0};
static bool g_has_pre_init_config = false;

extern "C" {

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    try {
        // Parse initialization arguments if provided
        const supacrypt_config_t* config = nullptr;
        
        {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            if (g_has_pre_init_config) {
                config = &g_pre_init_config;
            }
        }
        
        // Handle standard PKCS#11 initialization arguments
        if (pInitArgs != nullptr) {
            // For simplicity, we don't parse CK_C_INITIALIZE_ARGS for now
            // In a full implementation, we would parse thread safety settings
        }
        
        // Initialize the state manager
        CK_RV rv = StateManager::getInstance().initialize(config);
        if (rv != CKR_OK) {
            return rv;
        }
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    try {
        if (pReserved != nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        CK_RV rv = StateManager::getInstance().finalize();
        return rv;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pInfo == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        std::memset(pInfo, 0, sizeof(CK_INFO));
        
        // Fill in library information
        pInfo->cryptokiVersion.major = 2;
        pInfo->cryptokiVersion.minor = 40;
        
        std::strncpy(reinterpret_cast<char*>(pInfo->manufacturerID), 
                    SUPACRYPT_MANUFACTURER_ID, 32);
        
        std::strncpy(reinterpret_cast<char*>(pInfo->libraryDescription), 
                    SUPACRYPT_LIBRARY_DESCRIPTION, 32);
        
        pInfo->libraryVersion.major = SUPACRYPT_PKCS11_VERSION_MAJOR;
        pInfo->libraryVersion.minor = SUPACRYPT_PKCS11_VERSION_MINOR;
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pulCount == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        // We support exactly one slot
        const CK_ULONG slotCount = 1;
        
        if (pSlotList == nullptr) {
            // Just return the count
            *pulCount = slotCount;
            return CKR_OK;
        }
        
        if (*pulCount < slotCount) {
            *pulCount = slotCount;
            return CKR_BUFFER_TOO_SMALL;
        }
        
        // Return our single slot ID
        pSlotList[0] = 1;
        *pulCount = slotCount;
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pInfo == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        if (slotID != 1) {
            return CKR_SLOT_ID_INVALID;
        }
        
        std::memset(pInfo, 0, sizeof(CK_SLOT_INFO));
        
        std::strncpy(reinterpret_cast<char*>(pInfo->slotDescription), 
                    SUPACRYPT_SLOT_DESCRIPTION, 64);
        
        std::strncpy(reinterpret_cast<char*>(pInfo->manufacturerID), 
                    SUPACRYPT_MANUFACTURER_ID, 32);
        
        pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
        pInfo->hardwareVersion.major = 1;
        pInfo->hardwareVersion.minor = 0;
        pInfo->firmwareVersion.major = 1;
        pInfo->firmwareVersion.minor = 0;
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    try {
        if (!StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        if (pInfo == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        if (slotID != 1) {
            return CKR_SLOT_ID_INVALID;
        }
        
        std::memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
        
        std::strncpy(reinterpret_cast<char*>(pInfo->label), 
                    SUPACRYPT_TOKEN_LABEL, 32);
        
        std::strncpy(reinterpret_cast<char*>(pInfo->manufacturerID), 
                    SUPACRYPT_MANUFACTURER_ID, 32);
        
        std::strncpy(reinterpret_cast<char*>(pInfo->model), "Supacrypt Remote", 16);
        
        std::strncpy(reinterpret_cast<char*>(pInfo->serialNumber), "000001", 16);
        
        // Token flags - no PIN required, supports various operations
        pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
        
        pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
        pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
        pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
        pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
        pInfo->ulMaxPinLen = 0; // No PIN required
        pInfo->ulMinPinLen = 0;
        pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
        pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
        pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
        
        pInfo->hardwareVersion.major = 1;
        pInfo->hardwareVersion.minor = 0;
        pInfo->firmwareVersion.major = 1;
        pInfo->firmwareVersion.minor = 0;
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

} // extern "C"

// Supacrypt-specific configuration functions
extern "C" {

CK_RV SC_Configure(const supacrypt_config_t* config) {
    try {
        if (config == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        // Check if already initialized
        if (StateManager::getInstance().isInitialized()) {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        
        // Store configuration for later use during C_Initialize
        std::lock_guard<std::mutex> lock(g_config_mutex);
        g_pre_init_config = *config;
        g_has_pre_init_config = true;
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV SC_GetConfiguration(supacrypt_config_t* config) {
    try {
        if (config == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        if (StateManager::getInstance().isInitialized()) {
            // Return active configuration
            *config = StateManager::getInstance().getConfig();
        } else {
            // Return pre-initialization configuration
            std::lock_guard<std::mutex> lock(g_config_mutex);
            if (g_has_pre_init_config) {
                *config = g_pre_init_config;
            } else {
                std::memset(config, 0, sizeof(supacrypt_config_t));
            }
        }
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV SC_GetErrorString(CK_RV error_code, char* buffer, size_t buffer_size) {
    try {
        if (buffer == nullptr || buffer_size == 0) {
            return CKR_ARGUMENTS_BAD;
        }
        
        std::string errorMsg = getErrorMessage(error_code);
        std::strncpy(buffer, errorMsg.c_str(), buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV SC_SetLogging(CK_BBOOL enable, int log_level, const char* log_file) {
    try {
        // For now, just accept the settings without implementing actual logging
        // In a full implementation, this would configure the logging system
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

CK_RV SC_GetStatistics(void* stats) {
    try {
        if (stats == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        
        // For now, just zero out the statistics structure
        // In a full implementation, this would return actual metrics
        std::memset(stats, 0, 256); // Assume max 256 bytes for stats
        
        return CKR_OK;
    } catch (const std::exception&) {
        return CKR_GENERAL_ERROR;
    }
}

} // extern "C"
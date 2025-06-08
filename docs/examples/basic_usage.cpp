/**
 * @file basic_usage.cpp
 * @brief Basic PKCS#11 usage example demonstrating library initialization and slot enumeration
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <supacrypt/pkcs11/pkcs11.h>
#include <supacrypt/pkcs11/supacrypt_pkcs11.h>

// Helper function to check return values
void check_rv(CK_RV rv, const char* operation) {
    if (rv != CKR_OK) {
        char errorMsg[256];
        SC_GetErrorString(rv, errorMsg, sizeof(errorMsg));
        fprintf(stderr, "%s failed: %s (0x%08lX)\n", operation, errorMsg, rv);
        exit(1);
    }
}

int main() {
    CK_RV rv;
    
    // Configure backend connection
    printf("Configuring Supacrypt PKCS#11...\n");
    supacrypt_config_t config = {
        .backend_endpoint = "localhost:5000",
        .client_cert_path = "/etc/supacrypt/client.crt",
        .client_key_path = "/etc/supacrypt/client.key",
        .ca_cert_path = "/etc/supacrypt/ca.crt",
        .connection_timeout_ms = 30000,
        .request_timeout_ms = 10000
    };
    
    rv = SC_Configure(&config);
    check_rv(rv, "SC_Configure");
    
    // Initialize PKCS#11
    printf("Initializing PKCS#11...\n");
    rv = C_Initialize(NULL);
    check_rv(rv, "C_Initialize");
    
    // Get library info
    CK_INFO info;
    rv = C_GetInfo(&info);
    check_rv(rv, "C_GetInfo");
    
    printf("PKCS#11 Provider: %.32s\n", info.manufacturerID);
    printf("Library Version: %d.%d\n", 
           info.libraryVersion.major, info.libraryVersion.minor);
    
    // Get slot list
    CK_ULONG slotCount;
    rv = C_GetSlotList(CK_TRUE, NULL, &slotCount);
    check_rv(rv, "C_GetSlotList (count)");
    printf("Found %lu slot(s)\n", slotCount);
    
    if (slotCount > 0) {
        CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID) * slotCount);
        rv = C_GetSlotList(CK_TRUE, pSlotList, &slotCount);
        check_rv(rv, "C_GetSlotList");
        
        // Get slot info
        for (CK_ULONG i = 0; i < slotCount; i++) {
            CK_SLOT_INFO slotInfo;
            rv = C_GetSlotInfo(pSlotList[i], &slotInfo);
            check_rv(rv, "C_GetSlotInfo");
            
            printf("Slot %lu: %.64s\n", pSlotList[i], slotInfo.slotDescription);
            printf("  Manufacturer: %.32s\n", slotInfo.manufacturerID);
            printf("  Hardware Version: %d.%d\n", 
                   slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
        }
        
        // Open session on first slot
        printf("Opening session on slot %lu...\n", pSlotList[0]);
        CK_SESSION_HANDLE hSession;
        rv = C_OpenSession(pSlotList[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                           NULL, NULL, &hSession);
        check_rv(rv, "C_OpenSession");
        
        // Get session info
        CK_SESSION_INFO sessionInfo;
        rv = C_GetSessionInfo(hSession, &sessionInfo);
        check_rv(rv, "C_GetSessionInfo");
        
        printf("Session opened successfully\n");
        printf("  Session state: %lu\n", sessionInfo.state);
        printf("  Session flags: 0x%08lX\n", sessionInfo.flags);
        
        // Close session
        printf("Closing session...\n");
        C_CloseSession(hSession);
        
        free(pSlotList);
    }
    
    // Finalize
    printf("Finalizing PKCS#11...\n");
    C_Finalize(NULL);
    
    printf("Example completed successfully!\n");
    return 0;
}
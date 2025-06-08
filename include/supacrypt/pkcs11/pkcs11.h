/**
 * @file pkcs11.h
 * @brief Standard PKCS#11 interface definitions
 * 
 * This file contains the standard PKCS#11 C interface definitions
 * compatible with the PKCS#11 v2.40 specification.
 */

#ifndef SUPACRYPT_PKCS11_H
#define SUPACRYPT_PKCS11_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* PKCS#11 types */
typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long int CK_ULONG;
typedef long int CK_LONG;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_STATE;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_SLOT_ID;
typedef void *CK_VOID_PTR;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE_PTR CK_UTF8CHAR_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef CK_SESSION_HANDLE *CK_SESSION_HANDLE_PTR;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;

/* Additional types */
typedef CK_ULONG CK_NOTIFICATION;
typedef CK_NOTIFICATION (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

/* Session flags */
#define CKF_SERIAL_SESSION      0x00000004UL
#define CKF_RW_SESSION         0x00000002UL

/* Session states */
#define CKS_RO_PUBLIC_SESSION  0UL
#define CKS_RO_USER_FUNCTIONS  1UL
#define CKS_RW_PUBLIC_SESSION  2UL
#define CKS_RW_USER_FUNCTIONS  3UL
#define CKS_RW_SO_FUNCTIONS    4UL

/* Slot and token flags */
#define CKF_TOKEN_PRESENT      0x00000001UL
#define CKF_REMOVABLE_DEVICE   0x00000002UL
#define CKF_HW_SLOT           0x00000004UL

/* Additional return codes */
#define CKR_SESSION_HANDLE_INVALID     0x000000B3UL
#define CKR_BUFFER_TOO_SMALL          0x00000150UL

/* Constants */
#define CK_TRUE 1
#define CK_FALSE 0

/* Return values */
#define CKR_OK                          0x00000000UL
#define CKR_CANCEL                      0x00000001UL
#define CKR_HOST_MEMORY                 0x00000002UL
#define CKR_SLOT_ID_INVALID             0x00000003UL
#define CKR_GENERAL_ERROR               0x00000005UL
#define CKR_FUNCTION_FAILED             0x00000006UL
#define CKR_ARGUMENTS_BAD               0x00000007UL
#define CKR_NO_EVENT                    0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS      0x00000009UL
#define CKR_CANT_LOCK                   0x0000000AUL
#define CKR_ATTRIBUTE_READ_ONLY         0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE         0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID      0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID     0x00000013UL
#define CKR_CRYPTOKI_NOT_INITIALIZED    0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL
#define CKR_MUTEX_BAD                   0x000001A0UL
#define CKR_MUTEX_NOT_LOCKED            0x000001A1UL

/* PKCS#11 version structure */
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef CK_VERSION *CK_VERSION_PTR;

/* Library info structure */
typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef CK_INFO *CK_INFO_PTR;

/* Token info structure */
typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_BYTE serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_UTF8CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

/* Slot info structure */
typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;

/* Session info structure */
typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_STATE state;
    CK_FLAGS flags;
    CK_ULONG ulDeviceError;
} CK_SESSION_INFO;

typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;

/* Main PKCS#11 function declarations */

/**
 * @brief Initialize the PKCS#11 library
 * @param pInitArgs Initialization arguments (can be NULL)
 * @return CK_RV Return value
 */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);

/**
 * @brief Finalize the PKCS#11 library
 * @param pReserved Reserved parameter (must be NULL)
 * @return CK_RV Return value
 */
CK_RV C_Finalize(CK_VOID_PTR pReserved);

/**
 * @brief Get library information
 * @param pInfo Pointer to info structure
 * @return CK_RV Return value
 */
CK_RV C_GetInfo(CK_INFO_PTR pInfo);

/**
 * @brief Get list of available slots
 * @param tokenPresent Whether to list only slots with tokens
 * @param pSlotList Pointer to slot list
 * @param pulCount Pointer to count
 * @return CK_RV Return value
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);

/**
 * @brief Get slot information
 * @param slotID Slot identifier
 * @param pInfo Pointer to slot info
 * @return CK_RV Return value
 */
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);

/**
 * @brief Get token information
 * @param slotID Slot identifier
 * @param pInfo Pointer to token info
 * @return CK_RV Return value
 */
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

/**
 * @brief Open a session
 * @param slotID Slot identifier
 * @param flags Session flags
 * @param pApplication Application pointer
 * @param Notify Notification callback
 * @param phSession Pointer to session handle
 * @return CK_RV Return value
 */
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);

/**
 * @brief Close a session
 * @param hSession Session handle
 * @return CK_RV Return value
 */
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);

/**
 * @brief Close all sessions for a slot
 * @param slotID Slot identifier
 * @return CK_RV Return value
 */
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);

/**
 * @brief Get session information
 * @param hSession Session handle
 * @param pInfo Pointer to session info
 * @return CK_RV Return value
 */
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

#ifdef __cplusplus
}
#endif

#endif /* SUPACRYPT_PKCS11_H */
/**
 * @file supacrypt_pkcs11.h
 * @brief Supacrypt PKCS#11 provider specific definitions
 * 
 * This file contains Supacrypt-specific extensions and utilities
 * for the PKCS#11 implementation.
 */

#ifndef SUPACRYPT_PKCS11_SUPACRYPT_H
#define SUPACRYPT_PKCS11_SUPACRYPT_H

#include "pkcs11.h"

/* Export macro for now */
#ifndef SUPACRYPT_PKCS11_EXPORT
#  if defined(_WIN32)
#    define SUPACRYPT_PKCS11_EXPORT __declspec(dllexport)
#  else
#    define SUPACRYPT_PKCS11_EXPORT __attribute__((visibility("default")))
#  endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Supacrypt version information */
#define SUPACRYPT_PKCS11_VERSION_MAJOR 0
#define SUPACRYPT_PKCS11_VERSION_MINOR 1
#define SUPACRYPT_PKCS11_VERSION_PATCH 0

/* Supacrypt manufacturer ID */
#define SUPACRYPT_MANUFACTURER_ID "Supacrypt                       "

/* Supacrypt library description */
#define SUPACRYPT_LIBRARY_DESCRIPTION "Supacrypt PKCS#11 Provider     "

/* Supacrypt slot description */
#define SUPACRYPT_SLOT_DESCRIPTION "Supacrypt Remote HSM Slot                                      "

/* Supacrypt token label */
#define SUPACRYPT_TOKEN_LABEL "Supacrypt Token                 "

/* Configuration structure for Supacrypt provider */
typedef struct {
    const char* backend_endpoint;    /**< gRPC backend endpoint */
    const char* client_cert_path;    /**< Client certificate path */
    const char* client_key_path;     /**< Client private key path */
    const char* ca_cert_path;        /**< CA certificate path */
    int connection_timeout_ms;       /**< Connection timeout in milliseconds */
    int request_timeout_ms;          /**< Request timeout in milliseconds */
} supacrypt_config_t;

/**
 * @brief Configure the Supacrypt PKCS#11 provider
 * 
 * This function must be called before C_Initialize to configure
 * the connection parameters for the backend service.
 * 
 * @param config Configuration structure
 * @return CK_RV Return value
 */
SUPACRYPT_PKCS11_EXPORT CK_RV SC_Configure(const supacrypt_config_t* config);

/**
 * @brief Get the current configuration
 * 
 * @param config Pointer to configuration structure to fill
 * @return CK_RV Return value
 */
SUPACRYPT_PKCS11_EXPORT CK_RV SC_GetConfiguration(supacrypt_config_t* config);

/**
 * @brief Get detailed error information
 * 
 * @param error_code The PKCS#11 error code
 * @param buffer Buffer to store error message
 * @param buffer_size Size of the buffer
 * @return CK_RV Return value
 */
SUPACRYPT_PKCS11_EXPORT CK_RV SC_GetErrorString(CK_RV error_code, char* buffer, size_t buffer_size);

/**
 * @brief Enable or disable logging
 * 
 * @param enable Whether to enable logging
 * @param log_level Log level (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)
 * @param log_file Log file path (NULL for stdout)
 * @return CK_RV Return value
 */
SUPACRYPT_PKCS11_EXPORT CK_RV SC_SetLogging(CK_BBOOL enable, int log_level, const char* log_file);

/**
 * @brief Get provider statistics
 * 
 * @param stats Pointer to statistics structure
 * @return CK_RV Return value
 */
SUPACRYPT_PKCS11_EXPORT CK_RV SC_GetStatistics(void* stats);

#ifdef __cplusplus
}
#endif

#endif /* SUPACRYPT_PKCS11_SUPACRYPT_H */
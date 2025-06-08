/**
 * @file error_mapping.h
 * @brief Error code mapping between gRPC and PKCS#11
 */

#ifndef SUPACRYPT_PKCS11_ERROR_MAPPING_H
#define SUPACRYPT_PKCS11_ERROR_MAPPING_H

#include "supacrypt/pkcs11/pkcs11.h"
#include <string>

// Forward declaration
namespace grpc {
    class Status;
}

namespace supacrypt {
namespace pkcs11 {

/**
 * @brief Map gRPC status to PKCS#11 error code
 * @param status gRPC status
 * @return CK_RV PKCS#11 error code
 */
CK_RV mapGrpcError(const grpc::Status& status);

/**
 * @brief Map Supacrypt protobuf error code to PKCS#11 error code
 * @param errorCode Supacrypt error code
 * @return CK_RV PKCS#11 error code
 */
CK_RV mapSupacryptError(int32_t errorCode);

/**
 * @brief Get human-readable error message for PKCS#11 error code
 * @param errorCode PKCS#11 error code
 * @return Error message string
 */
std::string getErrorMessage(CK_RV errorCode);

/**
 * @brief Check if error is retriable
 * @param errorCode PKCS#11 error code
 * @return true if error is retriable
 */
bool isRetriableError(CK_RV errorCode);

} // namespace pkcs11
} // namespace supacrypt

#endif // SUPACRYPT_PKCS11_ERROR_MAPPING_H
/**
 * @file error_mapping.cpp
 * @brief Implementation of error code mapping between gRPC and PKCS#11
 */

#include "error_mapping.h"
#include <grpcpp/grpcpp.h>
#include <unordered_map>
#include <string>

namespace supacrypt {
namespace pkcs11 {

// Static error message mapping
static const std::unordered_map<CK_RV, std::string> errorMessages = {
    {CKR_OK, "Success"},
    {CKR_CANCEL, "Operation cancelled"},
    {CKR_HOST_MEMORY, "Host memory allocation failed"},
    {CKR_SLOT_ID_INVALID, "Invalid slot ID"},
    {CKR_GENERAL_ERROR, "General error"},
    {CKR_FUNCTION_FAILED, "Function failed"},
    {CKR_ARGUMENTS_BAD, "Invalid arguments"},
    {CKR_NO_EVENT, "No event available"},
    {CKR_NEED_TO_CREATE_THREADS, "Need to create threads"},
    {CKR_CANT_LOCK, "Cannot lock resource"},
    {CKR_ATTRIBUTE_READ_ONLY, "Attribute is read-only"},
    {CKR_ATTRIBUTE_SENSITIVE, "Attribute is sensitive"},
    {CKR_ATTRIBUTE_TYPE_INVALID, "Invalid attribute type"},
    {CKR_ATTRIBUTE_VALUE_INVALID, "Invalid attribute value"},
    {CKR_DATA_INVALID, "Invalid data"},
    {CKR_DATA_LEN_RANGE, "Data length out of range"},
    {CKR_DEVICE_ERROR, "Device error"},
    {CKR_DEVICE_MEMORY, "Device memory allocation failed"},
    {CKR_DEVICE_REMOVED, "Device removed"},
    {CKR_ENCRYPTED_DATA_INVALID, "Invalid encrypted data"},
    {CKR_ENCRYPTED_DATA_LEN_RANGE, "Encrypted data length out of range"},
    {CKR_FUNCTION_CANCELED, "Function cancelled"},
    {CKR_FUNCTION_NOT_PARALLEL, "Function not parallel"},
    {CKR_FUNCTION_NOT_SUPPORTED, "Function not supported"},
    {CKR_KEY_HANDLE_INVALID, "Invalid key handle"},
    {CKR_KEY_SIZE_RANGE, "Key size out of range"},
    {CKR_KEY_TYPE_INCONSISTENT, "Key type inconsistent"},
    {CKR_KEY_NOT_NEEDED, "Key not needed"},
    {CKR_KEY_CHANGED, "Key changed"},
    {CKR_KEY_NEEDED, "Key needed"},
    {CKR_KEY_INDIGESTIBLE, "Key indigestible"},
    {CKR_KEY_FUNCTION_NOT_PERMITTED, "Key function not permitted"},
    {CKR_KEY_NOT_WRAPPABLE, "Key not wrappable"},
    {CKR_KEY_UNEXTRACTABLE, "Key unextractable"},
    {CKR_MECHANISM_INVALID, "Invalid mechanism"},
    {CKR_MECHANISM_PARAM_INVALID, "Invalid mechanism parameter"},
    {CKR_OBJECT_HANDLE_INVALID, "Invalid object handle"},
    {CKR_OPERATION_ACTIVE, "Operation active"},
    {CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized"},
    {CKR_PIN_INCORRECT, "PIN incorrect"},
    {CKR_PIN_INVALID, "PIN invalid"},
    {CKR_PIN_LEN_RANGE, "PIN length out of range"},
    {CKR_PIN_EXPIRED, "PIN expired"},
    {CKR_PIN_LOCKED, "PIN locked"},
    {CKR_SESSION_CLOSED, "Session closed"},
    {CKR_SESSION_COUNT, "Session count exceeded"},
    {CKR_SESSION_HANDLE_INVALID, "Invalid session handle"},
    {CKR_SESSION_PARALLEL_NOT_SUPPORTED, "Parallel sessions not supported"},
    {CKR_SESSION_READ_ONLY, "Session is read-only"},
    {CKR_SESSION_EXISTS, "Session exists"},
    {CKR_SESSION_READ_ONLY_EXISTS, "Read-only session exists"},
    {CKR_SESSION_READ_WRITE_SO_EXISTS, "Read-write SO session exists"},
    {CKR_SIGNATURE_INVALID, "Invalid signature"},
    {CKR_SIGNATURE_LEN_RANGE, "Signature length out of range"},
    {CKR_TEMPLATE_INCOMPLETE, "Template incomplete"},
    {CKR_TEMPLATE_INCONSISTENT, "Template inconsistent"},
    {CKR_TOKEN_NOT_PRESENT, "Token not present"},
    {CKR_TOKEN_NOT_RECOGNIZED, "Token not recognized"},
    {CKR_TOKEN_WRITE_PROTECTED, "Token write protected"},
    {CKR_UNWRAPPING_KEY_HANDLE_INVALID, "Invalid unwrapping key handle"},
    {CKR_UNWRAPPING_KEY_SIZE_RANGE, "Unwrapping key size out of range"},
    {CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, "Unwrapping key type inconsistent"},
    {CKR_USER_ALREADY_LOGGED_IN, "User already logged in"},
    {CKR_USER_NOT_LOGGED_IN, "User not logged in"},
    {CKR_USER_PIN_NOT_INITIALIZED, "User PIN not initialized"},
    {CKR_USER_TYPE_INVALID, "Invalid user type"},
    {CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "Another user already logged in"},
    {CKR_USER_TOO_MANY_TYPES, "Too many user types"},
    {CKR_WRAPPED_KEY_INVALID, "Invalid wrapped key"},
    {CKR_WRAPPED_KEY_LEN_RANGE, "Wrapped key length out of range"},
    {CKR_WRAPPING_KEY_HANDLE_INVALID, "Invalid wrapping key handle"},
    {CKR_WRAPPING_KEY_SIZE_RANGE, "Wrapping key size out of range"},
    {CKR_WRAPPING_KEY_TYPE_INCONSISTENT, "Wrapping key type inconsistent"},
    {CKR_RANDOM_SEED_NOT_SUPPORTED, "Random seed not supported"},
    {CKR_RANDOM_NO_RNG, "No random number generator"},
    {CKR_DOMAIN_PARAMS_INVALID, "Invalid domain parameters"},
    {CKR_BUFFER_TOO_SMALL, "Buffer too small"},
    {CKR_SAVED_STATE_INVALID, "Invalid saved state"},
    {CKR_INFORMATION_SENSITIVE, "Information sensitive"},
    {CKR_STATE_UNSAVEABLE, "State unsaveable"},
    {CKR_CRYPTOKI_NOT_INITIALIZED, "Cryptoki not initialized"},
    {CKR_CRYPTOKI_ALREADY_INITIALIZED, "Cryptoki already initialized"},
    {CKR_MUTEX_BAD, "Bad mutex"},
    {CKR_MUTEX_NOT_LOCKED, "Mutex not locked"}
};

CK_RV mapGrpcError(const grpc::Status& status) {
    if (status.ok()) {
        return CKR_OK;
    }

    // Map gRPC status codes to PKCS#11 error codes
    switch (status.error_code()) {
        case grpc::StatusCode::OK:
            return CKR_OK;
            
        case grpc::StatusCode::CANCELLED:
            return CKR_CANCEL;
            
        case grpc::StatusCode::UNKNOWN:
            return CKR_GENERAL_ERROR;
            
        case grpc::StatusCode::INVALID_ARGUMENT:
            return CKR_ARGUMENTS_BAD;
            
        case grpc::StatusCode::DEADLINE_EXCEEDED:
            return CKR_FUNCTION_FAILED;
            
        case grpc::StatusCode::NOT_FOUND:
            return CKR_KEY_HANDLE_INVALID;
            
        case grpc::StatusCode::ALREADY_EXISTS:
            return CKR_FUNCTION_FAILED;
            
        case grpc::StatusCode::PERMISSION_DENIED:
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
            
        case grpc::StatusCode::RESOURCE_EXHAUSTED:
            return CKR_DEVICE_MEMORY;
            
        case grpc::StatusCode::FAILED_PRECONDITION:
            return CKR_OPERATION_NOT_INITIALIZED;
            
        case grpc::StatusCode::ABORTED:
            return CKR_FUNCTION_FAILED;
            
        case grpc::StatusCode::OUT_OF_RANGE:
            return CKR_DATA_LEN_RANGE;
            
        case grpc::StatusCode::UNIMPLEMENTED:
            return CKR_FUNCTION_NOT_SUPPORTED;
            
        case grpc::StatusCode::INTERNAL:
            return CKR_DEVICE_ERROR;
            
        case grpc::StatusCode::UNAVAILABLE:
            return CKR_DEVICE_ERROR;
            
        case grpc::StatusCode::DATA_LOSS:
            return CKR_DATA_INVALID;
            
        case grpc::StatusCode::UNAUTHENTICATED:
            return CKR_USER_NOT_LOGGED_IN;
            
        default:
            return CKR_GENERAL_ERROR;
    }
}

CK_RV mapSupacryptError(int32_t errorCode) {
    // Map Supacrypt protobuf error codes to PKCS#11 error codes
    // These would correspond to the ErrorCode enum in supacrypt.proto
    switch (errorCode) {
        case 1: // ERROR_CODE_SUCCESS
            return CKR_OK;
            
        case 2: // ERROR_CODE_INVALID_REQUEST
            return CKR_ARGUMENTS_BAD;
            
        case 3: // ERROR_CODE_KEY_NOT_FOUND
            return CKR_KEY_HANDLE_INVALID;
            
        case 4: // ERROR_CODE_KEY_ALREADY_EXISTS
            return CKR_FUNCTION_FAILED;
            
        case 5: // ERROR_CODE_UNSUPPORTED_ALGORITHM
            return CKR_MECHANISM_INVALID;
            
        case 6: // ERROR_CODE_INVALID_SIGNATURE
            return CKR_SIGNATURE_INVALID;
            
        case 7: // ERROR_CODE_OPERATION_NOT_SUPPORTED
            return CKR_FUNCTION_NOT_SUPPORTED;
            
        case 8: // ERROR_CODE_AUTHENTICATION_FAILED
            return CKR_USER_NOT_LOGGED_IN;
            
        case 9: // ERROR_CODE_AUTHORIZATION_FAILED
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
            
        case 10: // ERROR_CODE_NETWORK_ERROR
            return CKR_DEVICE_ERROR;
            
        case 11: // ERROR_CODE_INTERNAL_ERROR
            return CKR_DEVICE_ERROR;
            
        case 12: // ERROR_CODE_KEY_SIZE_NOT_SUPPORTED
            return CKR_KEY_SIZE_RANGE;
            
        case 13: // ERROR_CODE_CURVE_NOT_SUPPORTED
            return CKR_MECHANISM_PARAM_INVALID;
            
        case 14: // ERROR_CODE_HASH_NOT_SUPPORTED
            return CKR_MECHANISM_PARAM_INVALID;
            
        case 15: // ERROR_CODE_PADDING_NOT_SUPPORTED
            return CKR_MECHANISM_PARAM_INVALID;
            
        case 16: // ERROR_CODE_DECRYPTION_FAILED
            return CKR_ENCRYPTED_DATA_INVALID;
            
        case 17: // ERROR_CODE_ENCRYPTION_FAILED
            return CKR_DATA_INVALID;
            
        case 18: // ERROR_CODE_AZURE_KV_ERROR
            return CKR_DEVICE_ERROR;
            
        case 19: // ERROR_CODE_PKCS11_ERROR
            return CKR_GENERAL_ERROR;
            
        case 20: // ERROR_CODE_CSP_ERROR
            return CKR_GENERAL_ERROR;
            
        case 21: // ERROR_CODE_KSP_ERROR
            return CKR_GENERAL_ERROR;
            
        case 22: // ERROR_CODE_CTK_ERROR
            return CKR_GENERAL_ERROR;
            
        default:
            return CKR_GENERAL_ERROR;
    }
}

std::string getErrorMessage(CK_RV errorCode) {
    auto it = errorMessages.find(errorCode);
    if (it != errorMessages.end()) {
        return it->second;
    }
    
    return "Unknown error code: 0x" + std::to_string(errorCode);
}

bool isRetriableError(CK_RV errorCode) {
    switch (errorCode) {
        case CKR_DEVICE_ERROR:
        case CKR_FUNCTION_FAILED:
        case CKR_CANCEL:
            return true;
        default:
            return false;
    }
}

} // namespace pkcs11
} // namespace supacrypt
/**
 * @file grpc_connection_pool.h
 * @brief gRPC connection pool for backend communication
 */

#ifndef SUPACRYPT_PKCS11_GRPC_CONNECTION_POOL_H
#define SUPACRYPT_PKCS11_GRPC_CONNECTION_POOL_H

#include "supacrypt/pkcs11/supacrypt_pkcs11.h"
#include <memory>
#include <vector>
#include <mutex>
#include <chrono>
#include <functional>
#include <thread>

// Forward declarations for gRPC types
namespace grpc {
    class Channel;
    class Status;
    class ClientContext;
    enum StatusCode : int;
}

// Forward declaration of protobuf service stub
namespace supacrypt {
namespace v1 {
    class SupacryptService;
}
}

namespace supacrypt {
namespace pkcs11 {

/**
 * @brief Connection wrapper for gRPC stub
 */
struct Connection {
    std::shared_ptr<grpc::Channel> channel;
    std::unique_ptr<supacrypt::v1::SupacryptService::Stub> stub;
    std::chrono::steady_clock::time_point lastUsed;
    bool inUse = false;
    
    Connection() = default;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&) = default;
    Connection& operator=(Connection&&) = default;
};

/**
 * @brief Thread-safe gRPC connection pool
 * 
 * Manages a pool of gRPC connections to the backend service
 * with automatic reconnection and load balancing.
 */
class GrpcConnectionPool {
public:
    /**
     * @brief Constructor
     */
    GrpcConnectionPool();

    /**
     * @brief Destructor
     */
    ~GrpcConnectionPool();

    /**
     * @brief Initialize connection pool
     * @param config Backend configuration
     * @return CK_RV Return code
     */
    CK_RV initialize(const supacrypt_config_t* config);

    /**
     * @brief Shutdown connection pool
     */
    void shutdown();

    /**
     * @brief Get a connection from the pool
     * @return Shared pointer to service stub
     */
    std::shared_ptr<supacrypt::v1::SupacryptService::Stub> getConnection();

    /**
     * @brief Return a connection to the pool
     * @param stub Service stub to return
     */
    void returnConnection(std::shared_ptr<supacrypt::v1::SupacryptService::Stub> stub);

    /**
     * @brief Execute RPC with retry logic
     * @tparam RequestType gRPC request type
     * @tparam ResponseType gRPC response type
     * @param operationName Operation name for logging
     * @param request Request object
     * @param response Response object
     * @param rpcCall Function to execute the RPC
     * @return CK_RV Return code
     */
    template<typename RequestType, typename ResponseType>
    CK_RV executeRpc(
        const std::string& operationName,
        const RequestType& request,
        ResponseType& response,
        std::function<grpc::Status(supacrypt::v1::SupacryptService::Stub*, 
                                  grpc::ClientContext*, 
                                  const RequestType&, 
                                  ResponseType*)> rpcCall);

    /**
     * @brief Check if pool is initialized
     * @return true if initialized
     */
    bool isInitialized() const { return initialized_; }

private:
    std::mutex poolMutex_;
    std::vector<Connection> connections_;
    supacrypt_config_t config_{};
    bool initialized_ = false;
    static constexpr size_t DEFAULT_POOL_SIZE = 4;

    /**
     * @brief Create a secure gRPC channel
     * @return Shared pointer to channel
     */
    std::shared_ptr<grpc::Channel> createSecureChannel();

    /**
     * @brief Create an insecure gRPC channel (for testing)
     * @return Shared pointer to channel
     */
    std::shared_ptr<grpc::Channel> createInsecureChannel();

    /**
     * @brief Check if gRPC status is retryable
     * @param status gRPC status
     * @return true if retryable
     */
    bool isRetryable(const grpc::Status& status) const;

    /**
     * @brief Get timeout for operation
     * @param operationName Operation name
     * @return Timeout duration
     */
    std::chrono::milliseconds getOperationTimeout(const std::string& operationName) const;

    /**
     * @brief Generate operation ID for tracing
     * @return Operation ID string
     */
    std::string generateOperationId() const;

    /**
     * @brief Read file contents
     * @param filepath Path to file
     * @return File contents as string
     */
    std::string readFile(const std::string& filepath) const;
};

// Template implementation
template<typename RequestType, typename ResponseType>
CK_RV GrpcConnectionPool::executeRpc(
    const std::string& operationName,
    const RequestType& request,
    ResponseType& response,
    std::function<grpc::Status(supacrypt::v1::SupacryptService::Stub*, 
                              grpc::ClientContext*, 
                              const RequestType&, 
                              ResponseType*)> rpcCall) {
    
    if (!initialized_) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    auto stub = getConnection();
    if (!stub) {
        return CKR_DEVICE_ERROR;
    }

    const uint32_t maxRetries = 3;
    
    for (uint32_t attempt = 0; attempt <= maxRetries; ++attempt) {
        grpc::ClientContext context;
        
        // Set timeout
        auto timeout = getOperationTimeout(operationName);
        context.set_deadline(std::chrono::system_clock::now() + timeout);
        
        // Add metadata for tracing
        context.AddMetadata("x-operation-id", generateOperationId());
        context.AddMetadata("x-operation-name", operationName);
        
        // Execute RPC
        grpc::Status status = rpcCall(stub.get(), &context, request, &response);
        
        if (status.ok()) {
            returnConnection(stub);
            return CKR_OK;
        }
        
        // Check if we should retry
        if (!isRetryable(status) || attempt == maxRetries) {
            returnConnection(stub);
            // Map gRPC error to PKCS#11 error (will implement in error_mapping.cpp)
            return CKR_FUNCTION_FAILED; // Placeholder
        }
        
        // Exponential backoff
        auto backoff = std::chrono::milliseconds(100 * (1 << attempt));
        std::this_thread::sleep_for(backoff);
    }
    
    returnConnection(stub);
    return CKR_FUNCTION_FAILED;
}

} // namespace pkcs11
} // namespace supacrypt

#endif // SUPACRYPT_PKCS11_GRPC_CONNECTION_POOL_H
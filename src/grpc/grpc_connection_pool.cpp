/**
 * @file grpc_connection_pool.cpp
 * @brief Implementation of gRPC connection pool
 */

#include "grpc_connection_pool.h"
#include <grpcpp/security/credentials.h>
#include <grpcpp/create_channel.h>
#include <fstream>
#include <random>
#include <sstream>
#include <thread>
#include <iomanip>

// Include generated protobuf headers (these would be generated from supacrypt.proto)
// For now we'll use forward declarations and implement the stub interface

namespace supacrypt {
namespace pkcs11 {

GrpcConnectionPool::GrpcConnectionPool() {
    connections_.reserve(DEFAULT_POOL_SIZE);
}

GrpcConnectionPool::~GrpcConnectionPool() {
    shutdown();
}

CK_RV GrpcConnectionPool::initialize(const supacrypt_config_t* config) {
    if (initialized_) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    if (!config) {
        return CKR_ARGUMENTS_BAD;
    }

    config_ = *config;

    std::lock_guard<std::mutex> lock(poolMutex_);

    // Create initial connections
    for (size_t i = 0; i < DEFAULT_POOL_SIZE; ++i) {
        Connection conn;
        
        // Create secure or insecure channel based on configuration
        if (config_.client_cert_path && config_.client_key_path && config_.ca_cert_path) {
            conn.channel = createSecureChannel();
        } else {
            conn.channel = createInsecureChannel();
        }

        if (!conn.channel) {
            // Cleanup partially initialized connections
            connections_.clear();
            return CKR_DEVICE_ERROR;
        }

        // For now, we'll comment out the stub creation since we don't have the generated code
        // conn.stub = supacrypt::v1::SupacryptService::NewStub(conn.channel);
        
        conn.lastUsed = std::chrono::steady_clock::now();
        connections_.push_back(std::move(conn));
    }

    initialized_ = true;
    return CKR_OK;
}

void GrpcConnectionPool::shutdown() {
    if (!initialized_) {
        return;
    }

    std::lock_guard<std::mutex> lock(poolMutex_);
    connections_.clear();
    initialized_ = false;
}

std::shared_ptr<supacrypt::v1::SupacryptService::Stub> GrpcConnectionPool::getConnection() {
    if (!initialized_) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(poolMutex_);

    // Find an available connection
    for (auto& conn : connections_) {
        if (!conn.inUse && conn.stub) {
            conn.inUse = true;
            conn.lastUsed = std::chrono::steady_clock::now();
            return conn.stub.get()->shared_from_this(); // This won't work without proper shared_ptr management
        }
    }

    // All connections are in use, return nullptr for now
    // In a production implementation, we would either wait or create a new connection
    return nullptr;
}

void GrpcConnectionPool::returnConnection(std::shared_ptr<supacrypt::v1::SupacryptService::Stub> stub) {
    if (!initialized_ || !stub) {
        return;
    }

    std::lock_guard<std::mutex> lock(poolMutex_);

    // Find the connection and mark it as available
    for (auto& conn : connections_) {
        if (conn.stub.get() == stub.get()) {
            conn.inUse = false;
            conn.lastUsed = std::chrono::steady_clock::now();
            break;
        }
    }
}

std::shared_ptr<grpc::Channel> GrpcConnectionPool::createSecureChannel() {
    try {
        grpc::SslCredentialsOptions sslOpts;
        
        // Read certificate files
        sslOpts.pem_root_certs = readFile(config_.ca_cert_path);
        sslOpts.pem_private_key = readFile(config_.client_key_path);
        sslOpts.pem_cert_chain = readFile(config_.client_cert_path);

        if (sslOpts.pem_root_certs.empty() || 
            sslOpts.pem_private_key.empty() || 
            sslOpts.pem_cert_chain.empty()) {
            return nullptr;
        }

        auto creds = grpc::SslCredentials(sslOpts);
        
        grpc::ChannelArguments args;
        args.SetMaxReceiveMessageSize(4 * 1024 * 1024); // 4MB
        args.SetMaxSendMessageSize(4 * 1024 * 1024);    // 4MB
        args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 30000);
        args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 5000);
        args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);

        return grpc::CreateCustomChannel(config_.backend_endpoint, creds, args);
    } catch (const std::exception&) {
        return nullptr;
    }
}

std::shared_ptr<grpc::Channel> GrpcConnectionPool::createInsecureChannel() {
    try {
        grpc::ChannelArguments args;
        args.SetMaxReceiveMessageSize(4 * 1024 * 1024); // 4MB
        args.SetMaxSendMessageSize(4 * 1024 * 1024);    // 4MB

        return grpc::CreateCustomChannel(config_.backend_endpoint, 
                                       grpc::InsecureChannelCredentials(), args);
    } catch (const std::exception&) {
        return nullptr;
    }
}

bool GrpcConnectionPool::isRetryable(const grpc::Status& status) const {
    switch (status.error_code()) {
        case grpc::StatusCode::UNAVAILABLE:
        case grpc::StatusCode::DEADLINE_EXCEEDED:
        case grpc::StatusCode::RESOURCE_EXHAUSTED:
        case grpc::StatusCode::ABORTED:
            return true;
        default:
            return false;
    }
}

std::chrono::milliseconds GrpcConnectionPool::getOperationTimeout(const std::string& operationName) const {
    // Different operations might have different timeout requirements
    if (operationName == "GenerateKey") {
        return std::chrono::milliseconds(config_.request_timeout_ms * 3); // Key generation takes longer
    }
    
    return std::chrono::milliseconds(config_.request_timeout_ms);
}

std::string GrpcConnectionPool::generateOperationId() const {
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    static thread_local std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

std::string GrpcConnectionPool::readFile(const std::string& filepath) const {
    if (filepath.empty()) {
        return "";
    }

    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        return "";
    }

    return std::string(std::istreambuf_iterator<char>(file),
                      std::istreambuf_iterator<char>());
}

} // namespace pkcs11
} // namespace supacrypt
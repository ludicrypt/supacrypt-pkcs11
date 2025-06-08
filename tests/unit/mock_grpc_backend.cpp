// tests/unit/mock_grpc_backend.cpp

#include "mock_grpc_backend.h"
#include <random>

namespace supacrypt::test {

MockSupacryptStub::MockSupacryptStub() {
    setupDefaultBehavior();
}

void MockSupacryptStub::setupDefaultBehavior() {
    // Default successful responses for common operations
    ON_CALL(*this, GenerateKey(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::GenerateKeyRequest& request,
                         supacrypt::v1::GenerateKeyResponse* response) {
            auto* success = response->mutable_success();
            auto* metadata = success->mutable_metadata();
            
            // Generate a mock key ID
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(10000, 99999);
            
            metadata->set_key_id("test-key-" + std::to_string(dis(gen)));
            metadata->set_key_name(request.name());
            metadata->set_algorithm(request.algorithm());
            metadata->set_created_at(std::time(nullptr));
            metadata->set_key_usage(supacrypt::v1::KeyUsage::KEY_USAGE_SIGN_VERIFY);
            
            if (request.algorithm() == supacrypt::v1::KeyAlgorithm::KEY_ALGORITHM_RSA) {
                auto* rsa_metadata = metadata->mutable_rsa_metadata();
                rsa_metadata->set_key_size(request.parameters().rsa_params().key_size());
                rsa_metadata->set_public_exponent(65537);
            } else if (request.algorithm() == supacrypt::v1::KeyAlgorithm::KEY_ALGORITHM_ECDSA) {
                auto* ec_metadata = metadata->mutable_ec_metadata();
                ec_metadata->set_curve(request.parameters().ec_params().curve());
            }
            
            return grpc::Status::OK;
        });
    
    ON_CALL(*this, SignData(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::SignDataRequest& request,
                         supacrypt::v1::SignDataResponse* response) {
            auto* success = response->mutable_success();
            
            // Generate mock signature (just random bytes for testing)
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint8_t> dis(0, 255);
            
            size_t sig_size = 256; // RSA-2048 signature size
            std::string signature;
            signature.reserve(sig_size);
            
            for (size_t i = 0; i < sig_size; ++i) {
                signature.push_back(static_cast<char>(dis(gen)));
            }
            
            success->set_signature(signature);
            return grpc::Status::OK;
        });
    
    ON_CALL(*this, VerifySignature(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::VerifySignatureRequest& request,
                         supacrypt::v1::VerifySignatureResponse* response) {
            auto* success = response->mutable_success();
            success->set_valid(true); // Always valid for default mock
            return grpc::Status::OK;
        });
    
    ON_CALL(*this, GetKey(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::GetKeyRequest& request,
                         supacrypt::v1::GetKeyResponse* response) {
            auto* success = response->mutable_success();
            auto* metadata = success->mutable_metadata();
            
            metadata->set_key_id(request.key_id());
            metadata->set_key_name("Test Key");
            metadata->set_algorithm(supacrypt::v1::KeyAlgorithm::KEY_ALGORITHM_RSA);
            metadata->set_created_at(std::time(nullptr));
            metadata->set_key_usage(supacrypt::v1::KeyUsage::KEY_USAGE_SIGN_VERIFY);
            
            auto* rsa_metadata = metadata->mutable_rsa_metadata();
            rsa_metadata->set_key_size(supacrypt::v1::RSAKeySize::RSA_KEY_SIZE_2048);
            rsa_metadata->set_public_exponent(65537);
            
            return grpc::Status::OK;
        });
    
    ON_CALL(*this, ListKeys(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::ListKeysRequest& request,
                         supacrypt::v1::ListKeysResponse* response) {
            auto* success = response->mutable_success();
            
            // Add a few mock keys
            for (int i = 1; i <= 3; ++i) {
                auto* metadata = success->add_keys();
                metadata->set_key_id("test-key-" + std::to_string(i));
                metadata->set_key_name("Test Key " + std::to_string(i));
                metadata->set_algorithm(supacrypt::v1::KeyAlgorithm::KEY_ALGORITHM_RSA);
                metadata->set_created_at(std::time(nullptr) - (i * 3600));
                metadata->set_key_usage(supacrypt::v1::KeyUsage::KEY_USAGE_SIGN_VERIFY);
            }
            
            return grpc::Status::OK;
        });
    
    ON_CALL(*this, DeleteKey(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::DeleteKeyRequest& request,
                         supacrypt::v1::DeleteKeyResponse* response) {
            auto* success = response->mutable_success();
            success->set_deleted(true);
            return grpc::Status::OK;
        });
}

void MockSupacryptStub::simulateNetworkError() {
    ON_CALL(*this, GenerateKey(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Return(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Backend unavailable")));
    
    ON_CALL(*this, SignData(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Return(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Backend unavailable")));
    
    ON_CALL(*this, VerifySignature(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Return(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Backend unavailable")));
}

void MockSupacryptStub::simulateKeyNotFound() {
    ON_CALL(*this, GetKey(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::GetKeyRequest& request,
                         supacrypt::v1::GetKeyResponse* response) {
            auto* error = response->mutable_error();
            error->set_code(supacrypt::v1::ErrorCode::ERROR_CODE_KEY_NOT_FOUND);
            error->set_message("Key not found: " + request.key_id());
            return grpc::Status::OK;
        });
    
    ON_CALL(*this, SignData(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::SignDataRequest& request,
                         supacrypt::v1::SignDataResponse* response) {
            auto* error = response->mutable_error();
            error->set_code(supacrypt::v1::ErrorCode::ERROR_CODE_KEY_NOT_FOUND);
            error->set_message("Key not found: " + request.key_id());
            return grpc::Status::OK;
        });
}

void MockSupacryptStub::simulateInvalidSignature() {
    ON_CALL(*this, VerifySignature(testing::_, testing::_, testing::_))
        .WillByDefault([](grpc::ClientContext*, 
                         const supacrypt::v1::VerifySignatureRequest& request,
                         supacrypt::v1::VerifySignatureResponse* response) {
            auto* success = response->mutable_success();
            success->set_valid(false);
            return grpc::Status::OK;
        });
}

std::unique_ptr<MockGrpcBackend> MockGrpcBackend::instance_;
std::mutex MockGrpcBackend::instance_mutex_;

MockGrpcBackend& MockGrpcBackend::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = std::unique_ptr<MockGrpcBackend>(new MockGrpcBackend());
    }
    return *instance_;
}

void MockGrpcBackend::reset() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    instance_.reset();
}

MockGrpcBackend::MockGrpcBackend() 
    : stub_(std::make_unique<MockSupacryptStub>()) {
}

MockSupacryptStub* MockGrpcBackend::getStub() {
    return stub_.get();
}

} // namespace supacrypt::test
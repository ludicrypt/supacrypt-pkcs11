// tests/unit/mock_grpc_backend.h

#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <mutex>

// Include the generated protobuf headers
#include "supacrypt.grpc.pb.h"

namespace supacrypt::test {

class MockSupacryptStub : public supacrypt::v1::SupacryptService::StubInterface {
public:
    MockSupacryptStub();

    // Mock methods for all gRPC service calls
    MOCK_METHOD(grpc::Status, GenerateKey,
        (grpc::ClientContext* context, 
         const supacrypt::v1::GenerateKeyRequest& request,
         supacrypt::v1::GenerateKeyResponse* response), (override));

    MOCK_METHOD(grpc::Status, SignData,
        (grpc::ClientContext* context,
         const supacrypt::v1::SignDataRequest& request,
         supacrypt::v1::SignDataResponse* response), (override));

    MOCK_METHOD(grpc::Status, VerifySignature,
        (grpc::ClientContext* context,
         const supacrypt::v1::VerifySignatureRequest& request,
         supacrypt::v1::VerifySignatureResponse* response), (override));

    MOCK_METHOD(grpc::Status, EncryptData,
        (grpc::ClientContext* context,
         const supacrypt::v1::EncryptDataRequest& request,
         supacrypt::v1::EncryptDataResponse* response), (override));

    MOCK_METHOD(grpc::Status, DecryptData,
        (grpc::ClientContext* context,
         const supacrypt::v1::DecryptDataRequest& request,
         supacrypt::v1::DecryptDataResponse* response), (override));

    MOCK_METHOD(grpc::Status, GetKey,
        (grpc::ClientContext* context,
         const supacrypt::v1::GetKeyRequest& request,
         supacrypt::v1::GetKeyResponse* response), (override));

    MOCK_METHOD(grpc::Status, ListKeys,
        (grpc::ClientContext* context,
         const supacrypt::v1::ListKeysRequest& request,
         supacrypt::v1::ListKeysResponse* response), (override));

    MOCK_METHOD(grpc::Status, DeleteKey,
        (grpc::ClientContext* context,
         const supacrypt::v1::DeleteKeyRequest& request,
         supacrypt::v1::DeleteKeyResponse* response), (override));

    // Async method mocks (not implemented for now, but required by interface)
    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<supacrypt::v1::GenerateKeyResponse>*,
        AsyncGenerateKeyRaw,
        (grpc::ClientContext* context,
         const supacrypt::v1::GenerateKeyRequest& request,
         grpc::CompletionQueue* cq), (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<supacrypt::v1::GenerateKeyResponse>*,
        PrepareAsyncGenerateKeyRaw,
        (grpc::ClientContext* context,
         const supacrypt::v1::GenerateKeyRequest& request,
         grpc::CompletionQueue* cq), (override));

    // Add other async methods as needed...

    // Helper methods for setting up test scenarios
    void setupDefaultBehavior();
    void simulateNetworkError();
    void simulateKeyNotFound();
    void simulateInvalidSignature();

private:
    // Stub out async methods with nullptr for now
    grpc::ClientAsyncResponseReaderInterface<supacrypt::v1::GenerateKeyResponse>*
    AsyncGenerateKeyRaw(grpc::ClientContext*, const supacrypt::v1::GenerateKeyRequest&, grpc::CompletionQueue*) override {
        return nullptr;
    }

    grpc::ClientAsyncResponseReaderInterface<supacrypt::v1::GenerateKeyResponse>*
    PrepareAsyncGenerateKeyRaw(grpc::ClientContext*, const supacrypt::v1::GenerateKeyRequest&, grpc::CompletionQueue*) override {
        return nullptr;
    }
};

// Singleton mock backend for tests
class MockGrpcBackend {
public:
    static MockGrpcBackend& getInstance();
    static void reset();

    MockSupacryptStub* getStub();

private:
    MockGrpcBackend();
    
    static std::unique_ptr<MockGrpcBackend> instance_;
    static std::mutex instance_mutex_;
    
    std::unique_ptr<MockSupacryptStub> stub_;
};

// RAII helper for test setup/teardown
class MockBackendTestFixture {
public:
    MockBackendTestFixture() {
        mock_backend_ = &MockGrpcBackend::getInstance();
    }
    
    ~MockBackendTestFixture() {
        MockGrpcBackend::reset();
    }
    
    MockSupacryptStub* getStub() {
        return mock_backend_->getStub();
    }

private:
    MockGrpcBackend* mock_backend_;
};

} // namespace supacrypt::test
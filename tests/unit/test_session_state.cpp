// tests/unit/test_session_state.cpp

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <string>

// Mock PKCS#11 definitions
typedef unsigned long CK_ULONG;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_STATE;
typedef void* CK_VOID_PTR;
typedef unsigned char* CK_BYTE_PTR;
typedef CK_BYTE_PTR CK_UTF8CHAR_PTR;

#define CKF_SERIAL_SESSION    0x00000004UL
#define CKF_RW_SESSION        0x00000002UL
#define CKS_RO_PUBLIC_SESSION 0UL
#define CKS_RO_USER_FUNCTIONS 1UL
#define CKS_RW_PUBLIC_SESSION 2UL
#define CKS_RW_USER_FUNCTIONS 3UL

// Mock mechanism structure
struct CK_MECHANISM {
    CK_ULONG mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
};

#define CKM_RSA_PKCS          0x00000001UL
#define CKM_SHA256_RSA_PKCS   0x00000040UL
#define CKM_ECDSA             0x00001041UL

namespace supacrypt::pkcs11 {

enum class OperationType {
    None,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Digest
};

struct OperationContext {
    OperationType type = OperationType::None;
    CK_MECHANISM mechanism{0, nullptr, 0};
    std::string keyId;
    std::vector<uint8_t> accumulatedData;
    bool isActive = false;
    
    void reset() {
        type = OperationType::None;
        mechanism = {0, nullptr, 0};
        keyId.clear();
        accumulatedData.clear();
        isActive = false;
    }
};

class SessionState {
public:
    SessionState(CK_SESSION_HANDLE handle, CK_FLAGS flags)
        : handle_(handle), flags_(flags), state_(CKS_RO_PUBLIC_SESSION) {
        updateState();
    }
    
    ~SessionState() = default;
    
    // Basic getters
    CK_SESSION_HANDLE getHandle() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return handle_;
    }
    
    CK_FLAGS getFlags() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return flags_;
    }
    
    CK_STATE getState() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return state_;
    }
    
    bool isReadWrite() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return (flags_ & CKF_RW_SESSION) != 0;
    }
    
    // Operation management
    CK_RV beginOperation(OperationType type, const CK_MECHANISM* mechanism, const std::string& keyId) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        
        if (operation_context_.isActive) {
            return CKR_OPERATION_ACTIVE;
        }
        
        operation_context_.type = type;
        if (mechanism) {
            operation_context_.mechanism = *mechanism;
        }
        operation_context_.keyId = keyId;
        operation_context_.accumulatedData.clear();
        operation_context_.isActive = true;
        
        return CKR_OK;
    }
    
    CK_RV updateOperation(const uint8_t* data, size_t dataLen) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        
        if (!operation_context_.isActive) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        
        if (data && dataLen > 0) {
            operation_context_.accumulatedData.insert(
                operation_context_.accumulatedData.end(),
                data, data + dataLen);
        }
        
        return CKR_OK;
    }
    
    CK_RV finalizeOperation() {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        
        if (!operation_context_.isActive) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        
        operation_context_.reset();
        return CKR_OK;
    }
    
    void cancelOperation() {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        operation_context_.reset();
    }
    
    const OperationContext& getOperationContext() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return operation_context_;
    }
    
    bool hasActiveOperation() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return operation_context_.isActive;
    }
    
    // State management
    CK_RV login(CK_UTF8CHAR_PTR pin, CK_ULONG pinLen) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        
        if (is_logged_in_) {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        
        // Mock PIN validation (in real implementation, this would be more complex)
        if (!pin || pinLen == 0) {
            return CKR_PIN_INCORRECT;
        }
        
        is_logged_in_ = true;
        updateState();
        return CKR_OK;
    }
    
    CK_RV logout() {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        
        if (!is_logged_in_) {
            return CKR_USER_NOT_LOGGED_IN;
        }
        
        is_logged_in_ = false;
        // Cancel any active operations on logout
        operation_context_.reset();
        updateState();
        return CKR_OK;
    }
    
    bool isLoggedIn() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return is_logged_in_;
    }
    
    // Thread safety validation
    void performConcurrentReads(int iterations) const {
        for (int i = 0; i < iterations; ++i) {
            auto handle = getHandle();
            auto flags = getFlags();
            auto state = getState();
            auto loggedIn = isLoggedIn();
            auto context = getOperationContext();
            
            // Use the values to prevent optimization
            (void)handle; (void)flags; (void)state; (void)loggedIn; (void)context;
            
            if (i % 100 == 0) {
                std::this_thread::yield();
            }
        }
    }

private:
    void updateState() {
        // Update session state based on flags and login status
        if (is_logged_in_) {
            state_ = isReadWrite() ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
        } else {
            state_ = isReadWrite() ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
        }
    }
    
    mutable std::shared_mutex mutex_;
    CK_SESSION_HANDLE handle_;
    CK_FLAGS flags_;
    CK_STATE state_;
    bool is_logged_in_ = false;
    OperationContext operation_context_;
};

} // namespace supacrypt::pkcs11

using namespace supacrypt::pkcs11;

// Mock return codes
#define CKR_OK                          0x00000000UL
#define CKR_OPERATION_ACTIVE            0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED   0x00000091UL
#define CKR_USER_ALREADY_LOGGED_IN      0x00000100UL
#define CKR_USER_NOT_LOGGED_IN          0x00000101UL
#define CKR_PIN_INCORRECT               0x000000A0UL

class SessionStateTest : public ::testing::Test {
protected:
    void SetUp() override {
        session_ = std::make_unique<SessionState>(1, CKF_SERIAL_SESSION);
        rw_session_ = std::make_unique<SessionState>(2, CKF_SERIAL_SESSION | CKF_RW_SESSION);
    }
    
    void TearDown() override {
        session_.reset();
        rw_session_.reset();
    }
    
    std::unique_ptr<SessionState> session_;
    std::unique_ptr<SessionState> rw_session_;
};

TEST_F(SessionStateTest, BasicProperties) {
    EXPECT_EQ(1, session_->getHandle());
    EXPECT_EQ(CKF_SERIAL_SESSION, session_->getFlags());
    EXPECT_EQ(CKS_RO_PUBLIC_SESSION, session_->getState());
    EXPECT_FALSE(session_->isReadWrite());
    EXPECT_FALSE(session_->isLoggedIn());
    
    EXPECT_EQ(2, rw_session_->getHandle());
    EXPECT_EQ(CKF_SERIAL_SESSION | CKF_RW_SESSION, rw_session_->getFlags());
    EXPECT_EQ(CKS_RW_PUBLIC_SESSION, rw_session_->getState());
    EXPECT_TRUE(rw_session_->isReadWrite());
    EXPECT_FALSE(rw_session_->isLoggedIn());
}

TEST_F(SessionStateTest, OperationLifecycle) {
    EXPECT_FALSE(session_->hasActiveOperation());
    
    CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(CKR_OK, session_->beginOperation(
        OperationType::Sign, &mech, "test-key-id"));
    
    EXPECT_TRUE(session_->hasActiveOperation());
    
    // Cannot start another operation
    EXPECT_EQ(CKR_OPERATION_ACTIVE, session_->beginOperation(
        OperationType::Verify, &mech, "another-key"));
    
    // Update operation
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    EXPECT_EQ(CKR_OK, session_->updateOperation(data.data(), data.size()));
    
    const auto& context = session_->getOperationContext();
    EXPECT_EQ(OperationType::Sign, context.type);
    EXPECT_EQ("test-key-id", context.keyId);
    EXPECT_EQ(data, context.accumulatedData);
    EXPECT_EQ(CKM_RSA_PKCS, context.mechanism.mechanism);
    EXPECT_TRUE(context.isActive);
    
    // Finalize operation
    EXPECT_EQ(CKR_OK, session_->finalizeOperation());
    EXPECT_FALSE(session_->hasActiveOperation());
    EXPECT_EQ(OperationType::None, session_->getOperationContext().type);
}

TEST_F(SessionStateTest, OperationCancel) {
    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(CKR_OK, session_->beginOperation(
        OperationType::Sign, &mech, "test-key"));
    
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_EQ(CKR_OK, session_->updateOperation(data.data(), data.size()));
    
    EXPECT_TRUE(session_->hasActiveOperation());
    EXPECT_FALSE(session_->getOperationContext().accumulatedData.empty());
    
    session_->cancelOperation();
    
    EXPECT_FALSE(session_->hasActiveOperation());
    EXPECT_EQ(OperationType::None, session_->getOperationContext().type);
    EXPECT_TRUE(session_->getOperationContext().accumulatedData.empty());
}

TEST_F(SessionStateTest, MultipartOperations) {
    CK_MECHANISM mech = {CKM_ECDSA, nullptr, 0};
    EXPECT_EQ(CKR_OK, session_->beginOperation(
        OperationType::Sign, &mech, "ec-key-256"));
    
    // Add data in multiple parts
    std::vector<uint8_t> part1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> part2 = {0x04, 0x05};
    std::vector<uint8_t> part3 = {0x06, 0x07, 0x08, 0x09};
    
    EXPECT_EQ(CKR_OK, session_->updateOperation(part1.data(), part1.size()));
    EXPECT_EQ(CKR_OK, session_->updateOperation(part2.data(), part2.size()));
    EXPECT_EQ(CKR_OK, session_->updateOperation(part3.data(), part3.size()));
    
    const auto& context = session_->getOperationContext();
    EXPECT_EQ(9, context.accumulatedData.size());
    
    std::vector<uint8_t> expected = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    EXPECT_EQ(expected, context.accumulatedData);
}

TEST_F(SessionStateTest, OperationWithoutInitialization) {
    // Update without begin should fail
    uint8_t data[] = {1, 2, 3};
    EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED,
              session_->updateOperation(data, sizeof(data)));
    
    // Finalize without begin should fail
    EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED,
              session_->finalizeOperation());
}

TEST_F(SessionStateTest, LoginLogout) {
    EXPECT_FALSE(session_->isLoggedIn());
    EXPECT_EQ(CKS_RO_PUBLIC_SESSION, session_->getState());
    
    // Valid login
    CK_UTF8CHAR_PTR pin = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>("1234"));
    EXPECT_EQ(CKR_OK, session_->login(pin, 4));
    
    EXPECT_TRUE(session_->isLoggedIn());
    EXPECT_EQ(CKS_RO_USER_FUNCTIONS, session_->getState());
    
    // Double login should fail
    EXPECT_EQ(CKR_USER_ALREADY_LOGGED_IN, session_->login(pin, 4));
    
    // Logout
    EXPECT_EQ(CKR_OK, session_->logout());
    EXPECT_FALSE(session_->isLoggedIn());
    EXPECT_EQ(CKS_RO_PUBLIC_SESSION, session_->getState());
    
    // Double logout should fail
    EXPECT_EQ(CKR_USER_NOT_LOGGED_IN, session_->logout());
}

TEST_F(SessionStateTest, ReadWriteSessionStates) {
    // Read-write session states
    EXPECT_EQ(CKS_RW_PUBLIC_SESSION, rw_session_->getState());
    
    CK_UTF8CHAR_PTR pin = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>("1234"));
    EXPECT_EQ(CKR_OK, rw_session_->login(pin, 4));
    EXPECT_EQ(CKS_RW_USER_FUNCTIONS, rw_session_->getState());
    
    EXPECT_EQ(CKR_OK, rw_session_->logout());
    EXPECT_EQ(CKS_RW_PUBLIC_SESSION, rw_session_->getState());
}

TEST_F(SessionStateTest, InvalidPinLogin) {
    // Null pin
    EXPECT_EQ(CKR_PIN_INCORRECT, session_->login(nullptr, 4));
    
    // Zero length pin
    CK_UTF8CHAR_PTR pin = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>("1234"));
    EXPECT_EQ(CKR_PIN_INCORRECT, session_->login(pin, 0));
    
    EXPECT_FALSE(session_->isLoggedIn());
}

TEST_F(SessionStateTest, LogoutCancelsOperations) {
    CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
    
    // Login and start operation
    CK_UTF8CHAR_PTR pin = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>("1234"));
    EXPECT_EQ(CKR_OK, session_->login(pin, 4));
    EXPECT_EQ(CKR_OK, session_->beginOperation(OperationType::Sign, &mech, "key"));
    
    uint8_t data[] = {1, 2, 3, 4};
    EXPECT_EQ(CKR_OK, session_->updateOperation(data, sizeof(data)));
    EXPECT_TRUE(session_->hasActiveOperation());
    
    // Logout should cancel operation
    EXPECT_EQ(CKR_OK, session_->logout());
    EXPECT_FALSE(session_->hasActiveOperation());
    EXPECT_EQ(OperationType::None, session_->getOperationContext().type);
}

TEST_F(SessionStateTest, ThreadSafety) {
    const int numThreads = 100;
    const int operationsPerThread = 1000;
    std::vector<std::thread> threads;
    std::atomic<int> errors{0};
    
    // Concurrent reads should be safe
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&]() {
            try {
                session_->performConcurrentReads(operationsPerThread);
            } catch (...) {
                errors++;
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(0, errors) << "Concurrent reads should not cause errors";
}

TEST_F(SessionStateTest, ConcurrentOperationManagement) {
    const int numThreads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successfulBegins{0};
    std::atomic<int> operationActiveErrors{0};
    std::atomic<bool> shouldStop{false};
    
    // One thread that starts/stops operations
    threads.emplace_back([&]() {
        CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
        for (int i = 0; i < 100 && !shouldStop; ++i) {
            if (session_->beginOperation(OperationType::Sign, &mech, "key") == CKR_OK) {
                successfulBegins++;
                
                // Keep operation active for a short time
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                
                session_->cancelOperation();
            }
            
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
    });
    
    // Multiple threads trying to start operations (should mostly fail)
    for (int i = 0; i < numThreads - 1; ++i) {
        threads.emplace_back([&]() {
            CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
            for (int j = 0; j < 200 && !shouldStop; ++j) {
                auto rv = session_->beginOperation(OperationType::Verify, &mech, "key2");
                if (rv == CKR_OPERATION_ACTIVE) {
                    operationActiveErrors++;
                } else if (rv == CKR_OK) {
                    session_->cancelOperation();
                }
                
                std::this_thread::yield();
            }
        });
    }
    
    // Let threads run for a short time
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    shouldStop = true;
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_GT(successfulBegins, 0) << "At least some operations should succeed";
    EXPECT_GT(operationActiveErrors, 0) << "Should get operation active errors from concurrent access";
}

TEST_F(SessionStateTest, StressTestStateChanges) {
    const int numIterations = 1000;
    std::vector<std::thread> threads;
    std::atomic<int> errors{0};
    
    // Thread doing login/logout cycles
    threads.emplace_back([&]() {
        CK_UTF8CHAR_PTR pin = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>("1234"));
        for (int i = 0; i < numIterations / 10; ++i) {
            try {
                if (session_->login(pin, 4) == CKR_OK) {
                    std::this_thread::sleep_for(std::chrono::microseconds(10));
                    session_->logout();
                }
            } catch (...) {
                errors++;
            }
        }
    });
    
    // Threads reading state
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < numIterations; ++j) {
                try {
                    auto state = session_->getState();
                    auto loggedIn = session_->isLoggedIn();
                    auto flags = session_->getFlags();
                    
                    // Validate consistency
                    if (loggedIn && state != CKS_RO_USER_FUNCTIONS) {
                        errors++;
                    }
                    if (!loggedIn && state != CKS_RO_PUBLIC_SESSION) {
                        errors++;
                    }
                    
                    (void)flags; // Suppress unused variable warning
                } catch (...) {
                    errors++;
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(0, errors) << "No errors should occur during stress test";
}
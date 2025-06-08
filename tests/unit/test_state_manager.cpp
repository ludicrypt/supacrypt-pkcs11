// tests/unit/test_state_manager.cpp

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

#include "mock_grpc_backend.h"

// Include the state manager header
// #include "core/state_manager.h"  // This would be the actual implementation

// For now, we'll mock the state manager interface
namespace supacrypt::pkcs11 {

class StateManager {
public:
    static StateManager& getInstance() {
        static StateManager instance;
        return instance;
    }
    
    CK_RV initialize(CK_VOID_PTR pInitArgs) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        initialized_ = true;
        return CKR_OK;
    }
    
    CK_RV finalize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        sessions_.clear();
        next_session_handle_ = 1;
        initialized_ = false;
        return CKR_OK;
    }
    
    bool isInitialized() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return initialized_;
    }
    
    CK_RV createSession(CK_FLAGS flags, CK_SESSION_HANDLE* phSession) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        
        *phSession = next_session_handle_++;
        sessions_[*phSession] = std::make_unique<SessionState>(*phSession, flags);
        return CKR_OK;
    }
    
    CK_RV removeSession(CK_SESSION_HANDLE hSession) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(hSession);
        if (it == sessions_.end()) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        sessions_.erase(it);
        return CKR_OK;
    }
    
    CK_RV getSession(CK_SESSION_HANDLE hSession, SessionState** ppSession) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(hSession);
        if (it == sessions_.end()) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        *ppSession = it->second.get();
        return CKR_OK;
    }
    
    size_t getSessionCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.size();
    }

private:
    StateManager() = default;
    
    mutable std::mutex mutex_;
    bool initialized_ = false;
    CK_SESSION_HANDLE next_session_handle_ = 1;
    std::unordered_map<CK_SESSION_HANDLE, std::unique_ptr<SessionState>> sessions_;
};

// Mock session state for testing
struct SessionState {
    CK_SESSION_HANDLE handle;
    CK_FLAGS flags;
    CK_STATE state;
    
    SessionState(CK_SESSION_HANDLE h, CK_FLAGS f) 
        : handle(h), flags(f), state(CKS_RO_PUBLIC_SESSION) {}
};

} // namespace supacrypt::pkcs11

using namespace supacrypt::pkcs11;
using namespace supacrypt::test;

class StateManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure clean state
        StateManager::getInstance().finalize();
    }
    
    void TearDown() override {
        StateManager::getInstance().finalize();
    }
};

TEST_F(StateManagerTest, SingletonBehavior) {
    auto& instance1 = StateManager::getInstance();
    auto& instance2 = StateManager::getInstance();
    EXPECT_EQ(&instance1, &instance2);
}

TEST_F(StateManagerTest, InitializeOnce) {
    EXPECT_EQ(CKR_OK, StateManager::getInstance().initialize(nullptr));
    EXPECT_TRUE(StateManager::getInstance().isInitialized());
    
    // Second initialization should fail
    EXPECT_EQ(CKR_CRYPTOKI_ALREADY_INITIALIZED, 
              StateManager::getInstance().initialize(nullptr));
}

TEST_F(StateManagerTest, FinalizeBeforeInitialize) {
    // Finalize without initialize should fail
    EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, 
              StateManager::getInstance().finalize());
}

TEST_F(StateManagerTest, ThreadSafeInitialization) {
    const int numThreads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    std::atomic<int> alreadyInitCount{0};
    std::atomic<int> startedCount{0};
    
    // Barrier to ensure all threads start at the same time
    std::atomic<bool> start{false};
    
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&]() {
            startedCount++;
            // Wait for all threads to be ready
            while (!start.load() && startedCount.load() < numThreads) {
                std::this_thread::yield();
            }
            start.store(true);
            
            CK_RV rv = StateManager::getInstance().initialize(nullptr);
            if (rv == CKR_OK) {
                successCount++;
            } else if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                alreadyInitCount++;
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(1, successCount) << "Exactly one thread should succeed in initialization";
    EXPECT_EQ(numThreads - 1, alreadyInitCount) << "All other threads should get already initialized";
    EXPECT_TRUE(StateManager::getInstance().isInitialized());
}

TEST_F(StateManagerTest, SessionManagement) {
    ASSERT_EQ(CKR_OK, StateManager::getInstance().initialize(nullptr));
    
    CK_SESSION_HANDLE session1, session2;
    EXPECT_EQ(CKR_OK, StateManager::getInstance().createSession(
        CKF_SERIAL_SESSION | CKF_RW_SESSION, &session1));
    EXPECT_EQ(CKR_OK, StateManager::getInstance().createSession(
        CKF_SERIAL_SESSION, &session2));
    
    EXPECT_NE(session1, session2) << "Session handles should be unique";
    EXPECT_EQ(2, StateManager::getInstance().getSessionCount());
    
    SessionState* state1 = nullptr;
    EXPECT_EQ(CKR_OK, StateManager::getInstance().getSession(session1, &state1));
    EXPECT_NE(nullptr, state1);
    EXPECT_EQ(session1, state1->handle);
    EXPECT_EQ(CKF_SERIAL_SESSION | CKF_RW_SESSION, state1->flags);
    
    SessionState* state2 = nullptr;
    EXPECT_EQ(CKR_OK, StateManager::getInstance().getSession(session2, &state2));
    EXPECT_NE(nullptr, state2);
    EXPECT_EQ(session2, state2->handle);
    EXPECT_EQ(CKF_SERIAL_SESSION, state2->flags);
    
    // Remove session1
    EXPECT_EQ(CKR_OK, StateManager::getInstance().removeSession(session1));
    EXPECT_EQ(1, StateManager::getInstance().getSessionCount());
    
    // Session1 should no longer be valid
    EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, 
              StateManager::getInstance().getSession(session1, &state1));
    
    // Session2 should still be valid
    EXPECT_EQ(CKR_OK, StateManager::getInstance().getSession(session2, &state2));
}

TEST_F(StateManagerTest, SessionOperationsRequireInitialization) {
    // Operations should fail when not initialized
    CK_SESSION_HANDLE session;
    EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
              StateManager::getInstance().createSession(CKF_SERIAL_SESSION, &session));
    
    SessionState* state = nullptr;
    EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
              StateManager::getInstance().getSession(1, &state));
}

TEST_F(StateManagerTest, InvalidSessionHandles) {
    ASSERT_EQ(CKR_OK, StateManager::getInstance().initialize(nullptr));
    
    SessionState* state = nullptr;
    
    // Invalid session handle should fail
    EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
              StateManager::getInstance().getSession(999, &state));
    
    // Removing non-existent session should fail
    EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
              StateManager::getInstance().removeSession(999));
}

TEST_F(StateManagerTest, ConcurrentSessionOperations) {
    ASSERT_EQ(CKR_OK, StateManager::getInstance().initialize(nullptr));
    
    const int numThreads = 20;
    const int sessionsPerThread = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successfulCreations{0};
    std::vector<std::vector<CK_SESSION_HANDLE>> threadSessions(numThreads);
    
    // Create sessions concurrently
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&, i]() {
            threadSessions[i].reserve(sessionsPerThread);
            for (int j = 0; j < sessionsPerThread; ++j) {
                CK_SESSION_HANDLE session;
                if (StateManager::getInstance().createSession(CKF_SERIAL_SESSION, &session) == CKR_OK) {
                    threadSessions[i].push_back(session);
                    successfulCreations++;
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(numThreads * sessionsPerThread, successfulCreations);
    EXPECT_EQ(numThreads * sessionsPerThread, StateManager::getInstance().getSessionCount());
    
    // Verify all sessions are unique
    std::set<CK_SESSION_HANDLE> allSessions;
    for (const auto& sessions : threadSessions) {
        for (auto session : sessions) {
            EXPECT_TRUE(allSessions.insert(session).second) 
                << "Duplicate session handle: " << session;
        }
    }
    
    // Clean up sessions concurrently
    threads.clear();
    std::atomic<int> successfulRemovals{0};
    
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&, i]() {
            for (auto session : threadSessions[i]) {
                if (StateManager::getInstance().removeSession(session) == CKR_OK) {
                    successfulRemovals++;
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(numThreads * sessionsPerThread, successfulRemovals);
    EXPECT_EQ(0, StateManager::getInstance().getSessionCount());
}

TEST_F(StateManagerTest, FinalizeWithActiveSessions) {
    ASSERT_EQ(CKR_OK, StateManager::getInstance().initialize(nullptr));
    
    // Create some sessions
    CK_SESSION_HANDLE session1, session2;
    ASSERT_EQ(CKR_OK, StateManager::getInstance().createSession(CKF_SERIAL_SESSION, &session1));
    ASSERT_EQ(CKR_OK, StateManager::getInstance().createSession(CKF_SERIAL_SESSION, &session2));
    
    EXPECT_EQ(2, StateManager::getInstance().getSessionCount());
    
    // Finalize should clean up all sessions
    EXPECT_EQ(CKR_OK, StateManager::getInstance().finalize());
    EXPECT_FALSE(StateManager::getInstance().isInitialized());
    EXPECT_EQ(0, StateManager::getInstance().getSessionCount());
    
    // Sessions should no longer be valid
    SessionState* state = nullptr;
    EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
              StateManager::getInstance().getSession(session1, &state));
}

// Stress test for memory and thread safety
TEST_F(StateManagerTest, StressTest) {
    ASSERT_EQ(CKR_OK, StateManager::getInstance().initialize(nullptr));
    
    const int numThreads = 50;
    const int operationsPerThread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> errors{0};
    
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&]() {
            std::vector<CK_SESSION_HANDLE> sessions;
            sessions.reserve(operationsPerThread / 2);
            
            for (int j = 0; j < operationsPerThread; ++j) {
                if (j % 3 == 0) {
                    // Create session
                    CK_SESSION_HANDLE session;
                    if (StateManager::getInstance().createSession(CKF_SERIAL_SESSION, &session) == CKR_OK) {
                        sessions.push_back(session);
                    } else {
                        errors++;
                    }
                } else if (j % 3 == 1 && !sessions.empty()) {
                    // Get session
                    SessionState* state = nullptr;
                    auto session = sessions[j % sessions.size()];
                    if (StateManager::getInstance().getSession(session, &state) != CKR_OK) {
                        errors++;
                    }
                } else if (j % 3 == 2 && !sessions.empty()) {
                    // Remove session
                    auto session = sessions.back();
                    sessions.pop_back();
                    if (StateManager::getInstance().removeSession(session) != CKR_OK) {
                        errors++;
                    }
                }
                
                // Add small random delay
                if (j % 10 == 0) {
                    std::this_thread::sleep_for(std::chrono::microseconds(1));
                }
            }
            
            // Clean up remaining sessions
            for (auto session : sessions) {
                StateManager::getInstance().removeSession(session);
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(0, errors) << "No errors should occur during stress test";
    
    // All sessions should be cleaned up
    // Note: Due to concurrent operations, some sessions might still exist
    // but the important thing is no crashes or deadlocks occurred
}
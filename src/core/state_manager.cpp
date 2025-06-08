/**
 * @file state_manager.cpp
 * @brief Implementation of the global state manager
 */

#include "state_manager.h"
#include <algorithm>
#include <cstring>

namespace supacrypt {
namespace pkcs11 {

StateManager* StateManager::instance_ = nullptr;
std::once_flag StateManager::initFlag_;

StateManager& StateManager::getInstance() {
    std::call_once(initFlag_, []() {
        instance_ = new StateManager();
    });
    return *instance_;
}

CK_RV StateManager::initialize(const supacrypt_config_t* config) {
    if (initialized_.load()) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    if (config) {
        config_ = *config;
    } else {
        // Set default configuration
        std::memset(&config_, 0, sizeof(config_));
        config_.backend_endpoint = "localhost:5000";
        config_.connection_timeout_ms = 30000;
        config_.request_timeout_ms = 10000;
    }

    // Initialize gRPC connection pool
    CK_RV rv = connectionPool_.initialize(&config_);
    if (rv != CKR_OK) {
        return rv;
    }

    initialized_.store(true);
    return CKR_OK;
}

CK_RV StateManager::finalize() {
    if (!initialized_.load()) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // Close all sessions
    closeAllSessions();

    // Shutdown connection pool
    connectionPool_.shutdown();

    // Clear object cache
    objectCache_.clear();

    initialized_.store(false);
    return CKR_OK;
}

CK_RV StateManager::createSession(CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession) {
    if (!initialized_.load()) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!phSession) {
        return CKR_ARGUMENTS_BAD;
    }

    CK_SESSION_HANDLE handle = nextSessionHandle_.fetch_add(1);
    auto session = std::make_unique<SessionState>(handle, flags);

    std::unique_lock<std::shared_mutex> lock(sessionMutex_);
    sessions_[handle] = std::move(session);
    lock.unlock();

    *phSession = handle;
    return CKR_OK;
}

CK_RV StateManager::getSession(CK_SESSION_HANDLE hSession, SessionState** ppSession) {
    if (!initialized_.load()) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!ppSession) {
        return CKR_ARGUMENTS_BAD;
    }

    std::shared_lock<std::shared_mutex> lock(sessionMutex_);
    auto it = sessions_.find(hSession);
    if (it == sessions_.end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    *ppSession = it->second.get();
    return CKR_OK;
}

CK_RV StateManager::removeSession(CK_SESSION_HANDLE hSession) {
    if (!initialized_.load()) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    std::unique_lock<std::shared_mutex> lock(sessionMutex_);
    auto it = sessions_.find(hSession);
    if (it == sessions_.end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    // Cancel any active operations
    it->second->cancelOperation();

    sessions_.erase(it);
    return CKR_OK;
}

void StateManager::closeAllSessions() {
    std::unique_lock<std::shared_mutex> lock(sessionMutex_);
    
    // Cancel operations in all sessions
    for (auto& [handle, session] : sessions_) {
        session->cancelOperation();
    }
    
    sessions_.clear();
    nextSessionHandle_.store(1);
}

} // namespace pkcs11
} // namespace supacrypt
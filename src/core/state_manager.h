/**
 * @file state_manager.h
 * @brief Global state management for Supacrypt PKCS#11 provider
 */

#ifndef SUPACRYPT_PKCS11_STATE_MANAGER_H
#define SUPACRYPT_PKCS11_STATE_MANAGER_H

#include "supacrypt/pkcs11/pkcs11.h"
#include "supacrypt/pkcs11/supacrypt_pkcs11.h"
#include "session_state.h"
#include "object_cache.h"
#include "../grpc/grpc_connection_pool.h"
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <atomic>
#include <mutex>

namespace supacrypt {
namespace pkcs11 {

/**
 * @brief Thread-safe global state manager for PKCS#11 provider
 * 
 * This singleton manages all global state including sessions, objects,
 * and gRPC connections. It ensures thread safety across all PKCS#11 operations.
 */
class StateManager {
public:
    /**
     * @brief Get the singleton instance
     * @return Reference to the StateManager instance
     */
    static StateManager& getInstance();

    /**
     * @brief Initialize the state manager
     * @param config Configuration for backend connection
     * @return CK_RV Return code
     */
    CK_RV initialize(const supacrypt_config_t* config);

    /**
     * @brief Finalize and cleanup the state manager
     * @return CK_RV Return code
     */
    CK_RV finalize();

    /**
     * @brief Check if the provider is initialized
     * @return true if initialized
     */
    bool isInitialized() const { return initialized_.load(); }

    /**
     * @brief Create a new session
     * @param flags Session flags
     * @param phSession Pointer to receive session handle
     * @return CK_RV Return code
     */
    CK_RV createSession(CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession);

    /**
     * @brief Get a session by handle
     * @param hSession Session handle
     * @param ppSession Pointer to receive session pointer
     * @return CK_RV Return code
     */
    CK_RV getSession(CK_SESSION_HANDLE hSession, SessionState** ppSession);

    /**
     * @brief Remove a session
     * @param hSession Session handle
     * @return CK_RV Return code
     */
    CK_RV removeSession(CK_SESSION_HANDLE hSession);

    /**
     * @brief Close all sessions
     */
    void closeAllSessions();

    /**
     * @brief Get the object cache
     * @return Reference to object cache
     */
    ObjectCache& getObjectCache() { return objectCache_; }

    /**
     * @brief Get the gRPC connection pool
     * @return Reference to connection pool
     */
    GrpcConnectionPool& getConnectionPool() { return connectionPool_; }

    /**
     * @brief Get current configuration
     * @return Current configuration
     */
    const supacrypt_config_t& getConfig() const { return config_; }

private:
    StateManager() = default;
    ~StateManager() = default;

    // Prevent copying
    StateManager(const StateManager&) = delete;
    StateManager& operator=(const StateManager&) = delete;

    static StateManager* instance_;
    static std::once_flag initFlag_;

    std::atomic<bool> initialized_{false};
    mutable std::shared_mutex sessionMutex_;
    std::unordered_map<CK_SESSION_HANDLE, std::unique_ptr<SessionState>> sessions_;
    std::atomic<CK_SESSION_HANDLE> nextSessionHandle_{1};

    ObjectCache objectCache_;
    GrpcConnectionPool connectionPool_;
    supacrypt_config_t config_{};
};

} // namespace pkcs11
} // namespace supacrypt

#endif // SUPACRYPT_PKCS11_STATE_MANAGER_H
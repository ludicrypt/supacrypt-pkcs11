/**
 * @file circuit_breaker.h
 * @brief Circuit breaker pattern implementation for gRPC resilience
 */

#ifndef SUPACRYPT_PKCS11_CIRCUIT_BREAKER_H
#define SUPACRYPT_PKCS11_CIRCUIT_BREAKER_H

#include <atomic>
#include <chrono>
#include <mutex>

namespace supacrypt {
namespace pkcs11 {

/**
 * @brief Circuit breaker implementation for preventing cascade failures
 * 
 * Implements the circuit breaker pattern to protect against cascade
 * failures when the backend service is unavailable or overloaded.
 */
class CircuitBreaker {
public:
    enum class State {
        CLOSED,    // Normal operation
        OPEN,      // Circuit is open, requests are rejected
        HALF_OPEN  // Testing if service has recovered
    };

    /**
     * @brief Constructor
     * @param failureThreshold Number of failures before opening circuit
     * @param timeoutSeconds Timeout before attempting to close circuit
     * @param successThreshold Number of successes needed to close circuit
     */
    explicit CircuitBreaker(
        int failureThreshold = 5,
        int timeoutSeconds = 60,
        int successThreshold = 3
    );

    /**
     * @brief Check if a request should be allowed
     * @return true if request should be allowed
     */
    bool allowRequest();

    /**
     * @brief Record a successful operation
     */
    void recordSuccess();

    /**
     * @brief Record a failed operation
     */
    void recordFailure();

    /**
     * @brief Get current circuit breaker state
     * @return Current state
     */
    State getState() const { return state_.load(); }

    /**
     * @brief Get current failure count
     * @return Failure count
     */
    int getFailureCount() const { return failureCount_.load(); }

    /**
     * @brief Get current success count (in half-open state)
     * @return Success count
     */
    int getSuccessCount() const { return successCount_.load(); }

    /**
     * @brief Reset circuit breaker to closed state
     */
    void reset();

private:
    std::atomic<State> state_{State::CLOSED};
    std::atomic<int> failureCount_{0};
    std::atomic<int> successCount_{0};
    std::chrono::steady_clock::time_point lastFailureTime_;
    mutable std::mutex stateMutex_;
    
    const int failureThreshold_;
    const std::chrono::seconds timeout_;
    const int successThreshold_;

    /**
     * @brief Transition from open to half-open if timeout has elapsed
     * @return true if transition occurred
     */
    bool tryTransitionToHalfOpen();

    /**
     * @brief Transition to open state
     */
    void transitionToOpen();

    /**
     * @brief Transition to closed state
     */
    void transitionToClosed();
};

} // namespace pkcs11
} // namespace supacrypt

#endif // SUPACRYPT_PKCS11_CIRCUIT_BREAKER_H
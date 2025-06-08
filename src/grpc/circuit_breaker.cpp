/**
 * @file circuit_breaker.cpp
 * @brief Circuit breaker pattern implementation
 */

#include "circuit_breaker.h"
#include "../utils/logging.h"

namespace supacrypt {
namespace pkcs11 {

CircuitBreaker::CircuitBreaker(
    int failureThreshold,
    int timeoutSeconds,
    int successThreshold
) : failureThreshold_(failureThreshold),
    timeout_(std::chrono::seconds(timeoutSeconds)),
    successThreshold_(successThreshold),
    lastFailureTime_(std::chrono::steady_clock::now()) {
}

bool CircuitBreaker::allowRequest() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    switch (state_.load()) {
        case State::CLOSED:
            return true;
            
        case State::OPEN:
            if (tryTransitionToHalfOpen()) {
                return true;
            }
            return false;
            
        case State::HALF_OPEN:
            return true;
    }
    
    return false;
}

void CircuitBreaker::recordSuccess() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    State currentState = state_.load();
    
    if (currentState == State::HALF_OPEN) {
        int currentSuccessCount = successCount_.fetch_add(1) + 1;
        logDebug("Circuit breaker: recorded success (" + 
                std::to_string(currentSuccessCount) + "/" + 
                std::to_string(successThreshold_) + ")");
        
        if (currentSuccessCount >= successThreshold_) {
            transitionToClosed();
        }
    } else if (currentState == State::CLOSED) {
        // Reset failure count on success in closed state
        failureCount_.store(0);
    }
}

void CircuitBreaker::recordFailure() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    int currentFailureCount = failureCount_.fetch_add(1) + 1;
    lastFailureTime_ = std::chrono::steady_clock::now();
    
    State currentState = state_.load();
    
    logDebug("Circuit breaker: recorded failure (" + 
            std::to_string(currentFailureCount) + "/" + 
            std::to_string(failureThreshold_) + ")");
    
    if (currentState == State::CLOSED && currentFailureCount >= failureThreshold_) {
        transitionToOpen();
    } else if (currentState == State::HALF_OPEN) {
        // Any failure in half-open immediately opens the circuit
        transitionToOpen();
    }
}

void CircuitBreaker::reset() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    state_.store(State::CLOSED);
    failureCount_.store(0);
    successCount_.store(0);
    
    logInfo("Circuit breaker: manually reset to CLOSED state");
}

bool CircuitBreaker::tryTransitionToHalfOpen() {
    // Should be called with lock held
    auto now = std::chrono::steady_clock::now();
    
    if (now - lastFailureTime_ > timeout_) {
        state_.store(State::HALF_OPEN);
        successCount_.store(0);
        
        logInfo("Circuit breaker: transitioned from OPEN to HALF_OPEN");
        return true;
    }
    
    return false;
}

void CircuitBreaker::transitionToOpen() {
    // Should be called with lock held
    state_.store(State::OPEN);
    
    logWarning("Circuit breaker: transitioned to OPEN state after " +
              std::to_string(failureCount_.load()) + " failures");
}

void CircuitBreaker::transitionToClosed() {
    // Should be called with lock held
    state_.store(State::CLOSED);
    failureCount_.store(0);
    successCount_.store(0);
    
    logInfo("Circuit breaker: transitioned to CLOSED state after " +
           std::to_string(successCount_.load()) + " successful requests");
}

} // namespace pkcs11
} // namespace supacrypt
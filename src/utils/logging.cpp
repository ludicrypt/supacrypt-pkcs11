/**
 * @file logging.cpp
 * @brief Logging utilities
 */

#include "logging.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <mutex>

namespace supacrypt {
namespace pkcs11 {

static LogLevel currentLogLevel = LogLevel::INFO;
static std::mutex logMutex;

void logMessage(LogLevel level, const std::string& levelStr, const std::string& message) {
    if (level > currentLogLevel) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(logMutex);
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::cerr << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") 
              << " [" << levelStr << "] "
              << "supacrypt-pkcs11: " << message << std::endl;
}

void logError(const std::string& message) {
    logMessage(LogLevel::ERROR, "ERROR", message);
}

void logWarning(const std::string& message) {
    logMessage(LogLevel::WARNING, "WARN", message);
}

void logInfo(const std::string& message) {
    logMessage(LogLevel::INFO, "INFO", message);
}

void logDebug(const std::string& message) {
    logMessage(LogLevel::DEBUG, "DEBUG", message);
}

void setLogLevel(LogLevel level) {
    currentLogLevel = level;
}

LogLevel getLogLevel() {
    return currentLogLevel;
}

} // namespace pkcs11
} // namespace supacrypt
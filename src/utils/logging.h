/**
 * @file logging.h
 * @brief Logging utilities for PKCS#11 provider
 */

#ifndef SUPACRYPT_PKCS11_LOGGING_H
#define SUPACRYPT_PKCS11_LOGGING_H

#include <string>

namespace supacrypt {
namespace pkcs11 {

/**
 * @brief Log levels
 */
enum class LogLevel {
    ERROR = 0,
    WARNING = 1,
    INFO = 2,
    DEBUG = 3
};

/**
 * @brief Log an error message
 * @param message Error message
 */
void logError(const std::string& message);

/**
 * @brief Log a warning message
 * @param message Warning message
 */
void logWarning(const std::string& message);

/**
 * @brief Log an info message
 * @param message Info message
 */
void logInfo(const std::string& message);

/**
 * @brief Log a debug message
 * @param message Debug message
 */
void logDebug(const std::string& message);

/**
 * @brief Set logging level
 * @param level Minimum log level to output
 */
void setLogLevel(LogLevel level);

/**
 * @brief Get current logging level
 * @return Current log level
 */
LogLevel getLogLevel();

} // namespace pkcs11
} // namespace supacrypt

#endif // SUPACRYPT_PKCS11_LOGGING_H
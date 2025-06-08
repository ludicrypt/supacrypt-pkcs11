# Build examples
cmake_minimum_required(VERSION 3.10)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SUPACRYPT_PKCS11 REQUIRED supacrypt-pkcs11)

# Basic usage example
add_executable(basic_usage basic_usage.cpp)
target_link_libraries(basic_usage ${SUPACRYPT_PKCS11_LIBRARIES})
target_include_directories(basic_usage PUBLIC ${SUPACRYPT_PKCS11_INCLUDE_DIRS})

# Other examples...
add_executable(multi_threading multi_threading.cpp)
target_link_libraries(multi_threading ${SUPACRYPT_PKCS11_LIBRARIES} pthread)

add_executable(key_management key_management.cpp)
target_link_libraries(key_management ${SUPACRYPT_PKCS11_LIBRARIES})

add_executable(error_handling error_handling.cpp)
target_link_libraries(error_handling ${SUPACRYPT_PKCS11_LIBRARIES})
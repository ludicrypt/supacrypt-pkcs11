# cmake/Dependencies.cmake
include(FetchContent)

# Thread support
find_package(Threads REQUIRED)

# OpenSSL (for local crypto operations)
find_package(OpenSSL REQUIRED)

# Protobuf and gRPC (required for cryptographic operations)
option(ENABLE_GRPC "Enable gRPC support" ON)
if(ENABLE_GRPC)
    FetchContent_Declare(
        gRPC
        GIT_REPOSITORY https://github.com/grpc/grpc
        GIT_TAG        v1.65.0
    )
    set(gRPC_BUILD_TESTS OFF)
    set(gRPC_BUILD_EXAMPLES OFF)
    FetchContent_MakeAvailable(gRPC)
    
    # Find generated protobuf files
    find_package(Protobuf REQUIRED)
    
    # Link gRPC libraries to main target
    target_link_libraries(supacrypt-pkcs11 PRIVATE
        gRPC::grpc++
        gRPC::grpc++_reflection
        protobuf::libprotobuf
    )
endif()

# Google Test (for testing)
if(BUILD_TESTING)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.15.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# OpenTelemetry C++ SDK (optional for basic build)
option(ENABLE_OBSERVABILITY "Enable OpenTelemetry observability" OFF)
if(ENABLE_OBSERVABILITY)
    FetchContent_Declare(
        opentelemetry-cpp
        GIT_REPOSITORY https://github.com/open-telemetry/opentelemetry-cpp.git
        GIT_TAG        v1.16.0
    )
    set(BUILD_TESTING OFF)
    set(WITH_EXAMPLES OFF)
    set(WITH_OTLP_GRPC ON)
    set(WITH_OTLP_HTTP OFF)
    FetchContent_MakeAvailable(opentelemetry-cpp)
endif()

# Platform-specific dependencies
if(WIN32)
    # Windows-specific dependencies
elseif(APPLE)
    # macOS-specific dependencies
    find_library(SECURITY_FRAMEWORK Security)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
else()
    # Linux-specific dependencies
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBDL REQUIRED libdl)
endif()
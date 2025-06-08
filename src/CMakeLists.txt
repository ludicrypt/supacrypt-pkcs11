# src/CMakeLists.txt

# Source files
set(PKCS11_SOURCES
    core/pkcs11_init.cpp
    core/pkcs11_session.cpp
    core/pkcs11_object.cpp
    core/pkcs11_crypto.cpp
    core/pkcs11_key.cpp
    core/pkcs11_mechanism.cpp
    grpc/grpc_client.cpp
    grpc/grpc_connection_pool.cpp
    security/certificate_manager.cpp
    security/secure_memory.cpp
    observability/metrics.cpp
    observability/tracing.cpp
    utils/error_mapping.cpp
    utils/logging.cpp
)

# Add sources to target
target_sources(supacrypt-pkcs11 PRIVATE ${PKCS11_SOURCES})

# Include directories
target_include_directories(supacrypt-pkcs11
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link dependencies
target_link_libraries(supacrypt-pkcs11
    PUBLIC
        Threads::Threads
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Optional gRPC dependencies
if(ENABLE_GRPC)
    target_link_libraries(supacrypt-pkcs11 PRIVATE
        gRPC::grpc++
        protobuf::libprotobuf
    )
    target_compile_definitions(supacrypt-pkcs11 PRIVATE SUPACRYPT_ENABLE_GRPC)
endif()

# Optional OpenTelemetry dependencies
if(ENABLE_OBSERVABILITY)
    target_link_libraries(supacrypt-pkcs11 PRIVATE
        opentelemetry-cpp::api
        opentelemetry-cpp::sdk
        opentelemetry-cpp::otlp_grpc_exporter
    )
    target_compile_definitions(supacrypt-pkcs11 PRIVATE SUPACRYPT_ENABLE_OBSERVABILITY)
endif()

# Platform-specific linking
if(WIN32)
    target_link_libraries(supacrypt-pkcs11 PRIVATE ws2_32 crypt32)
elseif(APPLE)
    target_link_libraries(supacrypt-pkcs11 PRIVATE 
        ${SECURITY_FRAMEWORK} 
        ${COREFOUNDATION_FRAMEWORK}
    )
else()
    target_link_libraries(supacrypt-pkcs11 PRIVATE ${LIBDL_LIBRARIES})
endif()

# Generate export header
include(GenerateExportHeader)
generate_export_header(supacrypt-pkcs11
    BASE_NAME SUPACRYPT_PKCS11
    EXPORT_MACRO_NAME SUPACRYPT_PKCS11_EXPORT
    EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/supacrypt/pkcs11/export.h
)
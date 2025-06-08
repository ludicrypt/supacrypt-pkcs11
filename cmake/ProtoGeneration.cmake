# cmake/ProtoGeneration.cmake
# This module sets up automatic generation of C++ protobuf and gRPC stubs

set(PROTO_PATH "${CMAKE_SOURCE_DIR}/../supacrypt-common/proto")
set(PROTO_FILE "${PROTO_PATH}/supacrypt.proto")

# Find required tools
find_program(PROTOC protoc REQUIRED)
find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)

if(NOT PROTOC)
    message(FATAL_ERROR "protoc compiler not found. Please install protobuf.")
endif()

if(NOT GRPC_CPP_PLUGIN)
    message(FATAL_ERROR "grpc_cpp_plugin not found. Please install gRPC.")
endif()

# Output files
set(PROTO_SRCS "${CMAKE_CURRENT_BINARY_DIR}/supacrypt.pb.cc")
set(PROTO_HDRS "${CMAKE_CURRENT_BINARY_DIR}/supacrypt.pb.h")
set(GRPC_SRCS "${CMAKE_CURRENT_BINARY_DIR}/supacrypt.grpc.pb.cc")
set(GRPC_HDRS "${CMAKE_CURRENT_BINARY_DIR}/supacrypt.grpc.pb.h")

# Check if proto file exists
if(NOT EXISTS "${PROTO_FILE}")
    message(FATAL_ERROR "Proto file not found: ${PROTO_FILE}")
endif()

# Custom command to generate protobuf files
add_custom_command(
    OUTPUT ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
    COMMAND ${PROTOC}
    ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
         --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
         -I "${PROTO_PATH}"
         --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN}"
         "${PROTO_FILE}"
    DEPENDS "${PROTO_FILE}"
    COMMENT "Generating protobuf and gRPC C++ files from ${PROTO_FILE}"
    VERBATIM
)

# Create custom target for proto generation
add_custom_target(generate_protos 
    DEPENDS ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
)

# Add generated sources to the main library
target_sources(supacrypt-pkcs11 PRIVATE
    ${PROTO_SRCS}
    ${GRPC_SRCS}
)

# Include generated headers directory
target_include_directories(supacrypt-pkcs11 PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Make sure proto generation happens before building the main library
add_dependencies(supacrypt-pkcs11 generate_protos)

# Export variables for use in other CMake files
set(SUPACRYPT_PROTO_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)
set(SUPACRYPT_PROTO_HEADERS ${PROTO_HDRS} ${GRPC_HDRS} PARENT_SCOPE)
set(SUPACRYPT_PROTO_SOURCES ${PROTO_SRCS} ${GRPC_SRCS} PARENT_SCOPE)
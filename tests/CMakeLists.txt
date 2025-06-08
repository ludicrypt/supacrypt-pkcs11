# tests/CMakeLists.txt

# ================================
# Unit Tests
# ================================
add_executable(supacrypt-pkcs11-unit-tests)

set(UNIT_TEST_SOURCES
    unit/test_main.cpp
    unit/test_state_manager.cpp
    unit/test_session_state.cpp
    unit/test_pkcs11_init.cpp
    unit/test_session_management.cpp
    unit/test_crypto_operations.cpp
    unit/test_key_management.cpp
    unit/test_error_handling.cpp
    unit/test_object_management.cpp
    unit/test_mechanism_validation.cpp
    unit/mock_grpc_backend.cpp
)

target_sources(supacrypt-pkcs11-unit-tests PRIVATE ${UNIT_TEST_SOURCES})

target_link_libraries(supacrypt-pkcs11-unit-tests
    PRIVATE
        supacrypt::pkcs11
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
        Threads::Threads
)

target_compile_definitions(supacrypt-pkcs11-unit-tests
    PRIVATE 
        TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
        UNIT_TESTING=1
)

# ================================
# Integration Tests
# ================================
add_executable(supacrypt-pkcs11-integration-tests)

set(INTEGRATION_TEST_SOURCES
    integration/test_main.cpp
    integration/test_backend_fixture.cpp
    integration/test_grpc_connection.cpp
    integration/test_backend_operations.cpp
    integration/test_e2e_operations.cpp
    integration/test_multipart_operations.cpp
    integration/test_error_scenarios.cpp
)

target_sources(supacrypt-pkcs11-integration-tests PRIVATE ${INTEGRATION_TEST_SOURCES})

target_link_libraries(supacrypt-pkcs11-integration-tests
    PRIVATE
        supacrypt::pkcs11
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
        Threads::Threads
)

target_compile_definitions(supacrypt-pkcs11-integration-tests
    PRIVATE 
        TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
        INTEGRATION_TESTING=1
)

# ================================
# Conformance Tests
# ================================
option(BUILD_CONFORMANCE_TESTS "Build PKCS#11 conformance tests" OFF)

if(BUILD_CONFORMANCE_TESTS)
    # Google pkcs11test integration
    FetchContent_Declare(
        pkcs11test
        GIT_REPOSITORY https://github.com/google/pkcs11test.git
        GIT_TAG main
    )
    FetchContent_MakeAvailable(pkcs11test)
    
    add_executable(supacrypt-pkcs11-conformance-tests)
    
    set(CONFORMANCE_TEST_SOURCES
        conformance/test_main.cpp
        conformance/conformance_runner.cpp
        conformance/test_oasis_profiles.cpp
        conformance/test_mechanism_coverage.cpp
    )
    
    target_sources(supacrypt-pkcs11-conformance-tests PRIVATE ${CONFORMANCE_TEST_SOURCES})
    
    target_link_libraries(supacrypt-pkcs11-conformance-tests
        PRIVATE
            supacrypt::pkcs11
            pkcs11test
            GTest::gtest
            GTest::gtest_main
            ${CMAKE_DL_LIBS}
    )
endif()

# ================================
# Platform-Specific Tests
# ================================
add_executable(supacrypt-pkcs11-platform-tests)

set(PLATFORM_TEST_SOURCES
    platform/test_main.cpp
    platform/test_library_loading.cpp
    platform/test_symbol_exports.cpp
)

if(WIN32)
    list(APPEND PLATFORM_TEST_SOURCES platform/test_windows.cpp)
elseif(APPLE)
    list(APPEND PLATFORM_TEST_SOURCES platform/test_macos.cpp)
else()
    list(APPEND PLATFORM_TEST_SOURCES platform/test_linux.cpp)
endif()

target_sources(supacrypt-pkcs11-platform-tests PRIVATE ${PLATFORM_TEST_SOURCES})

target_link_libraries(supacrypt-pkcs11-platform-tests
    PRIVATE
        supacrypt::pkcs11
        GTest::gtest
        GTest::gtest_main
        ${CMAKE_DL_LIBS}
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(supacrypt-pkcs11-platform-tests PRIVATE
        kernel32 user32 advapi32 crypt32)
elseif(APPLE)
    target_link_libraries(supacrypt-pkcs11-platform-tests PRIVATE
        ${SECURITY_FRAMEWORK} ${COREFOUNDATION_FRAMEWORK})
endif()

# ================================
# Performance Benchmarks
# ================================
if(BUILD_BENCHMARKS)
    add_executable(supacrypt-pkcs11-benchmarks)
    
    set(BENCHMARK_SOURCES
        benchmarks/benchmark_main.cpp
        benchmarks/pkcs11_benchmarks.cpp
        benchmarks/crypto_benchmarks.cpp
        benchmarks/session_benchmarks.cpp
    )
    
    target_sources(supacrypt-pkcs11-benchmarks PRIVATE ${BENCHMARK_SOURCES})
    
    target_link_libraries(supacrypt-pkcs11-benchmarks
        PRIVATE
            supacrypt::pkcs11
            benchmark::benchmark
            benchmark::benchmark_main
            OpenSSL::SSL
            OpenSSL::Crypto
    )
    
    target_compile_definitions(supacrypt-pkcs11-benchmarks
        PRIVATE BENCHMARKING=1
    )
endif()

# ================================
# Security Tests
# ================================
option(BUILD_SECURITY_TESTS "Build security and fuzzing tests" OFF)

if(BUILD_SECURITY_TESTS)
    add_executable(supacrypt-pkcs11-security-tests)
    
    set(SECURITY_TEST_SOURCES
        security/test_main.cpp
        security/test_memory_safety.cpp
        security/test_input_validation.cpp
        security/test_thread_safety.cpp
    )
    
    target_sources(supacrypt-pkcs11-security-tests PRIVATE ${SECURITY_TEST_SOURCES})
    
    target_link_libraries(supacrypt-pkcs11-security-tests
        PRIVATE
            supacrypt::pkcs11
            GTest::gtest
            GTest::gtest_main
            Threads::Threads
    )
    
    # Enable sanitizers for security tests
    if(ENABLE_SANITIZERS)
        target_compile_options(supacrypt-pkcs11-security-tests PRIVATE
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(supacrypt-pkcs11-security-tests PRIVATE
            -fsanitize=address,undefined)
    endif()
    
    # Fuzzing targets
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_executable(fuzz-pkcs11
            fuzzing/fuzz_pkcs11.cpp
        )
        
        target_link_libraries(fuzz-pkcs11 PRIVATE supacrypt::pkcs11)
        
        target_compile_options(fuzz-pkcs11 PRIVATE
            -fsanitize=fuzzer,address -g -O1)
        target_link_options(fuzz-pkcs11 PRIVATE
            -fsanitize=fuzzer,address)
    endif()
endif()

# ================================
# Test Registration
# ================================
include(GoogleTest)

# Register unit tests
gtest_discover_tests(supacrypt-pkcs11-unit-tests
    TEST_PREFIX "unit."
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Register integration tests
gtest_discover_tests(supacrypt-pkcs11-integration-tests
    TEST_PREFIX "integration."
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Register platform tests
gtest_discover_tests(supacrypt-pkcs11-platform-tests
    TEST_PREFIX "platform."
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

if(BUILD_CONFORMANCE_TESTS)
    gtest_discover_tests(supacrypt-pkcs11-conformance-tests
        TEST_PREFIX "conformance."
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

if(BUILD_SECURITY_TESTS)
    gtest_discover_tests(supacrypt-pkcs11-security-tests
        TEST_PREFIX "security."
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

# ================================
# Code Coverage
# ================================
if(ENABLE_COVERAGE)
    # Create coverage configuration
    add_custom_target(coverage
        COMMAND ${CMAKE_COMMAND} -E remove_directory coverage-report
        COMMAND ${CMAKE_COMMAND} -E make_directory coverage-report
        COMMAND lcov --directory . --zerocounters
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R "unit\\.|integration\\."
        COMMAND lcov --directory . --capture --output-file coverage.info
        COMMAND lcov --remove coverage.info '/usr/*' '*/tests/*' '*/examples/*' '*/benchmarks/*' '*/_deps/*' --output-file coverage.filtered.info
        COMMAND genhtml coverage.filtered.info --output-directory coverage-report --title "Supacrypt PKCS#11 Coverage"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating coverage report"
    )
    
    # Coverage targets for individual test suites
    add_custom_target(coverage-unit
        COMMAND lcov --directory . --zerocounters
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R "unit\\."
        COMMAND lcov --directory . --capture --output-file coverage-unit.info
        COMMAND lcov --remove coverage-unit.info '/usr/*' '*/tests/*' --output-file coverage-unit.filtered.info
        COMMAND genhtml coverage-unit.filtered.info --output-directory coverage-unit-report
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating unit test coverage report"
    )
endif()
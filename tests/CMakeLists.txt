# tests/CMakeLists.txt

# Test executable
add_executable(supacrypt-pkcs11-tests)

# Test sources
set(TEST_SOURCES
    unit/test_main.cpp
    unit/test_pkcs11_init.cpp
    unit/test_session_management.cpp
    unit/test_crypto_operations.cpp
    unit/test_key_management.cpp
    unit/test_error_handling.cpp
    integration/test_grpc_connection.cpp
    integration/test_backend_operations.cpp
    compliance/test_pkcs11_compliance.cpp
)

target_sources(supacrypt-pkcs11-tests PRIVATE ${TEST_SOURCES})

# Link test dependencies
target_link_libraries(supacrypt-pkcs11-tests
    PRIVATE
        supacrypt::pkcs11
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
)

# Add test fixtures directory
target_compile_definitions(supacrypt-pkcs11-tests
    PRIVATE TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(supacrypt-pkcs11-tests)

# Coverage target
if(ENABLE_COVERAGE)
    include(CodeCoverage)
    setup_target_for_coverage_gcovr_html(
        NAME coverage
        EXECUTABLE supacrypt-pkcs11-tests
        EXCLUDE "*/tests/*" "*/examples/*" "*/benchmarks/*"
    )
endif()
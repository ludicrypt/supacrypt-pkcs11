# CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(supacrypt-pkcs11 
    VERSION 0.1.0
    DESCRIPTION "Supacrypt PKCS#11 Cryptographic Provider"
    LANGUAGES C CXX)

# CMake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Project options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTING "Build test suite" ON)
option(BUILD_EXAMPLES "Build example applications" ON)
option(BUILD_BENCHMARKS "Build performance benchmarks" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_SANITIZERS "Enable sanitizers" OFF)

# C++ and C standards
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Export compile commands for IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include modules
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(Dependencies)
include(CompilerOptions)
include(Platform)
include(ProtoGeneration)

# Create main library target
add_library(supacrypt-pkcs11)
add_library(supacrypt::pkcs11 ALIAS supacrypt-pkcs11)

# Set target properties
set_target_properties(supacrypt-pkcs11 PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Add subdirectories
add_subdirectory(src)
add_subdirectory(include)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# Installation
include(Installation)

# CPack configuration
include(Packaging)
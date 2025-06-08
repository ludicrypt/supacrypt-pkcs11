# cmake/Platform.cmake

# Platform detection and configuration
if(WIN32)
    add_compile_definitions(
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0601  # Windows 7 minimum
    )
    
    # Export all symbols for PKCS#11 DLL
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    
elseif(APPLE)
    # macOS specific settings
    set(CMAKE_MACOSX_RPATH ON)
    set(CMAKE_INSTALL_RPATH "@loader_path/../lib")
    
    # Universal binary support
    if(CMAKE_OSX_ARCHITECTURES)
        message(STATUS "Building universal binary for: ${CMAKE_OSX_ARCHITECTURES}")
    endif()
    
elseif(UNIX)
    # Linux/Unix specific settings
    set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
    
    # Position independent code for shared libraries
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# Architecture detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_64BIT TRUE)
else()
    set(ARCH_32BIT TRUE)
endif()

# Endianness detection
include(TestBigEndian)
test_big_endian(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
    add_compile_definitions(SUPACRYPT_BIG_ENDIAN)
endif()
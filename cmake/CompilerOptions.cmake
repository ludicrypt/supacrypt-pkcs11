# cmake/CompilerOptions.cmake

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Common flags for GCC and Clang
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wcast-align
        -Wcast-qual
        -Wconversion
        -Wformat=2
        -Wnull-dereference
        -Wold-style-cast
        -Woverloaded-virtual
        -Wshadow
        -Wsign-conversion
        -Wunused
        -Wno-unknown-pragmas
    )
    
    # C++-specific warnings
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wnon-virtual-dtor")
    
    # Debug-specific flags
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Og -ggdb3")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Og -ggdb3")
    
    # Release optimization
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")
    
    # Sanitizers
    if(ENABLE_SANITIZERS)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
    
elseif(MSVC)
    # MSVC flags
    add_compile_options(
        /W4
        /permissive-
        /Zc:__cplusplus
        /Zc:inline
        /Zc:throwingNew
        /EHsc
        /MP
    )
    
    # Disable specific warnings
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    
    # Debug configuration
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od /RTC1")
    
    # Release optimization
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Ob2 /DNDEBUG")
endif()

# Coverage flags
if(ENABLE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
endif()
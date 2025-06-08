# include/CMakeLists.txt

# Add the include directory to the target
target_include_directories(supacrypt-pkcs11
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
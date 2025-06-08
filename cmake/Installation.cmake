# cmake/Installation.cmake

# Install library
install(TARGETS supacrypt-pkcs11
    EXPORT supacrypt-pkcs11-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(DIRECTORY include/supacrypt
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# Install generated export header
install(FILES ${CMAKE_BINARY_DIR}/include/supacrypt/pkcs11/export.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/supacrypt/pkcs11
)

# Install CMake config files
install(EXPORT supacrypt-pkcs11-targets
    FILE supacrypt-pkcs11-targets.cmake
    NAMESPACE supacrypt::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/supacrypt-pkcs11
)

# Generate config file
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/supacrypt-pkcs11-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/supacrypt-pkcs11-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/supacrypt-pkcs11
)

# Generate version file
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/supacrypt-pkcs11-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install config files
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/supacrypt-pkcs11-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/supacrypt-pkcs11-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/supacrypt-pkcs11
)
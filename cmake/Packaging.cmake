# cmake/Packaging.cmake

# CPack configuration
set(CPACK_PACKAGE_NAME "supacrypt-pkcs11")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Supacrypt PKCS#11 Cryptographic Provider")
set(CPACK_PACKAGE_VENDOR "ludicrypt")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# Platform-specific packaging
if(WIN32)
    set(CPACK_GENERATOR "NSIS")
    set(CPACK_NSIS_DISPLAY_NAME "Supacrypt PKCS#11 Provider")
    set(CPACK_NSIS_PACKAGE_NAME "Supacrypt PKCS#11")
    set(CPACK_NSIS_HELP_LINK "https://github.com/ludicrypt/supacrypt")
    set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/ludicrypt/supacrypt")
elseif(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
    set(CPACK_DMG_VOLUME_NAME "Supacrypt PKCS#11")
    set(CPACK_DMG_FORMAT "UDBZ")
else()
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    
    # Debian package configuration
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "ludicrypt")
    set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3, libprotobuf23")
    
    # RPM package configuration
    set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
    set(CPACK_RPM_PACKAGE_LICENSE "MIT")
    set(CPACK_RPM_PACKAGE_REQUIRES "openssl-libs, protobuf")
endif()

include(CPack)
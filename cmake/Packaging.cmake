# Installers: NSIS and a ZIP on Windows, DEB and a tarball on Linux.
#   cmake --build --preset <release preset> && cpack --config build/<preset>/CPackConfig.cmake
set(CPACK_PACKAGE_NAME "Sectoryn")
set(CPACK_PACKAGE_VENDOR "Manav Gupta")
set(CPACK_PACKAGE_CONTACT "Manav Gupta <manavgupta0808@gmail.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "Sectoryn")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_CHECKSUM SHA256)
set(CPACK_STRIP_FILES ON)

install(FILES LICENSE THIRD_PARTY_NOTICES.md README.md DESTINATION share/doc/sectoryn)

if(WIN32)
  set(CPACK_GENERATOR "NSIS;ZIP")
  set(CPACK_NSIS_DISPLAY_NAME "Sectoryn")
  set(CPACK_NSIS_PACKAGE_NAME "Sectoryn ${PROJECT_VERSION}")
  set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
  set(CPACK_PACKAGE_EXECUTABLES "sectoryn;Sectoryn")

  # Qt's deployment tool copies the Qt libraries and plugins the executable needs.
  if(TARGET sectoryn AND COMMAND qt_generate_deploy_app_script)
    qt_generate_deploy_app_script(
      TARGET sectoryn
      OUTPUT_SCRIPT sectoryn_deploy_script
      NO_UNSUPPORTED_PLATFORM_ERROR)
    install(SCRIPT "${sectoryn_deploy_script}")
  endif()
else()
  set(CPACK_GENERATOR "DEB;TGZ")
  set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
  set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
  # Shared library dependencies (Qt, OpenSSL, libyara) are read from the binaries.
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

  if(TARGET sectoryn)
    install(FILES resources/linux/sectoryn.desktop DESTINATION share/applications)
  endif()
endif()

include(CPack)

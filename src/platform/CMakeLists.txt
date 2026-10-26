add_library(sectoryn_platform)
add_library(Sectoryn::platform ALIAS sectoryn_platform)

file(GLOB SECTORYN_PLATFORM_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_platform PRIVATE ${SECTORYN_PLATFORM_SOURCES})
target_link_libraries(sectoryn_platform PUBLIC sectoryn_core)

# Windows verifies Authenticode with WinVerifyTrust; elsewhere verification is reported as
# unavailable and only the certificate table structure is inspected.
if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/win/AuthenticodeVerifier.cpp")
  target_sources(sectoryn_platform PRIVATE
    win/AuthenticodeVerifier.hpp
    win/AuthenticodeVerifier.cpp)
  target_compile_definitions(sectoryn_platform PRIVATE
    SECTORYN_HAVE_AUTHENTICODE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_link_libraries(sectoryn_platform PRIVATE wintrust crypt32)
endif()

sectoryn_set_warnings(sectoryn_platform)

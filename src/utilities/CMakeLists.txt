add_library(sectoryn_utilities)
add_library(Sectoryn::utilities ALIAS sectoryn_utilities)

file(GLOB SECTORYN_UTILITIES_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_utilities PRIVATE ${SECTORYN_UTILITIES_SOURCES})

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

target_link_libraries(sectoryn_utilities
  PUBLIC sectoryn_core
  PRIVATE OpenSSL::Crypto)
sectoryn_set_warnings(sectoryn_utilities)

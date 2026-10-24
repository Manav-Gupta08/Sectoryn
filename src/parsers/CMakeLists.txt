add_library(sectoryn_parsers)
add_library(Sectoryn::parsers ALIAS sectoryn_parsers)

file(GLOB SECTORYN_PARSERS_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_parsers PRIVATE ${SECTORYN_PARSERS_SOURCES})

target_link_libraries(sectoryn_parsers
  PUBLIC sectoryn_core
  PRIVATE LIEF::LIEF)
sectoryn_set_warnings(sectoryn_parsers)

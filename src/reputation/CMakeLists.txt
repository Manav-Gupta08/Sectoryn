add_library(sectoryn_reputation)
add_library(Sectoryn::reputation ALIAS sectoryn_reputation)

file(GLOB SECTORYN_REPUTATION_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_reputation PRIVATE ${SECTORYN_REPUTATION_SOURCES})

# No network library here: providers build requests and parse responses, the UI transfers them.
target_link_libraries(sectoryn_reputation
  PUBLIC sectoryn_core
  PRIVATE nlohmann_json::nlohmann_json)
sectoryn_set_warnings(sectoryn_reputation)

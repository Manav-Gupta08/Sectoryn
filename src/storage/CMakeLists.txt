add_library(sectoryn_storage)
add_library(Sectoryn::storage ALIAS sectoryn_storage)

file(GLOB SECTORYN_STORAGE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_storage PRIVATE ${SECTORYN_STORAGE_SOURCES})

target_link_libraries(sectoryn_storage
  PUBLIC sectoryn_core sectoryn_engine
  PRIVATE sectoryn_reports sectoryn_utilities nlohmann_json::nlohmann_json)
sectoryn_set_warnings(sectoryn_storage)

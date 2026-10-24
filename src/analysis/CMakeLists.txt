add_library(sectoryn_analysis)
add_library(Sectoryn::analysis ALIAS sectoryn_analysis)

file(GLOB SECTORYN_ANALYSIS_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_analysis PRIVATE ${SECTORYN_ANALYSIS_SOURCES})

target_link_libraries(sectoryn_analysis PUBLIC sectoryn_core sectoryn_utilities)
sectoryn_set_warnings(sectoryn_analysis)

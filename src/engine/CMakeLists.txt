add_library(sectoryn_engine)
add_library(Sectoryn::engine ALIAS sectoryn_engine)

file(GLOB SECTORYN_ENGINE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_engine PRIVATE ${SECTORYN_ENGINE_SOURCES})

target_compile_definitions(sectoryn_engine PRIVATE SECTORYN_VERSION="${PROJECT_VERSION}")
target_link_libraries(sectoryn_engine
  PUBLIC sectoryn_core sectoryn_utilities sectoryn_parsers sectoryn_analysis sectoryn_detectors)
sectoryn_set_warnings(sectoryn_engine)

# The YARA enrichment exists only when the detectors were built with libyara.
if(TARGET Yara::yara)
  file(GLOB SECTORYN_ENGINE_YARA_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/yara/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/yara/*.cpp")
  target_sources(sectoryn_engine PRIVATE ${SECTORYN_ENGINE_YARA_SOURCES})
endif()

if(TARGET sectoryn_platform)
  file(GLOB SECTORYN_ENGINE_SIGNATURE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/signature/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/signature/*.cpp")
  target_sources(sectoryn_engine PRIVATE ${SECTORYN_ENGINE_SIGNATURE_SOURCES})
  target_link_libraries(sectoryn_engine PUBLIC sectoryn_platform)
endif()

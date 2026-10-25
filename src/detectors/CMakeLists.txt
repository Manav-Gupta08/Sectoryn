add_library(sectoryn_detectors)
add_library(Sectoryn::detectors ALIAS sectoryn_detectors)

file(GLOB SECTORYN_DETECTORS_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/rules/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/rules/*.cpp")
target_sources(sectoryn_detectors PRIVATE ${SECTORYN_DETECTORS_SOURCES})

# The default API catalogue is compiled in so analysis works without any external files.
set(api_catalogue "${PROJECT_SOURCE_DIR}/resources/rules/api_indicators.json")
if(EXISTS "${api_catalogue}")
  file(READ "${api_catalogue}" SECTORYN_API_CATALOGUE_JSON)
  set(generated "${CMAKE_CURRENT_BINARY_DIR}/ApiCatalogueData.cpp")
  file(CONFIGURE OUTPUT "${generated}" @ONLY CONTENT [=[
#include "detectors/ApiCatalogue.hpp"

namespace sectoryn {

std::string_view builtInApiCatalogueJson() noexcept {
    return R"sectoryn_json(@SECTORYN_API_CATALOGUE_JSON@)sectoryn_json";
}

} // namespace sectoryn
]=])
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${api_catalogue}")
  target_sources(sectoryn_detectors PRIVATE "${generated}")
endif()

target_link_libraries(sectoryn_detectors
  PUBLIC sectoryn_core sectoryn_analysis
  PRIVATE nlohmann_json::nlohmann_json)
sectoryn_set_warnings(sectoryn_detectors)

# YARA support is compiled only when libyara was found; SECTORYN_HAVE_YARA tells dependents.
if(TARGET Yara::yara)
  file(GLOB SECTORYN_YARA_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/yara/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/yara/*.cpp")
  target_sources(sectoryn_detectors PRIVATE ${SECTORYN_YARA_SOURCES})
  target_link_libraries(sectoryn_detectors PUBLIC sectoryn_utilities PRIVATE Yara::yara)
  target_compile_definitions(sectoryn_detectors PUBLIC SECTORYN_HAVE_YARA)
endif()

add_library(sectoryn_core)
add_library(Sectoryn::core ALIAS sectoryn_core)

file(GLOB SECTORYN_CORE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_core PRIVATE ${SECTORYN_CORE_SOURCES})

find_package(Threads REQUIRED)

target_include_directories(sectoryn_core PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_compile_features(sectoryn_core PUBLIC cxx_std_20)
target_link_libraries(sectoryn_core PUBLIC Threads::Threads)
sectoryn_set_warnings(sectoryn_core)

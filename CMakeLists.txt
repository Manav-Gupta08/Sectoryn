cmake_minimum_required(VERSION 3.25)

project(Sectoryn
  VERSION 0.1.0
  DESCRIPTION "Static PE analysis and malware triage workbench"
  HOMEPAGE_URL "https://github.com/Manav-Gupta08/Sectoryn"
  LANGUAGES CXX)

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not supported. Use a preset or a separate build directory.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

option(SECTORYN_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(SECTORYN_BUILD_APP "Build the Qt desktop application" ON)
option(SECTORYN_BUILD_FUZZERS "Build libFuzzer harnesses (Clang only)" OFF)
option(SECTORYN_BUILD_BENCHMARKS "Build benchmark executables" OFF)
option(BUILD_TESTING "Build the test suites" ON)

include(CompilerWarnings)
include(Sanitizers OPTIONAL)
include(Dependencies OPTIONAL)

# Libraries are listed in dependency order; each one is added once its directory exists.
set(SECTORYN_LIBRARY_MODULES
  core
  utilities
  parsers
  analysis
  detectors
  reports
  storage
  platform
  reputation
  engine)

foreach(module IN LISTS SECTORYN_LIBRARY_MODULES)
  if(EXISTS "${PROJECT_SOURCE_DIR}/src/${module}/CMakeLists.txt")
    add_subdirectory("src/${module}")
  endif()
endforeach()

if(SECTORYN_BUILD_APP)
  foreach(module IN ITEMS ui app)
    if(EXISTS "${PROJECT_SOURCE_DIR}/src/${module}/CMakeLists.txt")
      add_subdirectory("src/${module}")
    endif()
  endforeach()
endif()

if(BUILD_TESTING AND EXISTS "${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt")
  enable_testing()
  add_subdirectory(tests)
endif()

if(SECTORYN_BUILD_BENCHMARKS AND EXISTS "${PROJECT_SOURCE_DIR}/benchmarks/CMakeLists.txt")
  add_subdirectory(benchmarks)
endif()

include(Packaging OPTIONAL)

find_package(GTest 1.11 REQUIRED)
include(GoogleTest)

set(SECTORYN_TEST_LIBRARIES)
foreach(module IN LISTS SECTORYN_LIBRARY_MODULES)
  if(TARGET sectoryn_${module})
    list(APPEND SECTORYN_TEST_LIBRARIES sectoryn_${module})
  endif()
endforeach()

file(GLOB SECTORYN_TEST_SUPPORT_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/support/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/support/*.cpp")

function(sectoryn_add_test_suite target label pattern)
  file(GLOB suite_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${pattern}")
  if(NOT suite_sources)
    return()
  endif()

  add_executable(${target} ${suite_sources} ${SECTORYN_TEST_SUPPORT_SOURCES})
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(${target} PRIVATE ${SECTORYN_TEST_LIBRARIES} GTest::gtest GTest::gtest_main)
  target_compile_definitions(${target} PRIVATE
    SECTORYN_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
  sectoryn_set_warnings(${target})

  gtest_discover_tests(${target}
    DISCOVERY_MODE PRE_TEST
    PROPERTIES LABELS ${label})
endfunction()

sectoryn_add_test_suite(sectoryn_unit_tests unit "unit/test_*.cpp")
sectoryn_add_test_suite(sectoryn_integration_tests integration "integration/test_*.cpp")
sectoryn_add_test_suite(sectoryn_regression_tests regression "regression/test_*.cpp")

if(TARGET sectoryn_ui)
  sectoryn_add_test_suite(sectoryn_ui_tests ui "ui/test_*.cpp")
  if(TARGET sectoryn_ui_tests)
    target_link_libraries(sectoryn_ui_tests PRIVATE sectoryn_ui)
  endif()
endif()

if(TARGET sectoryn)
  add_test(NAME app.startup_shutdown COMMAND sectoryn --exit-after-startup)
  set_tests_properties(app.startup_shutdown PROPERTIES
    LABELS app
    TIMEOUT 60
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()

if(SECTORYN_BUILD_FUZZERS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/CMakeLists.txt")
  add_subdirectory(fuzz)
endif()

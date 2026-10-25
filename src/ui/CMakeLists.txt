find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Network)

add_library(sectoryn_ui)
add_library(Sectoryn::ui ALIAS sectoryn_ui)

file(GLOB SECTORYN_UI_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/models/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/models/*.cpp")
target_sources(sectoryn_ui PRIVATE ${SECTORYN_UI_SOURCES})
set_target_properties(sectoryn_ui PROPERTIES AUTOMOC ON)

set(styles_dir "${PROJECT_SOURCE_DIR}/resources/styles")
if(EXISTS "${styles_dir}/dark.qss")
  qt_add_resources(sectoryn_ui sectoryn_styles
    PREFIX "/styles"
    BASE "${styles_dir}"
    FILES "${styles_dir}/dark.qss")
endif()

# Views exist for every module, so the UI links each library that is part of the build.
set(ui_libraries)
foreach(module IN LISTS SECTORYN_LIBRARY_MODULES)
  if(TARGET sectoryn_${module})
    list(APPEND ui_libraries sectoryn_${module})
  endif()
endforeach()

target_compile_definitions(sectoryn_ui
  PUBLIC QT_NO_KEYWORDS
  PRIVATE QT_NO_CAST_FROM_ASCII)
target_link_libraries(sectoryn_ui PUBLIC ${ui_libraries} Qt6::Widgets)
# Only the optional reputation lookup uses the network.
if(TARGET sectoryn_reputation)
  target_link_libraries(sectoryn_ui PRIVATE Qt6::Network)
endif()
sectoryn_set_warnings(sectoryn_ui)

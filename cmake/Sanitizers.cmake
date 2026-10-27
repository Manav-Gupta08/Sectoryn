# AddressSanitizer and UndefinedBehaviorSanitizer for GCC and Clang. The flags are added globally
# so that LIEF is instrumented as well; a partly instrumented build misses errors inside it.
option(SECTORYN_ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(SECTORYN_ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer" OFF)

set(sectoryn_sanitizers)
if(SECTORYN_ENABLE_ASAN)
  list(APPEND sectoryn_sanitizers address)
endif()
if(SECTORYN_ENABLE_UBSAN)
  list(APPEND sectoryn_sanitizers undefined)
endif()

if(sectoryn_sanitizers)
  if(MSVC)
    if(SECTORYN_ENABLE_UBSAN)
      message(FATAL_ERROR "MSVC does not provide UndefinedBehaviorSanitizer")
    endif()
    add_compile_options(/fsanitize=address)
  elseif(MINGW)
    message(FATAL_ERROR "MinGW toolchains do not ship the sanitizer runtimes")
  else()
    list(JOIN sectoryn_sanitizers "," sectoryn_sanitizer_list)
    add_compile_options(-fsanitize=${sectoryn_sanitizer_list} -fno-omit-frame-pointer
                        -fno-sanitize-recover=all)
    add_link_options(-fsanitize=${sectoryn_sanitizer_list})
    message(STATUS "Sanitizers enabled: ${sectoryn_sanitizer_list}")
  endif()
endif()

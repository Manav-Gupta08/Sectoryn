function(sectoryn_set_warnings target)
  if(MSVC)
    set(warnings
      /W4
      /permissive-
      /w14242 # possible loss of data in conversion
      /w14254 # larger bit field assigned to smaller bit field
      /w14263 # member function does not override base virtual
      /w14265 # class has virtual functions but non-virtual destructor
      /w14287 # unsigned/negative constant mismatch
      /w14296 # expression is always true/false
      /w14311 # pointer truncation
      /w14826 # sign-extended conversion
      /w14905 # wide string literal cast to LPSTR
      /w14906 # string literal cast to LPWSTR
      /w14928 # illegal copy-initialization
      /utf-8)
    if(SECTORYN_WARNINGS_AS_ERRORS)
      list(APPEND warnings /WX)
    endif()
  else()
    set(warnings
      -Wall
      -Wextra
      -Wpedantic
      -Wshadow
      -Wconversion
      -Wsign-conversion
      -Wold-style-cast
      -Wnon-virtual-dtor
      -Woverloaded-virtual
      -Wcast-align
      -Wnull-dereference
      -Wdouble-promotion
      -Wformat=2
      -Wimplicit-fallthrough)
    if(SECTORYN_WARNINGS_AS_ERRORS)
      list(APPEND warnings -Werror)
    endif()
  endif()

  target_compile_options(${target} PRIVATE ${warnings})
endfunction()

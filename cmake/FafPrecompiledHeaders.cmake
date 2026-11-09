# Precompiled header for the engine's sources: about 2.5 times faster builds on
# Windows and 3.4 times on Linux. On by default (ENGINE); OFF builds without it.
#
# FAF_PCH=STD      the standard headers most sources include
# FAF_PCH=ENGINE   those plus the reflection and container headers
#
# Call faf_precompile after the per-source settings: a source with its own
# defines or options can't share the header, and neither can third-party code.

set(FAF_PCH "ENGINE" CACHE STRING "Precompiled header for the engine's sources: OFF, STD or ENGINE")
set_property(CACHE FAF_PCH PROPERTY STRINGS OFF STD ENGINE)

function(faf_precompile target)
  # A syntax-only build (the Layout check) writes no files, so it has no header to share.
  if(FAF_PCH STREQUAL "OFF" OR FAF_SYNTAX_ONLY)
    return()
  endif()
  set(_headers
    <algorithm> <cmath> <cstddef> <cstdint> <cstdio> <cstdlib> <cstring>
    <limits> <new> <stdexcept> <string> <typeinfo> <vector>)
  if(FAF_PCH STREQUAL "ENGINE")
    list(APPEND _headers
      "${PROJECT_SOURCE_DIR}/src/gpg/core/reflection/Reflection.h"
      "${PROJECT_SOURCE_DIR}/src/gpg/core/containers/String.h"
      "${PROJECT_SOURCE_DIR}/src/gpg/core/utils/Global.h"
      "${PROJECT_SOURCE_DIR}/src/gpg/core/utils/Logging.h")
  endif()
  foreach(_header IN LISTS _headers)
    target_precompile_headers(${target} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:${_header}>")
  endforeach()

  get_target_property(_sources ${target} SOURCES)
  get_target_property(_source_dir ${target} SOURCE_DIR)
  foreach(_src IN LISTS _sources)
    get_filename_component(_full "${_src}" ABSOLUTE BASE_DIR "${_source_dir}")
    get_source_file_property(_defs "${_src}" COMPILE_DEFINITIONS)
    get_source_file_property(_opts "${_src}" COMPILE_OPTIONS)
    if(_defs OR _opts OR NOT _full MATCHES "^${PROJECT_SOURCE_DIR}/src/")
      set_property(SOURCE "${_src}" PROPERTY SKIP_PRECOMPILE_HEADERS ON)
    endif()
  endforeach()
endfunction()

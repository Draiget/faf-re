# Source-based code coverage (clang -fprofile-instr-generate -fcoverage-mapping), for
# tools/coverage/report.sh. Presets clang-x64-coverage and linux-clang-x64-coverage turn it on.
#
#   FAF_COVERAGE=ON   every object counts which lines and branches ran. A test writes the
#                     counts to LLVM_PROFILE_FILE when it ends; headless writes them before it
#                     terminates (src/headless/HeadlessMain.cpp, FAF_COVERAGE_PROFILE).
#
# Not for builds anyone plays or measures speed with: the counters slow the code down.
option(FAF_COVERAGE "Instrument every object for llvm-cov source-based coverage" OFF)
if(NOT FAF_COVERAGE)
  return()
endif()
if(FAF_PGO_GENERATE OR FAF_PGO_PROFILE)
  message(FATAL_ERROR "FAF_COVERAGE excludes FAF_PGO_GENERATE and FAF_PGO_PROFILE.")
endif()

add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:-fprofile-instr-generate;-fcoverage-mapping>")
add_compile_definitions(FAF_COVERAGE_PROFILE=1)
if(WIN32)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_faf_profile_rt_name clang_rt.profile-x86_64.lib)
  else()
    set(_faf_profile_rt_name clang_rt.profile-i386.lib)
  endif()
  file(GLOB _faf_profile_rt "${FAF_LLVM_ROOT}/lib/clang/*/lib/windows/${_faf_profile_rt_name}")
  if(NOT _faf_profile_rt)
    message(FATAL_ERROR "${_faf_profile_rt_name} not found under ${FAF_LLVM_ROOT}/lib/clang.")
  endif()
  # lld-link takes no -fprofile-instr-generate; the runtime goes in by name.
  link_libraries("${_faf_profile_rt}")
  add_link_options(/INCLUDE:__llvm_profile_runtime)
else()
  add_link_options(-fprofile-instr-generate)
endif()
message(STATUS "FAF_COVERAGE: every object is instrumented for llvm-cov")

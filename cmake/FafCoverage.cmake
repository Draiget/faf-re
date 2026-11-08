# Source-based code coverage (clang -fprofile-instr-generate -fcoverage-mapping), for
# tools/coverage/report.sh. Presets clang-x64-release-coverage and linux-clang-x64-release-coverage
# turn it on.
#
#   FAF_COVERAGE=ON   every object counts which lines and branches ran. A test writes the
#                     counts to LLVM_PROFILE_FILE when it ends; headless writes them before it
#                     terminates (src/headless/HeadlessMain.cpp, FAF_COVERAGE_PROFILE).
#
# On Windows the linker keeps functions nothing calls (/OPT:NOREF): their coverage records sit in
# the function's own section, and dropping them would leave unreached code out of the total. Linux
# keeps --gc-sections, because faf_sim links only by dropping code that refers to the client
# (CameraImpl, UserEntity, ...), so its total counts only the code a test executable keeps.
# Not for builds anyone plays or measures speed with: the counters slow the code down. x64 only.
option(FAF_COVERAGE "Instrument every object for llvm-cov source-based coverage" OFF)
if(NOT FAF_COVERAGE)
  return()
endif()
if(FAF_PGO_GENERATE OR FAF_PGO_PROFILE)
  message(FATAL_ERROR "FAF_COVERAGE excludes FAF_PGO_GENERATE and FAF_PGO_PROFILE.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "FAF_COVERAGE is x64 only.")
endif()

add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:-fprofile-instr-generate;-fcoverage-mapping>")
add_compile_definitions(FAF_COVERAGE_PROFILE=1)
if(WIN32)
  file(GLOB _faf_profile_rt "${FAF_LLVM_ROOT}/lib/clang/*/lib/windows/clang_rt.profile-x86_64.lib")
  if(NOT _faf_profile_rt)
    message(FATAL_ERROR "clang_rt.profile-x86_64.lib not found under ${FAF_LLVM_ROOT}/lib/clang.")
  endif()
  # lld-link takes no -fprofile-instr-generate; the runtime goes in by name.
  link_libraries("${_faf_profile_rt}")
  # Later options win, so these override the /OPT:REF and /OPT:ICF of the release flags.
  add_link_options(/INCLUDE:__llvm_profile_runtime /OPT:NOREF /OPT:NOICF)
else()
  add_link_options(-fprofile-instr-generate)
endif()
message(STATUS "FAF_COVERAGE: every object is instrumented for llvm-cov")

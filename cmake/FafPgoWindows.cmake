# Profile-guided Windows x64 build (docs/SWITCHES.md): the clang-x64-release preset uses it, and
# clang-x64-release-plain doesn't.
#
#   FAF_PGO_GENERATE=ON                counts what the code does; headless writes the counts when it
#                                      ends (LLVM_PROFILE_FILE names the file; docs/SWITCHES.md).
#   FAF_PGO_PROFILE=<file.profdata>    compiles with those counts. A profile from older source still
#                                      applies to the functions that did not change.
#
# x64 only: x86 runs its math under the x87 control word, which this hasn't been tried with.
option(FAF_PGO_GENERATE "Build headless to record a profile for FAF_PGO_PROFILE" OFF)
set(FAF_PGO_PROFILE "" CACHE FILEPATH "Merged LLVM profile to optimise with")
if(FAF_PGO_GENERATE AND FAF_PGO_PROFILE)
  message(FATAL_ERROR "FAF_PGO_GENERATE and FAF_PGO_PROFILE exclude each other.")
endif()
if((FAF_PGO_GENERATE OR FAF_PGO_PROFILE) AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "The profile-guided Windows build is x64 only.")
endif()
if(FAF_PGO_GENERATE)
  file(GLOB _faf_profile_rt "${FAF_LLVM_ROOT}/lib/clang/*/lib/windows/clang_rt.profile-x86_64.lib")
  if(NOT _faf_profile_rt)
    message(FATAL_ERROR "clang_rt.profile-x86_64.lib not found under ${FAF_LLVM_ROOT}/lib/clang.")
  endif()
  add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:-fprofile-generate>")
  add_compile_definitions(FAF_COVERAGE_PROFILE=1)
  link_libraries("${_faf_profile_rt}")
  add_link_options(/INCLUDE:__llvm_profile_runtime)
elseif(FAF_PGO_PROFILE)
  add_compile_options(
    "$<$<COMPILE_LANGUAGE:C,CXX>:-fprofile-use=${FAF_PGO_PROFILE};-Wno-profile-instr-unprofiled;-Wno-profile-instr-out-of-date;-Wno-backend-plugin>")
endif()

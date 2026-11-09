# Engine addition (dedicated-server plan WPR.21): faf_math_dump, the difffuzz
# targets' own side linked against the engine's objects (README.md,
# "Cross-platform dump"). Included by tests/CMakeLists.txt (Windows, on
# faf_engine) and cmake/FafLinux.cmake (Linux, on faf_sim), with
# FAF_MATH_DUMP_ENGINE naming that target.
#
# Built with every build and checked right after it against
# tests/math_dump/golden.txt, retail's outputs (difffuzz --dump): the first two
# blocks per target (131,072 inputs, about a second), and against
# tests/math_dump/retail_values.txt, retail's values for up to 64 inputs per
# target (difffuzz --values, plan WPL.26). The `math_dump` test checks all
# 1,000,000 inputs and the values.

set(_faf_math_dump_src "${CMAKE_CURRENT_LIST_DIR}/src")
add_executable(faf_math_dump
  "${_faf_math_dump_src}/dump_main.cpp"
  "${_faf_math_dump_src}/gen.cpp"
  "${_faf_math_dump_src}/targets_math.cpp"
  "${_faf_math_dump_src}/targets_sim.cpp"
  "${_faf_math_dump_src}/sdk_mirror.cpp"
  "${_faf_math_dump_src}/retail_absent.cpp")
target_compile_definitions(faf_math_dump PRIVATE DIFFFUZZ_ENGINE_LINKED)
target_include_directories(faf_math_dump PRIVATE "${_faf_math_dump_src}")
target_link_libraries(faf_math_dump PRIVATE ${FAF_MATH_DUMP_ENGINE})

get_filename_component(_faf_math_dump_golden "${CMAKE_CURRENT_LIST_DIR}/../../tests/math_dump/golden.txt" ABSOLUTE)
get_filename_component(_faf_math_dump_values "${CMAKE_CURRENT_LIST_DIR}/../../tests/math_dump/retail_values.txt" ABSOLUTE)
add_custom_command(TARGET faf_math_dump POST_BUILD
  COMMAND "$<TARGET_FILE:faf_math_dump>" --check "${_faf_math_dump_golden}" --values "${_faf_math_dump_values}" --iters 131072
  COMMENT "Checking the engine's math against retail (tests/math_dump/golden.txt, retail_values.txt)"
  VERBATIM)
add_test(NAME math_dump COMMAND "$<TARGET_FILE:faf_math_dump>" --check "${_faf_math_dump_golden}" --values "${_faf_math_dump_values}")

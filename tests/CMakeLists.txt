# Engine tests: console programs linked against the engine's own objects
# (faf_engine, src/CMakeLists.txt). Not part of the default build:
#
#   cmake --build --preset clang-x64-release --target faf_net_tests
#   ctest --test-dir build/clang-x64-release

add_executable(faf_net_tests EXCLUDE_FROM_ALL net/NetRobustnessTests.cpp)
target_link_libraries(faf_net_tests PRIVATE faf_engine)

add_test(NAME net_robustness COMMAND faf_net_tests)

add_executable(faf_profiler_tests EXCLUDE_FROM_ALL profiling/ProfilerFacadeTests.cpp)
target_include_directories(faf_profiler_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

add_test(NAME profiler_facade COMMAND faf_profiler_tests)

# Engine addition (dedicated-server plan WPL.23): golden sim-math tests
# (tests/sim_math). Built with every build, and run right after it: a change
# that moves one result of the simulation's parity-sensitive arithmetic fails
# the build. `faf_sim_math_tests --generate <file>` rewrites the golden file
# (only on Windows x64, see the source).
add_executable(faf_sim_math_tests sim_math/SimMathTests.cpp)
target_link_libraries(faf_sim_math_tests PRIVATE faf_engine)
set(_faf_sim_math_golden "${CMAKE_CURRENT_SOURCE_DIR}/sim_math/golden.txt")
# The x86 build's recorded differences from the x64 golden (the file's header
# gives the reason).
set(_faf_sim_math_known "${CMAKE_CURRENT_SOURCE_DIR}/sim_math/known_windows-${FAF_TARGET_ARCH}.txt")
set(_faf_sim_math_args "${_faf_sim_math_golden}")
if(EXISTS "${_faf_sim_math_known}")
  list(APPEND _faf_sim_math_args --known "${_faf_sim_math_known}")
endif()
if(EXISTS "${_faf_sim_math_golden}")
  add_custom_command(TARGET faf_sim_math_tests POST_BUILD
    COMMAND "$<TARGET_FILE:faf_sim_math_tests>" ${_faf_sim_math_args}
    COMMENT "Checking the simulation's arithmetic against tests/sim_math/golden.txt"
    VERBATIM)
  add_test(NAME sim_math COMMAND "$<TARGET_FILE:faf_sim_math_tests>" ${_faf_sim_math_args})
endif()

# Engine addition (dedicated-server plan WPL.4, WPR.11): what the static
# initialisers of faf_main's objects registered (tests/registry).
add_executable(faf_registration_dump EXCLUDE_FROM_ALL registry/RegistrationDump.cpp)
target_link_libraries(faf_registration_dump PRIVATE faf_engine)

# Engine addition (dedicated-server plan WPL.4, WPR.11): every map in a list
# loaded with the client's and the headless terrain resource, compared
# (tests/terrain). Needs the game data: run it from a folder staged like the
# game's bin folder, with /init.
add_executable(faf_terrain_check EXCLUDE_FROM_ALL terrain/TerrainCheck.cpp)
target_link_libraries(faf_terrain_check PRIVATE faf_engine)
add_subdirectory(remote)

# Entity update scroll snapshots and payload ownership.
add_executable(faf_recon_scroll_packet_tests EXCLUDE_FROM_ALL sim/ReconScrollPacketTests.cpp)
target_link_libraries(faf_recon_scroll_packet_tests PRIVATE faf_engine)
add_test(NAME recon_scroll_packet COMMAND faf_recon_scroll_packet_tests)
set_tests_properties(recon_scroll_packet PROPERTIES TIMEOUT 120)

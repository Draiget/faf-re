# Engine tests: console programs linked against the engine's own objects
# (faf_engine, src/CMakeLists.txt). Not part of the default build:
#
#   cmake --build --preset clang-x64-release --target faf_net_tests
#   ctest --test-dir build/clang-x64-release

add_executable(faf_net_tests EXCLUDE_FROM_ALL net/NetRobustnessTests.cpp)
target_link_libraries(faf_net_tests PRIVATE faf_engine)

add_test(NAME net_robustness COMMAND faf_net_tests)

# Peer transports of the UDP connector (issue #232): two connectors in one
# process, over their sockets and through transports.
add_executable(faf_peer_transport_tests EXCLUDE_FROM_ALL net/PeerTransportTests.cpp)
target_link_libraries(faf_peer_transport_tests PRIVATE faf_engine)

add_test(NAME net_peer_transport COMMAND faf_peer_transport_tests)

# net_FastRetransmit (issue #237): a lost DATA packet's recovery with the
# switch off and on, at a fast rate and at the game's rate.
add_executable(faf_fast_retransmit_tests EXCLUDE_FROM_ALL net/FastRetransmitTests.cpp)
target_link_libraries(faf_fast_retransmit_tests PRIVATE faf_engine)

add_test(NAME net_fast_retransmit COMMAND faf_fast_retransmit_tests)

# libjuice gathering against a STUN/TURN server (issue #228), run by hand:
#   faf_juice_gather <host> <port> [<turn user> <turn password>]
add_executable(faf_juice_gather EXCLUDE_FROM_ALL netlink/JuiceGatherTest.cpp)
target_link_libraries(faf_juice_gather PRIVATE faf_juice faf_codegen)

# netlink (issue #229): JSON, signalling and SDP checks, then two links in one
# process. --bind <address> where inbound UDP to 0.0.0.0 is dropped.
add_executable(faf_netlink_tests EXCLUDE_FROM_ALL netlink/NetlinkTests.cpp)
target_link_libraries(faf_netlink_tests PRIVATE faf_netlink faf_codegen)

# libdatachannel (issue #238): two local peers open an unordered, unreliable
# data channel and echo datagrams. --bind <address> as above.
add_executable(faf_datachannel_test EXCLUDE_FROM_ALL netlink/DataChannelTest.cpp)
target_link_libraries(faf_datachannel_test PRIVATE faf_datachannel faf_codegen)
set_target_properties(faf_datachannel_test PROPERTIES CXX_STANDARD 17)
if(MSVC)
  target_compile_options(faf_datachannel_test PRIVATE /EHsc)
endif()

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

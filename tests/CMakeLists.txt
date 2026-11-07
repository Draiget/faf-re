# Engine tests: console programs linked against the engine's own objects
# (faf_engine, src/CMakeLists.txt). Use GoogleTest (gtest / gtest_main) for all
# tests instead of custom test harnesses.
#
#   cmake --build --preset clang-x64-release --target existing_tests
#   ctest --test-dir build/clang-x64-release -L Existing

add_executable(faf_net_tests EXCLUDE_FROM_ALL net/NetRobustnessTests.cpp)
target_link_libraries(faf_net_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_net_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME net_robustness COMMAND faf_net_tests)
set_tests_properties(net_robustness PROPERTIES LABELS "Existing")

# Peer transports of the UDP connector (issue #232): two connectors in one
# process, over their sockets and through transports.
add_executable(faf_peer_transport_tests EXCLUDE_FROM_ALL net/PeerTransportTests.cpp)
target_link_libraries(faf_peer_transport_tests PRIVATE faf_engine gtest)
set_target_properties(faf_peer_transport_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME net_peer_transport COMMAND faf_peer_transport_tests)
set_tests_properties(net_peer_transport PROPERTIES LABELS "Existing")

# net_FastRetransmit (issue #237): a lost DATA packet's recovery with the
# switch off and on, at a fast rate and at the game's rate.
add_executable(faf_fast_retransmit_tests EXCLUDE_FROM_ALL net/FastRetransmitTests.cpp)
target_link_libraries(faf_fast_retransmit_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_fast_retransmit_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME net_fast_retransmit COMMAND faf_fast_retransmit_tests)
set_tests_properties(net_fast_retransmit PROPERTIES LABELS "Existing")

# libjuice gathering against a STUN/TURN server (issue #228), run by hand:
#   faf_juice_gather <host> <port> [<turn user> <turn password>]
add_executable(faf_juice_gather EXCLUDE_FROM_ALL netlink/JuiceGatherTest.cpp)
target_link_libraries(faf_juice_gather PRIVATE faf_juice faf_codegen)

# netlink (issue #229): JSON, signalling and SDP checks, then two links in one
# process. --bind <address> where inbound UDP to 0.0.0.0 is dropped.
add_executable(faf_netlink_tests EXCLUDE_FROM_ALL netlink/NetlinkTests.cpp)
target_link_libraries(faf_netlink_tests PRIVATE faf_netlink faf_codegen gtest)
set_target_properties(faf_netlink_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME netlink COMMAND faf_netlink_tests)
set_tests_properties(netlink PROPERTIES LABELS "Existing")

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
target_link_libraries(faf_profiler_tests PRIVATE gtest_main)
set_target_properties(faf_profiler_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME profiler_facade COMMAND faf_profiler_tests)
set_tests_properties(profiler_facade PROPERTIES LABELS "Existing")

# Engine addition: EffectScan.h against the std::regex patterns it replaced, on generated text.
add_executable(faf_effect_scan_tests EXCLUDE_FROM_ALL effect_scan/EffectScanTests.cpp)
target_include_directories(faf_effect_scan_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_effect_scan_tests PRIVATE gtest_main)
set_target_properties(faf_effect_scan_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME effect_scan COMMAND faf_effect_scan_tests)
set_tests_properties(effect_scan PROPERTIES LABELS "Existing")

# Engine addition: where UserDecal:SetOrientation puts a decal's corner so it stays centred.
add_executable(faf_scripted_decal_tests EXCLUDE_FROM_ALL scripted_decal/PlacementTests.cpp)
target_include_directories(faf_scripted_decal_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME scripted_decal_placement COMMAND faf_scripted_decal_tests)

# Engine addition: ImageCodec's DDS writer against the d3dx11_43.dll the process loads, so the
# same exe checks Microsoft's on Windows and Wine's under Wine.
add_executable(faf_image_codec_tests EXCLUDE_FROM_ALL image_codec/ImageCodecTests.cpp)
target_link_libraries(faf_image_codec_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_image_codec_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME image_codec COMMAND faf_image_codec_tests)
set_tests_properties(image_codec PROPERTIES LABELS "Existing")

# The DDS topology rule is shared with D3D11 and can be checked without D3DX/WARP.
add_executable(faf_texture_quality_tests EXCLUDE_FROM_ALL image_codec/TextureQualityTests.cpp)
target_include_directories(faf_texture_quality_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_texture_quality_tests PRIVATE gtest_main)
set_target_properties(faf_texture_quality_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME texture_quality COMMAND faf_texture_quality_tests)
set_tests_properties(texture_quality PROPERTIES LABELS "Existing")

# Engine addition (dedicated-server plan WPL.23): golden sim-math tests
# (tests/sim_math). Built with every build, and run right after it: a change
# that moves one result of the simulation's parity-sensitive arithmetic fails
# the build. `faf_sim_math_tests --generate <file>` rewrites the golden file
# (only on Windows x64, see the source).
add_executable(faf_sim_math_tests sim_math/SimMathTests.cpp)
target_link_libraries(faf_sim_math_tests PRIVATE faf_engine gtest)
set_target_properties(faf_sim_math_tests PROPERTIES FOLDER "Tests/Existing")
set(_faf_sim_math_golden "${CMAKE_CURRENT_SOURCE_DIR}/sim_math/golden.txt")
# The x86 build's recorded differences from the x64 golden (the file's header
# gives the reason).
set(_faf_sim_math_known "${CMAKE_CURRENT_SOURCE_DIR}/sim_math/known_windows-${FAF_TARGET_ARCH}.txt")
target_compile_definitions(faf_sim_math_tests PRIVATE
  FAF_SIM_MATH_GOLDEN="${_faf_sim_math_golden}"
)
if(EXISTS "${_faf_sim_math_known}")
  target_compile_definitions(faf_sim_math_tests PRIVATE
    FAF_SIM_MATH_KNOWN="${_faf_sim_math_known}"
  )
endif()
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
  set_tests_properties(sim_math PROPERTIES LABELS "Existing")
endif()

# Engine addition (replay timeline): reading a replay's length leaves the stream as it was
# (tests/replay).
add_executable(faf_replay_scan_tests EXCLUDE_FROM_ALL replay/ReplayScanTests.cpp)
target_link_libraries(faf_replay_scan_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_replay_scan_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME replay_scan COMMAND faf_replay_scan_tests)
set_tests_properties(replay_scan PROPERTIES LABELS "Existing")

# CZipFile reads entries whose data starts at or past 2 GiB, as the binary does (tests/zip, PR #291).
add_executable(faf_zip_offset_tests EXCLUDE_FROM_ALL zip/ZipOffsetTests.cpp)
target_link_libraries(faf_zip_offset_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_zip_offset_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME zip_offset COMMAND faf_zip_offset_tests)
set_tests_properties(zip_offset PROPERTIES LABELS "Existing")

# Engine addition (#247): the user preferences from several threads at once
# (tests/prefs); fails without USER_PreferencesLock.
add_executable(faf_prefs_thread_tests EXCLUDE_FROM_ALL prefs/PrefsThreadTests.cpp)
target_link_libraries(faf_prefs_thread_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_prefs_thread_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME prefs_threads COMMAND faf_prefs_thread_tests)
set_tests_properties(prefs_threads PROPERTIES LABELS "Existing")

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

# Engine addition (dedicated-server plan WPR.21): the difffuzz targets on the
# engine's objects, checked against retail's outputs (tests/math_dump/golden.txt)
# after every build (tools/difffuzz/dump.cmake).
set(FAF_MATH_DUMP_ENGINE faf_engine)
include("${CMAKE_SOURCE_DIR}/tools/difffuzz/dump.cmake")
add_subdirectory(remote)

add_subdirectory(memory)
add_subdirectory(tread_rotation)

# Entity update scroll snapshots and payload ownership.
add_executable(faf_recon_scroll_packet_tests EXCLUDE_FROM_ALL sim/ReconScrollPacketTests.cpp)
target_link_libraries(faf_recon_scroll_packet_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_recon_scroll_packet_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME recon_scroll_packet COMMAND faf_recon_scroll_packet_tests)
set_tests_properties(recon_scroll_packet PROPERTIES TIMEOUT 120 LABELS "Existing")

# Lua coroutine tests (coroutine.create / resume / yield / status / wrap).
add_executable(faf_coroutine_tests EXCLUDE_FROM_ALL lua/CoroutineTests.cpp)
target_link_libraries(faf_coroutine_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_coroutine_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME lua_coroutine COMMAND faf_coroutine_tests)
set_tests_properties(lua_coroutine PROPERTIES LABELS "Existing")

# Engine addition: the MSDF font cook (issue #306), with FreeType and msdfgen linked statically.
add_executable(faf_msdf_cook_tests EXCLUDE_FROM_ALL font/MsdfFontCookTests.cpp ${CMAKE_SOURCE_DIR}/src/moho/render/font/MsdfFontCook.cpp)
target_include_directories(faf_msdf_cook_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_msdf_cook_tests PRIVATE faf_freetype faf_msdfgen faf_zstd gtest)
set_target_properties(faf_msdf_cook_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME msdf_font_cook COMMAND faf_msdf_cook_tests)
set_tests_properties(msdf_font_cook PROPERTIES LABELS "Existing")

# Engine addition: fuzzes what a mod's font goes through (issue #305). FAF_FONTFUZZ_SANITIZE adds
# AddressSanitizer to it and to the two font libraries, so build it in a folder of its own.
option(FAF_FONTFUZZ_SANITIZE "Build faf_fontfuzz and the font libraries with AddressSanitizer" OFF)
add_executable(faf_fontfuzz EXCLUDE_FROM_ALL ${CMAKE_SOURCE_DIR}/tools/fontfuzz/FontFuzz.cpp
  ${CMAKE_SOURCE_DIR}/src/moho/render/font/MsdfFontCheck.cpp
  ${CMAKE_SOURCE_DIR}/src/moho/render/font/MsdfFontCook.cpp)
target_include_directories(faf_fontfuzz PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_fontfuzz PRIVATE faf_freetype faf_msdfgen faf_zstd)
if(FAF_FONTFUZZ_SANITIZE)
  foreach(_target faf_fontfuzz faf_freetype faf_msdfgen)
    target_compile_options(${_target} PRIVATE -fsanitize=address -fno-omit-frame-pointer -g)
  endforeach()
  target_link_options(faf_fontfuzz PRIVATE -fsanitize=address)
endif()

# Engine addition: the checks and limits on a mod's font (issue #305). Without a folder it reads Windows' Arial.
if(WIN32)
  add_executable(faf_msdf_safety_tests EXCLUDE_FROM_ALL font/MsdfFontSafetyTests.cpp
    ${CMAKE_SOURCE_DIR}/src/moho/render/font/MsdfFontCheck.cpp
    ${CMAKE_SOURCE_DIR}/src/moho/render/font/MsdfFontCook.cpp)
  target_include_directories(faf_msdf_safety_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
  target_link_libraries(faf_msdf_safety_tests PRIVATE faf_freetype faf_msdfgen faf_zstd gtest)
  set_target_properties(faf_msdf_safety_tests PROPERTIES FOLDER "Tests/Existing")
  add_test(NAME msdf_font_safety COMMAND faf_msdf_safety_tests)
  set_tests_properties(msdf_font_safety PROPERTIES LABELS "Existing")
endif()

# Group all existing test executables into a custom target.
set(_faf_existing_test_targets
  faf_net_tests
  faf_peer_transport_tests
  faf_fast_retransmit_tests
  faf_netlink_tests
  faf_profiler_tests
  faf_effect_scan_tests
  faf_image_codec_tests
  faf_texture_quality_tests
  faf_sim_math_tests
  faf_replay_scan_tests
  faf_prefs_thread_tests
  faf_zip_offset_tests
  faf_recon_scroll_packet_tests
  faf_coroutine_tests
  faf_msdf_cook_tests
  faf_tread_rotation_tests
)
if(TARGET faf_netchannel_tests)
  list(APPEND _faf_existing_test_targets faf_netchannel_tests)
endif()
if(TARGET faf_gamelink_tests)
  list(APPEND _faf_existing_test_targets faf_gamelink_tests)
endif()
if(TARGET faf_remote_tests)
  list(APPEND _faf_existing_test_targets faf_remote_tests)
endif()
if(TARGET faf_msdf_safety_tests)
  list(APPEND _faf_existing_test_targets faf_msdf_safety_tests)
endif()
add_custom_target(existing_tests DEPENDS ${_faf_existing_test_targets})
set_target_properties(existing_tests PROPERTIES FOLDER "Tests/Existing")

add_subdirectory(vulkan)

# Engine tests: console programs linked against the engine's own objects
# (faf_engine, src/CMakeLists.txt). Use GoogleTest (gtest / gtest_main) for all
# tests instead of custom test harnesses.
#
#   cmake --build --preset clang-x64-release --target faf_tests
#   ctest --test-dir build/clang-x64-release --output-on-failure
#
# faf_tests builds every executable here that links gtest (cmake/FafTests.cmake).

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

# platform::net (issue #259): loopback sockets and the socket events the lockstep transport
# waits on; Linux runs the same file on NetPosix.cpp (cmake/FafLinux.cmake).
add_executable(faf_platform_net_tests EXCLUDE_FROM_ALL net/PlatformNetTests.cpp)
target_link_libraries(faf_platform_net_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_platform_net_tests PROPERTIES FOLDER "Tests/Net")
add_test(NAME platform_net COMMAND faf_platform_net_tests)
set_tests_properties(platform_net PROPERTIES LABELS "Net")

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

# Engine addition: the stable shadow box (ren_ShadowStable), pure maths with no device.
add_executable(faf_shadow_fit_tests EXCLUDE_FROM_ALL render/ShadowStableFitTests.cpp)
target_include_directories(faf_shadow_fit_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_shadow_fit_tests PRIVATE gtest_main)
set_target_properties(faf_shadow_fit_tests PROPERTIES FOLDER "Tests/Render")
add_test(NAME shadow_stable_fit COMMAND faf_shadow_fit_tests)
set_tests_properties(shadow_stable_fit PROPERTIES LABELS "Render")

# Engine addition: EffectScan.h against the std::regex patterns it replaced, on generated text.
# The SFD movie header parser on synthetic headers (moved from tools/sfd-inspect); no engine needed.
add_executable(faf_sfd_parser_tests EXCLUDE_FROM_ALL movie/SfdHeaderParserTests.cpp
  ${CMAKE_SOURCE_DIR}/src/moho/movie/sfd/SfdHeaderParser.cpp)
target_include_directories(faf_sfd_parser_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_sfd_parser_tests PRIVATE gtest_main)
set_target_properties(faf_sfd_parser_tests PROPERTIES FOLDER "Tests/Movie")
add_test(NAME sfd_header_parser COMMAND faf_sfd_parser_tests)
set_tests_properties(sfd_header_parser PROPERTIES LABELS "Movie")

add_executable(faf_effect_scan_tests EXCLUDE_FROM_ALL effect_scan/EffectScanTests.cpp)
target_include_directories(faf_effect_scan_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_effect_scan_tests PRIVATE gtest_main)
set_target_properties(faf_effect_scan_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME effect_scan COMMAND faf_effect_scan_tests)
set_tests_properties(effect_scan PROPERTIES LABELS "Existing")

# Engine addition (dedicated-server plan WP9.1): the server's encoder of the sim's effect operations, its per-view
# effects lane and the lane's reader; plan WP9.3: the client's applier of the lane.
add_executable(faf_effect_op_encoder_tests EXCLUDE_FROM_ALL server/EffectOpEncoderTests.cpp server/EffectOpRouterTests.cpp
  server/EffectLaneApplierTests.cpp
  ${CMAKE_SOURCE_DIR}/src/server/EffectOpEncoder.cpp ${CMAKE_SOURCE_DIR}/src/server/EffectOpRouter.cpp
  ${CMAKE_SOURCE_DIR}/src/remote/wire/EffectLane.cpp ${CMAKE_SOURCE_DIR}/src/remote/client/EffectLaneApplier.cpp)
target_include_directories(faf_effect_op_encoder_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_effect_op_encoder_tests PRIVATE gtest_main)
set_target_properties(faf_effect_op_encoder_tests PROPERTIES FOLDER "Tests/Headless")
add_test(NAME effect_op_encoder COMMAND faf_effect_op_encoder_tests)
set_tests_properties(effect_op_encoder PROPERTIES LABELS "Headless")

# Engine addition (dedicated-server plan WP10.9, WPR.14): the server-mode client's interpolation buffer, its beat
# synthesis and the display model they run under, on scripted view arrivals; no engine needed.
add_executable(faf_interp_buffer_tests EXCLUDE_FROM_ALL remote/InterpBufferTests.cpp
  ${CMAKE_SOURCE_DIR}/src/remote/client/InterpBuffer.cpp ${CMAKE_SOURCE_DIR}/src/remote/client/BeatSynthesis.cpp
  ${CMAKE_SOURCE_DIR}/src/remote/client/DisplayModel.cpp ${CMAKE_SOURCE_DIR}/src/remote/client/BeatClock.cpp)
target_include_directories(faf_interp_buffer_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_interp_buffer_tests PRIVATE gtest_main)
set_target_properties(faf_interp_buffer_tests PROPERTIES FOLDER "Tests/Headless")
add_test(NAME interp_buffer COMMAND faf_interp_buffer_tests)
set_tests_properties(interp_buffer PROPERTIES LABELS "Headless")

# Engine addition: where UserDecal:SetOrientation puts a decal's corner so it stays centred.
add_executable(faf_scripted_decal_tests EXCLUDE_FROM_ALL scripted_decal/PlacementTests.cpp)
target_include_directories(faf_scripted_decal_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_scripted_decal_tests PRIVATE gtest_main)
set_target_properties(faf_scripted_decal_tests PROPERTIES FOLDER "Tests/Render")
add_test(NAME scripted_decal_placement COMMAND faf_scripted_decal_tests)
set_tests_properties(scripted_decal_placement PROPERTIES LABELS "Render")

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

# Recorded games played back by headless with every checksum compared (tests/replay); skipped
# without FAF_REPLAY_DATA. Games take minutes, hence the timeout.
add_executable(faf_replay_playback_tests EXCLUDE_FROM_ALL replay/ReplayPlaybackTests.cpp)
target_link_libraries(faf_replay_playback_tests PRIVATE gtest_main)
# No engine library, so no force-included platform/PlatformDefines.h: the test includes it from src.
target_include_directories(faf_replay_playback_tests PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_compile_definitions(faf_replay_playback_tests PRIVATE FAF_HEADLESS_EXE="$<TARGET_FILE:headless>"
  FAF_REPLAY_ZOO_DIR="${CMAKE_CURRENT_SOURCE_DIR}/replay/zoo")
if(FAF_SERVER_MODE)
  # The server's checks (--seats, --oracle-check, --view-frames, ...) exist only in a server-mode headless.
  target_compile_definitions(faf_replay_playback_tests PRIVATE FAF_HEADLESS_SERVER_MODE=1)
endif()
add_dependencies(faf_replay_playback_tests headless)
set_target_properties(faf_replay_playback_tests PROPERTIES FOLDER "Tests/Replay")
add_test(NAME replay_playback COMMAND faf_replay_playback_tests)
set_tests_properties(replay_playback PROPERTIES LABELS "Replay" TIMEOUT 7200)

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

# Engine addition (#396): RScmResource::GetSkeleton from several threads at once
# (tests/resource); every thread must get the one skeleton built for the resource.
add_executable(faf_skeleton_build_thread_tests EXCLUDE_FROM_ALL resource/SkeletonBuildThreadTests.cpp)
target_link_libraries(faf_skeleton_build_thread_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_skeleton_build_thread_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME skeleton_build_threads COMMAND faf_skeleton_build_thread_tests)
set_tests_properties(skeleton_build_threads PROPERTIES LABELS "Existing")

# Engine addition (dedicated-server plan WPL.4, WPR.11): what the static
# initialisers of faf_main's objects registered (tests/registry).
add_executable(faf_registration_dump EXCLUDE_FROM_ALL registry/RegistrationDump.cpp)
target_link_libraries(faf_registration_dump PRIVATE faf_engine)

# Engine addition (dedicated-server plan WPL.4, WPR.11): every map in a list
# loaded with the client's and the headless terrain resource, compared
# (tests/terrain). Needs the game data: run it from a folder staged like the
# game's bin folder with --maps <list> /init <init.lua>; without them its test is skipped.
add_executable(faf_terrain_check EXCLUDE_FROM_ALL terrain/TerrainCheck.cpp)
target_link_libraries(faf_terrain_check PRIVATE faf_engine gtest)
set_target_properties(faf_terrain_check PROPERTIES FOLDER "Tests/Terrain")

# Engine addition (dedicated-server plan WPR.21): the difffuzz targets on the
# engine's objects, checked against retail's outputs (tests/math_dump/golden.txt)
# after every build (tools/difffuzz/dump.cmake).
set(FAF_MATH_DUMP_ENGINE faf_engine)
include("${CMAKE_SOURCE_DIR}/tools/difffuzz/dump.cmake")
add_subdirectory(remote)

add_subdirectory(memory)
add_subdirectory(tread_rotation)
add_subdirectory(core)
add_subdirectory(containers)
add_subdirectory(lua)
add_subdirectory(gal)
add_subdirectory(reflection)
add_subdirectory(render_math)
add_subdirectory(startup)
add_subdirectory(netcore)

# Entity update scroll snapshots and payload ownership.
add_executable(faf_recon_scroll_packet_tests EXCLUDE_FROM_ALL sim/ReconScrollPacketTests.cpp)
target_link_libraries(faf_recon_scroll_packet_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_recon_scroll_packet_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME recon_scroll_packet COMMAND faf_recon_scroll_packet_tests)
set_tests_properties(recon_scroll_packet PROPERTIES TIMEOUT 120 LABELS "Existing")

# Engine addition: water bodies filled over a height field (.plans/water-levels/PLAN.md).
add_executable(faf_water_bodies_tests EXCLUDE_FROM_ALL sim/WaterBodiesTests.cpp ${CMAKE_SOURCE_DIR}/src/moho/sim/WaterBodies.cpp)
target_include_directories(faf_water_bodies_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_water_bodies_tests PRIVATE gtest_main)
set_target_properties(faf_water_bodies_tests PROPERTIES FOLDER "Tests/Sim")
add_test(NAME water_bodies COMMAND faf_water_bodies_tests)
set_tests_properties(water_bodies PROPERTIES LABELS "Sim")

# Engine addition: the map's water queries with water bodies.
add_executable(faf_water_bodies_map_tests EXCLUDE_FROM_ALL sim/WaterBodiesMapTests.cpp)
target_link_libraries(faf_water_bodies_map_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_water_bodies_map_tests PROPERTIES FOLDER "Tests/Sim")
add_test(NAME water_bodies_map COMMAND faf_water_bodies_map_tests)
set_tests_properties(water_bodies_map PROPERTIES TIMEOUT 120 LABELS "Sim")

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

# Rendering-only bounded terrain splat output; no game data or renderer required.
add_executable(faf_splat_budget_tests EXCLUDE_FROM_ALL terrain/splat_budget/SplatBudgetTests.cpp)
target_link_libraries(faf_splat_budget_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_splat_budget_tests PROPERTIES FOLDER "Tests/Terrain")
add_test(NAME splat_budget COMMAND faf_splat_budget_tests)
set_tests_properties(splat_budget PROPERTIES TIMEOUT 120 LABELS "Terrain")

# Regression for lua damage stack; no game data required.
add_executable(faf_damage_callback_stack_tests EXCLUDE_FROM_ALL "lua/DamageCallbackStackTests.cpp")
target_link_libraries(faf_damage_callback_stack_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_damage_callback_stack_tests PROPERTIES FOLDER "Tests/Sim")
add_test(NAME damage_callback_stack COMMAND faf_damage_callback_stack_tests)
set_tests_properties(damage_callback_stack PROPERTIES LABELS "Sim")

# Regression for collision allocator; no game data required.
add_executable(faf_occupation_manager_tests EXCLUDE_FROM_ALL "collision_allocator/OccupationManagerTests.cpp")
target_link_libraries(faf_occupation_manager_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_occupation_manager_tests PROPERTIES FOLDER "Tests/Sim")
add_test(NAME occupation_manager COMMAND faf_occupation_manager_tests)
set_tests_properties(occupation_manager PROPERTIES LABELS "Sim")

# The map editor's terrain field library (src/editor/terrain, from FAF Studio): golden checksums at every thread count,
# the Generate ops, the interop ops. Engine independent.
add_executable(faf_editor_field_tests EXCLUDE_FROM_ALL editor/FieldTests.cpp editor/FieldLandTests.cpp editor/FieldInteropTests.cpp editor/ErosionTests.cpp
  editor/MapTexturesTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdMapTextures.cpp
  editor/GroundKindTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdGroundKind.cpp
  editor/MaskGenTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdMaskGen.cpp
  editor/RecipeTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdRecipes.cpp
  editor/TextureSetsTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdTexScale.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdTextureSets.cpp
  editor/SlopeRulesTests.cpp
  ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdErosion.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldEro2.cpp
  ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldCore.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldFilt.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldGen.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldLand.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldSc.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldPath.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldInterop.cpp)
target_include_directories(faf_editor_field_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(faf_editor_field_tests PRIVATE FAF_FIELD_CASES="${CMAKE_CURRENT_SOURCE_DIR}/editor/data/field_cases.lua"
  FAF_EROSION_CASES="${CMAKE_CURRENT_SOURCE_DIR}/editor/data/erosion_cases.lua")
target_compile_options(faf_editor_field_tests PRIVATE /EHsc -Wno-unused-function)
target_link_libraries(faf_editor_field_tests PRIVATE gtest_main)
set_target_properties(faf_editor_field_tests PROPERTIES FOLDER "Tests/Editor")
add_test(NAME editor_field COMMAND faf_editor_field_tests)

# The map editor height brush, symmetry check, height files and undo (src/editor/tools, src/editor/undo): exact symmetry,
# byte-exact undo, height images read back as written.
add_executable(faf_editor_brush_tests EXCLUDE_FROM_ALL editor/HeightBrushTests.cpp editor/HeightHistoryTests.cpp editor/SymmetryCheckTests.cpp editor/HeightFileTests.cpp
  editor/NewMapTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdNewMap.cpp
  editor/MaskBrushTests.cpp editor/MaskEncodingTests.cpp editor/MaskBrushOptionsTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdMaskBrush.cpp
  editor/BrushLibraryTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdBrushLibrary.cpp
  editor/SymmetryFollowTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdSymmetryFollow.cpp
  editor/ShaderProfileTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdShaderProfiles.cpp
  editor/LayerConvertTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdLayerConvert.cpp
  editor/SymmetrizeTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdSymmetrize.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldSc.cpp
  editor/SaveFileTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdSaveFile.cpp
  editor/MarkerTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdMarkers.cpp
  editor/DecalShapeTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdDecalShape.cpp
  editor/UnitTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdUnits.cpp
  editor/UnitFateTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdUnitFate.cpp
  editor/GroupOptionsTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdGroupOptions.cpp
  editor/LuaSyntaxTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdLuaSyntax.cpp
  editor/ViewStateTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdViewState.cpp
  editor/AdaptiveModelTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdAdaptiveModel.cpp
  editor/CheckTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdChecks.cpp
  editor/ShaderSlotTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdShaderSlots.cpp
  editor/NodeGraphTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/graph/EdNodeGraph.cpp
  editor/EmitterTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdEmitter.cpp
  editor/EffectGraphTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/graph/EdEffectGraph.cpp
  editor/TextureGraphTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/graph/EdTextureGraph.cpp
  editor/PathingTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdPathing.cpp
  editor/PackageTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdPackage.cpp
  editor/WaterPresetTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdWaterPreset.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdJson.cpp
  editor/LightingTests.cpp editor/ColourTextTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdLighting.cpp
  editor/MarkerPresetTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdMarkerPreset.cpp
  editor/UnitPresetTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdUnitPreset.cpp
  editor/LayerPresetTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdLayerPreset.cpp
  editor/PropPaintTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdPropPaint.cpp
  editor/SkyboxTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdSkybox.cpp
  editor/WaveTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdWaves.cpp
  editor/TerrainTypeTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdTerrainTypes.cpp
  editor/ImageChunkTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdImageChunks.cpp
  editor/ViewAidTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdViewAids.cpp
  editor/ArmySlotTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdArmySlots.cpp
  editor/AdaptiveTablesTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdAdaptiveTables.cpp
  editor/RecentMapsTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdRecentMaps.cpp
  editor/VaultTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdVault.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdHttp.cpp
  editor/FafApiTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdFafApi.cpp
  editor/CommandsTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdCommands.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdWindowChrome.cpp
  editor/KeymapTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdKeymap.cpp
  editor/WorkspacesTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdWorkspaces.cpp
  editor/StatusTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdStatus.cpp
  editor/SettingsTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdSettings.cpp
  editor/HomeModelTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdHomeModel.cpp
  editor/AutosaveTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdAutosave.cpp
  editor/HistoryTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdHistory.cpp
  editor/HelpTopicsTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdHelpTopics.cpp
  editor/ProblemsTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdProblems.cpp
  editor/CanvasFitTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdCanvasFit.cpp
  editor/DdsSizeTests.cpp
  editor/LuaApiTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdLuaApi.cpp
  editor/DebugRulesTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/EdDebugRules.cpp
  editor/UnitCatalogTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdUnitCatalog.cpp
  editor/LayoutTests.cpp
  editor/WaterBodiesEditTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdWaterBodies.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdLuaText.cpp
  ${CMAKE_SOURCE_DIR}/src/moho/sim/WaterBodies.cpp
  ${CMAKE_SOURCE_DIR}/src/editor/tools/EdHeightBrush.cpp ${CMAKE_SOURCE_DIR}/src/editor/tools/EdSymmetryCheck.cpp
  ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdErosion.cpp ${CMAKE_SOURCE_DIR}/src/editor/terrain/EdFieldCore.cpp
  ${CMAKE_SOURCE_DIR}/src/editor/tools/EdHeightFile.cpp
  ${CMAKE_SOURCE_DIR}/src/editor/undo/EdHeightHistory.cpp)
target_include_directories(faf_editor_brush_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
# The terrain library (Water erode, Rain and Deposit) turns running out of memory into an op error.
target_compile_options(faf_editor_brush_tests PRIVATE /EHsc)
# The zlib the engine links: 1.2.3 on both architectures (src/CMakeLists.txt).
target_link_libraries(faf_editor_brush_tests PRIVATE gtest_main ole32 windowscodecs zlib123 winhttp crypt32 shell32)
set_target_properties(faf_editor_brush_tests PROPERTIES FOLDER "Tests/Editor")
add_test(NAME editor_height_brush COMMAND faf_editor_brush_tests)
set_tests_properties(editor_height_brush PROPERTIES LABELS "Editor")

# The material editor's DDS files, read back by the engine's own decoder (so it links the engine).
add_executable(faf_editor_bake_tests EXCLUDE_FROM_ALL editor/TextureBakeTests.cpp editor/SoundMuteTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/graph/EdTextureBake.cpp
  ${CMAKE_SOURCE_DIR}/src/editor/graph/EdTextureGraph.cpp ${CMAKE_SOURCE_DIR}/src/editor/graph/EdNodeGraph.cpp ${CMAKE_SOURCE_DIR}/src/editor/doc/EdJson.cpp
  editor/ThemeTests.cpp ${CMAKE_SOURCE_DIR}/src/editor/ui/EdTheme.cpp)
target_include_directories(faf_editor_bake_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_editor_bake_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_editor_bake_tests PROPERTIES FOLDER "Tests/Editor")
add_test(NAME editor_texture_bake COMMAND faf_editor_bake_tests)
set_tests_properties(editor_texture_bake PROPERTIES LABELS "Editor")

# Engine addition: the cue AudioEngine::Play hands out, which outlives a rebuild of the XACT engine
# on a new sound output (src/moho/audio/RecoverableCue.h). Fake XACT cues and banks; no audio device.
add_executable(faf_audio_tests EXCLUDE_FROM_ALL audio/AudioCueRecoveryTests.cpp)
target_include_directories(faf_audio_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(faf_audio_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_audio_tests PROPERTIES FOLDER "Tests/Audio")
add_test(NAME audio_cue_recovery COMMAND faf_audio_tests)
set_tests_properties(audio_cue_recovery PROPERTIES LABELS "Audio")

# The shell's mouse events from window-system events: wheel positions on the screen, as
# WM_MOUSEWHEEL's (src/platform/shell/mouse.h). Shell.cpp is a client file, in faf_engine here;
# the Linux client links it into the client alone.
add_executable(faf_shell_mouse_tests EXCLUDE_FROM_ALL shell/ShellMouseEventTests.cpp)
target_link_libraries(faf_shell_mouse_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_shell_mouse_tests PROPERTIES FOLDER "Tests/Shell")
add_test(NAME shell_mouse COMMAND faf_shell_mouse_tests)
set_tests_properties(shell_mouse PROPERTIES LABELS "Shell")

add_executable(faf_slab_tests EXCLUDE_FROM_ALL entity/FixedSlabPoolTests.cpp)
target_link_libraries(faf_slab_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_slab_tests PROPERTIES FOLDER "Tests/Sim")
add_test(NAME slab_tests COMMAND faf_slab_tests)
set_tests_properties(slab_tests PROPERTIES LABELS "Sim")

# Every GoogleTest executable above and in the subdirectories. Keep this last: it sees only the
# targets defined before it, so a test added below it is never built by faf_tests and ctest
# reports it as Not Run.
include(FafTests)
faf_add_tests_target("${CMAKE_CURRENT_SOURCE_DIR}")

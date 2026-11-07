# netlink: peer links compatible with FAF's Java ICE adapter, on libjuice
# (issue #229). Used by faf-netbridge (src/netbridge) and later by the engine.
# Engine addition, not recovered code.

add_library(faf_netlink STATIC
  GameCounters.cpp
  Json.cpp
  Signal.cpp
  Link.cpp
  LinkKeys.cpp
  WebRtc.cpp)
target_include_directories(faf_netlink PUBLIC "${PROJECT_SOURCE_DIR}/src")
# The test shaping file is read with plain getenv, fopen and fscanf, as faf_engine does.
if(WIN32)
  target_compile_definitions(faf_netlink PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
target_link_libraries(faf_netlink PUBLIC faf_juice PRIVATE faf_datachannel faf_netchannel faf_monocypher faf_codegen)
# WebRtc.cpp catches libdatachannel's exceptions (issue #239); the root
# CMakeLists.txt leaves exception handling to each target.
if(MSVC)
  set_source_files_properties(WebRtc.cpp PROPERTIES COMPILE_OPTIONS "/EHsc")
endif()
set_target_properties(faf_netlink PROPERTIES FOLDER "net")

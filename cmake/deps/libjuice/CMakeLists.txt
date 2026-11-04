# libjuice 1.7.4 (MPL-2.0, dependencies/libjuice/LICENSE): the ICE agent
# (RFC 8445, STUN, TURN) behind src/netlink. dependencies/libjuice is the
# unmodified tag archive, see cmake/FafDependencies.cmake. Built here as one
# static library with the engine's code generation; libjuice's own
# CMakeLists.txt is not used, so its options are the definitions below.
#
#   USE_NETTLE=0   its own SHA-1/SHA-256 and HMAC, no Nettle
#   NO_SERVER      the built-in STUN/TURN server is left out (tests use
#                  tools/turnsrv)

set(_juice_src "${FAF_DEPENDENCIES_DIR}/libjuice")
if(NOT EXISTS "${_juice_src}/src/agent.c")
  message(FATAL_ERROR "libjuice sources not found in ${_juice_src} (cmake -P cmake/FafDependencies.cmake)")
endif()

add_library(faf_juice STATIC
  "${_juice_src}/src/addr.c" "${_juice_src}/src/agent.c" "${_juice_src}/src/crc32.c"
  "${_juice_src}/src/const_time.c" "${_juice_src}/src/conn.c" "${_juice_src}/src/conn_poll.c"
  "${_juice_src}/src/conn_thread.c" "${_juice_src}/src/conn_mux.c" "${_juice_src}/src/base64.c"
  "${_juice_src}/src/hash.c" "${_juice_src}/src/hmac.c" "${_juice_src}/src/ice.c"
  "${_juice_src}/src/juice.c" "${_juice_src}/src/log.c" "${_juice_src}/src/random.c"
  "${_juice_src}/src/server.c" "${_juice_src}/src/stun.c" "${_juice_src}/src/timestamp.c"
  "${_juice_src}/src/tcp.c" "${_juice_src}/src/turn.c" "${_juice_src}/src/udp.c")
target_include_directories(faf_juice PUBLIC "${_juice_src}/include")
target_include_directories(faf_juice PRIVATE "${_juice_src}/include/juice" "${_juice_src}/src")
target_compile_definitions(faf_juice PUBLIC JUICE_STATIC)
target_compile_definitions(faf_juice PRIVATE JUICE_EXPORTS USE_NETTLE=0 NO_SERVER
  $<$<CONFIG:Release>:RELEASE=1>)
set_target_properties(faf_juice PROPERTIES C_STANDARD 11 FOLDER "dependencies")
if(FAF_LINUX)
  target_compile_options(faf_juice PRIVATE -w)
  find_package(Threads REQUIRED)
  target_link_libraries(faf_juice PRIVATE Threads::Threads)
else()
  target_compile_definitions(faf_juice PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_options(faf_juice PRIVATE /W0)
  target_link_libraries(faf_juice PUBLIC ws2_32 bcrypt)
endif()
target_link_libraries(faf_juice PRIVATE faf_codegen)

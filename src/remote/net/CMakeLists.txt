# The net channel (plan §7.1, D1; WP10.2, WP10.3, WP10.6, WP10.8): datagram header and acks,
# the reliable stream, AEAD, keepalive and statistics. No engine dependency and no I/O, so
# every build has it: the dedicated server on Linux, and the client for links between our
# engines (issue #240). Tests: tests/remote/net (faf_netchannel_tests).

if(NOT TARGET faf_monocypher)
  return()  # cmake/deps/monocypher said why
endif()

add_library(faf_netchannel STATIC
  Datagram.cpp
  DatagramCipher.cpp
  GameLinks.cpp
  Handshake.cpp
  LobbySignals.cpp
  NetChannel.cpp
  ReliableStream.cpp
  StyleProof.cpp
  UdpSocket.cpp
)
target_include_directories(faf_netchannel PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_compile_features(faf_netchannel PUBLIC cxx_std_20)
target_link_libraries(faf_netchannel PRIVATE faf_monocypher faf_codegen)
if(FAF_LINUX)
  target_compile_options(faf_netchannel PRIVATE -Wall -Wextra)
else()
  target_compile_options(faf_netchannel PRIVATE /W4 /EHsc)
  target_link_libraries(faf_netchannel PRIVATE ws2_32 bcrypt)
endif()

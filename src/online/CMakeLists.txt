# faf_online: talking to FAF and to our servers, shared by the map editor and the game's launcher
# (.plans/ingame-launcher, WP1-WP2): JSON, URL encoding, FAF's sign-in and lobby, and the platform:: parts they stand
# on (HTTP and WebSocket requests, the sealed token store, running a helper program). Engine addition, not recovered
# code.

add_library(faf_online STATIC
  ControlService.cpp
  FafAuth.cpp
  FafLobby.cpp
  FafReplay.cpp
  FafVault.cpp
  GameLink.cpp
  Json.cpp
  LaunchArgs.cpp
  ReplayRelay.cpp
  "${PROJECT_SOURCE_DIR}/src/netbridge/GpgNet.cpp"
  Url.cpp)
target_include_directories(faf_online PUBLIC "${PROJECT_SOURCE_DIR}/src")
if(FAFRE_PLATFORM_WINDOWS)
  target_sources(faf_online PRIVATE
    "${PROJECT_SOURCE_DIR}/src/platform/windows/HttpWindows.cpp"
    "${PROJECT_SOURCE_DIR}/src/platform/windows/ProcessWindows.cpp"
    "${PROJECT_SOURCE_DIR}/src/platform/windows/SecretStoreWindows.cpp")
  target_link_libraries(faf_online PUBLIC winhttp crypt32 ws2_32 shell32 ole32)
else()
  # Linux and macOS: BSD sockets with Mbed TLS (the build's faf_mbedtls, cmake/deps/libdatachannel).
  target_sources(faf_online PRIVATE
    "${PROJECT_SOURCE_DIR}/src/platform/posix/HttpPosix.cpp"
    "${PROJECT_SOURCE_DIR}/src/platform/posix/ProcessPosix.cpp"
    "${PROJECT_SOURCE_DIR}/src/platform/posix/SecretStorePosix.cpp")
  find_package(Threads REQUIRED)
  target_link_libraries(faf_online PUBLIC faf_mbedtls Threads::Threads)
endif()
# zlib and zstd: the replay vault's .fafreplay files (FafReplay.cpp).
target_link_libraries(faf_online PRIVATE faf_codegen zlib123 faf_zstd)
set_target_properties(faf_online PROPERTIES FOLDER "net")

# faf-online-probe: signs in to FAF's lobby and prints what it sees (WP2's check, local stacks and the live server).
add_executable(faf_online_probe EXCLUDE_FROM_ALL probe/ProbeMain.cpp)
target_link_libraries(faf_online_probe PRIVATE faf_online faf_codegen)
# The token and data folders come from plain getenv, as faf_netlink reads its settings.
target_compile_definitions(faf_online_probe PRIVATE _CRT_SECURE_NO_WARNINGS)
set_target_properties(faf_online_probe PROPERTIES OUTPUT_NAME "faf-online-probe" FOLDER "net")

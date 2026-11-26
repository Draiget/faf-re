# faf_online: talking to FAF and to our servers, shared by the map editor and the game's launcher
# (.plans/ingame-launcher, WP1): JSON, URL encoding, FAF's sign-in, and the platform:: parts they stand on
# (HTTP and WebSocket requests, the sealed token store). Engine addition, not recovered code.

add_library(faf_online STATIC
  FafAuth.cpp
  Json.cpp
  Url.cpp)
target_include_directories(faf_online PUBLIC "${PROJECT_SOURCE_DIR}/src")
if(FAFRE_PLATFORM_WINDOWS)
  target_sources(faf_online PRIVATE
    "${PROJECT_SOURCE_DIR}/src/platform/windows/HttpWindows.cpp"
    "${PROJECT_SOURCE_DIR}/src/platform/windows/SecretStoreWindows.cpp")
  target_link_libraries(faf_online PUBLIC winhttp crypt32)
endif()
target_link_libraries(faf_online PRIVATE faf_codegen)
set_target_properties(faf_online PROPERTIES FOLDER "net")

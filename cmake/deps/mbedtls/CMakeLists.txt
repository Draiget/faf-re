# Mbed TLS 3.6 (dependencies/mbedtls, cmake/FafDependencies.cmake) as faf_mbedtls: libdatachannel's DTLS
# (cmake/deps/libdatachannel) and faf_online's HTTPS and WebSocket on Linux and macOS (src/platform/posix/HttpPosix.cpp)
# use it. Built only for what links it.

set(_mbed "${FAF_DEPENDENCIES_DIR}/mbedtls")
if(NOT EXISTS "${_mbed}/library/ssl_tls.c")
  message(FATAL_ERROR "${_mbed}/library/ssl_tls.c not found (cmake -P cmake/FafDependencies.cmake)")
endif()
file(GLOB _mbed_sources CONFIGURE_DEPENDS "${_mbed}/library/*.c")
add_library(faf_mbedtls STATIC ${_mbed_sources})
target_include_directories(faf_mbedtls PUBLIC "${_mbed}/include")
target_include_directories(faf_mbedtls PRIVATE "${_mbed}/library")
# faf_mbedtls_config.h: DTLS-SRTP on, which libdatachannel's DTLS code uses.
target_compile_definitions(faf_mbedtls PUBLIC
  "MBEDTLS_USER_CONFIG_FILE=\"${CMAKE_CURRENT_SOURCE_DIR}/faf_mbedtls_config.h\"")
set_target_properties(faf_mbedtls PROPERTIES C_STANDARD 99 FOLDER "dependencies")
if(FAFRE_PLATFORM_POSIX)
  target_compile_options(faf_mbedtls PRIVATE -w)
else()
  target_compile_definitions(faf_mbedtls PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_options(faf_mbedtls PRIVATE /W0)
  target_link_libraries(faf_mbedtls PUBLIC bcrypt)
endif()

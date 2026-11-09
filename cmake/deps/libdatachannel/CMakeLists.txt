# libdatachannel 0.24.6 (MPL-2.0) with what WebRTC data channels need (issue
# #238): usrsctp (BSD-3-Clause) for SCTP, Mbed TLS 3.6.7 (Apache-2.0) for
# DTLS, plog (MIT, headers only) for its log, and faf_juice (libjuice 1.7.4,
# the tag libdatachannel 0.24.6 pins) for ICE. Every tree is the unmodified
# archive, see cmake/FafDependencies.cmake; their own CMakeLists.txt files are
# not used, so their options are the definitions below.
#
#   RTC_ENABLE_MEDIA=0       no media tracks, RTP or SRTP (libsrtp not needed)
#   RTC_ENABLE_WEBSOCKET=0   no WebSocket client or server
#   USE_MBEDTLS=1            DTLS and certificates through Mbed TLS, with
#                            MBEDTLS_SSL_DTLS_SRTP (faf_mbedtls_config.h)
#   usrsctp                  without INET / INET6: libdatachannel feeds it
#                            through AF_CONN, as its CMakeLists.txt sets
#                            sctp_inet / sctp_inet6 OFF

set(_dc "${FAF_DEPENDENCIES_DIR}/libdatachannel")
set(_sctp "${FAF_DEPENDENCIES_DIR}/usrsctp/usrsctplib")
set(_mbed "${FAF_DEPENDENCIES_DIR}/mbedtls")
set(_plog "${FAF_DEPENDENCIES_DIR}/plog")
foreach(_probe "${_dc}/src/peerconnection.cpp" "${_sctp}/user_socket.c" "${_mbed}/library/ssl_tls.c"
               "${_plog}/include/plog/Log.h")
  if(NOT EXISTS "${_probe}")
    message(FATAL_ERROR "${_probe} not found (cmake -P cmake/FafDependencies.cmake)")
  endif()
endforeach()

# --- Mbed TLS ----------------------------------------------------------------
file(GLOB _mbed_sources CONFIGURE_DEPENDS "${_mbed}/library/*.c")
add_library(faf_mbedtls STATIC ${_mbed_sources})
target_include_directories(faf_mbedtls PUBLIC "${_mbed}/include")
target_include_directories(faf_mbedtls PRIVATE "${_mbed}/library")
# faf_mbedtls_config.h: DTLS-SRTP on, which libdatachannel's DTLS code uses.
target_compile_definitions(faf_mbedtls PUBLIC
  "MBEDTLS_USER_CONFIG_FILE=\"${CMAKE_CURRENT_SOURCE_DIR}/faf_mbedtls_config.h\"")
set_target_properties(faf_mbedtls PROPERTIES C_STANDARD 99 FOLDER "dependencies")

# --- usrsctp -----------------------------------------------------------------
add_library(faf_usrsctp STATIC
  "${_sctp}/netinet/sctp_asconf.c" "${_sctp}/netinet/sctp_auth.c" "${_sctp}/netinet/sctp_bsd_addr.c"
  "${_sctp}/netinet/sctp_callout.c" "${_sctp}/netinet/sctp_cc_functions.c" "${_sctp}/netinet/sctp_crc32.c"
  "${_sctp}/netinet/sctp_indata.c" "${_sctp}/netinet/sctp_input.c" "${_sctp}/netinet/sctp_output.c"
  "${_sctp}/netinet/sctp_pcb.c" "${_sctp}/netinet/sctp_peeloff.c" "${_sctp}/netinet/sctp_sha1.c"
  "${_sctp}/netinet/sctp_ss_functions.c" "${_sctp}/netinet/sctp_sysctl.c" "${_sctp}/netinet/sctp_timer.c"
  "${_sctp}/netinet/sctp_userspace.c" "${_sctp}/netinet/sctp_usrreq.c" "${_sctp}/netinet/sctputil.c"
  "${_sctp}/netinet6/sctp6_usrreq.c" "${_sctp}/user_environment.c" "${_sctp}/user_mbuf.c"
  "${_sctp}/user_recv_thread.c" "${_sctp}/user_socket.c")
target_include_directories(faf_usrsctp PUBLIC "${_sctp}")
target_compile_definitions(faf_usrsctp PRIVATE __Userspace__ SCTP_SIMPLE_ALLOCATOR SCTP_PROCESS_LEVEL_LOCKS)
target_compile_definitions(faf_usrsctp PUBLIC "SCTP_STDINT_INCLUDE=<stdint.h>")
set_target_properties(faf_usrsctp PROPERTIES C_STANDARD 99 FOLDER "dependencies")

# --- libdatachannel ----------------------------------------------------------
set(_dc_sources
  candidate.cpp channel.cpp configuration.cpp datachannel.cpp dependencydescriptor.cpp description.cpp
  iceudpmuxlistener.cpp mediahandler.cpp global.cpp message.cpp peerconnection.cpp rtcpreceivingsession.cpp
  track.cpp websocket.cpp websocketserver.cpp rtppacketizationconfig.cpp rtcpsrreporter.cpp rtppacketizer.cpp
  rtpdepacketizer.cpp h264rtppacketizer.cpp h264rtpdepacketizer.cpp nalunit.cpp h265rtppacketizer.cpp
  h265rtpdepacketizer.cpp h265nalunit.cpp av1rtppacketizer.cpp rtcpnackresponder.cpp rtp.cpp capi.cpp
  plihandler.cpp pacinghandler.cpp rembhandler.cpp
  impl/certificate.cpp impl/channel.cpp impl/datachannel.cpp impl/dtlssrtptransport.cpp impl/dtlstransport.cpp
  impl/icetransport.cpp impl/iceudpmuxlistener.cpp impl/init.cpp impl/peerconnection.cpp impl/logcounter.cpp
  impl/sctptransport.cpp impl/threadpool.cpp impl/tls.cpp impl/track.cpp impl/utils.cpp impl/processor.cpp
  impl/sha.cpp impl/pollinterrupter.cpp impl/pollservice.cpp impl/http.cpp impl/httpproxytransport.cpp
  impl/tcpserver.cpp impl/tcptransport.cpp impl/tlstransport.cpp impl/transport.cpp
  impl/verifiedtlstransport.cpp impl/websocket.cpp impl/websocketserver.cpp impl/wstransport.cpp
  impl/wshandshake.cpp)
list(TRANSFORM _dc_sources PREPEND "${_dc}/src/")
add_library(faf_datachannel STATIC ${_dc_sources})
target_include_directories(faf_datachannel PUBLIC "${_dc}/include")
target_include_directories(faf_datachannel PRIVATE "${_dc}/include/rtc" "${_dc}/src" "${_plog}/include")
target_compile_definitions(faf_datachannel PUBLIC RTC_STATIC RTC_ENABLE_MEDIA=0 RTC_ENABLE_WEBSOCKET=0)
target_compile_definitions(faf_datachannel PRIVATE RTC_EXPORTS USE_MBEDTLS=1 USE_GNUTLS=0 USE_NICE=0
  RTC_SYSTEM_SRTP=0)
set_target_properties(faf_datachannel PROPERTIES CXX_STANDARD 17 FOLDER "dependencies")
target_link_libraries(faf_datachannel PRIVATE faf_usrsctp faf_mbedtls faf_juice)

if(FAF_LINUX)
  foreach(_t faf_mbedtls faf_usrsctp faf_datachannel)
    target_compile_options(${_t} PRIVATE -w)
  endforeach()
  find_package(Threads REQUIRED)
  target_link_libraries(faf_usrsctp PUBLIC Threads::Threads)
  target_link_libraries(faf_datachannel PUBLIC Threads::Threads)
else()
  foreach(_t faf_mbedtls faf_usrsctp faf_datachannel)
    target_compile_definitions(${_t} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
    target_compile_options(${_t} PRIVATE /W0)
  endforeach()
  # libdatachannel throws; the root CMakeLists.txt leaves exceptions to each target.
  target_compile_options(faf_datachannel PRIVATE /EHsc)
  target_link_libraries(faf_mbedtls PUBLIC bcrypt)
  target_link_libraries(faf_usrsctp PUBLIC ws2_32 iphlpapi)
  target_link_libraries(faf_datachannel PUBLIC ws2_32)
endif()
# Built only for what links them (faf_netlink since #239, faf_datachannel_test).
foreach(_t faf_mbedtls faf_usrsctp faf_datachannel)
  target_link_libraries(${_t} PRIVATE faf_codegen)
  set_target_properties(${_t} PROPERTIES EXCLUDE_FROM_ALL TRUE)
endforeach()

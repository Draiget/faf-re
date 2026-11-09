# faf-netbridge: the launcher-compatible ICE adapter replacement (issue #230).
# Engine addition, not recovered code.

add_executable(faf_netbridge
  Bridge.cpp
  GpgNet.cpp
  main.cpp)
target_link_libraries(faf_netbridge PRIVATE faf_netlink faf_codegen)
if(WIN32)
  target_link_libraries(faf_netbridge PRIVATE ws2_32)
  # The environment overrides and the log file use plain getenv and fopen, as faf_netlink does.
  target_compile_definitions(faf_netbridge PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
set_target_properties(faf_netbridge PROPERTIES OUTPUT_NAME "faf-netbridge" FOLDER "net")

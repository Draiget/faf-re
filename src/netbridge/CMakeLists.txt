# faf-netbridge: the launcher-compatible ICE adapter replacement (issue #230).
# Engine addition, not recovered code.

add_executable(faf_netbridge
  Bridge.cpp
  GpgNet.cpp
  main.cpp)
target_link_libraries(faf_netbridge PRIVATE faf_netlink faf_codegen)
if(WIN32)
  target_link_libraries(faf_netbridge PRIVATE ws2_32)
endif()
set_target_properties(faf_netbridge PROPERTIES OUTPUT_NAME "faf-netbridge" FOLDER "net")

# netlink: peer links compatible with FAF's Java ICE adapter, on libjuice
# (issue #229). Used by faf-netbridge (src/netbridge) and later by the engine.
# Engine addition, not recovered code.

add_library(faf_netlink STATIC
  Json.cpp
  Signal.cpp
  Link.cpp)
target_include_directories(faf_netlink PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(faf_netlink PUBLIC faf_juice PRIVATE faf_codegen)
set_target_properties(faf_netlink PROPERTIES FOLDER "net")

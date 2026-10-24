# Server mode (FAF_SERVER_MODE, see docs/SWITCHES.md). Paths are relative to src/.
#
# FAF_REMOTE_CLIENT_SOURCES: the client half, compiled into faf_engine. These go after every
# FAF_ENGINE_SOURCES object, so the engine's static-init order (see sources.cmake) is
# unchanged.

set(FAF_REMOTE_CLIENT_SOURCES
  remote/client/ServerConnect.cpp
)

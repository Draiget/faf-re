# Server mode (FAF_SERVER_MODE, see docs/SWITCHES.md). Paths are relative to src/.
#
# Both lists are compiled into faf_engine after every FAF_ENGINE_SOURCES object, so the
# engine's static-init order (see sources.cmake) is unchanged.
#
# FAF_REMOTE_SOURCES: shared by client and server (D11): the wire format.
# FAF_REMOTE_CLIENT_SOURCES: the client half.

set(FAF_REMOTE_SOURCES
  remote/FrameBuilder.cpp
  remote/ContentTables.cpp
  remote/wire/BitStream.cpp
  remote/wire/EntityFrame.cpp
  remote/wire/OrdinalTable.cpp
  remote/wire/Quantize.cpp
  remote/wire/SoundTable.cpp
  remote/wire/WireVersion.cpp
)

set(FAF_REMOTE_CLIENT_SOURCES
  remote/client/RemoteSimDriver.cpp
  remote/client/ServerConnect.cpp
  remote/client/SessionSummary.cpp
  remote/client/SyncRebuilder.cpp
)

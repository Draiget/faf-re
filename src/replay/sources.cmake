# Server mode (FAF_SERVER_MODE, see docs/SWITCHES.md). Paths are relative to src/.
#
# FAF_REPLAY_SOURCES: faf-replay, the headless replay runner. Its own sources only; it links
# every faf_engine object (v1: wx, D3D and XACT are linked but never started).

set(FAF_REPLAY_SOURCES
  replay/ReplayMain.cpp
  replay/ReplayRunner.cpp
  replay/ReplayWireStats.cpp
)

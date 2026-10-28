# Server mode (FAF_SERVER_MODE, see docs/SWITCHES.md). Paths are relative to src/.
#
# FAF_HEADLESS_SOURCES: headless, the headless replay runner. Its own sources only; the
# simulation's objects come from faf_engine (Windows) or faf_sim (Linux).

set(FAF_HEADLESS_SOURCES
  headless/ReplayBoneStats.cpp
  headless/ReplayCommandCheck.cpp
  headless/ReplayFpuReport.cpp
  headless/ReplayLaunchCheck.cpp
  headless/ReplayLuaState.cpp
  headless/HeadlessMain.cpp
  headless/ReplayRunner.cpp
  headless/ReplaySyncWriters.cpp
  headless/ReplayWireStats.cpp
)

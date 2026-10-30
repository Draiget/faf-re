# headless, the console replay runner (docs/SWITCHES.md, "headless"). Paths are relative
# to src/.
#
# FAF_HEADLESS_SOURCES: its own sources only; the simulation comes from faf_sim
# (src/CMakeLists.txt, cmake/FafLinux.cmake). Every Windows build has headless; FAF_SERVER_MODE adds the
# wire format and the remote client (src/remote), which --wire-stats, --loopback,
# --command-check and --oracle-check use. Without it the build leaves out FAF_HEADLESS_SERVER_SOURCES and
# those switches (#if FAF_SERVER_MODE in the rest). The Linux build is always server mode.

set(FAF_HEADLESS_SOURCES
  headless/ReplayBoneStats.cpp
  headless/ReplayCommandCheck.cpp
  headless/ReplayFpuReport.cpp
  headless/ReplayLaunchCheck.cpp
  headless/ReplayLuaState.cpp
  headless/ReplayOracleCheck.cpp
  headless/HeadlessMain.cpp
  headless/ReplayRunner.cpp
  headless/ReplaySyncWriters.cpp
  headless/ReplayWireStats.cpp
)

set(FAF_HEADLESS_SERVER_SOURCES
  headless/ReplayCommandCheck.cpp
  headless/ReplayOracleCheck.cpp
  headless/ReplayWireStats.cpp
)

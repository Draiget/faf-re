# The map editor's own sources (src/editor/CMakeLists.txt). Paths are relative to src/editor.

set(FAF_EDITOR_SOURCES
  EdMain.cpp
  EdApp.cpp
  EdLog.cpp
  EdMemMap.cpp
  EdMemTrace.cpp
  EdPlay.cpp
  EdShell.cpp
  EdTools.cpp
  doc/EdDocument.cpp
  doc/EdMapFile.cpp
  doc/EdRoundTrip.cpp
  tools/EdHeightBrush.cpp
  tools/EdSymmetryCheck.cpp
  undo/EdHeightHistory.cpp
  view/EdMapScene.cpp
  ui/EdImGuiRenderer.cpp
)

// The map editor's entry point (.plans/map-editor). faf_engine carries the game's WinMain, so
// the editor starts here instead (/ENTRY:mainCRTStartup in src/editor/CMakeLists.txt).

#include "editor/EdApp.h"

int main()
{
  return faf::editor::RunEditor();
}

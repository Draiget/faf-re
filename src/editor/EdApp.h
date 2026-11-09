#pragma once

namespace faf::editor
{
  /**
   * Runs the map editor: the engine's common services (log, reflection types, the game data
   * through `/init <file>`), a window with a Direct3D 12 or Vulkan device, and the editor's
   * panels until the window closes. Returns the process exit code.
   */
  int RunEditor();
} // namespace faf::editor

#pragma once

#include <string>

namespace faf::editor
{
  class EdDevice;
  class EdLog;

  /**
   * The editor's window layout: the menu bar, the docked panels (tools, 3D viewport, map, log)
   * and the status bar. Stage 0 of .plans/map-editor: the panels are in place; the viewport,
   * tools and map panels get their content in the later stages.
   */
  class EdShell
  {
  public:
    EdShell(EdDevice& device, EdLog& log);

    /** Builds this frame's UI. Returns false when the user chose File > Exit. */
    [[nodiscard]] bool Draw();

  private:
    void BuildDefaultLayout(unsigned int dockspaceId);
    void DrawMenuBar();
    void DrawToolsPanel();
    void DrawViewportPanel();
    void DrawMapPanel();
    void DrawStatusBar();

    EdDevice& mDevice;
    EdLog& mLog;
    std::string mAdapter;
    std::string mSwapChain;
    int mTool = 1;
    bool mExit = false;
    bool mShowDemo = false;
    bool mShowTools = true;
    bool mShowViewport = true;
    bool mShowMap = true;
    bool mShowLog = true;
    bool mLayoutBuilt = false;
  };
} // namespace faf::editor

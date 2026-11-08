#include "editor/EdShell.h"

#include <cstdio>

#include "editor/EdDevice.h"
#include "editor/EdLog.h"
#include "gpg/gal/Device.hpp"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  namespace
  {
    constexpr const char* kToolsWindow = "Tools";
    constexpr const char* kViewportWindow = "Viewport";
    constexpr const char* kMapWindow = "Map";
    constexpr const char* kLogWindow = "Log";

    // The tools the plan lists, in its order (.plans/map-editor, "Goal").
    constexpr const char* kTools[] = {"Select", "Terrain", "Texture", "Water", "Props", "Decals", "Markers"};
  } // namespace

  EdShell::EdShell(EdDevice& device, EdLog& log)
    : mDevice(device)
    , mLog(log)
  {
    gpg::gal::DeviceRuntimeInfo info;
    if (gpg::gal::Device* const gal = device.Gal(); gal != nullptr && gal->GetRuntimeInfo(info)) {
      mAdapter = info.adapter.c_str();
      mSwapChain = info.swapChain.c_str();
    }
  }

  bool EdShell::Draw()
  {
    DrawMenuBar();

    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const float statusHeight = ImGui::GetFrameHeight();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - statusHeight));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kHostFlags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
                                            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
                                            ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBackground;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("##EditorDockHost", nullptr, kHostFlags);
    ImGui::PopStyleVar(3);
    const ImGuiID dockspaceId = ImGui::GetID("EditorDockSpace");
    if (!mLayoutBuilt) {
      mLayoutBuilt = true;
      if (ImGui::DockBuilderGetNode(dockspaceId) == nullptr) {
        BuildDefaultLayout(dockspaceId);
      }
    }
    ImGui::DockSpace(dockspaceId, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_PassthruCentralNode);
    ImGui::End();

    if (mShowTools) {
      DrawToolsPanel();
    }
    if (mShowViewport) {
      DrawViewportPanel();
    }
    if (mShowMap) {
      DrawMapPanel();
    }
    if (mShowLog) {
      if (ImGui::Begin(kLogWindow, &mShowLog)) {
        mLog.Draw();
      }
      ImGui::End();
    }
    if (mShowDemo) {
      ImGui::ShowDemoWindow(&mShowDemo);
    }
    DrawStatusBar();
    return !mExit;
  }

  void EdShell::BuildDefaultLayout(const unsigned int dockspaceId)
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::DockBuilderRemoveNode(dockspaceId);
    ImGui::DockBuilderAddNode(dockspaceId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspaceId, viewport->WorkSize);
    ImGuiID center = dockspaceId;
    const ImGuiID left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.18f, nullptr, &center);
    const ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.24f, nullptr, &center);
    const ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.24f, nullptr, &center);
    ImGui::DockBuilderDockWindow(kToolsWindow, left);
    ImGui::DockBuilderDockWindow(kMapWindow, right);
    ImGui::DockBuilderDockWindow(kLogWindow, bottom);
    ImGui::DockBuilderDockWindow(kViewportWindow, center);
    ImGui::DockBuilderFinish(dockspaceId);
  }

  void EdShell::DrawMenuBar()
  {
    if (!ImGui::BeginMainMenuBar()) {
      return;
    }
    if (ImGui::BeginMenu("File")) {
      ImGui::BeginDisabled();
      ImGui::MenuItem("New map...", "Ctrl+N");
      ImGui::MenuItem("Open map...", "Ctrl+O");
      ImGui::MenuItem("Save", "Ctrl+S");
      ImGui::MenuItem("Save as new version...");
      ImGui::EndDisabled();
      ImGui::Separator();
      if (ImGui::MenuItem("Exit", "Alt+F4")) {
        mExit = true;
      }
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
      ImGui::MenuItem(kToolsWindow, nullptr, &mShowTools);
      ImGui::MenuItem(kViewportWindow, nullptr, &mShowViewport);
      ImGui::MenuItem(kMapWindow, nullptr, &mShowMap);
      ImGui::MenuItem(kLogWindow, nullptr, &mShowLog);
      ImGui::Separator();
      if (ImGui::MenuItem("Reset layout")) {
        BuildDefaultLayout(ImGui::GetID("EditorDockSpace"));
      }
      ImGui::MenuItem("ImGui demo", nullptr, &mShowDemo);
      ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
  }

  void EdShell::DrawToolsPanel()
  {
    if (ImGui::Begin(kToolsWindow, &mShowTools)) {
      for (int i = 0; i < static_cast<int>(IM_ARRAYSIZE(kTools)); ++i) {
        if (ImGui::Selectable(kTools[i], mTool == i)) {
          mTool = i;
        }
      }
      ImGui::Separator();
      ImGui::TextWrapped("The tools come in stages 3 to 6 of the plan (.plans/map-editor).");
    }
    ImGui::End();
  }

  void EdShell::DrawViewportPanel()
  {
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    const bool open = ImGui::Begin(kViewportWindow, &mShowViewport);
    ImGui::PopStyleVar();
    if (open) {
      const ImVec2 origin = ImGui::GetCursorScreenPos();
      const ImVec2 size = ImGui::GetContentRegionAvail();
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      draw->AddRectFilled(origin, ImVec2(origin.x + size.x, origin.y + size.y), IM_COL32(13, 15, 18, 255));
      const char* const line1 = "3D viewport";
      const char* const line2 = "The game's terrain, water, decal and mesh renderers draw here from stage 1.";
      const ImVec2 size1 = ImGui::CalcTextSize(line1);
      const ImVec2 size2 = ImGui::CalcTextSize(line2);
      const float middleY = origin.y + size.y * 0.5f;
      draw->AddText(ImVec2(origin.x + (size.x - size1.x) * 0.5f, middleY - size1.y), IM_COL32(220, 220, 225, 255), line1);
      draw->AddText(ImVec2(origin.x + (size.x - size2.x) * 0.5f, middleY + 4.0f), IM_COL32(140, 147, 157, 255), line2);
    }
    ImGui::End();
  }

  void EdShell::DrawMapPanel()
  {
    if (ImGui::Begin(kMapWindow, &mShowMap)) {
      ImGui::TextDisabled("No map open.");
      ImGui::Spacing();
      ImGui::TextWrapped("Opening and saving FAF maps is stage 2 of the plan.");
    }
    ImGui::End();
  }

  void EdShell::DrawStatusBar()
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const float height = ImGui::GetFrameHeight();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - height));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoDocking |
                                        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                                        ImGuiWindowFlags_NoNav;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 2.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    if (ImGui::Begin("##StatusBar", nullptr, kFlags)) {
      ImGui::Text("%s", mDevice.ApiName());
      if (!mSwapChain.empty()) {
        ImGui::SetItemTooltip("Swap chain: %s", mSwapChain.c_str());
      }
      if (!mAdapter.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", mAdapter.c_str());
      }
      ImGui::SameLine();
      ImGui::TextDisabled("| %ux%u", mDevice.Width(), mDevice.Height());
      const int warnings = mLog.WarningCount();
      if (warnings > 0) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "| %d warnings in the log", warnings);
      }
      const char* const fps = "%.0f fps";
      char text[32];
      (void)std::snprintf(text, sizeof(text), fps, ImGui::GetIO().Framerate);
      ImGui::SameLine(ImGui::GetWindowWidth() - ImGui::CalcTextSize(text).x - 12.0f);
      ImGui::TextUnformatted(text);
    }
    ImGui::End();
    ImGui::PopStyleVar(2);
  }
} // namespace faf::editor

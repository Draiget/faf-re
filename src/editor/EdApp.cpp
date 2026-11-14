#include "editor/doc/EdScenarioInfo.h"
#include "editor/EdApp.h"
#include "editor/ui/EdControls.h"
#include "editor/EdPath.h"
#include "editor/view/EdPropThumbnails.h"
#include "editor/doc/EdAdaptiveTables.h"
#include <iterator>
#include <fstream>
#include <sstream>
#include <regex>
#include "moho/resource/blueprints/RUnitBlueprint.h"

#include <Windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <commdlg.h>

#include <algorithm>
#include <cfloat>
#include <optional>
#include <cstdio>
#include <array>
#include <chrono>
#include <deque>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <thread>
#include <string>
#include <vector>

#include "editor/doc/EdAutosave.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "editor/doc/EdRoundTrip.h"
#include "editor/doc/EdUnitWrecks.h"
#include "editor/doc/EdWaterPreset.h"
#include "editor/EdLog.h"
#include "editor/EdMemTrace.h"
#include "editor/EdLuaDebugger.h"
#include "editor/EdPlay.h"
#include "editor/EdShell.h"
#include "editor/doc/EdEffectMerge.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/sim/CWldSession.h"
#include "editor/tools/EdHeightFile.h"
#include "editor/tools/EdResize.h"
#include "editor/doc/EdPreview.h"
#include "editor/tools/EdAlphaGen.h"
#include "editor/tools/EdLayoutMarkers.h"
#include "editor/tools/EdMapLayout.h"
#include "editor/tools/EdSymmetrize.h"
#include "editor/tools/EdSymmetryCheck.h"
#include "editor/tools/EdTextureLibrary.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdFonts.h"
#include "editor/graph/EdTextureBake.h"
#include "editor/doc/EdLighting.h"
#include "editor/tools/EdShaderSlots.h"
#include "editor/tools/EdMapTextures.h"
#include "editor/doc/EdLayerPreset.h"
#include "editor/tools/EdTexScale.h"
#include "editor/tools/EdTextureSets.h"
#include "editor/tools/EdRecipes.h"
#include "editor/tools/EdMaskBrush.h"
#include "editor/tools/EdMaskGen.h"
#include "editor/tools/EdGroundKind.h"
#include "editor/tools/EdShaderProfiles.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdHelp.h"
#include "editor/ui/EdHomeModel.h"
#include "editor/ui/EdKeymap.h"
#include "editor/ui/EdKeysPage.h"
#include "editor/ui/EdPalette.h"
#include "editor/ui/EdSettings.h"
#include "editor/ui/EdStatus.h"
#include "editor/ui/EdTheme.h"
#include "editor/ui/EdThemeStyle.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWindowChrome.h"
#include "editor/ui/EdWorkspaces.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "editor/view/EdLiveTerrain.h"
#include "editor/view/EdMapScene.h"
#include "gpg/core/diagnostics/CrashHooks.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/RenderProfiler.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_internal.h"
#include "misc/freetype/imgui_freetype.h"
#include "moho/app/CScApp.h"
#include "moho/console/CConCommand.h"
#include "moho/app/WinApp.h"
#include "moho/app/AppRuntimeTypes.h"
#include "moho/audio/AudioEngine.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/SessionStartup.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/AmbientOcclusionRenderer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/render/RCamManager.h"
#include "moho/render/WRenViewport.h"
#include "moho/sim/CVFSImpl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/ui/IUIManager.h"
#include <cstring>

// imgui_impl_win32.h leaves this declaration to the application.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace faf::editor
{
  namespace
  {
    constexpr wchar_t kTitle[] = L"FAF Map Editor";

    /** `%LOCALAPPDATA%\FAForever\Editor`, made when missing; empty when there's no such folder. */
    [[nodiscard]] std::filesystem::path EditorSettingsFolder()
    {
      const char* const localAppData = std::getenv("LOCALAPPDATA");
      if (localAppData == nullptr) {
        return {};
      }
      std::filesystem::path folder = std::filesystem::path(localAppData) / "FAForever" / "Editor";
      std::error_code error;
      std::filesystem::create_directories(folder, error);
      return error ? std::filesystem::path{} : folder;
    }

    /**
     * Whether the command line is a test run's: any of the editor's test options. A test run writes back the
     * workspace, panels and settings it read, never what it showed (so it leaves the user's alone). `/open` alone is
     * a user's (a map opened from outside).
     */
    [[nodiscard]] bool IsTestRunCommandLine()
    {
      static const char* const kOptions[] = {
        "/command",
        "/palette",
        "/theme",
        "/keysfile",
        "/focuspanel",
        "/uiclicks",
        "/hidegameunits",
        "/movelayer",
        "/pickfilter",
        "/mapwide",
        "/tool",
        "/proptool",
        "/play",
        "/debugarm",
        "/breakpoint",
        "/check",
        "/decaltool",
        "/markertool",
        "/unittool",
        "/hoverprop",
        "/selectprops",
        "/selectunit",
        "/propswap",
        "/saveas",
        "/settingsfile",
        "/autosavefolder",
        "/askunsaved",
        "/particlebrowser",
        "/particlenew",
        "/particleopen",
        "/materialeditor",
        "/uiscale",
        "/testrun",
        "/openall",
        "/roundtrip",
        "/vault",
        "/vaultsearch",
        "/vaultmap",
        "/newmap",
        "/stamp",
        "/brush",
        "/layer",
        "/waterbody",
        "/ruler",
        "/adaptivewindow",
        "/maskrule",
        "/maskgen",
        "/symhover",
        "/stbfont",
        "/recipe",
        "/texset",
        "/layerop",
        "/slopeview",
        "/typesfromlayers",
        "/uncapped",
        "/nominimap",
        "/followtest",
        "/arrangetest",
        "/findtest",
        "/findopen",
        "/filltest",
        "/modaltest",
        "/looktest",
        "/looksfolder",
        "/envtest",
        "/watermasktest",
        "/nowaterhires",
        "/camat",
        "/erosiontest",
        "/sctest",
        "/symmenu",
        "/panelbottom",
        "/shader",
        "/brushtest",
        "/brushshape",
        "/stampsource",
        "/stampstroke",
        "/symoptions",
        "/maskoptions",
        "/masktest",
        "/shaderbrowser",
        "/convertlayers",
        "/interoptest",
        "/gentest",
        "/layouttest",
        "/playcopytest",
        "/missiontest",
        "/modtest",
        "/unitlabtest",
        "/effectmodtest",
        "/assettest",
        "/thumbcache",
        "/assetmarks",
        "/editormods",
        "/editormodtest",
        "/unitviewtest",
        "/runmarker",
        "/pausetest",
        "/viewmenu",
        "/mapinfotest",
        "/dropdefaultcube",
        "/exportpreview",
        "/resizetest",
      };
      for (const char* const option : kOptions) {
        if (moho::CFG_GetArgOption(option, 0, nullptr)) {
          return true;
        }
      }
      return false;
    }

    // The panels' scale the user chose (the toolbar's - / % / +), kept in layout.ini as [FafEditor][Ui] Scale=<x>: read
    // there at the first frame (-1 until then), the one in use written back.
    float gUiScaleRead = -1.0f;
    float gUiScaleNow = 1.0f;

    void* UiSettingsOpen(
      ImGuiContext*,
      ImGuiSettingsHandler*,
      const char* const name
    )
    {
      return std::strcmp(name, "Ui") == 0 ? &gUiScaleRead : nullptr;
    }

    // The theme the user chose (View > Theme), kept beside the scale as Theme=<name>: read at the first frame. The one
    // on screen can differ: `/theme` (test runs) shows one without keeping it, as the other test options keep nothing.
    std::string gThemeRead;
    std::string gThemeNow;
    std::string gThemeKept;

    // The workspace shown last and the panels each one showed (Workspace=<key>, Panels.<key>=<ids>), as read at the
    // first frame. A test run (gTestRun) writes these back unchanged, so it leaves the user's as they were.
    constexpr const char* kReviewOnlyLooks = "the Review workspace only looks (Alt+1 to edit)";
    std::string gWorkspaceRead;
    std::map<std::string, std::vector<std::string>> gPanelsRead;
    std::map<std::string, int> gLayoutsRead;
    bool gTestRun = false;

    void UiSettingsLine(
      ImGuiContext*,
      ImGuiSettingsHandler*,
      void*,
      const char* const line
    )
    {
      if (float scale = 0.0f; std::sscanf(line, "Scale=%f", &scale) == 1 && scale >= 0.5f && scale <= 3.0f) {
        gUiScaleRead = scale;
      }
      if (std::strncmp(line, "Theme=", 6) == 0 && line[6] != 0) {
        gThemeRead = line + 6;
        gThemeKept = gThemeRead;
      }
      if (std::strncmp(line, "Workspace=", 10) == 0 && WorkspaceByKey(line + 10) >= 0) {
        gWorkspaceRead = line + 10;
        SetActiveWorkspace(WorkspaceByKey(gWorkspaceRead));
      }
      if (
        const char* const equals = std::strchr(line, '='); std::strncmp(line, "Layout.", 7) == 0 && equals != nullptr
      ) {
        const std::string key(line + 7, equals);
        if (WorkspaceByKey(key) >= 0) {
          LayoutVersions()[key] = std::atoi(equals + 1);
          gLayoutsRead[key] = LayoutVersions()[key];
        }
      }
      if (
        const char* const equals = std::strchr(line, '='); std::strncmp(line, "Panels.", 7) == 0 && equals != nullptr
      ) {
        const std::string key(line + 7, equals);
        if (WorkspaceByKey(key) >= 0) {
          ShownPanels()[key] = SplitPanelList(equals + 1);
          gPanelsRead[key] = ShownPanels()[key];
        }
      }
    }

    void UiSettingsWrite(
      ImGuiContext*,
      ImGuiSettingsHandler* const handler,
      ImGuiTextBuffer* const out
    )
    {
      out->appendf("[%s][Ui]\nScale=%.3f\n", handler->TypeName, static_cast<double>(gUiScaleNow));
      if (!gThemeKept.empty()) {
        out->appendf("Theme=%s\n", gThemeKept.c_str());
      }
      const std::string workspace = gTestRun ? gWorkspaceRead : Workspaces()[ActiveWorkspace()].key;
      if (!workspace.empty()) {
        out->appendf("Workspace=%s\n", workspace.c_str());
      }
      for (const auto& [key, panels] : gTestRun ? gPanelsRead : ShownPanels()) {
        out->appendf("Panels.%s=%s\n", key.c_str(), JoinPanelList(panels).c_str());
      }
      for (const auto& [key, version] : gTestRun ? gLayoutsRead : LayoutVersions()) {
        out->appendf("Layout.%s=%d\n", key.c_str(), version);
      }
      out->append("\n");
    }

    // The window procedures the editor put in front of the game's, and what they replaced.
    WNDPROC gViewportProc = nullptr;
    WNDPROC gFrameProc = nullptr;
    bool gWindowClosing = false;

    // The editor's panels: a child window of the game's frame under the game's viewport, with its own head on
    // the device (moho::gAppBeforeDeviceCreate). The game draws its head 0 into the viewport, which the editor
    // keeps over the middle of the dock layout; ImGui draws head 1 here, around it.
    constexpr wchar_t kPanelWindowClass[] = L"FafMapEditorPanels";
    HWND gPanelWindow = nullptr;
    constexpr std::uint32_t kPanelHead = 1U;

    // The window's menu bar (File, View, Play): outside the game's picture, so the game's interface keeps its
    // whole area. Its commands go to the running app.
    enum EMenuCommand : UINT
    {
      kMenuExit = 1001,
      kMenuTools = 1101,
      kMenuMap = 1102,
      kMenuLog = 1103,
      kMenuInfo = 1107,
      kMenuMarkers = 1108,
      kMenuCheck = 1109,
      kMenuScript = 1110,
      kMenuLighting = 1111,
      kMenuFullHelp = 1112,
      kMenuArmies = 1113,
      kMenuProperties = 1114,
      kMenuMaterialEditor = 1115,
      kMenuParticleEditor = 1116,
      kMenuParticleBrowser = 1117,
      kMenuAdaptiveWindow = 1118,
      kMenuPanelsWhilePlaying = 1104,
      kMenuResetLayout = 1105,
      kMenuImGuiDemo = 1106,
      kMenuPlayStop = 1201,
      kMenuSave = 1002,
      kMenuSaveAs = 1003,
      kMenuNew = 1004,
      kMenuPackage = 1005,
      kMenuOpen = 1006,
      kMenuClearRecent = 1007,
      /** File > Open Recent's maps (EdDocument::RecentMaps, at most kRecentMapsKept). */
      kMenuFirstRecent = 3000,
      kMenuUndo = 1301,
      kMenuRedo = 1302,
      kMenuDelete = 1303,
      kMenuFirstMap = 2000,
    };

    class EditorApp;
    EditorApp* gEditorApp = nullptr;
    /**
     * The 3D view drawn into the panels' own picture (its head copied each frame, its window's region left empty)
     * rather than shown through holes in the view's window, which lagged behind moving popups (WPE.2). The view's
     * window keeps its place and gets the input over its area from the panels' window. `/nocomposite` turns it off.
     */
    bool gComposite = true;
    HWND gViewWindow = nullptr;
    /** This frame's copy of the game's view (CopyGameView), for the panels' renderer; null when there is none. */
    gpg::gal::RenderTarget* gViewSurface = nullptr;
    /** The view's rectangle in the panels' window, and the panels' popups and floating windows over it. */
    RECT gViewRect{};
    std::vector<RECT> gOverView;

    /** Whether a mouse message at `at` (the panels' window's client point) belongs to the 3D view under the panels. */
    [[nodiscard]] bool MouseIsTheViews(
      const POINT at
    )
    {
      if (!gComposite || gViewWindow == nullptr || ::PtInRect(&gViewRect, at) == FALSE) {
        return false;
      }
      if (
        ImGui::GetCurrentContext() != nullptr &&
        (ImGui::GetCurrentContext()->ActiveId != 0 || ImGui::GetTopMostPopupModal() != nullptr)
      ) {
        return false; // a drag that began on a panel, or a dialog
      }
      for (const RECT& over : gOverView) {
        if (::PtInRect(&over, at) != FALSE) {
          return false;
        }
      }
      return true;
    }
    /**
     * The vault the FAF client set: `custom_vault_path` in fa_path.lua, which the init file reads from the folder
     * above its own (`dofile(InitFileDir .. '/../fa_path.lua')`) and mounts the maps of. Empty without one.
     */
    [[nodiscard]] std::filesystem::path ClientVaultFolder()
    {
      const std::filesystem::path script = moho::DISK_GetDataPathScriptFile();
      if (script.empty()) {
        return {};
      }
      std::ifstream file(script.parent_path().parent_path() / "fa_path.lua");
      std::string line;
      while (std::getline(file, line)) {
        const std::size_t name = line.find("custom_vault_path");
        const std::size_t open = name == std::string::npos ? name : line.find('"', name);
        const std::size_t close = open == std::string::npos ? open : line.find('"', open + 1);
        if (close == std::string::npos) {
          continue;
        }
        const std::string value = line.substr(open + 1, close - open - 1);
        std::filesystem::path folder(std::u8string(reinterpret_cast<const char8_t*>(value.data()), value.size()));
        // The client's "relative game paths" option writes it without the home folder.
        if (!folder.empty() && !folder.has_root_name()) {
          if (PWSTR profile = nullptr; SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_Profile, 0, nullptr, &profile))) {
            folder = std::filesystem::path(profile) / folder.relative_path();
            ::CoTaskMemFree(profile);
          }
        }
        return folder;
      }
      return {};
    }

    /** Whether this Windows user can list and write `folder`'s maps (another user's Documents can't). */
    [[nodiscard]] bool VaultUsable(
      const std::filesystem::path& folder
    )
    {
      std::error_code code;
      if (folder.empty() || !std::filesystem::is_directory(folder, code)) {
        return false;
      }
      std::filesystem::create_directories(folder / "maps", code);
      std::filesystem::directory_iterator listing(folder / "maps", code);
      if (code) {
        return false;
      }
      const std::filesystem::path probe = folder / "maps" / ".faf_editor_write_check";
      bool written = false;
      {
        std::ofstream out(probe, std::ios::binary);
        written = out.good();
      }
      std::filesystem::remove(probe, code);
      return written;
    }

    /**
     * Mounts the vault's map folders the init file didn't (it mounts the FAF client's vault only, so maps
     * downloaded into another one were gone after a restart: user report). A folder whose name the game
     * already lists is left alone, as the init file does (two folders of one name would mix).
     */
    void MountVaultMaps(
      const std::filesystem::path& vault
    )
    {
      const auto lower = [](std::string text) {
        std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
        return text;
      };
      moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS();
      std::vector<std::pair<std::filesystem::path, std::string>> folders;
      std::error_code code;
      for (const auto& entry : std::filesystem::directory_iterator(vault / "maps", code)) {
        if (!entry.is_directory(code)) {
          continue;
        }
        std::string scenario;
        for (const auto& file : std::filesystem::directory_iterator(entry.path(), code)) {
          const std::string name = lower(file.path().filename().string());
          if (name.size() > 13 && name.compare(name.size() - 13, 13, "_scenario.lua") == 0) {
            scenario = name;
          }
        }
        const std::string folder = lower(entry.path().filename().string());
        // FindFile returns its out string whether or not it found the file; an empty one is "not there".
        fa::string disk;
        if (vfs != nullptr && !scenario.empty()) {
          (void)vfs->FindFile(&disk, ("/maps/" + folder + "/" + scenario).c_str(), nullptr);
        }
        if (scenario.empty() || !disk.empty()) {
          continue;
        }
        folders.emplace_back(entry.path(), "/maps/" + folder);
      }
      if (folders.empty()) {
        return;
      }
      if (!moho::DISK_MountDirectoriesNow(folders)) {
        gpg::Warnf("editor: the vault's %zu map folders not in the game's list couldn't be mounted", folders.size());
        return;
      }
      gpg::Logf(
        "editor: mounted %zu map folders of the vault the init file doesn't mount (first: %s)",
        folders.size(),
        folders.front().first.string().c_str()
      );
    }

    void OnMenuCommand(UINT command);
    bool OnViewportMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam);
    [[nodiscard]] bool EditorViewOverPlay();
    /** The window's close and File > Exit with unsaved changes: the question asked first; true when it was. */
    bool AskBeforeExit();
    /** The title row's menu that Alt and this letter opens, or -1. */
    [[nodiscard]] int MenuIndexForKey(char key);
    /** What a point of the frame (screen coordinates) is, by the title row's layout (own caption only). */
    [[nodiscard]] EdHit FrameHit(HWND frame, LPARAM screenPoint);
    [[nodiscard]] bool SessionActive();

    /**
     * The game's viewport keeps its own input (mouse and keys reach the game as in the game); while a play has it,
     * only the keys of the editor's Play/Stop and view switch (F5, F6 unless rebound) stop here, whatever a
     * player's own key bindings say (EditorApp::HandleViewportMessage).
     */
    LRESULT CALLBACK EditorViewportProc(
      const HWND window,
      const UINT message,
      const WPARAM wParam,
      const LPARAM lParam
    )
    {
      // Between plays the opened map's camera takes the mouse (EdMapScene).
      if (OnViewportMessage(window, message, wParam, lParam)) {
        return 0;
      }
      // The editor's view in front of a play: what it doesn't take doesn't reach the game behind it either (a click
      // there must not order the session's units).
      if (
        EditorViewOverPlay() &&
        ((message >= WM_MOUSEFIRST && message <= WM_MOUSELAST) || (message >= WM_KEYFIRST && message <= WM_KEYLAST))
      ) {
        return 0;
      }
      return ::CallWindowProcW(gViewportProc, window, message, wParam, lParam);
    }

    /** The panels' window: its input is ImGui's; a click takes the keyboard focus from the game. */
    LRESULT CALLBACK PanelWindowProc(
      const HWND window,
      const UINT message,
      const WPARAM wParam,
      const LPARAM lParam
    )
    {
      // Over the title row's empty parts, its caption buttons and the top resize band, this window steps aside
      // (HTTRANSPARENT) and the frame answers (EditorFrameProc): it covers the frame's whole client area from 0,0.
      if (message == WM_NCHITTEST && WindowChrome().own) {
        const HWND frame = ::GetParent(window);
        if (frame != nullptr && FrameHit(frame, lParam) != EdHit::Client) {
          return HTTRANSPARENT;
        }
      }
      // Over the composited 3D view: the mouse is the view's (in its own client coordinates), and a click gives it
      // the keyboard. ImGui still sees the moves, so a panel under the cursor before stops being hovered.
      if (gComposite && gViewWindow != nullptr) {
        const bool wheel = message == WM_MOUSEWHEEL || message == WM_MOUSEHWHEEL;
        const bool mouse = (message >= WM_MOUSEFIRST && message <= WM_MOUSELAST) || wheel;
        if (mouse || message == WM_SETCURSOR) {
          POINT at{};
          if (mouse && !wheel) {
            at = POINT{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
          } else {
            (void)::GetCursorPos(&at);
            (void)::ScreenToClient(window, &at);
          }
          if (MouseIsTheViews(at)) {
            if (message == WM_SETCURSOR) {
              return ::SendMessageW(gViewWindow, WM_SETCURSOR, reinterpret_cast<WPARAM>(gViewWindow), lParam);
            }
            if (message == WM_MOUSEMOVE && ImGui::GetCurrentContext() != nullptr) {
              (void)ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam);
              // The keyboard goes where the mouse is, as in Blender: over the view, WASD and the tools' keys are
              // the view's without a click first (not while a text field of the panels is being typed in).
              const HWND focus = ::GetFocus();
              if ((focus == window || focus == ::GetAncestor(window, GA_ROOT)) && !ImGui::GetIO().WantTextInput) {
                ::SetFocus(gViewWindow);
              }
            }
            if (message == WM_LBUTTONDOWN || message == WM_RBUTTONDOWN || message == WM_MBUTTONDOWN) {
              ::SetFocus(gViewWindow);
            }
            const LPARAM viewPoint = wheel ? lParam : MAKELPARAM(at.x - gViewRect.left, at.y - gViewRect.top);
            return ::SendMessageW(gViewWindow, message, wParam, viewPoint);
          }
        }
      }
      if (message == WM_LBUTTONDOWN || message == WM_RBUTTONDOWN || message == WM_MBUTTONDOWN) {
        ::SetFocus(window);
      }
      if (
        ImGui::GetCurrentContext() != nullptr && ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam) != 0
      ) {
        return 1;
      }
      if (message == WM_ERASEBKGND) {
        return 1;
      }
      return ::DefWindowProcW(window, message, wParam, lParam);
    }

    /** moho::gAppBeforeDeviceCreate: the panels' window, under the game's viewport, and its head. */
    void AddPanelHead(
      gpg::gal::DeviceContext& context,
      void* const frameWindow
    )
    {
      const HWND frame = static_cast<HWND>(frameWindow);
      const HINSTANCE instance = ::GetModuleHandleW(nullptr);
      WNDCLASSEXW windowClass{};
      windowClass.cbSize = sizeof(windowClass);
      windowClass.style = CS_DBLCLKS;
      windowClass.lpfnWndProc = &PanelWindowProc;
      windowClass.hInstance = instance;
      windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
      windowClass.lpszClassName = kPanelWindowClass;
      (void)::RegisterClassExW(&windowClass);

      RECT client{};
      ::GetClientRect(frame, &client);
      const int width = std::max(1L, client.right - client.left);
      const int height = std::max(1L, client.bottom - client.top);
      gPanelWindow = ::CreateWindowExW(
        0,
        kPanelWindowClass,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0,
        0,
        width,
        height,
        frame,
        nullptr,
        instance,
        nullptr
      );
      ::SetWindowPos(gPanelWindow, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

      gpg::gal::Head head{};
      head.mWindowed = false; // a window (the flag is the full-screen one)
      head.mWidth = static_cast<std::uint32_t>(width);
      head.mHeight = static_cast<std::uint32_t>(height);
      head.framesPerSecond = 60U;
      head.mHandle = frame;
      head.mWindow = gPanelWindow;
      context.AddHead(head);
    }

    /**
     * The top-level frame: closing it closes the editor. The game would hand a close to its Lua UI instead
     * (an "are you sure" dialog from the main menu's scripts, which the editor never starts), so the loop is
     * ended here and the app's Destroy takes the windows down.
     */
    /** The resize band along a caption-less edge, and what a maximised window hides off-screen on each side. */
    [[nodiscard]] int FrameBorder(
      const HWND window
    )
    {
      const UINT dpi = ::GetDpiForWindow(window);
      return ::GetSystemMetricsForDpi(SM_CYFRAME, dpi) + ::GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
    }

    [[nodiscard]] LRESULT HitCode(
      const EdHit hit
    )
    {
      switch (hit) {
      case EdHit::Caption:
        return HTCAPTION;
      case EdHit::Minimize:
        return HTMINBUTTON;
      case EdHit::Maximize:
        return HTMAXBUTTON;
      case EdHit::Close:
        return HTCLOSE;
      case EdHit::Top:
        return HTTOP;
      case EdHit::TopLeft:
        return HTTOPLEFT;
      case EdHit::TopRight:
        return HTTOPRIGHT;
      case EdHit::Client:
        break;
      }
      return HTCLIENT;
    }

    [[nodiscard]] EdHit CaptionButtonOf(
      const WPARAM code
    )
    {
      return code == HTMINBUTTON ? EdHit::Minimize
        : code == HTMAXBUTTON    ? EdHit::Maximize
        : code == HTCLOSE        ? EdHit::Close
                                 : EdHit::Client;
    }

    /** What a point of the frame (screen coordinates) is, by the title row's layout. */
    [[nodiscard]] EdHit FrameHit(
      const HWND frame,
      const LPARAM screenPoint
    )
    {
      POINT at{GET_X_LPARAM(screenPoint), GET_Y_LPARAM(screenPoint)};
      (void)::ScreenToClient(frame, &at);
      RECT client{};
      (void)::GetClientRect(frame, &client);
      return TitleHit(
        WindowChrome(),
        static_cast<float>(at.x),
        static_cast<float>(at.y),
        static_cast<float>(client.right),
        static_cast<float>(FrameBorder(frame))
      );
    }

    /**
     * The editor's own title row (design §3, as Discord and VS Code): Windows draws no caption. The client area takes
     * the caption's place (WM_NCCALCSIZE; a maximised window keeps its hidden border out of sight); the row's empty
     * parts drag the window and its buttons are Windows' own (WM_NCHITTEST: HTCAPTION, HTMINBUTTON, HTMAXBUTTON so
     * Windows 11 shows its snap layouts, HTCLOSE); the window keeps WS_OVERLAPPEDWINDOW, so Aero Snap, Win+arrows,
     * the shadow and rounded corners stay. True when the message was handled, with `result`.
     */
    bool HandleOwnCaption(
      const HWND window,
      const UINT message,
      const WPARAM wParam,
      const LPARAM lParam,
      LRESULT& result
    )
    {
      EdWindowChrome& chrome = WindowChrome();
      switch (message) {
      case WM_NCCALCSIZE:
        if (wParam == TRUE) {
          NCCALCSIZE_PARAMS* const params = reinterpret_cast<NCCALCSIZE_PARAMS*>(lParam);
          const LONG top = params->rgrc[0].top;
          (void)::CallWindowProcW(gFrameProc, window, message, wParam, lParam);
          params->rgrc[0].top = top + (::IsZoomed(window) ? FrameBorder(window) : 0);
          result = 0;
          return true;
        }
        return false;
      case WM_NCHITTEST: {
        const LRESULT base = ::CallWindowProcW(gFrameProc, window, message, wParam, lParam);
        result = base == HTCLIENT ? HitCode(FrameHit(window, lParam)) : base;
        return true;
      }
      case WM_NCMOUSEMOVE: {
        chrome.hot = CaptionButtonOf(wParam);
        TRACKMOUSEEVENT track{sizeof(TRACKMOUSEEVENT), TME_LEAVE | TME_NONCLIENT, window, 0};
        (void)::TrackMouseEvent(&track);
        // The mouse left the panels: nothing of them stays hovered.
        if (ImGui::GetCurrentContext() != nullptr) {
          ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
        }
        return false;
      }
      case WM_NCMOUSELEAVE:
        chrome.hot = EdHit::Client;
        chrome.pressed = EdHit::Client;
        return false;
      case WM_NCLBUTTONDOWN:
      case WM_NCLBUTTONDBLCLK:
        // The caption buttons are drawn by the panels; Windows mustn't draw its classic ones over them.
        if (CaptionButtonOf(wParam) != EdHit::Client) {
          chrome.pressed = CaptionButtonOf(wParam);
          result = 0;
          return true;
        }
        return false;
      case WM_NCLBUTTONUP:
        if (CaptionButtonOf(wParam) != EdHit::Client) {
          const EdHit button = CaptionButtonOf(wParam);
          if (button == chrome.pressed) {
            if (button == EdHit::Minimize) {
              (void)::ShowWindow(window, SW_MINIMIZE);
            } else if (button == EdHit::Maximize) {
              (void)::ShowWindow(window, ::IsZoomed(window) ? SW_RESTORE : SW_MAXIMIZE);
            } else {
              (void)::PostMessageW(window, WM_CLOSE, 0, 0);
            }
          }
          chrome.pressed = EdHit::Client;
          result = 0;
          return true;
        }
        return false;
      case WM_NCACTIVATE:
        chrome.active = wParam != FALSE;
        // lParam -1: Windows doesn't repaint a caption that isn't there.
        result = ::CallWindowProcW(gFrameProc, window, message, wParam, -1);
        return true;
      case WM_SIZE:
        chrome.maximised = wParam == SIZE_MAXIMIZED;
        return false;
      default:
        return false;
      }
    }

    LRESULT CALLBACK EditorFrameProc(
      const HWND window,
      const UINT message,
      const WPARAM wParam,
      const LPARAM lParam
    )
    {
      if (WindowChrome().own) {
        LRESULT result = 0;
        if (HandleOwnCaption(window, message, wParam, lParam, result)) {
          return result;
        }
      }
      // Alt alone or F10 opens the title row's first menu; Alt and a letter the menu with that letter (the menus are
      // the panels' now). During play the game has Alt (its own bindings), so only a click does.
      if (message == WM_SYSCOMMAND && (wParam & 0xFFF0U) == SC_KEYMENU && !SessionActive()) {
        const int menu = lParam == 0 ? 0 : MenuIndexForKey(static_cast<char>(lParam));
        if (menu >= 0) {
          WindowChrome().openMenu = menu;
          (void)::SetFocus(gPanelWindow);
          return 0;
        }
      }
      if (message == WM_CLOSE && AskBeforeExit()) {
        return 0;
      }
      if (message == WM_CLOSE) {
        // A sim held at a breakpoint goes on now: the main loop ends before the next frame, and the session's end
        // waits for the sim thread.
        EdLuaDebugger::Get().Release();
        gWindowClosing = true;
        if (gShellApp != nullptr) {
          gShellApp->ExitMainLoop();
        }
        return 0;
      }
      // The old menu ids still run their commands (test runs post them: shot_input.ps1 -MenuCommand).
      if (message == WM_COMMAND && HIWORD(wParam) == 0 && LOWORD(wParam) >= kMenuExit) {
        OnMenuCommand(LOWORD(wParam));
        return 0;
      }
      // During play the game has Alt (its own bindings).
      if (message == WM_SYSCOMMAND && (wParam & 0xFFF0U) == SC_KEYMENU && lParam == 0 && SessionActive()) {
        return 0;
      }
      return ::CallWindowProcW(gFrameProc, window, message, wParam, lParam);
    }

    /** UTF-8 to the window's text. */
    [[nodiscard]] std::wstring Widen(
      const std::string& text
    )
    {
      if (text.empty()) {
        return {};
      }
      const int length = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring wide(static_cast<std::size_t>(length > 0 ? length : 0), L'\0');
      if (length > 0) {
        (void)::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), length);
      }
      return wide;
    }

    [[nodiscard]] HWND HandleOf(
      const ShellWindow* const window
    )
    {
      return window != nullptr ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window->GetHandle())) : nullptr;
    }

    namespace
    {
      std::filesystem::path
      AskFile(HWND owner, bool save, const wchar_t* filter, const wchar_t* extension, const wchar_t* title);
    } // namespace

    /**
     * The map editor as the engine's app: the game's own `CScApp` (window, Direct3D 12 or Vulkan device,
     * user interface, sound, world sessions) inside it, unchanged, and the editor around it: ImGui drawn over
     * the game's frame, and Play/Stop driving the game's session state machine.
     */
    class EditorApp final : public moho::IWinApp
    {
    public:
      EditorApp()
        : moho::IWinApp("SupCom", "SupremeCommander")
      {}

      bool Init() override;
      void Main() override;
      void Destroy() override;
      bool AppDoSuppressWindowsKeys() const override
      {
        return mGame.AppDoSuppressWindowsKeys();
      }

      /** An old menu id (WM_COMMAND from test runs) runs its command. */
      void HandleMenuCommand(UINT command);
      /** The title row's menu whose Alt letter is `key`, or -1. */
      [[nodiscard]] int MenuForKey(
        const char key
      ) const
      {
        const char wanted = static_cast<char>(std::toupper(static_cast<unsigned char>(key)));
        for (std::size_t i = 0; i < mMenus.size(); ++i) {
          if (MenuAccessKey(mMenus[i].label) == wanted) {
            return static_cast<int>(i);
          }
        }
        return -1;
      }
      bool HandleViewportMessage(
        HWND window,
        UINT message,
        WPARAM wParam,
        LPARAM lParam
      )
      {
        // A key bound to a command runs it (Settings > Keys). While a play has the view only F5's and F6's commands
        // do; the game keeps every other key. The key's release goes nowhere either, as its press didn't.
        // G or R running in the view takes every key (digits type a number there, not a tool's key).
        if (mScene.ModalOn() && (message == WM_KEYDOWN || message == WM_KEYUP)) {
          return mScene.OnWindowMessage(window, message, wParam, lParam);
        }
        if (message == WM_KEYDOWN || message == WM_SYSKEYDOWN) {
          const std::string chord = ChordOf(
            VirtualKeyName(static_cast<unsigned>(wParam)),
            (::GetKeyState(VK_CONTROL) & 0x8000) != 0,
            (::GetKeyState(VK_SHIFT) & 0x8000) != 0,
            (::GetKeyState(VK_MENU) & 0x8000) != 0
          );
          const bool game = mPlay.Active() && !mScene.OverPlay();
          if (RunChord(chord, game, (lParam & (1 << 30)) != 0)) {
            mSwallowKeyUp = static_cast<unsigned>(wParam);
            // What opened over the panels (the palette, Settings) gets the keys from here on.
            if (CommandPaletteOpen() || mShowSettings) {
              (void)::SetFocus(gPanelWindow);
            }
            return true;
          }
        }
        if ((message == WM_KEYUP || message == WM_SYSKEYUP) && mSwallowKeyUp != 0 && wParam == mSwallowKeyUp) {
          mSwallowKeyUp = 0;
          return true;
        }
        return mScene.OnWindowMessage(window, message, wParam, lParam);
      }
      [[nodiscard]] bool SessionActive() const
      {
        return mPlay.Active();
      }
      /**
       * The view switches and tool per map (doc/EdViewState): read when a map opens (a map not seen before keeps the
       * switches as they are), written within a second of a change. Command-line test runs (`/open`, `/play`) don't
       * write them, so they never change what the user's maps keep, unless `/viewsave` asks; a `/tool` given keeps its
       * tool over the file's.
       */
      void KeepViewState()
      {
        if (mDocument.GetState() != EdDocument::State::Open) {
          return;
        }
        EdTools& tools = mShell->Tools();
        const std::filesystem::path folder = EditorSettingsFolder();
        if (folder.empty()) {
          return;
        }
        const std::filesystem::path file = folder / "views" / ViewStateFileName(mDocument.Path());
        const double now = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
        if (mViewStateFor != mDocument.Path()) {
          mViewStateFor = mDocument.Path();
          mViewStateCheckAt = now + 1.0;
          if (std::ifstream in(file, std::ios::binary); in) {
            std::stringstream text;
            text << in.rdbuf();
            ViewState state = ReadViewState(text.str(), tools.GetViewState());
            if (moho::CFG_GetArgOption("/tool", 1, nullptr)) {
              state.tool = tools.GetViewState().tool;
            }
            tools.SetViewState(state);
            gpg::Logf("editor: the map's view switches and tool from %s", file.string().c_str());
          }
          mViewStateSaved = tools.GetViewState();
          return;
        }
        if (now < mViewStateCheckAt) {
          return;
        }
        mViewStateCheckAt = now + 1.0;
        const ViewState state = tools.GetViewState();
        if (state == mViewStateSaved) {
          return;
        }
        mViewStateSaved = state;
        static const bool testRun =
          (moho::CFG_GetArgOption("/open", 1, nullptr) || moho::CFG_GetArgOption("/play", 1, nullptr)) &&
          !moho::CFG_GetArgOption("/viewsave", 0, nullptr);
        if (testRun) {
          return;
        }
        std::error_code error;
        std::filesystem::create_directories(file.parent_path(), error);
        if (std::ofstream out(file, std::ios::binary | std::ios::trunc); out) {
          out << WriteViewState(state);
          gpg::Logf("editor: the map's view switches and tool kept in %s", file.string().c_str());
        }
      }
      std::string mViewStateFor;
      double mViewStateCheckAt = 0.0;
      ViewState mViewStateSaved;
      /** The style at the screen's DPI, before the user's UI scale; the scale in use on it. */
      ImGuiStyle mBaseStyle;
      float mDpiScale = 1.0f;
      std::vector<EdTheme> mThemes;
      std::filesystem::path mThemeFolder;
      std::filesystem::file_time_type mThemeStamp{};
      double mThemeCheckAt = 0.0;
      float mUiScaleApplied = 1.0f;
      bool mSoundFocused = true;

      /**
       * Sound only while the editor is the window in front (user ask 2026-11-11): its own windows and dialogs share its
       * frame's root owner; any other window in front mutes it (moho::kSndMuteUnfocused, beside the game's own mute
       * while minimized).
       */
      void KeepSoundToFocus()
      {
        const HWND frame = HandleOf(mGame.supcomFrame);
        const HWND front = ::GetForegroundWindow();
        const bool focused = frame != nullptr && front != nullptr &&
          ::GetAncestor(front, GA_ROOTOWNER) == ::GetAncestor(frame, GA_ROOTOWNER);
        if (focused == mSoundFocused) {
          return;
        }
        mSoundFocused = focused;
        moho::SND_MuteFor(moho::kSndMuteUnfocused, !focused);
        gpg::Logf(
          "editor: sound %s (the editor's window %s)",
          focused ? "on" : "muted",
          focused ? "is in front" : "isn't in front"
        );
      }
      double mPropSwapUndoAt = 0.0;

      /**
       * Before a frame: the scale read from layout.ini at the first frame into the toolbar's, `/uiscale <x>` (test
       * runs) once, then any change applied (sizes from the DPI style, fonts by FontScaleMain) and marked for saving.
       */
      /** The themes: the built-ins and the settings folder's `themes\*.lua` (a first run leaves an example there). */
      void LoadThemeList()
      {
        const std::filesystem::path settings = EditorSettingsFolder();
        mThemeFolder = settings.empty() ? std::filesystem::path{} : settings / "themes";
        std::error_code error;
        if (!mThemeFolder.empty() && !std::filesystem::exists(mThemeFolder, error)) {
          std::filesystem::create_directories(mThemeFolder, error);
          std::string example(BuiltInThemeSources().front()); // FAF Blue
          const std::size_t at = example.find("name = 'FAF Blue'");
          if (at != std::string::npos) {
            example.replace(at, 17, "name = 'My theme'");
          }
          std::ofstream(mThemeFolder / "my_theme.lua.example", std::ios::binary)
            << "-- Rename to my_theme.lua and change it: the editor picks it up at once (View > Theme).\n"
            << "-- Colours are any of ImGui's by name (ImGuiCol_ without the prefix).\n"
            << example;
        }
        mThemes = LoadThemes(mThemeFolder);
        mThemeStamp = ThemeFolderStamp();
        for (const EdTheme& theme : mThemes) {
          for (const std::string& problem : theme.problems) {
            gpg::Warnf("editor: theme %s: %s", theme.name.c_str(), problem.c_str());
          }
        }
        gpg::Logf("editor: %zu themes (%s)", mThemes.size(), mThemeFolder.string().c_str());
      }

      /**
       * The theme by name (the first when there's none of that name), over ImGui's sizes at the screen's DPI. `keep`:
       * the user picked it, so layout.ini keeps it; the start, `/theme` and reloads only show it.
       */
      void SetTheme(
        const std::string& name,
        const bool keep = false
      )
      {
        if (mThemes.empty()) {
          mThemes.push_back(ReadTheme(std::string(BuiltInThemeSources().front()), "built-in theme"));
        }
        const EdTheme* theme = &mThemes.front();
        for (const EdTheme& candidate : mThemes) {
          if (candidate.name == name) {
            theme = &candidate;
          }
        }
        ImGuiStyle style; // ImGui's own sizes at 100 %, the mockup's frames over them (ApplyTheme)
        for (const std::string& unknown : ApplyTheme(*theme, style)) {
          gpg::Warnf("editor: theme %s: ImGui has no colour %s", theme->name.c_str(), unknown.c_str());
        }
        style.ScaleAllSizes(mDpiScale);
        style.FontScaleDpi = mDpiScale;
        mBaseStyle = style; // the user's UI scale is applied over this (ApplyUiScale)
        ImGui::GetStyle() = style;
        mUiScaleApplied = -1.0f;
        if (keep && gThemeKept != theme->name) {
          gThemeKept = theme->name;
          if (ImGui::GetCurrentContext() != nullptr && ImGui::GetCurrentContext()->SettingsLoaded) {
            ImGui::MarkIniSettingsDirty();
          }
        }
        if (gThemeNow != theme->name) {
          gThemeNow = theme->name;
          gpg::Logf(
            "editor: theme %s%s",
            theme->name.c_str(),
            theme->file.empty() ? " (built-in)" : (" from " + theme->file).c_str()
          );
        }
      }

      /** The newest change in the themes folder (its .lua files), to reload them when one changes. */
      [[nodiscard]] std::filesystem::file_time_type ThemeFolderStamp() const
      {
        std::filesystem::file_time_type newest{};
        std::error_code error;
        if (mThemeFolder.empty() || !std::filesystem::is_directory(mThemeFolder, error)) {
          return newest;
        }
        for (const auto& entry : std::filesystem::directory_iterator(mThemeFolder, error)) {
          if (entry.path().extension() == ".lua") {
            newest = std::max(newest, entry.last_write_time(error));
          }
        }
        // A file taken away changes nothing else: its count goes into the stamp.
        return newest +
          std::filesystem::file_time_type::duration(
                 std::distance(std::filesystem::directory_iterator(mThemeFolder, error), {})
          );
      }

      /** Once a second: a theme file written, added or removed reloads them and puts the current one on again. */
      void WatchThemes()
      {
        const double now = ImGui::GetTime();
        if (now < mThemeCheckAt) {
          return;
        }
        mThemeCheckAt = now + 1.0;
        if (ThemeFolderStamp() == mThemeStamp) {
          return;
        }
        LoadThemeList();
        RegisterThemeCommands();
        const std::string current = gThemeNow;
        gThemeNow.clear();
        SetTheme(current);
        gpg::Logf("editor: themes reloaded");
      }

      /** View > Theme: one command a theme (in the palette as "Theme: <name>"), reload, the folder. */
      void RegisterThemeCommands()
      {
        for (std::size_t i = 0; i < 64; ++i) {
          if (mCommands.Find("view.theme." + std::to_string(i)) == nullptr && i >= mThemes.size()) {
            break;
          }
          if (i >= mThemes.size()) {
            // A theme that went away: its command stays, but says so.
            mCommands.Add(EdCommand{"view.theme." + std::to_string(i), "Theme: (removed)", "View", "", "", [] {}, [] {
              return std::string("the theme's file is gone");
            }, {}});
            continue;
          }
          const std::string name = mThemes[i].name;
          mCommands.Add(
            EdCommand{
              "view.theme." + std::to_string(i),
              "Theme: " + name,
              "View",
              "",
              mThemes[i].file.empty() ? "Built in" : mThemes[i].file,
              [this, name] {
            SetTheme(name, true);
          },
              {},
              [name] {
            return gThemeNow == name;
          },
            }
          );
        }
        mCommands.Add(
          EdCommand{"view.theme.reload", "Reload themes", "View", "", "Read the themes folder again", [this] {
          LoadThemeList();
          RegisterThemeCommands();
          const std::string current = gThemeNow;
          gThemeNow.clear();
          SetTheme(current);
        }, {}, {}}
        );
        mCommands.Add(
          EdCommand{
            "view.theme.folder",
            "Open the themes folder",
            "View",
            "",
            "Your own themes: *.lua files (my_theme.lua.example shows how)",
            [this] {
          (void)::ShellExecuteW(nullptr, L"open", mThemeFolder.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        },
            [this]() -> std::string {
          return mThemeFolder.empty() ? "there is no settings folder" : "";
        },
            {}
          }
        );
      }

      void ApplyUiScale()
      {
        // The theme layout.ini names (read at the first frame), `/theme <name>` (test runs) once, then file changes.
        if (!gThemeRead.empty()) {
          SetTheme(gThemeRead);
          gThemeRead.clear();
        }
        static bool themeArgDone = false;
        if (!themeArgDone && ImGui::GetCurrentContext()->SettingsLoaded) {
          themeArgDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/theme", 1, &value) && !value.empty()) {
            SetTheme(value[0].c_str());
          }
        }
        WatchThemes();
        float& scale = mShell->UiScale();
        if (gUiScaleRead > 0.0f) {
          scale = gUiScaleRead;
          gUiScaleRead = -1.0f;
          gpg::Logf("editor: UI scale %.2f from layout.ini", static_cast<double>(scale));
        }
        // The test option once layout.ini has been read (ImGui reads it at the first frame), so it wins over the
        // file's.
        static bool argDone = false;
        if (!argDone && ImGui::GetCurrentContext()->SettingsLoaded) {
          argDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/uiscale", 1, &value) && !value.empty()) {
            scale = static_cast<float>(std::atof(value[0].c_str()));
          }
        }
        scale = std::clamp(scale, 0.5f, 3.0f);
        if (scale == mUiScaleApplied) {
          return;
        }
        ImGuiStyle& style = ImGui::GetStyle();
        style = mBaseStyle;
        style.ScaleAllSizes(scale);
        style.FontScaleMain = scale;
        mUiScaleApplied = scale;
        gUiScaleNow = scale;
        ImGui::MarkIniSettingsDirty();
        gpg::Logf("editor: UI scale %.2f", static_cast<double>(scale));
      }

      /**
       * A key pressed in the panels or the view: runs the first command bound to `chord` that can run now (several
       * can share a key, each for its own state). `overGame`: a play has the view, so only RunsOverGame's commands.
       * `repeat`: the key held down; only undo and redo run again then. True when a command took the key (also one
       * that can't run now, which says why in the log); false leaves it to the panel or the view.
       */
      bool RunChord(
        const std::string& chord,
        const bool overGame,
        const bool repeat = false
      )
      {
        if (chord.empty() || KeysPageCapturing()) {
          return false;
        }
        const EdCommand* blocked = nullptr;
        for (const EdCommand* const command : mCommands.AllForChord(chord)) {
          if (overGame && !RunsOverGame(command->id)) {
            continue;
          }
          if (repeat && command->id != "edit.undo" && command->id != "edit.redo") {
            return true;
          }
          if (!mCommands.WhyNot(command->id).empty()) {
            blocked = blocked != nullptr ? blocked : command;
            continue;
          }
          const std::string id = command->id;
          if (!repeat) {
            gpg::Logf("editor: key %s: %s", chord.c_str(), id.c_str());
          }
          (void)mCommands.Run(id);
          return true;
        }
        if (blocked != nullptr) {
          if (!repeat) {
            gpg::Logf(
              "editor: key %s: %s can't run now: %s",
              chord.c_str(),
              blocked->id.c_str(),
              mCommands.WhyNot(blocked->id).c_str()
            );
          }
          return true;
        }
        return false;
      }

      /**
       * The keys the user changed, from keys.ini in the settings folder (`/keysfile <path>`: that file instead, read
       * and written, so a test run leaves the user's alone), over the registry's defaults; read once after the
       * commands are registered.
       */
      void LoadKeymap()
      {
        mKeyDefaults = KeyDefaults(mCommands);
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/keysfile", 1, &value) && !value.empty()) {
          mKeysFile = std::filesystem::path(value[0].c_str());
        } else if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
          mKeysFile = folder / "keys.ini";
        }
        std::ifstream in(mKeysFile, std::ios::binary);
        if (mKeysFile.empty() || !in) {
          gpg::Logf("editor: keys: the defaults (no %s)", mKeysFile.string().c_str());
          UpdateToolKeys();
          return;
        }
        std::ostringstream text;
        text << in.rdbuf();
        for (const std::string& problem : ReadKeymap(mCommands, text.str())) {
          gpg::Warnf("editor: %s: %s", mKeysFile.filename().string().c_str(), problem.c_str());
        }
        int changed = 0;
        for (const EdCommand& command : mCommands.All()) {
          const auto found = mKeyDefaults.find(command.id);
          changed += found != mKeyDefaults.end() && found->second != command.keys ? 1 : 0;
        }
        gpg::Logf("editor: keys: %d changed in %s", changed, mKeysFile.string().c_str());
        for (const auto& [a, b] : mCommands.Clashes()) {
          gpg::Warnf("editor: keys: %s and %s share a key", a.c_str(), b.c_str());
        }
        UpdateToolKeys();
      }

      /** keys.ini rewritten with the keys now (Settings > Keys changed one). */
      void SaveKeymap()
      {
        UpdateToolKeys();
        if (mKeysFile.empty()) {
          return;
        }
        std::ofstream out(mKeysFile, std::ios::binary | std::ios::trunc);
        out << WriteKeymap(mCommands, mKeyDefaults);
        gpg::Logf("editor: keys written to %s", mKeysFile.string().c_str());
        PostStatusMessage("Keys saved");
      }

      /** The tool strip shows each tool's key (tool.N). */
      void UpdateToolKeys()
      {
        std::vector<std::string> keys;
        for (int i = 0; i < EdTools::ToolCount(); ++i) {
          const EdCommand* const command = mCommands.Find("tool." + std::to_string(i));
          keys.push_back(command != nullptr ? command->keys : std::string());
        }
        mShell->Tools().SetToolKeys(std::move(keys));
      }

      /**
       * settings.ini from the settings folder (`/settingsfile <path>`: that file, read and written, for test runs);
       * read in Init, before the window and the renderer exist. A test run without `/settingsfile` doesn't write it.
       */
      void LoadSettings()
      {
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/settingsfile", 1, &value) && !value.empty()) {
          mSettingsFile = std::filesystem::path(value[0].c_str());
        } else if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
          mSettingsFile = folder / "settings.ini";
          mSettingsWritable = !IsTestRunCommandLine();
        }
        if (std::ifstream in(mSettingsFile, std::ios::binary); !mSettingsFile.empty() && in) {
          std::ostringstream text;
          text << in.rdbuf();
          mSettingsProblems = mSettings.Read(text.str());
          mSettingsRead = true;
        }
        mStartTitleBar = mSettings.Get(EdSettings::kTitleBar);
        mStartRenderer = mSettings.Get(EdSettings::kRenderer);
      }

      void SaveSettings()
      {
        if (mSettingsFile.empty() || !mSettingsWritable) {
          return;
        }
        std::ofstream out(mSettingsFile, std::ios::binary | std::ios::trunc);
        out << mSettings.Write();
        gpg::Logf("editor: settings written to %s", mSettingsFile.string().c_str());
      }

      /**
       * The switches the View menu also changes (Full help text, Panels while playing): put on from settings.ini at
       * the first frame, and written back when they change, wherever from.
       */
      void SyncSettings()
      {
        static bool applied = false;
        if (!applied) {
          applied = true;
          // What Init read, said now that the log is open.
          gpg::Logf(
            "editor: settings %s %s (title row %s, renderer %s)",
            mSettingsRead ? "from" : "are the defaults, no",
            mSettingsFile.string().c_str(),
            mStartTitleBar.c_str(),
            mStartRenderer.c_str()
          );
          for (const std::string& problem : mSettingsProblems) {
            gpg::Warnf("editor: %s: %s", mSettingsFile.filename().string().c_str(), problem.c_str());
          }
          FullHelpText() = mSettings.GetBool(EdSettings::kFullHelp);
          mShell->PanelsWhilePlaying() = mSettings.GetBool(EdSettings::kPanelsWhilePlaying);
          mShell->HomeAtStart() = mSettings.GetBool(EdSettings::kStartScreen);
          mShell->HomeVaultItems() = mSettings.GetBool(EdSettings::kVaultItems);
          // The start screen, unless the command line asks for a map (or a test run for something).
          bool asked = false;
          for (const char* const option :
               {"/open", "/openall", "/openfolder", "/newmap", "/play", "/vaultmap", "/command", "/palette"}) {
            asked = asked || moho::CFG_GetArgOption(option, 0, nullptr);
          }
          if (mShell->HomeAtStart() && !asked) {
            mShell->ShowHome(0);
            gpg::Logf("editor: the start screen");
          }
          return;
        }
        bool changed = false;
        if (FullHelpText() != mSettings.GetBool(EdSettings::kFullHelp)) {
          changed = mSettings.SetBool(EdSettings::kFullHelp, FullHelpText()) || changed;
        }
        if (mShell->PanelsWhilePlaying() != mSettings.GetBool(EdSettings::kPanelsWhilePlaying)) {
          changed = mSettings.SetBool(EdSettings::kPanelsWhilePlaying, mShell->PanelsWhilePlaying()) || changed;
        }
        if (mShell->HomeAtStart() != mSettings.GetBool(EdSettings::kStartScreen)) {
          changed = mSettings.SetBool(EdSettings::kStartScreen, mShell->HomeAtStart()) || changed;
        }
        if (mShell->HomeVaultItems() != mSettings.GetBool(EdSettings::kVaultItems)) {
          changed = mSettings.SetBool(EdSettings::kVaultItems, mShell->HomeVaultItems()) || changed;
        }
        if (changed) {
          SaveSettings();
        }
      }

      /**
       * Settings > Viewport's background frame rate: while the editor isn't the window in front and no play runs,
       * the frame waits until 1/cap s passed since the last (the GPU and fans rest).
       */
      void CapBackgroundFrames()
      {
        // `/uncapped` (test runs): no background limit, so a capture behind other windows measures the real frame rate.
        static const bool uncapped = moho::CFG_GetArgOption("/uncapped", 0, nullptr);
        const int cap = uncapped ? 0 : mSettings.GetInt(EdSettings::kBackgroundFps);
        const auto now = std::chrono::steady_clock::now();
        const HWND front = ::GetForegroundWindow();
        const HWND frame = HandleOf(mGame.supcomFrame);
        const bool behind = front != frame && (front == nullptr || ::GetAncestor(front, GA_ROOT) != frame);
        if (cap > 0 && behind && !mPlay.Active()) {
          const auto wanted = std::chrono::microseconds(1000000 / cap);
          const auto spent = now - mLastBackgroundFrame;
          if (spent < wanted) {
            ::Sleep(static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(wanted - spent).count()));
          }
        }
        mLastBackgroundFrame = std::chrono::steady_clock::now();
      }

      /** One of a setting's values as a row of joined buttons, the one set filled; true when one was clicked. */
      bool SettingChoice(
        const char* const key,
        const std::vector<std::pair<const char*, const char*>>& choices
      )
      {
        bool clicked = false;
        const std::string now = mSettings.Get(key);
        for (std::size_t i = 0; i < choices.size(); ++i) {
          if (i > 0) {
            ImGui::SameLine(0.0f, Em(2.0f));
          }
          const bool on = now == choices[i].first;
          if (on) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_Header));
          }
          if (ImGui::Button(choices[i].second) && !on) {
            clicked = mSettings.Set(key, choices[i].first);
          }
          if (on) {
            ImGui::PopStyleColor();
          }
        }
        if (clicked) {
          gpg::Logf("editor: settings: %s=%s", key, mSettings.Get(key).c_str());
          SaveSettings();
          PostStatusMessage("Settings saved");
        }
        return clicked;
      }

      /** A page's heading and a setting's name over its control, with a line saying what it does. */
      static void SettingsHeading(
        const char* const text
      )
      {
        ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 1.25f);
        ImGui::TextUnformatted(text);
        ImGui::PopFont();
        ImGui::Spacing();
      }
      static void SettingLabel(
        const char* const name,
        const char* const about
      )
      {
        ImGui::Spacing();
        ImGui::TextUnformatted(name);
        if (about != nullptr && about[0] != 0) {
          ImGui::PushTextWrapPos(0.0f);
          ImGui::TextDisabled("%s", about);
          ImGui::PopTextWrapPos();
        }
      }

      /**
       * Settings (File > Settings, View > Keyboard shortcuts, the palette's "Settings: ..."): pages listed on the
       * left, the picked one on the right. General, Appearance (theme, panels' scale, title row), Keys, Viewport
       * (renderer, background frame rate) and Performance (what runs now).
       */
      void DrawSettings()
      {
        if (!mShowSettings) {
          return;
        }
        const ImGuiViewport* const viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowSize(
          ImVec2(std::min(Em(860.0f), viewport->WorkSize.x * 0.9f), std::min(Em(680.0f), viewport->WorkSize.y * 0.85f)),
          ImGuiCond_Appearing
        );
        ImGui::SetNextWindowPos(
          ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
          ImGuiCond_Appearing,
          ImVec2(0.5f, 0.5f)
        );
        if (ImGui::Begin("Settings", &mShowSettings, ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings)) {
          static constexpr const char* kPages[] = {"General", "Appearance", "Keys", "Viewport", "Performance"};
          // The pages, selected by fill.
          ImGui::BeginChild("##settingspages", ImVec2(Em(170.0f), 0.0f));
          for (int i = 0; i < static_cast<int>(std::size(kPages)); ++i) {
            if (ImGui::Selectable(kPages[i], mSettingsPage == i, ImGuiSelectableFlags_None, ImVec2(0.0f, Em(28.0f)))) {
              mSettingsPage = i;
            }
          }
          ImGui::EndChild();
          ImGui::SameLine(0.0f, Em(14.0f));
          ImGui::BeginChild("##settingspage", ImVec2(0.0f, 0.0f));
          SettingsHeading(kPages[mSettingsPage]);
          switch (mSettingsPage) {
          case 0: {
            SettingLabel("Help text", "The panels' help lines in full, or one line each (View > Full help text).");
            ImGui::Checkbox("Full help text", &FullHelpText());
            SettingLabel("Panels while playing", "The panels stay around the game while a play runs.");
            ImGui::Checkbox("Show the panels while playing", &mShell->PanelsWhilePlaying());
            SettingLabel(
              "Autosave",
              "While a map has unsaved changes, a copy of its files is kept outside the maps folder; if the "
              "editor stops, the next start offers it (File > Recover)."
            );
            bool autosave = mSettings.GetBool(EdSettings::kAutosave);
            if (ImGui::Checkbox("Autosave", &autosave)) {
              (void)mSettings.SetBool(EdSettings::kAutosave, autosave);
              mAutosaveOn = autosave && !mAutosaveRoot.empty();
              SaveSettings();
            }
            ImGui::SameLine();
            if (
              SettingChoice(
                EdSettings::kAutosaveMinutes, {{"1", "every minute"}, {"2", "2 min"}, {"5", "5 min"}, {"10", "10 min"}}
              )
            ) {
              mAutosaveEvery = 60.0 * mSettings.GetInt(EdSettings::kAutosaveMinutes);
            }
            SettingLabel(
              "Backups",
              "Before the first save of a session, the map's files are copied into the backups folder; "
              "each map keeps this many."
            );
            if (SettingChoice(EdSettings::kBackups, {{"0", "None"}, {"3", "3"}, {"10", "10"}, {"30", "30"}})) {
              mDocument.SetBackups(mBackupRoot, mSettings.GetInt(EdSettings::kBackups));
            }
            ImGui::TextDisabled("%s", mBackupRoot.string().c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Open##backups")) {
              std::error_code ignored;
              std::filesystem::create_directories(mBackupRoot, ignored);
              (void)::ShellExecuteW(nullptr, L"open", mBackupRoot.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            SettingLabel("Start screen", "New, recent work, your maps and the FAF vault (File > Start screen).");
            ImGui::Checkbox("Show the start screen when the editor starts", &mShell->HomeAtStart());
            ImGui::Checkbox("FAF vault items on the start screen", &mShell->HomeVaultItems());
            SettingLabel("Settings folder", nullptr);
            const std::filesystem::path folder = EditorSettingsFolder();
            ImGui::TextDisabled("%s", folder.string().c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Open")) {
              (void)::ShellExecuteW(nullptr, L"open", folder.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            ImGui::Spacing();
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextDisabled(
              "settings.ini keeps these settings, layout.ini the panels, the theme and the scale, keys.ini your keys."
            );
            ImGui::PopTextWrapPos();
            break;
          }
          case 1: {
            SettingLabel("Theme", "The editor's colours. Your own themes are Lua files in the themes folder.");
            const std::string current = gThemeNow;
            ImGui::SetNextItemWidth(Em(260.0f));
            if (EdBeginCombo("##theme", current.c_str())) {
              for (const EdTheme& theme : mThemes) {
                if (ImGui::Selectable(theme.name.c_str(), theme.name == current)) {
                  SetTheme(theme.name, true);
                  PostStatusMessage("Theme " + theme.name);
                }
              }
              ImGui::EndCombo();
            }
            ImGui::SameLine();
            if (ImGui::Button("Reload")) {
              (void)mCommands.Run("view.theme.reload");
            }
            ImGui::SameLine();
            if (ImGui::Button("Themes folder")) {
              (void)mCommands.Run("view.theme.folder");
            }
            SettingLabel("Panels' scale", "The size of the panels and their text (Ctrl+= / Ctrl+- / Ctrl+0).");
            float& scale = mShell->UiScale();
            int percent = static_cast<int>(std::lround(scale * 100.0f));
            ImGui::SetNextItemWidth(Em(260.0f));
            if (FillSliderInt("##uiscale", &percent, 75, 200, "%d %%", ImGuiSliderFlags_AlwaysClamp)) {
              scale = static_cast<float>(percent) / 100.0f;
            }
            ImGui::SameLine();
            if (ImGui::Button("100 %")) {
              scale = 1.0f;
            }
            SettingLabel(
              "Title row",
              "The editor draws its own title row with the menus and workspaces; Windows' caption instead suits remote "
              "desktop and screen readers. From the next start."
            );
            (void)SettingChoice(EdSettings::kTitleBar, {{"own", "The editor's"}, {"windows", "Windows'"}});
            if (mSettings.Get(EdSettings::kTitleBar) != mStartTitleBar) {
              ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "Changes when the editor starts again.");
            }
            break;
          }
          case 2:
            if (DrawKeysPage(mCommands, mKeyDefaults)) {
              SaveKeymap();
            }
            break;
          case 3: {
            SettingLabel(
              "Renderer",
              "Automatic tries Direct3D 12, then Vulkan. /d3d12 and /vulkan on the command line win. From "
              "the next start."
            );
            (void)SettingChoice(
              EdSettings::kRenderer, {{"auto", "Automatic"}, {"d3d12", "Direct3D 12"}, {"vulkan", "Vulkan"}}
            );
            gpg::gal::DeviceRuntimeInfo info;
            if (gpg::gal::Device::IsReady() && gpg::gal::Device::GetInstance()->GetRuntimeInfo(info)) {
              ImGui::TextDisabled("In use: %s on %s", info.api.c_str(), info.adapter.c_str());
            }
            if (mSettings.Get(EdSettings::kRenderer) != mStartRenderer) {
              ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "Changes when the editor starts again.");
            }
            SettingLabel(
              "Frame rate behind other windows",
              "While another window is in front and no play runs, the editor draws at most this often, so the GPU "
              "rests."
            );
            (void)SettingChoice(
              EdSettings::kBackgroundFps, {{"10", "10 fps"}, {"30", "30 fps"}, {"60", "60 fps"}, {"0", "No limit"}}
            );
            break;
          }
          default: {
            gpg::gal::DeviceRuntimeInfo info;
            if (gpg::gal::Device::IsReady() && gpg::gal::Device::GetInstance()->GetRuntimeInfo(info)) {
              SettingLabel("Renderer", nullptr);
              ImGui::TextDisabled("%s", info.api.c_str());
              SettingLabel("GPU", nullptr);
              ImGui::TextDisabled("%s", info.adapter.c_str());
            }
            SettingLabel("Frame", nullptr);
            ImGui::TextDisabled(
              "%.1f ms (%.0f fps)",
              1000.0 / std::max(1.0, static_cast<double>(ImGui::GetIO().Framerate)),
              static_cast<double>(ImGui::GetIO().Framerate)
            );
            SettingLabel("CPU threads", nullptr);
            ImGui::TextDisabled("%u", std::thread::hardware_concurrency());
            ImGui::Spacing();
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextDisabled(
              "GPU compute and thread counts are set here once the tools that use them (generators, erosion, bakes) "
              "have them."
            );
            ImGui::PopTextWrapPos();
            break;
          }
          }
          ImGui::EndChild();
        }
        ImGui::End();
      }

      /**
       * Autosave's and backups' folders and switches, after settings.ini is read: `%LOCALAPPDATA%\FAForever\Editor\
       * autosave` and `backups`. A test run autosaves only with `/autosavefolder <path>` (and backs up into
       * `/backupfolder <path>` if given), so it never touches the user's.
       */
      void SetUpAutosave()
      {
        const std::filesystem::path settings = EditorSettingsFolder();
        bool testFolders = false;
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/autosavefolder", 1, &value) && !value.empty()) {
          mAutosaveRoot = std::filesystem::path(value[0].c_str());
          testFolders = true;
        } else if (!settings.empty() && !gTestRun) {
          mAutosaveRoot = settings / "autosave";
        }
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/backupfolder", 1, &value) && !value.empty()) {
          mBackupRoot = std::filesystem::path(value[0].c_str());
        } else if (!settings.empty()) {
          mBackupRoot = settings / "backups";
        }
        mAutosaveEvery = 60.0 * mSettings.GetInt(EdSettings::kAutosaveMinutes);
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/autosaveevery", 1, &value) && !value.empty()) {
          mAutosaveEvery = std::max(1.0, std::atof(value[0].c_str()));
        }
        mAutosaveOn = !mAutosaveRoot.empty() && (testFolders || mSettings.GetBool(EdSettings::kAutosave));
        mDocument.SetBackups(mBackupRoot, mSettings.GetInt(EdSettings::kBackups));
        // One question before a map with unsaved changes is dropped (open, recent, new map, recover, exit); a test
        // run drops it without asking.
        mAskInTests = moho::CFG_GetArgOption("/askunsaved", 0, nullptr);
        mDocument.SetUnsavedGuard([this](std::function<void()> proceed) {
          if (gTestRun && !mAskInTests) {
            return false;
          }
          mGuardProceed = std::move(proceed);
          mGuardAsk = true;
          return true;
        });
        mRecoverable = mAutosaveRoot.empty() ? std::vector<EdAutosaveEntry>{} : ListAutosaves(mAutosaveRoot);
        mShowRecover = !mRecoverable.empty();
        gpg::Logf(
          "editor: autosave %s (every %.0f s into %s), %zu autosaved map%s to recover",
          mAutosaveOn ? "on" : "off",
          mAutosaveEvery,
          mAutosaveRoot.string().c_str(),
          mRecoverable.size(),
          mRecoverable.size() == 1 ? "" : "s"
        );
      }

      /**
       * Each frame: with unsaved changes, an autosave once the interval passed since the last one (or since the
       * changes began) and nothing was pressed for 3 s; not during a play. Only maps with files of their own on disk
       * (Recover puts the files back there).
       */
      void DriveAutosave()
      {
        const double now = StatusClock();
        const bool pressed = ImGui::IsAnyMouseDown() || (::GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0 ||
          (::GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0 || (::GetAsyncKeyState(VK_MBUTTON) & 0x8000) != 0 ||
          !ImGui::GetIO().InputQueueCharacters.empty();
        if (pressed) {
          mLastInput = now;
        }
        const bool open = mDocument.GetState() == EdDocument::State::Open;
        if (!open || !mDocument.Modified()) {
          mModifiedSince = -1.0;
          return;
        }
        if (mModifiedSince < 0.0) {
          mModifiedSince = now;
        }
        if (!mAutosaveOn || mPlay.Active() || mDocument.MapDiskFile().empty()) {
          return;
        }
        if (!AutosaveDue(now, true, std::max(mLastAutosave, mModifiedSince), mLastInput, mAutosaveEvery, 3.0)) {
          return;
        }
        mLastAutosave = now;
        const auto started = std::chrono::steady_clock::now();
        const std::filesystem::path folder = mAutosaveRoot / mDocument.FolderName();
        std::string error;
        if (!mDocument.WriteSnapshot(folder, error)) {
          gpg::Warnf("editor: autosave of %s failed: %s", mDocument.FolderName().c_str(), error.c_str());
          return;
        }
        EdAutosaveEntry entry;
        entry.scenario = mDocument.Path();
        entry.title = mDocument.FolderName();
        for (std::size_t i = 0; i < mPlay.Maps().size() && i < mPlay.Titles().size(); ++i) {
          if (_stricmp(mPlay.Maps()[i].c_str(), mDocument.Path().c_str()) == 0) {
            entry.title = mPlay.Titles()[i];
          }
        }
        entry.disk = mDocument.MapDiskFile().parent_path();
        entry.time = static_cast<std::int64_t>(std::time(nullptr));
        std::ofstream(folder / "autosave.txt", std::ios::binary | std::ios::trunc) << AutosaveNote(entry);
        const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
        gpg::Logf("editor: autosaved %s into %s in %.0f ms", entry.title.c_str(), folder.string().c_str(), ms);
        char clock[16];
        const std::time_t t = std::time(nullptr);
        std::tm local{};
        (void)localtime_s(&local, &t);
        (void)std::strftime(clock, sizeof(clock), "%H:%M", &local);
        PostStatusMessage(std::string("Autosaved ") + clock);
        mRecoverable = ListAutosaves(mAutosaveRoot);
      }

      /** Recover: the map's files backed up, the autosave's put in their place, the map opened. */
      void Recover(
        const EdAutosaveEntry& entry
      )
      {
        // The open map's unsaved changes are asked about before any file is touched.
        if ((!gTestRun || mAskInTests) && mDocument.GetState() == EdDocument::State::Open && mDocument.Modified()) {
          mGuardProceed = [this, entry] {
            Recover(entry);
          };
          mGuardAsk = true;
          return;
        }
        std::filesystem::path backup;
        std::string error;
        if (!RestoreAutosave(entry, mBackupRoot, std::max(3, mSettings.GetInt(EdSettings::kBackups)), backup, error)) {
          gpg::Warnf("editor: recover %s: %s", entry.title.c_str(), error.c_str());
          PostStatusMessage("Recover failed: " + error);
          return;
        }
        gpg::Logf(
          "editor: recovered %s from %s (its files before are in %s)",
          entry.title.c_str(),
          entry.folder.string().c_str(),
          backup.string().c_str()
        );
        RemoveAutosave(entry.folder);
        mRecoverable = ListAutosaves(mAutosaveRoot);
        mShell->HideHome();
        mShell->Browser().OpenListedMap(entry.scenario);
        PostStatusMessage("Recovered " + entry.title);
      }

      /**
       * The autosaves left by a crash or a close without saving, offered at the start and from File > Recover: each
       * with Recover (the map's files backed up first), Discard, or keep for later.
       */
      void DrawRecover()
      {
        if (mShowRecover && !ImGui::IsPopupOpen("Recover unsaved work")) {
          ImGui::OpenPopup("Recover unsaved work");
          gpg::Logf("editor: the recovery offer opens (%zu maps)", mRecoverable.size());
        }
        ImGui::SetNextWindowSize(ImVec2(Em(640.0f), 0.0f), ImGuiCond_Appearing);
        if (!ImGui::BeginPopupModal("Recover unsaved work", &mShowRecover)) {
          return;
        }
        // In front of the start screen, which is made a frame after this opens at the start (a window made later
        // goes in front of the ones before it).
        ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted(
          "The editor autosaved these maps and they weren't saved since (it closed without saving, or stopped). "
          "Recover puts the autosave's files in the map's folder and opens it; the map's files from before are backed "
          "up first."
        );
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        const double now = static_cast<double>(std::time(nullptr));
        std::optional<EdAutosaveEntry> recover;
        std::optional<std::filesystem::path> discard;
        for (const EdAutosaveEntry& entry : mRecoverable) {
          ImGui::PushID(entry.folder.string().c_str());
          ImGui::Separator();
          ImGui::TextUnformatted(entry.title.c_str());
          ImGui::SameLine();
          ImGui::TextDisabled("autosaved %s", AgoText(now - static_cast<double>(entry.time)).c_str());
          ImGui::TextDisabled("%s", entry.disk.string().c_str());
          if (ImGui::Button("Recover")) {
            recover = entry;
          }
          ImGui::SameLine();
          if (ImGui::Button("Discard")) {
            discard = entry.folder;
          }
          ImGui::PopID();
        }
        ImGui::Separator();
        if (ImGui::Button("Later")) {
          mShowRecover = false;
          ImGui::CloseCurrentPopup();
        }
        if (mRecoverable.empty()) {
          mShowRecover = false;
          ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
        if (discard) {
          gpg::Logf("editor: autosave discarded: %s", discard->string().c_str());
          RemoveAutosave(*discard);
          mRecoverable = ListAutosaves(mAutosaveRoot);
        }
        if (recover) {
          mShowRecover = false;
          Recover(*recover);
        }
      }

      /** The user's looks: `<settings>\Looks` (or `/looksfolder <dir>` in test runs), three FAFME files a look. */
      [[nodiscard]] static std::filesystem::path LooksFolder()
      {
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/looksfolder", 1, &value) && !value.empty()) {
          return std::filesystem::path(value[0].c_str());
        }
        const std::filesystem::path settings = EditorSettingsFolder();
        return settings.empty() ? settings : settings / "Looks";
      }

      void ListMyLooks()
      {
        std::vector<std::string> names;
        std::error_code error;
        const std::filesystem::path folder = LooksFolder();
        if (!folder.empty() && std::filesystem::is_directory(folder, error)) {
          for (const auto& entry : std::filesystem::directory_iterator(folder, error)) {
            if (entry.path().extension() == ".scmlighting") {
              names.push_back(entry.path().stem().string());
            }
          }
        }
        std::sort(names.begin(), names.end());
        mShell->SetMyLooks(std::move(names));
      }

      [[nodiscard]] static Look LookOfEnvironment(
        const EdDocument::LookEnvironment& environment
      )
      {
        Look look;
        look.lighting = environment.lighting;
        look.water = environment.water;
        look.sky = environment.sky;
        look.hasSky = true;
        look.cubes = environment.cubes;
        return look;
      }

      /** A look by id: a map's scenario path (its .scmap read through the game's files) or "mine:<name>". */
      bool LoadLook(
        const std::string& id,
        Look& look,
        std::string& error
      )
      {
        if (const auto cached = mLookCache.find(id); cached != mLookCache.end()) {
          look = cached->second;
          return true;
        }
        if (id.rfind("mine:", 0) == 0) {
          // The map's own look under the user's files (each file the look has).
          const std::string name = id.substr(5);
          const std::filesystem::path base = LooksFolder() / name;
          look = LookOfEnvironment(mDocument.LookEnvironmentNow());
          look.name = name;
          const auto read = [](const std::filesystem::path& path, std::string& text) {
            std::ifstream in(path, std::ios::binary);
            text.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            return in.good() || !text.empty();
          };
          std::string text;
          if (!read(std::filesystem::path(base).replace_extension(".scmlighting"), text)) {
            error = "no look named " + name;
            return false;
          }
          (void)LightingFromScmlighting(text, look.lighting, error);
          if (read(std::filesystem::path(base).replace_extension(".scmwtr"), text)) {
            (void)WaterFromScmwtr(text, look.water, error);
          }
          if (read(std::filesystem::path(base).replace_extension(".scmskybox"), text)) {
            look.hasSky = SkyboxFromScmskybox(text, look.sky, error);
          }
          error.clear();
        } else {
          std::string text;
          std::string bytes;
          std::smatch path;
          if (
            !ReadGameFile(id, text) ||
            !std::regex_search(text, path, std::regex(R"(\bmap\s*=\s*['"]([^'"]+\.scmap)['"])"))
          ) {
            error = id + " names no map file";
            return false;
          }
          if (!ReadGameFile(path[1].str(), bytes)) {
            error = "can't read " + path[1].str();
            return false;
          }
          if (!LookFromScmap(bytes, look, error)) {
            error = path[1].str() + ": " + error;
            return false;
          }
          look.name = MapDisplayName(id);
          gpg::Logf(
            "editor: look %s read: multiplier %.2f, water colour %.2f %.2f %.2f, %s (horizon %.2f %.2f %.2f, %zu "
            "planets, "
            "%s)",
            look.name.c_str(),
            static_cast<double>(look.lighting.multiplier),
            static_cast<double>(look.water.shader.mWaterColor[0]),
            static_cast<double>(look.water.shader.mWaterColor[1]),
            static_cast<double>(look.water.shader.mWaterColor[2]),
            look.hasSky ? "with its sky" : "no sky in the file",
            static_cast<double>(look.sky.horizonColor[0]),
            static_cast<double>(look.sky.horizonColor[1]),
            static_cast<double>(look.sky.horizonColor[2]),
            look.sky.planets.size(),
            look.sky.albedo.c_str()
          );
        }
        EdShell::LookSwatch swatch;
        std::memcpy(swatch.colours[0], look.sky.horizonColor, sizeof(swatch.colours[0]));
        std::memcpy(swatch.colours[1], look.sky.zenithColor, sizeof(swatch.colours[1]));
        std::memcpy(swatch.colours[2], look.lighting.sunColor, sizeof(swatch.colours[2]));
        std::memcpy(swatch.colours[3], look.water.shader.mWaterColor, sizeof(swatch.colours[3]));
        mShell->SetLookSwatch(id, swatch);
        mLookCache[id] = look;
        return true;
      }

      /** The Looks section's asks: try (no undo step), apply (one), revert, save the map's own, delete one. */
      void UpdateLooks()
      {
        if (!mLooksListed) {
          mLooksListed = true;
          ListMyLooks();
        }
        if (mDocument.GetState() != EdDocument::State::Open) {
          mLookOriginal.reset();
          mLookCache.clear();
          if (mShell->LookTrying()) {
            mShell->SetLookState({}, {});
          }
          return;
        }
        EdShell::LookRequest ask;
        if (!mShell->TakeLookRequest(ask)) {
          return;
        }
        using What = EdShell::LookRequest::What;
        const auto tryLook = [&]() {
          Look look;
          std::string error;
          if (!LoadLook(ask.id, look, error)) {
            mShell->SetLookState(mShell->LookTrying() ? mLookTriedId : std::string(), error);
            gpg::Warnf("editor: look: %s", error.c_str());
            return false;
          }
          if (!mLookOriginal.has_value()) {
            mLookOriginal = mDocument.LookEnvironmentNow();
          }
          const Look mixed = BlendLook(LookOfEnvironment(*mLookOriginal), look, ask.blend, ask.sections);
          mDocument.ApplyLookEnvironment({mixed.lighting, mixed.water, mixed.sky, mixed.cubes});
          mLookTriedId = ask.id;
          mLookTriedName = look.name;
          mShell->SetLookState(
            ask.id, "Trying " + look.name + ": Apply keeps it (one undo step), Revert takes it off."
          );
          gpg::Logf(
            "editor: trying look %s (blend %.2f, sections %u): multiplier %.2f",
            look.name.c_str(),
            static_cast<double>(ask.blend),
            ask.sections,
            static_cast<double>(mDocument.LightingNow().multiplier)
          );
          return true;
        };
        switch (ask.what) {
        case What::Try:
          (void)tryLook();
          break;
        case What::Apply:
          if (!mLookOriginal.has_value() && !tryLook()) {
            break;
          }
          mDocument.LookApplied(*mLookOriginal);
          mLookOriginal.reset();
          mShell->SetLookState({}, mLookTriedName + " applied: one undo step.");
          gpg::Logf("editor: look %s applied", mLookTriedName.c_str());
          break;
        case What::Revert:
          if (mLookOriginal.has_value()) {
            mDocument.ApplyLookEnvironment(*mLookOriginal);
            mLookOriginal.reset();
            mShell->SetLookState({}, "Reverted: the map's own look again.");
            gpg::Logf("editor: look %s reverted", mLookTriedName.c_str());
          }
          break;
        case What::Save: {
          const std::filesystem::path folder = LooksFolder();
          std::error_code error;
          std::filesystem::create_directories(folder, error);
          const EdDocument::LookEnvironment now = mDocument.LookEnvironmentNow();
          const std::filesystem::path base = folder / ask.name;
          const auto write = [](const std::filesystem::path& path, const std::string& text) {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out << text;
            return out.good();
          };
          const bool saved = !folder.empty() &&
            write(std::filesystem::path(base).replace_extension(".scmlighting"), LightingToScmlighting(now.lighting)) &&
            write(std::filesystem::path(base).replace_extension(".scmwtr"), WaterToScmwtr(now.water)) &&
            write(std::filesystem::path(base).replace_extension(".scmskybox"), SkyboxToScmskybox(now.sky));
          mLookCache.erase("mine:" + ask.name);
          mShell->SetLookState({}, saved ? "Saved as " + ask.name + "." : "Couldn't write to " + folder.string());
          gpg::Logf(
            "editor: look %s %s in %s", ask.name.c_str(), saved ? "saved" : "not saved", folder.string().c_str()
          );
          ListMyLooks();
          break;
        }
        case What::Delete: {
          const std::string name = ask.id.rfind("mine:", 0) == 0 ? ask.id.substr(5) : std::string();
          if (!name.empty()) {
            std::error_code error;
            for (const char* const extension : {".scmlighting", ".scmwtr", ".scmskybox"}) {
              std::filesystem::remove(std::filesystem::path(LooksFolder() / name).replace_extension(extension), error);
            }
            mLookCache.erase(ask.id);
            mShell->SetLookState(mShell->LookTrying() ? mLookTriedId : std::string(), "Deleted " + name + ".");
            ListMyLooks();
          }
          break;
        }
        case What::None:
          break;
        }
      }

      /**
       * The Generate workspace's terrain graph, each frame while its panels are shown: it runs on the view's ground,
       * and what it asks (a preview on the map, a build, taking the preview off) goes to the view.
       */
      /** The copies of a world point under a symmetry about the map's middle (none: an empty function). */
      LayoutImages LayoutImagesOf(
        const Symmetry symmetry,
        const int turns
      ) const
      {
        if (symmetry == Symmetry::None) {
          return {};
        }
        const MapFacts& facts = mDocument.Facts();
        const float cx = static_cast<float>(facts.fieldWidth - 1) * 0.5f;
        const float cz = static_cast<float>(facts.fieldHeight - 1) * 0.5f;
        return [symmetry, turns, cx, cz](const float x, const float z) {
          float outX[kMaxSymmetryCopies];
          float outZ[kMaxSymmetryCopies];
          const int n = SymmetryImages(symmetry, turns, cx, cz, x, z, outX, outZ);
          std::vector<std::pair<float, float>> out;
          for (int i = 0; i < n; ++i) {
            out.emplace_back(outX[i], outZ[i]);
          }
          return out;
        };
      }

      static Symmetry SymmetryOfOp(
        const std::string& name
      )
      {
        return name == "rot2"   ? Symmetry::HalfTurn
          : name == "mirror_xz" ? Symmetry::BothAxes
          : name == "mirror_x"  ? Symmetry::LeftRight
          : name == "mirror_z"  ? Symmetry::TopBottom
          : name == "rot4"      ? Symmetry::QuarterTurns
                                : Symmetry::None;
      }

      /**
       * Play of unsaved edits: a play of the open map while it has unsaved edits starts from a copy of it with the
       * edits (EdDocument::WritePlayCopy); the copy goes when the play has ended.
       */
      void DrivePlayCopy()
      {
        if (!mPlayCopyWired) {
          mPlayCopyWired = true;
          mPlay.SetScenarioFor([this](const std::string& selected) -> std::string {
            // A map with a mission plays from a copy too: its test run traces the nodes and can start at any stage.
            if (
              mDocument.GetState() != EdDocument::State::Open ||
              (!mDocument.Modified() && mDocument.MissionNow().Empty()) ||
              LowerPath(mDocument.Path()) != LowerPath(selected)
            ) {
              return selected;
            }
            std::string scenario;
            std::string message;
            if (!mDocument.WritePlayCopy(scenario, message)) {
              gpg::Warnf(
                "editor: play: the unsaved edits couldn't be copied (%s); playing the map as saved", message.c_str()
              );
              PostStatusMessage("Playing the map as saved: " + message);
              return selected;
            }
            // A folder made while the editor runs is mounted at /maps/<folder> as the game's init mounts the vault's
            // (once a session: the mount stays while the copy is written again for the next play).
            if (mPlayCopyMounted.insert(mDocument.PlayCopy()).second) {
              moho::RULE_FinishPreparingKept();
              moho::SIM_FinishPreparingLuaState();
              if (!moho::DISK_MountDirectoryNow(
                    mDocument.PlayCopyFolder(), ("/maps/" + mDocument.PlayCopy()).c_str()
                  )) {
                mPlayCopyMounted.erase(mDocument.PlayCopy());
                gpg::Warnf("editor: play: the copy couldn't be mounted; playing the map as saved");
                return selected;
              }
            }
            gpg::Logf("editor: play: %s; starting %s", message.c_str(), scenario.c_str());
            PostStatusMessage("Playing the map with its unsaved edits (a copy beside it, removed after the play).");
            return scenario;
          });
        }
        const bool active = mPlay.Active();
        if (mPlayCopyWasActive && !active && !mDocument.PlayCopy().empty()) {
          mDocument.RemovePlayCopy();
        }
        mPlayCopyWasActive = active;
      }
      /**
       * `/missiontest` (test runs): a two-stage mission (a line, a wait, the next stage's line) made in the Mission
       * workspace, checked, compiled into the script (it must load), then played from the play copy: its traces
       * (EDMISSION) come back in the log; then Stop, undo.
       */
      void TestMission()
      {
        if (
          mMissionTestStage >= 7 || (mMissionTestStage < 3 && (mScene.ModelsPending() || !mScene.Attached())) ||
          !moho::CFG_GetArgOption("/missiontest", 0, nullptr) || ++mMissionTestFrames % 120 != 0
        ) {
          return;
        }
        gpg::Logf(
          "editor: mission test stage %d: %zu stages, play %s, %zu undo steps; undo: %s",
          mMissionTestStage,
          mDocument.MissionNow().stages.size(),
          mPlay.Active() ? "on" : "off",
          mDocument.UndoOrder().size(),
          mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
        );
        switch (mMissionTestStage) {
        case 0: {
          mShell->SwitchWorkspace(5);
          mShell->HideHome();
          mShell->ShowMission();
          Mission before = mDocument.MissionNow();
          Mission& m = mDocument.EditMission();
          m = Mission{};
          MissionStage one;
          one.name = "Start";
          MissionNode text = NewMissionNode("dialogue");
          text.p["text"] = "Mission test: stage one";
          one.enter.push_back(text);
          MissionNode wait = NewMissionNode("wait");
          wait.p["seconds"] = "2";
          one.enter.push_back(wait);
          MissionStage two;
          two.name = "Next";
          MissionNode second = NewMissionNode("dialogue");
          second.p["text"] = "Mission test: stage two";
          two.enter.push_back(second);
          // A base on the second army, started empty at that army's start marker, and a line after it.
          const MissionFacts facts = MissionFactsOf(mDocument);
          const std::string army = facts.armies.size() > 1 ? facts.armies[1] : "ARMY_2";
          MissionBase base = NewMissionBase("TestBase", army);
          base.marker = army;
          base.startEmpty = true;
          MissionOpAI attack;
          attack.name = "TestAttack";
          attack.children = {"LightTanks"};
          attack.master = "default";
          base.opai.push_back(attack);
          m.bases = {base};
          MissionNode start = NewMissionNode("base_start");
          start.p["base"] = "TestBase";
          two.enter.push_back(start);
          MissionNode after = NewMissionNode("dialogue");
          after.p["text"] = "Mission test: after the base";
          two.enter.push_back(after);
          // A platoon template, registered when the script loads: a line reports it from the play.
          MissionPlatoon platoon;
          platoon.name = "PLATOON_Test";
          platoon.rows = {{"uel0201", 0, 4, "attack", "None"}, {"uel0103", 1, 2, "artillery", "None"}};
          m.platoons = {platoon};
          MissionNode report = NewMissionNode("raw");
          report.p["code"] = "LOG('EDMISSIONTEST platoon template PLATOON_Test: ' .. "
                             "table.getn(Scenario.Platoons['PLATOON_Test'] or {}) .. ' entries')";
          two.enter.push_back(report);
          m.stages = {one, two};
          mDocument.MissionEdited(std::move(before));
          std::size_t baseProblems = 0;
          for (const MissionProblem& p : CheckMission(m, facts)) {
            if (p.text.rfind("base ", 0) == 0) {
              ++baseProblems;
              gpg::Logf("editor: mission test: check: %c %s", p.level, p.text.c_str());
            }
          }
          gpg::Logf("editor: mission test: base on %s, %zu base problems", army.c_str(), baseProblems);
          break;
        }
        case 1: {
          mShell->RequestCheck();
          MissionPatch patch = MissionPatch::None;
          const std::string script = mDocument.ScriptWithMission(false, patch);
          const CheckIssue compiled = mDocument.CheckLuaText(script, "_script.lua");
          gpg::Logf(
            "editor: mission test: the script with the mission: %s, %zu bytes, %s",
            patch == MissionPatch::Written      ? "written"
              : patch == MissionPatch::Detached ? "detached"
                                                : "none",
            script.size(),
            compiled.text.empty() ? "it compiles" : ("does not compile: " + compiled.text).c_str()
          );
          break;
        }
        case 2: {
          // From the second stage (the Run panel's Play from a stage).
          mDocument.SetPlayStartStage(2);
          const std::vector<std::string>& maps = mPlay.Maps();
          const auto at = std::find_if(maps.begin(), maps.end(), [&](const std::string& p) {
            return LowerPath(p) == LowerPath(mDocument.Path());
          });
          if (at != maps.end()) {
            mPlay.Select(static_cast<int>(at - maps.begin()));
            mPlay.Play();
          }
          break;
        }
        case 4:
          gpg::Logf("editor: mission test: the Run panel holds %zu trace entries", mShell->MissionPanel().TraceCount());
          break;
        case 5:
          mPlay.Stop();
          break;
        case 6:
          gpg::Logf("editor: mission test: undo %s", mScene.Undo() ? "took a step back" : "had nothing");
          break;
        default:
          break;
        }
        ++mMissionTestStage;
      }
      /**
       * `/modtest` (test runs): a mod project in the vault's mods folder (made, or opened when it is there), a unit
       * with a weapon changed (mass cost, the first weapon's damage), written; the merge blueprint is logged and the
       * project reopened.
       */
      void TestModProject()
      {
        if (
          mModTestDone || !mScene.Attached() || !moho::CFG_GetArgOption("/modtest", 0, nullptr) ||
          ++mModTestFrames < 120
        ) {
          return;
        }
        moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
        if (rules == nullptr) {
          return;
        }
        mModTestDone = true;
        mShell->SwitchWorkspace(7);
        mShell->HideHome();
        mShell->ShowModProject();
        EdModPanel& panel = mShell->ModPanel();
        std::string error;
        if (!panel.Open("EditorModTest", error) && !panel.Create("EditorModTest", error)) {
          gpg::Warnf("editor: mod test: no project: %s", error.c_str());
          return;
        }
        // The first unit (by id) with a labelled weapon that does damage.
        std::vector<std::string> ids;
        for (const auto& [id, entry] : rules->GetUnitBlueprints()) {
          ids.emplace_back(id.c_str());
        }
        std::sort(ids.begin(), ids.end());
        for (const std::string& id : ids) {
          moho::RResId resId{};
          resId.name.assign(id.c_str());
          const moho::RUnitBlueprint* const bp = rules->GetUnitBlueprint(resId);
          if (bp == nullptr || bp->Weapons.WeaponBlueprints.empty()) {
            continue;
          }
          const moho::RUnitBlueprintWeapon& weapon = bp->Weapons.WeaponBlueprints.front();
          if (weapon.Label.empty() || weapon.Damage <= 0.0f) {
            continue;
          }
          ModProject& p = *panel.Project();
          const double mass = bp->Economy.BuildCostMass;
          (void)SetModEdit(p, id, "Economy.BuildCostMass", mass + 10.0, mass);
          (void)SetModEdit(
            p, id, std::string("Weapon:") + weapon.Label.c_str() + ".Damage", weapon.Damage * 2.0, weapon.Damage
          );
          panel.Touch();
          const ModWriteReport report = panel.Write();
          gpg::Logf(
            "editor: mod test: %s (mass %g, %s damage %g): %zu files written, %zu problems",
            id.c_str(),
            mass,
            weapon.Label.c_str(),
            static_cast<double>(weapon.Damage),
            report.written.size(),
            report.problems.size()
          );
          std::ifstream in(panel.Folder() / "units" / id / (id + "_unit.bp"), std::ios::binary);
          std::string line;
          while (std::getline(in, line)) {
            gpg::Logf("editor: mod test: bp | %s", line.c_str());
          }
          in.close(); // (Windows won't write over an open file)
          ModProject back;
          std::string reopenError;
          const bool reopened = OpenModProject(panel.Folder(), back, reopenError);
          gpg::Logf(
            "editor: mod test: reopened %s, uid %s, %zu units changed",
            reopened ? "fine" : reopenError.c_str(),
            back.uid == p.uid ? "kept" : "changed",
            back.edits.size()
          );
          // The checks, with a derived unit (no icon of its own) and a broken change, then the release.
          std::string error;
          (void)AddModDerived(p, "xaa0206", id, "", "", [&](const std::string& unit) {
            moho::RResId res{};
            res.name.assign(unit.c_str());
            return rules->GetUnitBlueprint(res) != nullptr;
          }, error);
          (void)SetModEdit(p, id, "Defense.MaxHealth", 0.0, 1.0);
          for (const ModIssue& issue : panel.Check()) {
            gpg::Logf("editor: mod test: check %c %s", issue.level, issue.text.c_str());
          }
          std::string releaseError;
          gpg::Logf(
            "editor: mod test: release with a broken change: %s",
            panel.Release(releaseError).empty() ? ("refused: " + releaseError).c_str() : "made"
          );
          p.edits[id].erase("Defense.MaxHealth");
          p.derived.clear();
          const std::filesystem::path zip = panel.Release(releaseError);
          gpg::Logf("editor: mod test: release %s", zip.empty() ? releaseError.c_str() : zip.string().c_str());
          return;
        }
        gpg::Warnf("editor: mod test: no unit with a labelled weapon");
      }
      /**
       * The unit lab's Test: the open mod project written, its folder mounted as /mods/<name> (once), its uid among
       * the play's mods, and the open map played (FAF's mods.lua finds the mod again: its cache is cleared first).
       */
      bool PlayModProject()
      {
        EdModPanel& panel = mShell->ModPanel();
        ModProject* const project = panel.Project();
        if (project == nullptr || mPlay.Active() || !mPlay.CanPlay()) {
          return false;
        }
        const ModWriteReport report = panel.Write();
        if (!report.problems.empty()) {
          gpg::Warnf(
            "editor: unit lab: the project wrote with %zu problems; testing what was written", report.problems.size()
          );
        }
        const std::string mount = "/mods/" + panel.Folder().filename().string();
        if (mModMounted.insert(mount).second) {
          moho::RULE_FinishPreparingKept();
          moho::SIM_FinishPreparingLuaState();
          if (!moho::DISK_MountDirectoryNow(panel.Folder(), mount.c_str())) {
            mModMounted.erase(mount);
            gpg::Warnf("editor: unit lab: couldn't mount %s as %s", panel.Folder().string().c_str(), mount.c_str());
            return false;
          }
          mPlay.FindModsAgain();
        }
        if (std::none_of(mPlay.Mods().begin(), mPlay.Mods().end(), [&](const PlayMod& mod) {
          return mod.uid == project->uid;
        })) {
          gpg::Warnf("editor: unit lab: the game doesn't list the project's mod (uid %s)", project->uid.c_str());
          return false;
        }
        const std::vector<std::string>& maps = mPlay.Maps();
        const auto at = std::find_if(maps.begin(), maps.end(), [&](const std::string& p) {
          return LowerPath(p) == LowerPath(mDocument.Path());
        });
        if (at == maps.end()) {
          gpg::Warnf("editor: unit lab: the open map isn't one the play lists");
          return false;
        }
        // After Select: it puts the map's remembered setup in place.
        mPlay.Select(static_cast<int>(at - maps.begin()));
        std::vector<std::string>& mods = mPlay.Setup().mods;
        if (std::find(mods.begin(), mods.end(), project->uid) == mods.end()) {
          mods.push_back(project->uid);
        }
        mPlay.Play();
        gpg::Logf(
          "editor: unit lab: testing mod project %s (%s, %zu units changed) on %s",
          project->name.c_str(),
          project->uid.c_str(),
          project->edits.size(),
          mDocument.Path().c_str()
        );
        return true;
      }
      std::set<std::string> mModMounted;

      /**
       * `/unitlabtest` (test runs): the unit lab on a project EditorUnitLabTest: a unit with a weapon (uel0201 when
       * the rules have it) gets mass +25 and its first weapon's damage x3 (two steps; undo and redo checked), Test
       * plays it, and the sim's own blueprint table is asked for both values during the play; then Stop.
       */
      void TestUnitLab()
      {
        if (
          mLabTestStage >= 9 || (mLabTestStage < 2 && (!mScene.Attached() || moho::RULE_PeekKept() == nullptr)) ||
          !moho::CFG_GetArgOption("/unitlabtest", 0, nullptr) || ++mLabTestFrames % 150 != 0
        ) {
          return;
        }
        EdUnitLabPanel& lab = mShell->UnitLab();
        switch (mLabTestStage) {
        case 0: {
          mShell->SwitchWorkspace(7);
          mShell->HideHome();
          mShell->ShowModProject();
          EdModPanel& panel = mShell->ModPanel();
          std::string error;
          if (!panel.Open("EditorUnitLabTest", error) && !panel.Create("EditorUnitLabTest", error)) {
            gpg::Warnf("editor: unit lab test: no project: %s", error.c_str());
            mLabTestStage = 9;
            return;
          }
          panel.Project()->edits.clear();
          std::string unit = "uel0201";
          if (EdUnitLabPanel::ReadUnit(unit).weapons.empty()) {
            for (const EdUnitInfo& info : mShell->Tools().UnitInfos()) {
              if (!EdUnitLabPanel::ReadUnit(info.id).weapons.empty()) {
                unit = info.id;
                break;
              }
            }
          }
          lab.SelectUnit(unit);
          const std::vector<UnitLabField> fields = UnitLabFields(EdUnitLabPanel::ReadUnit(unit));
          const UnitLabField* mass = nullptr;
          const UnitLabField* damage = nullptr;
          for (const UnitLabField& f : fields) {
            if (f.key == "Economy.BuildCostMass") {
              mass = &f;
            } else if (
              damage == nullptr && f.key.rfind("Weapon:", 0) == 0 && f.key.size() > 7 &&
              f.key.compare(f.key.size() - 7, 7, ".Damage") == 0
            ) {
              damage = &f;
            }
          }
          if (mass == nullptr || damage == nullptr) {
            gpg::Warnf("editor: unit lab test: %s has no mass cost or weapon damage", unit.c_str());
            mLabTestStage = 9;
            return;
          }
          (void)lab.SetField(*mass, mass->base + 25.0, false);
          (void)lab.SetField(*damage, damage->base * 3.0, false);
          ModProject& p = *panel.Project();
          const ModChanges after = ModChangesOf(p);
          const bool undone = panel.History().Undo(p);
          const std::size_t afterUndo = p.edits.count(unit) != 0 ? p.edits[unit].size() : 0;
          const bool redone = panel.History().Redo(p);
          gpg::Logf(
            "editor: unit lab test: %s, %zu fields; mass %g -> %g, %s %g -> %g; undo %s (%zu changes left), redo %s, "
            "same as before: %s",
            unit.c_str(),
            fields.size(),
            mass->base,
            mass->base + 25.0,
            damage->key.c_str(),
            damage->base,
            damage->base * 3.0,
            undone ? "took a step" : "had none",
            afterUndo,
            redone ? "took it again" : "had none",
            ModChangesOf(p) == after ? "yes" : "no"
          );
          mLabTestUnit = unit;
          // A derived unit of it: its own mass cost, named.
          p.derived.clear();
          std::string deriveError;
          if (lab.Derive("xel0201", "Lab Tank", "A heavier Medium Tank", deriveError)) {
            (void)lab.SetField(*mass, mass->base * 2.0 + 44.0, false);
            gpg::Logf(
              "editor: unit lab test: derived xel0201 from %s, mass %g; %zu history steps",
              unit.c_str(),
              mass->base * 2.0 + 44.0,
              panel.History().Size()
            );
          } else {
            gpg::Warnf("editor: unit lab test: no derived unit: %s", deriveError.c_str());
          }
          lab.SelectUnit(unit);
          {
            std::string label;
            std::string field;
            (void)ModWeaponKey(damage->key, label, field);
            mLabTestWeapon = EdModPanel::WeaponIndex(unit, label); // (the kept rules are rebuilt for the play)
          }
          break;
        }
        case 1:
          if (!PlayModProject()) {
            gpg::Warnf("editor: unit lab test: Test didn't start a play");
            mLabTestStage = 9;
            return;
          }
          break;
        case 4:
        case 6: {
          const int index = mLabTestWeapon;
          char command[400];
          (void)std::snprintf(
            command,
            sizeof(command),
            "SimLua local b = __blueprints['%s'] LOG('editor: unit lab test: the sim has mass ', "
            "b.Economy.BuildCostMass, "
            "', weapon %d damage ', b.Weapon[%d].Damage)",
            mLabTestUnit.c_str(),
            index,
            index
          );
          moho::CON_Execute(command);
          (void)std::snprintf(
            command,
            sizeof(command),
            "SimLua local d = __blueprints['xel0201'] if d then LOG('editor: unit lab test: the sim has xel0201: mass "
            "', "
            "d.Economy.BuildCostMass, ', name ', d.General.UnitName, ', weapon 1 damage ', d.Weapon[1].Damage) "
            "else LOG('editor: unit lab test: the sim has no xel0201') end"
          );
          moho::CON_Execute(command);
          break;
        }
        case 8:
          mPlay.Stop();
          break;
        default:
          break;
        }
        ++mLabTestStage;
      }
      /**
       * `/effectmodtest` (test runs): a game emitter opened in the particle editor, a copy with a longer lifetime
       * and a changed size curve written into a project EditorEffectTest (a merge), a copy with a curve cut to one key
       * (a replacement), the merge played: the sim's blueprint table asked for the emitter's lifetime.
       */
      void TestEffectMod()
      {
        static constexpr char kEmitter[] = "/effects/emitters/adisruptor_hit_01_emit.bp";
        if (
          mFxTestStage >= 7 || (mFxTestStage < 2 && (!mScene.Attached() || moho::RULE_PeekKept() == nullptr)) ||
          !moho::CFG_GetArgOption("/effectmodtest", 0, nullptr) || ++mFxTestFrames % 150 != 0
        ) {
          return;
        }
        EdParticleEditor& fx = mShell->ParticleEditor();
        switch (mFxTestStage) {
        case 0: {
          mShell->HideHome();
          mShell->ShowModProject();
          EdModPanel& panel = mShell->ModPanel();
          std::string error;
          if (!panel.Open("EditorEffectTest", error) && !panel.Create("EditorEffectTest", error)) {
            gpg::Warnf("editor: effect mod test: no project: %s", error.c_str());
            mFxTestStage = 7;
            return;
          }
          fx.SetModProject(panel.Folder(), panel.Project()->name);
          if (!fx.OpenGameEmitter(kEmitter) || fx.Emitters().empty()) {
            gpg::Warnf("editor: effect mod test: couldn't open %s: %s", kEmitter, fx.Status().c_str());
            mFxTestStage = 7;
            return;
          }
          // A replacement first (a curve cut to one key), then the merge over it.
          auto emitters = fx.Emitters();
          EmitterBlueprint& e = emitters.front().second;
          const float lifetime = e.lifetime;
          std::size_t longest = 0;
          for (std::size_t c = 1; c < e.curves.size(); ++c) {
            if (e.curves[c].keys.size() > e.curves[longest].keys.size()) {
              longest = c;
            }
          }
          // A replacement: another game emitter with a curve of two keys or more, cut to one.
          for (const char* other :
               {"/effects/emitters/aeon_light_displacement_missile_hit_02_emit.bp",
                "/effects/emitters/adisruptor_cannon_muzzle_01_emit.bp",
                "/effects/emitters/adisruptor_cannon_munition_01_emit.bp",
                "/effects/emitters/a3_end_nis_01_emit.bp",
                "/effects/emitters/a3_end_nis_02_emit.bp"}) {
            std::string text;
            EmitterBlueprint cut;
            std::string error;
            if (!ReadGameFile(other, text) || !ParseEmitter(text, cut, error)) {
              continue;
            }
            const auto many = std::find_if(cut.curves.begin(), cut.curves.end(), [](const EmitterCurve& c) {
              return c.keys.size() >= 2;
            });
            if (many == cut.curves.end()) {
              continue;
            }
            const std::size_t keys = many->keys.size();
            many->keys.resize(1);
            mFxCutLifetime = cut.lifetime;
            cut.lifetime += 3.0f;
            mFxCutPath = other;
            std::string base = other;
            base = base.substr(base.find_last_of('/') + 1);
            base = base.substr(0, base.size() - 3);
            (void)fx.SaveEmittersToMod({{base, cut}}, other);
            gpg::Logf(
              "editor: effect mod test: %s: %s cut from %zu keys to 1: %s",
              other,
              CurveInfo(static_cast<int>(many - cut.curves.begin())).name,
              keys,
              fx.Status().c_str()
            );
            std::ifstream replaced(panel.Folder() / EffectModFile(other), std::ios::binary);
            std::string head;
            for (int n = 0; n < 4 && std::getline(replaced, head); ++n) {
              gpg::Logf("editor: effect mod test: replacement | %s", head.c_str());
            }
            break;
          }
          e.lifetime = lifetime + 7.0f;
          if (!e.curves[longest].keys.empty()) {
            e.curves[longest].keys.front().y += 1.0f;
          }
          (void)fx.SaveEmittersToMod(emitters, fx.OpenedPaths());
          gpg::Logf("editor: effect mod test: lifetime %g -> %g: %s", lifetime, lifetime + 7.0f, fx.Status().c_str());
          std::ifstream in(panel.Folder() / EffectModFile(kEmitter), std::ios::binary);
          std::string line;
          while (std::getline(in, line)) {
            gpg::Logf("editor: effect mod test: bp | %s", line.c_str());
          }
          break;
        }
        case 1:
          if (!PlayModProject()) {
            gpg::Warnf("editor: effect mod test: no play");
            mFxTestStage = 7;
            return;
          }
          break;
        case 4: {
          // The play's own rules (the sim's Lua has no emitter blueprints): what the game made of the two files.
          const moho::CWldSession* const session = moho::WLD_GetActiveSession();
          moho::RRuleGameRules* const rules = session != nullptr ? session->mRules : nullptr;
          for (const std::string& path : {std::string(kEmitter), mFxCutPath}) {
            if (path.empty()) {
              continue;
            }
            const moho::REmitterBlueprint* const bp =
              rules != nullptr ? moho::RULE_FindEmitterBlueprintByName(rules, path.c_str()) : nullptr;
            gpg::Logf(
              "editor: effect mod test: the play's rules have %s: %s",
              path.c_str(),
              bp != nullptr ? ("lifetime " + std::to_string(bp->Lifetime)).c_str() : "no such emitter"
            );
          }
          break;
        }
        case 6:
          mPlay.Stop();
          break;
        default:
          break;
        }
        ++mFxTestStage;
      }
      /**
       * `/assettest` (test runs): the asset browser in Objects: each kind listed and searched, a prop picked (the Props
       * tool takes it), a favourite and the recent list; the prop pictures' cache counts logged.
       */
      void TestAssets()
      {
        if (
          mAssetTestStage >= 4 || !mScene.Attached() || moho::RULE_PeekKept() == nullptr ||
          !moho::CFG_GetArgOption("/assettest", 0, nullptr) || ++mAssetTestFrames % 120 != 0
        ) {
          return;
        }
        EdAssetBrowser& assets = mShell->Assets();
        switch (mAssetTestStage) {
        case 0: {
          mShell->SwitchWorkspace(1);
          mShell->HideHome();
          mShell->ShowAssets();
          for (int k = 0; k < kAssetKindCount; ++k) {
            const AssetKind kind = static_cast<AssetKind>(k);
            const std::vector<AssetEntry>& entries = assets.Entries(kind);
            std::string facets;
            for (const AssetFacet& facet : AssetFacets(kind)) {
              facets += std::string(" ") + facet.id + "=" + std::to_string(AssetFacetValues(entries, facet.id).size());
            }
            gpg::Logf(
              "editor: asset test: %s %zu entries, facets%s", AssetKindName(kind), entries.size(), facets.c_str()
            );
          }
          AssetQuery query;
          query.text = "pine";
          const std::vector<AssetEntry>& props = assets.Entries(AssetKind::Props);
          const std::vector<std::size_t> pines = FindAssets(props, query, assets.Marks());
          gpg::Logf("editor: asset test: 'pine' finds %zu props", pines.size());
          if (!pines.empty()) {
            assets.Pick(props[pines.front()]);
            assets.Marks().ToggleFavourite(props[pines.back()]);
            gpg::Logf(
              "editor: asset test: picked %s; the Props tool places %s; favourite %s",
              props[pines.front()].key.c_str(),
              mShell->Tools().PropBlueprint().c_str(),
              props[pines.back()].name.c_str()
            );
          }
          assets.Show(AssetKind::Props, "pine");
          break;
        }
        case 3: {
          AssetQuery recent;
          recent.recent = true;
          const std::vector<AssetEntry>& props = assets.Entries(AssetKind::Props);
          gpg::Logf(
            "editor: asset test: recent %zu, favourites %zu; prop pictures from the cache %d, written to it %d",
            FindAssets(props, recent, assets.Marks()).size(),
            assets.Marks().FavouriteCount(),
            mPropThumbnails.CacheHits(),
            mPropThumbnails.CacheWrites()
          );
          break;
        }
        default:
          break;
        }
        ++mAssetTestStage;
      }
      /**
       * `/editormodtest` (test runs): the test vault's EditorModApiTest turned on (its commands registered), its hello
       * command run through the registry (it logs the map's path and runs view.frame), then its failing command (the
       * mod turned off, its commands saying why).
       */
      void TestEditorMods()
      {
        if (
          mEditorModTestDone || !mScene.Attached() || !moho::CFG_GetArgOption("/editormodtest", 0, nullptr) ||
          ++mEditorModTestFrames < 150
        ) {
          return;
        }
        mEditorModTestDone = true;
        mShell->SwitchWorkspace(7);
        mShell->HideHome();
        mShell->ShowEditorMods();
        EdModHost& host = mShell->ModHost();
        for (const auto& mod : host.Mods()) {
          gpg::Logf(
            "editor: editor mod test: found %s (%s), api %d, %s",
            mod->info.name.c_str(),
            mod->info.uid.c_str(),
            mod->info.api,
            mod->running ? "running" : ("not running: " + mod->error).c_str()
          );
        }
        const std::string uid = "11111111-2222-4333-a444-555555555555";
        (void)host.SetEnabled(uid, true);
        const auto hello = EditorModCommandId("EditorModApiTest", "hello");
        const auto broken = EditorModCommandId("EditorModApiTest", "broken");
        gpg::Logf(
          "editor: editor mod test: %s in the registry: %s",
          hello.c_str(),
          mCommands.Find(hello) != nullptr ? "yes" : "no"
        );
        gpg::Logf(
          "editor: editor mod test: run hello: %s", mCommands.Run(hello) ? "ran" : mCommands.WhyNot(hello).c_str()
        );
        gpg::Logf(
          "editor: editor mod test: run broken: %s", mCommands.Run(broken) ? "ran" : mCommands.WhyNot(broken).c_str()
        );
        gpg::Logf(
          "editor: editor mod test: hello now: %s",
          mCommands.WhyNot(hello).empty() ? "can run" : mCommands.WhyNot(hello).c_str()
        );
        (void)host.SetEnabled(uid, false);
      }
      /**
       * `/unitviewtest` (test runs): a project EditorViewTest with xel0301 derived from uel0201; the unit viewer shows
       * it (the pixels the renderer drew counted), Make icon writes its icon, the derived unit then names it in the
       * hook.
       */
      void TestUnitViewer()
      {
        if (
          mViewTestStage >= 5 || !mScene.Attached() || moho::RULE_PeekKept() == nullptr ||
          !moho::CFG_GetArgOption("/unitviewtest", 0, nullptr) || ++mViewTestFrames % 90 != 0
        ) {
          return;
        }
        EdModPanel& panel = mShell->ModPanel();
        EdUnitViewer& viewer = mShell->UnitViewer();
        switch (mViewTestStage) {
        case 0: {
          mShell->SwitchWorkspace(7);
          mShell->HideHome();
          mShell->ShowModProject();
          mShell->ShowUnitViewer();
          std::string error;
          if (!panel.Open("EditorViewTest", error) && !panel.Create("EditorViewTest", error)) {
            gpg::Warnf("editor: unit view test: no project: %s", error.c_str());
            mViewTestStage = 5;
            return;
          }
          panel.Project()->derived.clear();
          panel.Project()->edits.clear();
          mShell->UnitLab().SelectUnit("uel0201");
          std::string deriveError;
          const bool derived = mShell->UnitLab().Derive("xel0301", "Viewer Tank", "", deriveError);
          viewer.SetAngles(35.0f, 15.0f);
          viewer.Focus();
          gpg::Logf("editor: unit view test: derived xel0301: %s", derived ? "yes" : deriveError.c_str());
          break;
        }
        case 1:
          viewer.Focus(); // again, after the workspace's layout is in place
          break;
        case 2: {
          gpg::Logf("editor: unit view test: the viewer drew %d of %d pixels", viewer.DrawnPixels(), 384 * 384);
          std::string error;
          gpg::Logf("editor: unit view test: make icon: %s", viewer.AskIcon(error) ? "asked" : error.c_str());
          break;
        }
        case 4: {
          gpg::Logf("editor: unit view test: %s", viewer.Status().c_str());
          std::error_code ec;
          const std::filesystem::path icon = panel.Folder() / ModUnitIconFile("xel0301");
          gpg::Logf(
            "editor: unit view test: icon file %s, %llu bytes (a 64 px DXT5 with mips is %llu)",
            std::filesystem::exists(icon, ec) ? "there" : "missing",
            static_cast<unsigned long long>(
              std::filesystem::exists(icon, ec) ? std::filesystem::file_size(icon, ec) : 0
            ),
            static_cast<unsigned long long>(DdsFileSize(64, DdsKind::Bc3))
          );
          const ModWriteReport report = panel.Write();
          std::ifstream hook(panel.Folder() / kModHookFile, std::ios::binary);
          std::ostringstream text;
          text << hook.rdbuf();
          gpg::Logf(
            "editor: unit view test: derived icon flag %s; the hook %s; icon note %s",
            panel.Project()->derived.count("xel0301") != 0 && panel.Project()->derived.at("xel0301").icon ? "set"
                                                                                                          : "not set",
            text.str().find("'Viewer Tank', '', true,") != std::string::npos ? "names the icon" : "doesn't name it",
            std::any_of(
              panel.Check().begin(),
              panel.Check().end(),
              [](const ModIssue& i) {
            return i.text.find("xel0301 shows") != std::string::npos;
          }
            )
              ? "still there"
              : "gone"
          );
          (void)report;
          break;
        }
        default:
          break;
        }
        ++mViewTestStage;
      }
      /**
       * `/pausetest` (test runs): the open map played; Play › Pause, the session's pause state and sim tick logged a
       * few seconds apart, then Pause again (resume), then Stop.
       */
      void TestPause()
      {
        if (
          mPauseTestStage >= 6 || (mPauseTestStage == 0 && !mScene.Attached()) ||
          !moho::CFG_GetArgOption("/pausetest", 0, nullptr) || ++mPauseTestFrames % 150 != 0
        ) {
          return;
        }
        const auto state = [this](const char* when) {
          moho::CWldSession* const session = moho::WLD_GetActiveSession();
          if (session == nullptr) {
            gpg::Logf("editor: pause test %s: no session", when);
            return;
          }
          const bool paused =
            session->mRequestingPauseState != 0U ? session->mRequestingPause != 0 : session->mSessionPauseStateA != 0;
          gpg::Logf("editor: pause test %s: paused %s, game tick %d", when, paused ? "yes" : "no", session->mGameTick);
        };
        switch (mPauseTestStage) {
        case 0: {
          const std::vector<std::string>& maps = mPlay.Maps();
          const auto at = std::find_if(maps.begin(), maps.end(), [&](const std::string& p) {
            return LowerPath(p) == LowerPath(mDocument.Path());
          });
          if (at != maps.end()) {
            mPlay.Select(static_cast<int>(at - maps.begin()));
            mPlay.Play();
          }
          break;
        }
        case 2:
          state("before");
          gpg::Logf(
            "editor: pause test: play.pause %s",
            mCommands.Run("play.pause") ? "ran" : mCommands.WhyNot("play.pause").c_str()
          );
          break;
        case 3:
          state("paused a while");
          (void)mCommands.Run("play.pause");
          break;
        case 4:
          state("resumed a while");
          break;
        case 5:
          mPlay.Stop();
          break;
        default:
          break;
        }
        ++mPauseTestStage;
      }
      bool mViewMenuTested = false;
      bool mMapInfoTested = false;
      int mViewMenuFrames = 0;
      int mPauseTestStage = 0;
      int mPauseTestFrames = 0;

      int mViewTestStage = 0;
      int mViewTestFrames = 0;

      bool mEditorModTestDone = false;
      int mEditorModTestFrames = 0;

      int mAssetTestStage = 0;
      int mAssetTestFrames = 0;

      int mFxTestStage = 0;
      int mFxTestFrames = 0;
      std::string mFxCutPath;
      float mFxCutLifetime = 0.0f;

      int mLabTestStage = 0;
      int mLabTestFrames = 0;
      std::string mLabTestUnit;
      int mLabTestWeapon = 1;

      bool mModTestDone = false;
      int mModTestFrames = 0;

      int mMissionTestStage = 0;
      int mMissionTestFrames = 0;

      bool mPlayCopyWired = false;
      bool mPlayCopyWasActive = false;
      std::set<std::string> mPlayCopyMounted;

      /**
       * `/playcopytest` (test runs): a marker moved (an unsaved edit), Play (the copy with the edit starts), then Stop
       * (the copy goes); the copy's folder and the play's state at each stage, two seconds apart.
       */
      void TestPlayCopy()
      {
        if (
          mPlayCopyTestStage >= 6 || (mPlayCopyTestStage < 2 && (mScene.ModelsPending() || !mScene.Attached())) ||
          !moho::CFG_GetArgOption("/playcopytest", 0, nullptr) || ++mPlayCopyTestFrames % 120 != 0
        ) {
          return;
        }
        const std::string copy = mDocument.PlayCopy();
        gpg::Logf(
          "editor: play copy test stage %d: modified %s, play %s, copy %s",
          mPlayCopyTestStage,
          mDocument.Modified() ? "yes" : "no",
          mPlay.Active() ? "on" : "off",
          copy.empty() ? "none" : copy.c_str()
        );
        switch (mPlayCopyTestStage) {
        case 0: {
          EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
          for (SaveEntry& marker : mDocument.SaveData().Markers()) {
            float x = 0.0f, y = 0.0f, z = 0.0f;
            if (MarkerPosition(marker, x, y, z)) {
              marker.Set("position", Vector3Value(x + 8.0f, y, z));
              gpg::Logf(
                "editor: play copy test: %s moved to %.1f, %.1f", marker.name.c_str(), x + 8.0, static_cast<double>(z)
              );
              break;
            }
          }
          mDocument.SaveDataEdited(std::move(before));
          break;
        }
        case 1: {
          const std::vector<std::string>& maps = mPlay.Maps();
          const auto at = std::find_if(maps.begin(), maps.end(), [&](const std::string& m) {
            return LowerPath(m) == LowerPath(mDocument.Path());
          });
          if (at == maps.end()) {
            gpg::Warnf("editor: play copy test: %s isn't in the play list", mDocument.Path().c_str());
            mPlayCopyTestStage = 6;
            return;
          }
          mPlay.Select(static_cast<int>(at - maps.begin()));
          mPlay.Play();
          break;
        }
        case 3:
          mPlay.Stop();
          break;
        default:
          break;
        }
        ++mPlayCopyTestStage;
      }
      int mPlayCopyTestStage = 0;
      int mPlayCopyTestFrames = 0;

      /**
       * The Layout workspace: strokes follow the editor's symmetry, a template's symmetry becomes the editor's, and
       * Generate terrain builds the layers' heights at the map's resolution (made symmetric by the editor's symmetry,
       * as Studio's generator does) and writes them with the water level as one undo step.
       */
      void DriveLayout()
      {
        EdLayoutPanel& panel = mShell->LayoutPanel();
        MapLayout& layout = mDocument.Layout();
        if (!mLayoutWired) {
          mLayoutWired = true;
          panel.SetImagesFor([this](const std::string& name) {
            return LayoutImagesOf(SymmetryOfOp(name), 3);
          });
        }
        if (mDocument.Map() == nullptr) {
          return;
        }
        std::string symmetryName;
        if (panel.TakeSymmetryAsk(symmetryName)) {
          mShell->Tools().PickSymmetry(static_cast<int>(SymmetryOfOp(symmetryName)));
        }
        const HeightBrush brush = mShell->Tools().CurrentHeightBrush();
        layout.SetImages(LayoutImagesOf(brush.symmetry, brush.turns));
        const bool planAsked = panel.TakePlanAsk();
        const bool placeAsked = panel.TakePlaceAsk();
        if ((planAsked || placeAsked) && (!mScene.Attached() || mScene.ModelsPending())) {
          panel.SetPlan(std::nullopt, "The map isn't ready yet; try again in a moment.");
        } else if (placeAsked) {
          PlaceLayoutMarkers();
        } else if (planAsked) {
          const LayoutMarkerPlan plan = PlanLayoutNow();
          gpg::Logf("editor: layout markers: plan: %s", plan.text.c_str());
          std::string text = "Plan: " + plan.text + ".";
          panel.SetPlan(plan, std::move(text));
        }
        if (!panel.TakeGenerateAsk()) {
          return;
        }
        if (!mScene.Attached() || mScene.ModelsPending()) {
          panel.SetStatus("The map isn't ready yet; generate again in a moment.");
          return;
        }
        const auto t0 = std::chrono::steady_clock::now();
        const MapFacts& facts = mDocument.Facts();
        const field::Grid like(facts.fieldWidth, facts.fieldHeight, 1.0f, 0.0f, 0.0f);
        field::Grid heights;
        std::string error;
        LayoutBuildOptions buildOptions;
        buildOptions.weather = layout.weather;
        if (!BuildLayout(layout, like, buildOptions, heights, nullptr, error)) {
          panel.SetStatus("Generate terrain: " + error);
          return;
        }
        if (brush.symmetry != Symmetry::None) {
          std::vector<std::uint16_t> words(heights.v.size());
          for (std::size_t k = 0; k < words.size(); ++k) {
            words[k] = static_cast<std::uint16_t>(std::clamp(std::lround(heights.v[k] * 128.0f), 0L, 65535L));
          }
          SymmetrizeOptions options;
          options.symmetry = brush.symmetry;
          options.turns = brush.turns;
          options.seam = 12.0f;
          std::string why;
          if (SymmetrizeHeights(words.data(), heights.w, heights.h, options, why)) {
            for (std::size_t k = 0; k < words.size(); ++k) {
              heights.v[k] = static_cast<float>(words[k]) / 128.0f;
            }
          }
        }
        std::string status = mScene.ApplyGraphBuild(heights, true, TerrainBuildWrites{});
        bool wet = false;
        for (const LayoutLayer& layer : layout.Layers()) {
          wet = wet || (layer.kind == LayoutKind::Water && layer.visible && LayoutLayerHas(layer, 0.3f));
        }
        if (wet) {
          const WaterState before = mDocument.WaterNow();
          WaterState water = before;
          water.enabled = true;
          water.elevation = layout.water;
          water.deep = layout.water - 12.0f;
          water.abyss = layout.water - 30.0f;
          if (!(water == before)) {
            mDocument.ApplyWater(water);
            mDocument.BuildAddWater(before);
            status += " The water level is now " + std::to_string(static_cast<int>(layout.water)) + ".";
          }
        }
        const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        gpg::Logf("editor: layout: generated in %.0f ms: %s", ms, status.c_str());
        panel.SetStatus(status);
      }

      /** What the start and resource generator checks against: the playable area, the heights, the sea. */
      LayoutGround LayoutGroundNow() const
      {
        LayoutGround g;
        mDocument.LayoutArea(g.x0, g.z0, g.x1, g.z1);
        const moho::CHeightField* const field = mDocument.Map() != nullptr && mDocument.Map()->mTerrainRes != nullptr
          ? mDocument.Map()->mTerrainRes->GetHeightField()
          : nullptr;
        if (field != nullptr) {
          g.height = [field](const float x, const float z) {
            const int ix = std::clamp(static_cast<int>(x), 0, field->width - 1);
            const int iz = std::clamp(static_cast<int>(z), 0, field->height - 1);
            return static_cast<float>(field->data[static_cast<std::size_t>(iz) * field->width + ix]) / 128.0f;
          };
        }
        const WaterState water = mDocument.WaterNow();
        g.water = water.enabled ? water.elevation : -1000.0f;
        return g;
      }

      /** Whether a marker the generator made is still there (its name at its place). */
      static bool GeneratedStill(
        const MapLayout::Generated& made,
        const SaveEntry& marker
      )
      {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        return marker.name == made.name && MarkerPosition(marker, x, y, z) && std::fabs(x - made.x) < 0.05f &&
          std::fabs(z - made.z) < 0.05f;
      }

      /** The map's start positions (its ARMY_<n> start markers, in the order of its armies). */
      std::vector<LayoutPoint> MapStarts() const
      {
        std::vector<LayoutPoint> out;
        for (const std::string& army : mDocument.Armies()) {
          for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
            float x = 0.0f, y = 0.0f, z = 0.0f;
            if (marker.name == army && MarkerPosition(marker, x, y, z)) {
              out.push_back({x, z, marker.name});
            }
          }
        }
        return out;
      }

      /** The resource markers that stay where they are (with Remove the old ones, not those the generator made). */
      std::vector<LayoutPoint> StayingResources(
        const bool clear
      ) const
      {
        std::vector<LayoutPoint> out;
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          const std::string type = MarkerTypeOf(marker);
          float x = 0.0f, y = 0.0f, z = 0.0f;
          if ((type != "Mass" && type != "Hydrocarbon") || !MarkerPosition(marker, x, y, z)) {
            continue;
          }
          bool made = false;
          for (const MapLayout::Generated& g : mDocument.Layout().generated) {
            made = made || GeneratedStill(g, marker);
          }
          if (!(clear && made)) {
            out.push_back({x, z, marker.name});
          }
        }
        return out;
      }

      LayoutMarkerPlan PlanLayoutNow() const
      {
        const LayoutMarkerSettings& s = mShell->LayoutPanel().MarkerSettings();
        const LayoutGround ground = LayoutGroundNow();
        std::vector<LayoutPoint> bases;
        for (const LayoutBase& base : mDocument.Layout().BaseCentres()) {
          bases.push_back({base.x, base.z, {}});
        }
        const std::vector<LayoutPoint> starts = LayoutStarts(s, ground, MapStarts(), bases);
        return PlanLayoutMarkers(s, ground, starts, StayingResources(s.clear));
      }

      /**
       * Place markers: the generator's markers from last time removed (Remove the old ones), the starts moved, added
       * or removed to match (Replace the start markers; armies follow), then the resources planned against the map
       * as it is now and placed; one undo step.
       */
      void PlaceLayoutMarkers()
      {
        EdLayoutPanel& panel = mShell->LayoutPanel();
        const LayoutMarkerSettings& s = panel.MarkerSettings();
        MapLayout& layout = mDocument.Layout();
        const LayoutGround ground = LayoutGroundNow();
        std::vector<LayoutPoint> bases;
        for (const LayoutBase& base : layout.BaseCentres()) {
          bases.push_back({base.x, base.z, {}});
        }
        const std::vector<LayoutPoint> starts = LayoutStarts(s, ground, MapStarts(), bases);
        if (s.starts != LayoutStartMode::Existing && starts.empty()) {
          panel.SetPlan(
            std::nullopt,
            s.starts == LayoutStartMode::Bases ? "No base is drawn in the layout (draw blobs on a Base layer)."
                                               : "No start positions."
          );
          return;
        }
        const MarkerType* const blank = FindMarkerType("Blank Marker");
        const MarkerType* const massType = FindMarkerType("Mass");
        const MarkerType* const hydroType = FindMarkerType("Hydrocarbon");
        if (blank == nullptr || massType == nullptr || hydroType == nullptr) {
          panel.SetPlan(std::nullopt, "The marker types are missing.");
          return;
        }
        EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
        std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
        const auto groundAt = [&](const float x, const float z) {
          return ground.height ? ground.height(x, z) : 0.0f;
        };
        std::size_t removed = 0;
        if (s.clear) {
          const std::size_t count0 = markers.size();
          markers.erase(
            std::remove_if(
              markers.begin(),
              markers.end(),
              [&](const SaveEntry& marker) {
            for (const MapLayout::Generated& g : layout.generated) {
              if (GeneratedStill(g, marker)) {
                return true;
              }
            }
            return false;
          }
            ),
            markers.end()
          );
          removed = count0 - markers.size();
        }
        layout.generated.clear();
        int startsMoved = 0;
        int startsAdded = 0;
        int startsRemoved = 0;
        if (s.starts != LayoutStartMode::Existing) {
          const std::vector<LayoutPoint> old = MapStarts();
          const auto freeArmy = [&] {
            const std::vector<std::string> taken = mDocument.ArmyNamesInUse();
            for (int k = 1;; ++k) {
              const std::string name = "ARMY_" + std::to_string(k);
              const bool used = std::find(taken.begin(), taken.end(), name) != taken.end() ||
                std::any_of(markers.begin(), markers.end(), [&](const SaveEntry& m) {
                return m.name == name;
              });
              if (!used) {
                return name;
              }
            }
          };
          for (std::size_t i = 0; i < starts.size(); ++i) {
            const LayoutPoint& p = starts[i];
            const float x = std::floor(p.x) + 0.5f;
            const float z = std::floor(p.z) + 0.5f;
            if (s.replaceStarts && i < old.size()) {
              for (SaveEntry& marker : markers) {
                if (marker.name == old[i].name) {
                  marker.Set("position", Vector3Value(x, groundAt(x, z), z));
                }
              }
              ++startsMoved;
            } else {
              const std::string name = freeArmy();
              mDocument.AddArmy(name);
              markers.push_back(NewMarker(*blank, name, x, groundAt(x, z), z));
              ++startsAdded;
            }
          }
          if (s.replaceStarts) {
            for (std::size_t i = starts.size(); i < old.size(); ++i) {
              const std::string name = old[i].name;
              markers.erase(
                std::remove_if(
                  markers.begin(),
                  markers.end(),
                  [&](const SaveEntry& m) {
                return m.name == name;
              }
                ),
                markers.end()
              );
              mDocument.RemoveArmy(name);
              ++startsRemoved;
            }
          }
        }
        // The resources, planned against the map as it is now (the old ones gone, the starts moved).
        const std::vector<LayoutPoint> planStarts =
          s.starts == LayoutStartMode::Existing || !s.replaceStarts ? starts : MapStarts();
        const LayoutMarkerPlan plan = PlanLayoutMarkers(s, ground, planStarts, StayingResources(false));
        for (const LayoutMarkerItem& item : plan.items) {
          const MarkerType& type = item.hydro ? *hydroType : *massType;
          const std::string name = NextMarkerName(markers, type);
          markers.push_back(NewMarker(type, name, item.x, groundAt(item.x, item.z), item.z));
          layout.generated.push_back({name, item.x, item.z});
        }
        mDocument.SaveDataEdited(std::move(before));
        layout.Touch();
        char text[320];
        (void)std::snprintf(
          text,
          sizeof(text),
          "Placed %d mass and %d hydrocarbon%s; starts: %d moved, %d added, %d removed; %zu old markers removed. One "
          "undo step.",
          plan.masses,
          plan.hydros,
          plan.failed > 0 ? (", " + std::to_string(plan.failed) + " did not fit").c_str() : "",
          startsMoved,
          startsAdded,
          startsRemoved,
          removed
        );
        gpg::Logf("editor: layout markers: %s", text);
        panel.SetPlan(std::nullopt, text);
      }

      /**
       * `/layouttest <template>` (test runs): the Layout workspace, the template drawn, Generate terrain, then undo of
       * the terrain and of the template; the heights' checksum, the water level and the undo steps at each stage.
       */
      void TestLayout()
      {
        fa::vector<fa::string> arg;
        if (
          mLayoutTestStage >= 7 || mScene.ModelsPending() || !mScene.Attached() ||
          !moho::CFG_GetArgOption("/layouttest", 1, &arg) || arg.empty() || ++mLayoutTestFrames % 120 != 0
        ) {
          return;
        }
        const std::uint64_t hash = mScene.HeightsHash();
        if (mLayoutTestStage == 0) {
          mLayoutTestStart = hash;
        }
        const MapLayout& layout = mDocument.Layout();
        gpg::Logf(
          "editor: layout test stage %d: heights %016llx%s, water %s %.1f, layout %s with %zu bases (%d x %d cells), "
          "%zu undo steps; undo: %s; markers: %d mass, %d hydrocarbon, %zu armies",
          mLayoutTestStage,
          static_cast<unsigned long long>(hash),
          hash == mLayoutTestStart ? " (the original)" : "",
          mDocument.WaterNow().enabled ? "on" : "off",
          static_cast<double>(mDocument.WaterNow().elevation),
          layout.Drawn() ? "drawn" : "empty",
          layout.BaseCentres().size(),
          layout.Frame().rw,
          layout.Frame().rh,
          mDocument.UndoOrder().size(),
          mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-",
          [this] {
          int n = 0;
          for (const SaveEntry& m : mDocument.SaveData().Markers()) {
            n += MarkerTypeOf(m) == "Mass" ? 1 : 0;
          }
          return n;
        }(),
          [this] {
          int n = 0;
          for (const SaveEntry& m : mDocument.SaveData().Markers()) {
            n += MarkerTypeOf(m) == "Hydrocarbon" ? 1 : 0;
          }
          return n;
        }(),
          mDocument.Armies().size()
        );
        // `/layouttest picture:<file>`: the picture into the Hills layer, Generate terrain weathered, then two undos.
        if (std::string(arg[0].c_str()).rfind("picture:", 0) == 0) {
          EdLayoutPanel& panel = mShell->LayoutPanel();
          switch (mLayoutTestStage) {
          case 0:
            mShell->SwitchWorkspace(3);
            mShell->HideHome();
            mShell->ShowLayout();
            mDocument.Layout().selected = 0;
            gpg::Logf("editor: layout test: %s", panel.ImportPicture(std::string(arg[0].c_str()).substr(8)).c_str());
            mDocument.Layout().weather = 0.5f;
            break;
          case 1:
            panel.AskGenerate();
            break;
          case 2:
          case 3:
            gpg::Logf("editor: layout test: undo %s", mScene.Undo() ? "took a step back" : "had nothing");
            break;
          default:
            break;
          }
          ++mLayoutTestStage;
          return;
        }
        // `/layouttest graph`: the Duel drawn, then Studio's layout_terrain graph built from it in the Generate
        // workspace (its Map layout nodes read the drawing), its node errors, undo.
        if (std::string(arg[0].c_str()) == "graph") {
          EdGenerate& generate = mShell->Generate();
          for (const auto& [id, error] : generate.LastReport().errors) {
            gpg::Logf("editor: layout test: node %d: %s", id, error.c_str());
          }
          switch (mLayoutTestStage) {
          case 0:
            mShell->SwitchWorkspace(3);
            mShell->HideHome();
            mShell->ShowLayout();
            (void)mShell->LayoutPanel().ApplyTemplate("duel");
            break;
          case 1:
            mShell->SwitchWorkspace(4);
            mShell->ShowGenerate();
            gpg::Logf(
              "editor: layout test: graph layout_terrain %s",
              generate.OpenShipped("layout_terrain") ? "opened" : "missing"
            );
            break;
          case 2:
            generate.AskBuild();
            break;
          case 3:
            gpg::Logf(
              "editor: layout test: %d nodes ran; undo %s",
              generate.LastReport().evaluated,
              mScene.Undo() ? "took a step back" : "had nothing"
            );
            break;
          default:
            break;
          }
          ++mLayoutTestStage;
          return;
        }
        // `/layouttest starts`: Preview, Place markers, undo, redo, Place markers again (the old ones replaced).
        if (std::string(arg[0].c_str()) == "starts") {
          EdLayoutPanel& panel = mShell->LayoutPanel();
          switch (mLayoutTestStage) {
          case 0:
            mShell->SwitchWorkspace(3);
            mShell->HideHome();
            mShell->ShowLayout();
            panel.AskPlan();
            break;
          case 1:
          case 4:
            panel.AskPlace();
            break;
          case 2:
            gpg::Logf("editor: layout test: undo %s", mScene.Undo() ? "took a step back" : "had nothing");
            break;
          case 3:
            gpg::Logf("editor: layout test: redo %s", mScene.Redo() ? "did a step again" : "had nothing");
            break;
          default:
            break;
          }
          ++mLayoutTestStage;
          return;
        }
        switch (mLayoutTestStage) {
        case 0:
          mShell->SwitchWorkspace(3);
          mShell->HideHome();
          mShell->ShowLayout();
          gpg::Logf(
            "editor: layout test: template %s: %s",
            arg[0].c_str(),
            mShell->LayoutPanel().ApplyTemplate(arg[0].c_str()) ? "drawn" : "no such template"
          );
          break;
        case 1:
          mShell->LayoutPanel().AskGenerate();
          break;
        case 2:
        case 3:
          gpg::Logf("editor: layout test: undo %s", mScene.Undo() ? "took a step back" : "had nothing");
          break;
        case 4:
          gpg::Logf("editor: layout test: redo %s", mScene.Redo() ? "did a step again" : "had nothing");
          break;
        default:
          break;
        }
        ++mLayoutTestStage;
      }

      /**
       * A terrain graph's Output: roughness / height atlas: each layer's tile from its textures (read at 256 pixels)
       * and its kind of ground, packed 2 x 2 into map_atlas.dds beside the map and put in the Upper layer (its own
       * undo step, as the map-wide textures are); on the Terrain2xx shaders the splat softness / contrast too.
       */
      std::string MakeAtlasTexture(
        const TerrainBuildWrites& writes
      )
      {
        const std::filesystem::path scmap = mDocument.MapDiskFile();
        const std::vector<EdTools::LayerSlot> slots = mScene.LayerSlots();
        gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
        if (scmap.empty()) {
          return "The atlas wasn't made: the map has no folder of its own (save it as a new map first).";
        }
        if (slots.size() < 10 || codec == nullptr) {
          return "The atlas wasn't made: the map has no Upper layer.";
        }
        const auto started = std::chrono::steady_clock::now();
        // A texture as kAtlasTile square BGRA bytes.
        const auto decode = [&](const std::string& path, std::vector<std::uint8_t>& bgra) {
          std::string bytes;
          if (path.empty() || !ReadGameFile(path, bytes)) {
            return false;
          }
          gpg::gal::imaging::DecodeOptions options;
          options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
          options.width = kAtlasTile;
          options.height = kAtlasTile;
          options.mipLevels = 1;
          gpg::gal::imaging::Image image;
          if (
            FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) || image.subresources.empty() ||
            image.format != DXGI_FORMAT_B8G8R8A8_UNORM
          ) {
            return false;
          }
          const auto& level = image.subresources.front();
          if (
            level.width != static_cast<std::uint32_t>(kAtlasTile) ||
            level.height != static_cast<std::uint32_t>(kAtlasTile)
          ) {
            return false;
          }
          bgra.resize(static_cast<std::size_t>(kAtlasTile) * kAtlasTile * 4);
          for (int y = 0; y < kAtlasTile; ++y) {
            std::memcpy(
              bgra.data() + static_cast<std::size_t>(y) * kAtlasTile * 4,
              image.bytes.data() + level.offset + static_cast<std::size_t>(y) * level.rowPitch,
              static_cast<std::size_t>(kAtlasTile) * 4
            );
          }
          return true;
        };
        EdTextureLibrary& library = mShell->Tools().Library();
        std::array<AtlasTile, 8> made;
        std::array<const AtlasTile*, 8> tiles{};
        std::array<GroundKind, 8> kinds{};
        std::string kindText;
        int textured = 0;
        for (int layer = 0; layer < 8; ++layer) {
          const EdTools::LayerSlot& slot = slots[static_cast<std::size_t>(layer)];
          if (slot.albedo.empty()) {
            continue;
          }
          float rgb[3] = {0.4f, 0.4f, 0.4f};
          const bool read = library.AverageColour(slot.albedo, rgb);
          kinds[static_cast<std::size_t>(layer)] = GroundKindOf(slot.albedo, read ? rgb : nullptr).kind;
          kindText += (kindText.empty() ? "" : ", ") + std::to_string(layer) + " " +
            GroundKindName(kinds[static_cast<std::size_t>(layer)]);
          std::vector<std::uint8_t> albedo;
          std::vector<std::uint8_t> normal;
          if (!decode(slot.albedo, albedo)) {
            continue; // a texture the game can't read keeps the neutral tile
          }
          (void)decode(slot.normals, normal);
          std::string error;
          if (
            MakeAtlasTile(
              albedo,
              normal,
              kinds[static_cast<std::size_t>(layer)],
              writes.atlasSettings,
              made[static_cast<std::size_t>(layer)],
              error
            )
          ) {
            tiles[static_cast<std::size_t>(layer)] = &made[static_cast<std::size_t>(layer)];
            ++textured;
          } else {
            gpg::Warnf("editor: atlas: layer %d: %s", layer, error.c_str());
          }
        }
        std::vector<float> rgba;
        PackAtlas(tiles, kinds, writes.atlasSettings, writes.atlasSize, rgba);
        TexImage image;
        image.Reset(writes.atlasSize, 4, 0.0f);
        image.data = std::move(rgba);
        std::vector<std::uint8_t> dds;
        std::string error;
        if (!EncodeDds(image, DdsKind::Bgra, dds, error)) {
          return "The atlas wasn't encoded: " + error + ".";
        }
        const std::filesystem::path folder = scmap.parent_path() / "env" / "layers";
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        {
          std::ofstream out(folder / "map_atlas.dds", std::ios::binary | std::ios::trunc);
          out.write(reinterpret_cast<const char*>(dds.data()), static_cast<std::streamsize>(dds.size()));
          if (!out) {
            return "Can't write " + (folder / "map_atlas.dds").string() + ".";
          }
        }
        const std::string game = "/maps/" + mDocument.FolderName() + "/env/layers/map_atlas.dds";
        EdTools::LayerSlot upper = slots[9];
        upper.albedo = game;
        mScene.ChangeLayerSlot(9, upper);
        std::string splat;
        if (writes.splatSoft > 0.0f || writes.splatContrast > 0.0f) {
          const LightingState before = mDocument.LightingNow();
          LightingState lighting = before;
          if (writes.splatSoft > 0.0f) {
            lighting.specular[0] = writes.splatSoft;
          }
          if (writes.splatContrast > 0.0f) {
            lighting.specular[1] = writes.splatContrast;
          }
          mDocument.ApplyLighting(lighting);
          mDocument.LightingEdited(before);
          char text[96];
          (void)std::snprintf(
            text,
            sizeof(text),
            " Splat softness %.2f, height contrast %.2f (its own undo step).",
            static_cast<double>(lighting.specular[0]),
            static_cast<double>(lighting.specular[1])
          );
          splat = text;
        }
        const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        gpg::Logf(
          "editor: atlas %s made in %.1f s: %dx%d, %d of 8 layers from their textures (%s)",
          game.c_str(),
          seconds,
          writes.atlasSize,
          writes.atlasSize,
          textured,
          kindText.c_str()
        );
        return "Roughness / height atlas made from " + std::to_string(textured) +
          " layers' textures and put in the Upper layer (its own undo step)." + splat;
      }

      /**
       * A terrain graph's Output: texture alpha: copies of the layers' textures (beside the map, the colours as they
       * were) whose alpha is what the shader reads, put in the layers as one undo step; Off puts the originals back.
       */
      std::string MakeTextureAlpha(
        const TerrainBuildWrites& writes
      )
      {
        const std::filesystem::path scmap = mDocument.MapDiskFile();
        const std::vector<EdTools::LayerSlot> slots = mScene.LayerSlots();
        const std::string shader = mScene.TerrainShader();
        const ShaderAlphaUse use = ShaderAlphaOf(shader);
        const ShaderProfile profile = ShaderProfileOf(shader);
        gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
        const auto originOf = [&](const std::string& path) {
          const auto found = mAlphaOrigins.find(LowerPath(path));
          return found != mAlphaOrigins.end() ? found->second : path;
        };
        std::vector<std::pair<int, LayerSettings>> changes;
        const auto change = [&](const int slot, const std::string& albedo) {
          const EdTools::LayerSlot& s = slots[static_cast<std::size_t>(slot)];
          changes.emplace_back(slot, LayerSettings{albedo, s.normals, s.albedoSize, s.normalsSize});
        };
        if (writes.texAlphaMode == TextureAlphaMode::Off) {
          for (int slot = 0; slot < static_cast<int>(slots.size()); ++slot) {
            const std::string origin = originOf(slots[static_cast<std::size_t>(slot)].albedo);
            if (origin != slots[static_cast<std::size_t>(slot)].albedo) {
              change(slot, origin);
            }
          }
          const int changed = mScene.ApplyLayerSettings({}, changes);
          return changed > 0
            ? "Texture alpha: the original textures of " + std::to_string(changed) + " layers are back (one undo step)."
            : "Texture alpha: the layers have their own textures already.";
        }
        const bool layers = use.layers == LayerAlphaUse::Specularity || use.layers == LayerAlphaUse::Matte;
        if (!layers && !use.baseOpacity) {
          return "Texture alpha: " + shader +
            " reads no alpha from the layer textures (TTerrain, TTerrainXP and the "
            "0xx shaders do; the 1xx / 2xx take roughness from the atlas).";
        }
        if (scmap.empty() || codec == nullptr) {
          return "Texture alpha: the map has no folder of its own (save it as a new map first).";
        }
        const std::filesystem::path folder = scmap.parent_path() / "env" / "layers";
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        EdTextureLibrary& library = mShell->Tools().Library();
        std::string kinds;
        std::string skipped;
        const auto made = [&](const int slot, const bool baseOnly) {
          const std::string origin = originOf(slots[static_cast<std::size_t>(slot)].albedo);
          std::string bytes;
          if (origin.empty() || !ReadGameFile(origin, bytes)) {
            return;
          }
          gpg::gal::imaging::DecodeOptions options;
          options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
          options.mipLevels = 1;
          gpg::gal::imaging::Image image;
          if (
            FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) || image.subresources.empty() ||
            image.format != DXGI_FORMAT_B8G8R8A8_UNORM
          ) {
            skipped += (skipped.empty() ? "" : ", ") + std::to_string(slot) + " (unreadable)";
            return;
          }
          const auto& level = image.subresources.front();
          if (level.width != level.height || level.width < 4) {
            skipped += (skipped.empty() ? "" : ", ") + std::to_string(slot) + " (not square)";
            return;
          }
          const int size = static_cast<int>(level.width);
          std::vector<std::uint8_t> bgra(static_cast<std::size_t>(size) * size * 4);
          for (int y = 0; y < size; ++y) {
            std::memcpy(
              bgra.data() + static_cast<std::size_t>(y) * size * 4,
              image.bytes.data() + level.offset + static_cast<std::size_t>(y) * level.rowPitch,
              static_cast<std::size_t>(size) * 4
            );
          }
          if (baseOnly) {
            SetConstantAlpha(bgra, writes.baseOpacity);
          } else {
            float rgb[3] = {0.4f, 0.4f, 0.4f};
            const bool read = library.AverageColour(origin, rgb);
            const GroundKind kind = GroundKindOf(origin, read ? rgb : nullptr).kind;
            kinds += (kinds.empty() ? "" : ", ") + std::to_string(slot) + " " + GroundKindName(kind);
            SetSpecularityAlpha(
              bgra,
              kind,
              use.layers == LayerAlphaUse::Matte,
              writes.texAlphaMode,
              writes.texAlphaDetail,
              writes.texAlphaAmount
            );
          }
          TexImage out;
          out.Reset(size, 4, 0.0f);
          for (std::size_t i = 0; i < bgra.size() / 4; ++i) {
            out.data[i * 4 + 0] = bgra[i * 4 + 2] / 255.0f;
            out.data[i * 4 + 1] = bgra[i * 4 + 1] / 255.0f;
            out.data[i * 4 + 2] = bgra[i * 4 + 0] / 255.0f;
            out.data[i * 4 + 3] = bgra[i * 4 + 3] / 255.0f;
          }
          std::vector<std::uint8_t> dds;
          std::string error;
          const std::string file = "layer" + std::to_string(slot) + (baseOnly ? "_opacity.dds" : "_alpha.dds");
          if (!EncodeDds(out, DdsKind::Bgra, dds, error)) {
            skipped += (skipped.empty() ? "" : ", ") + std::to_string(slot) + " (" + error + ")";
            return;
          }
          std::ofstream stream(folder / file, std::ios::binary | std::ios::trunc);
          stream.write(reinterpret_cast<const char*>(dds.data()), static_cast<std::streamsize>(dds.size()));
          if (!stream) {
            skipped += (skipped.empty() ? "" : ", ") + std::to_string(slot) + " (can't write)";
            return;
          }
          const std::string game = "/maps/" + mDocument.FolderName() + "/env/layers/" + file;
          mAlphaOrigins[LowerPath(game)] = origin;
          change(slot, game);
        };
        const int last = std::min(8, profile.painted);
        if (layers) {
          for (int slot = 0; slot <= last && slot < static_cast<int>(slots.size()); ++slot) {
            made(slot, false);
          }
        } else if (use.baseOpacity && !slots.empty()) {
          made(0, true);
        }
        const int changed = mScene.ApplyLayerSettings({}, changes);
        gpg::Logf(
          "editor: texture alpha on %s: %d layers (%s)%s%s",
          shader.c_str(),
          changed,
          layers ? kinds.c_str() : "the base layer's opacity",
          skipped.empty() ? "" : "; skipped ",
          skipped.c_str()
        );
        return "Texture alpha: " + std::to_string(changed) + " layers" +
          (layers ? std::string(use.layers == LayerAlphaUse::Matte ? " (1 - specularity)" : " (specularity)")
                  : std::string(" (the base texture's opacity)")) +
          ", one undo step." + (skipped.empty() ? "" : " Skipped: " + skipped + ".");
      }
      std::map<std::string, std::string> mAlphaOrigins; // a texture alpha copy (lower case game path) -> its original

      void DriveGenerate()
      {
        EdGenerate& generate = mShell->Generate();
        if (!mGenerateWired) {
          mGenerateWired = true;
          generate.SetGroundSource([this](TerrainGround& ground) {
            return mScene.Attached() && !mScene.ModelsPending() && mScene.GraphGround(ground);
          });
        }
        if (!mShell->GenerateShown()) {
          return;
        }
        generate.Tick(ImGui::GetIO().DeltaTime, mScene.Attached());
        EdGenerate::HeightsAsk ask;
        if (generate.TakeHeightsAsk(ask)) {
          switch (ask.kind) {
          case EdGenerate::HeightsAsk::Kind::Preview:
            generate.SetStatus(mScene.ApplyGraphHeights(ask.result, ask.plain, true));
            break;
          case EdGenerate::HeightsAsk::Kind::Build: {
            std::string status = mScene.ApplyGraphBuild(ask.result, ask.plain, ask.writes);
            // The map-wide textures from the built map (each its own step, as the Map-wide textures panel makes them).
            for (const int kind : ask.writes.mapTextures) {
              const bool made = MakeMapTexture(static_cast<MapTextureKind>(std::clamp(kind, 0, kMapTextureKinds - 1)));
              status += std::string(" Map-wide ") +
                (kind == 0     ? "normal map"
                   : kind == 1 ? "lighting"
                   : kind == 2 ? "specular"
                               : "macrotexture") +
                (made ? " made (its own undo step)."
                      : " not made: the map's shader doesn't read it, or it couldn't be written.");
            }
            if (ask.writes.atlas) {
              status += " " + MakeAtlasTexture(ask.writes);
            }
            if (ask.writes.texAlpha) {
              status += " " + MakeTextureAlpha(ask.writes);
            }
            generate.SetStatus(status);
            break;
          }
          case EdGenerate::HeightsAsk::Kind::Revert:
            generate.SetStatus(
              mScene.RevertGraphPreview() ? "The preview was taken off."
                                          : "The preview stays: other edits came after it."
            );
            break;
          default:
            break;
          }
        }
      }

      /**
       * `/gentest <graph>` (test runs): the shipped graph opened in the Generate workspace, its preview shown on the
       * map, another seed (the preview replaced), Build, then undo; the heights' checksum and the undo steps at each
       * stage, two and a half seconds apart.
       */
      void TestGenerate()
      {
        fa::vector<fa::string> arg;
        if (
          mGenTestStage >= 6 || mScene.ModelsPending() || !mScene.Attached() ||
          !moho::CFG_GetArgOption("/gentest", 1, &arg) || arg.empty() || ++mGenTestFrames % 150 != 0
        ) {
          return;
        }
        EdGenerate& generate = mShell->Generate();
        const std::uint64_t hash = mScene.HeightsHash();
        if (mGenTestStage == 0) {
          mGenTestStart = hash;
        }
        gpg::Logf(
          "editor: generate test stage %d: heights %016llx%s, masks %016llx, types %016llx, %d props, %zu undo steps; "
          "undo: %s; %d nodes ran, %zu errors",
          mGenTestStage,
          static_cast<unsigned long long>(hash),
          hash == mGenTestStart ? " (the original)" : "",
          static_cast<unsigned long long>(mScene.MasksHash()),
          [this] {
          std::uint64_t h = 1469598103934665603ULL;
          for (const std::uint8_t cell : mDocument.TerrainTypesNow()) {
            h = (h ^ cell) * 1099511628211ULL;
          }
          return static_cast<unsigned long long>(h);
        }(),
          mShell->Tools().MapCount(1),
          mDocument.UndoOrder().size(),
          mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-",
          generate.LastReport().evaluated,
          generate.LastReport().errors.size()
        );
        for (const auto& [id, error] : generate.LastReport().errors) {
          gpg::Logf("editor: generate test: node %d: %s", id, error.c_str());
        }
        switch (mGenTestStage) {
        case 0:
          mShell->SwitchWorkspace(4);
          mShell->ShowGenerate();
          gpg::Logf(
            "editor: generate test: open %s: %s",
            arg[0].c_str(),
            (std::string(arg[0].c_str()).rfind("file:", 0) == 0
               ? generate.OpenFile(std::filesystem::path(std::string(arg[0].c_str()).substr(5)))
               : generate.OpenShipped(arg[0].c_str()))
              ? "yes"
              : "no such graph"
          );
          generate.SetShowOnMap(true);
          generate.SetGalleryShown(true);
          generate.SelectFirst("range");
          break;
        case 1:
          generate.SetSeed(generate.Seed() + 1);
          break;
        case 2:
          generate.AskBuild();
          break;
        case 3:
          gpg::Logf("editor: generate test: undo %s", mScene.Undo() ? "took the build back" : "had nothing");
          break;
        default:
          break;
        }
        ++mGenTestStage;
      }

      /**
       * `/interoptest <folder>` (test runs): the Import / Export window's buttons in turn, a second and a half apart,
       * with another tool's saves played by writing the linked file here; the heights' checksum and the undo steps at
       * each stage. The files go in `<folder>` only.
       */
      void TestInterop()
      {
        fa::vector<fa::string> arg;
        if (
          mInteropTestStage >= 10 || mScene.ModelsPending() || !mScene.Attached() ||
          !moho::CFG_GetArgOption("/interoptest", 1, &arg) || arg.empty() || ++mInteropTestFrames % 90 != 0
        ) {
          return;
        }
        using Ask = EdTools::InteropAsk;
        EdTools& tools = mShell->Tools();
        const std::filesystem::path file = std::filesystem::path(arg[0].c_str()) / "interop_test.png";
        const std::uint64_t hash = mScene.HeightsHash();
        if (mInteropTestStage == 0) {
          mInteropTestStart = hash;
        }
        gpg::Logf(
          "editor: interop test stage %d: heights %016llx%s, %zu undo steps; undo: %s",
          mInteropTestStage,
          static_cast<unsigned long long>(hash),
          hash == mInteropTestStart ? " (the original)" : "",
          mDocument.UndoOrder().size(),
          mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
        );
        // Another tool's save: the linked file read, a square of it raised by 10 units, written back.
        const auto raiseInFile = [&] {
          HeightImage image;
          std::string error;
          if (!ReadHeightImage(file, 0, 0, image, error)) {
            gpg::Warnf("editor: interop test: can't read %s: %s", file.string().c_str(), error.c_str());
            return;
          }
          for (int z = 200; z < 300 && z < image.height; ++z) {
            for (int x = 200; x < 300 && x < image.width; ++x) {
              std::uint16_t& w = image.words[static_cast<std::size_t>(z) * image.width + x];
              w = static_cast<std::uint16_t>(std::min(65535, w + 1280));
            }
          }
          if (!WriteHeightImage(file, image, error)) {
            gpg::Warnf("editor: interop test: can't write %s: %s", file.string().c_str(), error.c_str());
            return;
          }
          gpg::Logf("editor: interop test: raised a square of %s by 10 units", file.filename().string().c_str());
        };
        switch (mInteropTestStage) {
        case 0:
          tools.SetInteropFile(true, file.string());
          tools.AskInterop(Ask::Export);
          break;
        case 1: {
          std::error_code error;
          const auto size = std::filesystem::file_size(file.string() + ".json", error);
          gpg::Logf("editor: interop test: sidecar %s bytes", error ? "missing," : std::to_string(size).c_str());
          tools.AskInterop(Ask::SendAndWatch);
          break;
        }
        case 2:
        case 4:
          raiseInFile();
          break;
        case 5:
          tools.SetInteropLive(false);
          gpg::Logf("editor: interop test: undo %s", mScene.Undo() ? "took the link's import back" : "had nothing");
          break;
        case 6: {
          tools.SetInteropFile(false, file.string());
          ImportSettings& s = tools.InteropSettings();
          s = ImportSettings{};
          s.low = 0.0f;
          s.high = 60.0f;
          s.flipX = true;
          s.turns = 1;
          s.blend = ImportSettings::Blend::Max;
          tools.AskInterop(Ask::Probe);
          break;
        }
        case 7:
          tools.AskInterop(Ask::Import);
          break;
        case 8:
          tools.AskInterop(Ask::Revert);
          break;
        default:
          break;
        }
        ++mInteropTestStage;
      }

      /**
       * `/envtest cubes|sky` (test runs): a reflection cube added, or the sky's horizon reddened and a planet taken, as
       * the Lighting panel does them (one undo step), then undone; each state logged.
       */
      void TestEnvironment()
      {
        if (mEnvTestArg.empty() || mScene.ModelsPending() || ++mEnvTestFrames < 150) {
          return;
        }
        const std::string what = std::exchange(mEnvTestArg, {});
        const auto log = [this](const char* const when) {
          const EdDocument::LookEnvironment now = mDocument.LookEnvironmentNow();
          std::string cubes;
          for (const auto& [name, cube] : now.cubes) {
            cubes += (cubes.empty() ? "" : ", ") + name + " " + cube;
          }
          gpg::Logf(
            "editor: env test %s: cubes [%s]; sky horizon %.2f %.2f %.2f, %zu planets; undo: %s",
            when,
            cubes.c_str(),
            static_cast<double>(now.sky.horizonColor[0]),
            static_cast<double>(now.sky.horizonColor[1]),
            static_cast<double>(now.sky.horizonColor[2]),
            now.sky.planets.size(),
            mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
          );
        };
        log("before");
        if (what == "level") {
          // The sea raised by 3, kept (the finer water map follows: its whole-map refresh is logged).
          const WaterState before = mDocument.WaterNow();
          WaterState raised = before;
          raised.elevation += 3.0f;
          mDocument.ApplyWater(raised);
          mDocument.WaterEdited(before);
          gpg::Logf(
            "editor: env test: the sea from %.2f to %.2f",
            static_cast<double>(before.elevation),
            static_cast<double>(raised.elevation)
          );
          return;
        }
        if (what == "cubes") {
          const EdDocument::LookEnvironment before = mDocument.LookEnvironmentNow();
          std::vector<std::pair<std::string, std::string>> cubes = before.cubes;
          cubes.emplace_back("aeon", "/textures/environment/envcube_aeon_desert.dds");
          mDocument.ApplyCubes(cubes);
          mDocument.LookApplied(before);
        } else {
          const SkyboxState before = mDocument.SkyboxNow();
          SkyboxState sky = before;
          sky.horizonColor[0] = 1.0f;
          sky.horizonColor[1] = 0.2f;
          sky.horizonColor[2] = 0.1f;
          if (!sky.planets.empty()) {
            sky.planets.pop_back();
          }
          mDocument.ApplySkybox(sky);
          mDocument.SkyboxEdited(before);
        }
        log("edited");
        (void)mScene.Undo();
        log("after undo");
      }

      /** `/looktest <map folder>,<sections>,<blend>,apply|revert|keep` (test runs): that map's look tried, then ended.
       */
      void TestLooks()
      {
        if (mLookTestArg.empty() || mScene.ModelsPending() || ++mLookTestFrames < 150) {
          return;
        }
        std::vector<std::string> parts;
        for (std::size_t from = 0;;) {
          const std::size_t comma = mLookTestArg.find(',', from);
          parts.push_back(mLookTestArg.substr(from, comma == std::string::npos ? std::string::npos : comma - from));
          if (comma == std::string::npos) {
            break;
          }
          from = comma + 1;
        }
        mLookTestArg.clear();
        // `/looktest save:<name>` saves the map's own look; `/looktest mine:<name>,...` tries a saved one.
        if (parts[0].rfind("save:", 0) == 0) {
          EdShell::LookRequest save;
          save.what = EdShell::LookRequest::What::Save;
          save.name = parts[0].substr(5);
          mShell->RequestLook(save);
          UpdateLooks();
          return;
        }
        std::string scenario = parts[0].rfind("mine:", 0) == 0 ? parts[0] : std::string();
        for (const std::string& map : mPlay.Maps()) {
          std::string folder = MapDisplayName(map);
          std::transform(folder.begin(), folder.end(), folder.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
          });
          if (folder == parts[0]) {
            scenario = map;
          }
        }
        if (scenario.empty()) {
          gpg::Logf("editor: look test: no map %s", parts[0].c_str());
          return;
        }
        const auto state = [this](const char* const when) {
          const EdDocument::LookEnvironment now = mDocument.LookEnvironmentNow();
          gpg::Logf(
            "editor: look test %s: multiplier %.2f, sun colour %.2f %.2f %.2f, water colour %.2f %.2f %.2f, water "
            "level "
            "%.2f, sky horizon %.2f %.2f %.2f, %zu planets; undo: %s",
            when,
            static_cast<double>(now.lighting.multiplier),
            static_cast<double>(now.lighting.sunColor[0]),
            static_cast<double>(now.lighting.sunColor[1]),
            static_cast<double>(now.lighting.sunColor[2]),
            static_cast<double>(now.water.shader.mWaterColor[0]),
            static_cast<double>(now.water.shader.mWaterColor[1]),
            static_cast<double>(now.water.shader.mWaterColor[2]),
            static_cast<double>(now.water.elevation),
            static_cast<double>(now.sky.horizonColor[0]),
            static_cast<double>(now.sky.horizonColor[1]),
            static_cast<double>(now.sky.horizonColor[2]),
            now.sky.planets.size(),
            mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
          );
        };
        state("before");
        EdShell::LookRequest ask;
        ask.what = EdShell::LookRequest::What::Try;
        ask.id = scenario;
        ask.sections = parts.size() > 1 ? static_cast<unsigned>(std::atoi(parts[1].c_str())) : kLookAll;
        ask.blend = parts.size() > 2 ? std::strtof(parts[2].c_str(), nullptr) : 1.0f;
        mShell->RequestLook(ask);
        UpdateLooks();
        state("trying");
        const std::string end = parts.size() > 3 ? parts[3] : "keep";
        if (end == "apply" || end == "revert") {
          ask.what = end == "apply" ? EdShell::LookRequest::What::Apply : EdShell::LookRequest::What::Revert;
          mShell->RequestLook(ask);
          UpdateLooks();
          state(end == "apply" ? "applied" : "reverted");
          if (end == "apply") {
            (void)mScene.Undo();
            state("after undo");
          }
        }
      }

      /**
       * Find and replace objects (Edit, Ctrl+F; the mockup's dialog): a type found on the map, where (the whole map,
       * the selection, the symmetry's first part), and Select matches or Replace all, with another type or deleting.
       */
      void DrawFind()
      {
        constexpr const char* kTitle = "Find and replace objects";
        if (std::exchange(mFindAsk, false) && mDocument.GetState() == EdDocument::State::Open) {
          mFindObjects = mScene.FindObjects();
          mFindTypes = CountFindTypes(mFindObjects);
          mFindChoice = std::clamp(mFindChoice, 0, std::max(0, static_cast<int>(mFindTypes.size()) - 1));
          mFindMessage.clear();
          ImGui::OpenPopup(kTitle);
        }
        ImGui::SetNextWindowSize(ImVec2(Em(560.0f), 0.0f), ImGuiCond_Appearing);
        if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_NoSavedSettings)) {
          return;
        }
        if (mFindTypes.empty()) {
          ImGui::TextUnformatted("The map has no objects.");
          if (ImGui::Button("Close")) {
            ImGui::CloseCurrentPopup();
          }
          ImGui::EndPopup();
          return;
        }
        const FindTypeCount& found = mFindTypes[static_cast<std::size_t>(mFindChoice)];
        const auto typeText = [](const FindTypeCount& t) {
          return std::string(FindKindName(t.kind)) + ": " + FindTypeLabel(t.kind, t.type) + "  (" +
            std::to_string(t.count) + ")";
        };
        const float labelWidth = Em(110.0f);
        const auto label = [&](const char* text) {
          ImGui::AlignTextToFramePadding();
          ImGui::TextUnformatted(text);
          ImGui::SameLine(labelWidth);
          ImGui::SetNextItemWidth(-1.0f);
        };
        bool changed = false;
        label("Find");
        if (ImGui::BeginCombo("##findtype", typeText(found).c_str(), ImGuiComboFlags_HeightLarge)) {
          for (int i = 0; i < static_cast<int>(mFindTypes.size()); ++i) {
            if (ImGui::Selectable(typeText(mFindTypes[static_cast<std::size_t>(i)]).c_str(), i == mFindChoice)) {
              mFindChoice = i;
              mFindReplace = 0;
              changed = true;
            }
          }
          ImGui::EndCombo();
        }
        static constexpr const char* kScopes[] = {"The whole map", "The selection", "One part (the symmetry's first)"};
        label("In");
        changed = ImGui::Combo("##findscope", &mFindScope, kScopes, IM_ARRAYSIZE(kScopes)) || changed;
        // Replace with: delete, or another type of the kind (markers: any type but a start position).
        const FindTypeCount& chosen = mFindTypes[static_cast<std::size_t>(mFindChoice)];
        std::vector<std::string> others;
        if (chosen.kind == FindKind::Marker) {
          if (chosen.type != "Blank Marker") {
            for (const MarkerType& type : MarkerTypes()) {
              if (type.type != chosen.type && std::string(type.type) != "Blank Marker") {
                others.emplace_back(type.type);
              }
            }
          }
        } else {
          for (const FindTypeCount& t : mFindTypes) {
            if (t.kind == chosen.kind && t.type != chosen.type && t.group == chosen.group) {
              others.push_back(t.type);
            }
          }
        }
        mFindReplace = std::clamp(mFindReplace, 0, static_cast<int>(others.size()));
        label("Replace with");
        const std::string shown = mFindReplace == 0
          ? "(delete)"
          : FindTypeLabel(chosen.kind, others[static_cast<std::size_t>(mFindReplace - 1)]);
        if (ImGui::BeginCombo("##findwith", shown.c_str(), ImGuiComboFlags_HeightLarge)) {
          if (ImGui::Selectable("(delete)", mFindReplace == 0)) {
            mFindReplace = 0;
          }
          for (int i = 0; i < static_cast<int>(others.size()); ++i) {
            if (
              ImGui::Selectable(
                FindTypeLabel(chosen.kind, others[static_cast<std::size_t>(i)]).c_str(), mFindReplace == i + 1
              )
            ) {
              mFindReplace = i + 1;
            }
          }
          ImGui::EndCombo();
        }
        const auto scope = static_cast<FindScope>(mFindScope);
        const std::size_t matches = FindMatches(mFindObjects, chosen.kind, chosen.type, scope).size();
        (void)changed;
        ImGui::Spacing();
        ImGui::TextDisabled(
          "%zu matches. Position, turn and scale are kept; one undo step.%s",
          matches,
          chosen.kind == FindKind::Marker && chosen.type == "Blank Marker" ? " Start positions can only be selected."
                                                                           : ""
        );
        if (!mFindMessage.empty()) {
          ImGui::TextUnformatted(mFindMessage.c_str());
        }
        ImGui::Spacing();
        const auto run = [&](const FindAction action) {
          const std::string with =
            mFindReplace == 0 ? std::string() : others[static_cast<std::size_t>(mFindReplace - 1)];
          const std::string message = mScene.FindApply(chosen.kind, chosen.type, scope, action, with);
          gpg::Logf("editor: find and replace: %s", message.c_str());
          PostStatusMessage(message);
          ImGui::CloseCurrentPopup();
        };
        ImGui::BeginDisabled(matches == 0);
        if (ImGui::Button("Select matches")) {
          run(FindAction::Select);
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(chosen.kind == FindKind::Marker && chosen.type == "Blank Marker");
        if (ImGui::Button(mFindReplace == 0 ? "Delete all" : "Replace all")) {
          run(mFindReplace == 0 ? FindAction::Delete : FindAction::Replace);
        }
        ImGui::EndDisabled();
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
          ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
      }

      /** The "Save changes?" question before unsaved changes are dropped: Save, Don't save, Cancel. */
      void DrawUnsavedQuestion()
      {
        constexpr const char* kTitle = "Save changes?";
        if (std::exchange(mGuardAsk, false)) {
          ImGui::OpenPopup(kTitle);
          gpg::Logf("editor: unsaved changes in %s: asked before going on", mDocument.FolderName().c_str());
        }
        if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
          return;
        }
        ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
        ImGui::Text("%s has unsaved changes.", mDocument.FolderName().c_str());
        ImGui::TextDisabled("Save them before going on?");
        ImGui::Spacing();
        std::function<void()> proceed;
        if (ImGui::Button("Save")) {
          SaveDocument();
          if (!mDocument.Modified()) {
            proceed = std::move(mGuardProceed);
          }
          ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Don't save")) {
          gpg::Logf("editor: %s: changes dropped", mDocument.FolderName().c_str());
          if (!mAutosaveRoot.empty()) {
            RemoveAutosave(mAutosaveRoot / mDocument.FolderName());
            mRecoverable = ListAutosaves(mAutosaveRoot);
          }
          // Dropped: what comes next doesn't ask again.
          mDocument.SetModified(false);
          proceed = std::move(mGuardProceed);
          ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
          mGuardProceed = nullptr;
          ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
        if (proceed) {
          proceed();
        }
      }

      /** The question before the editor closes with unsaved changes (not in test runs); true when it was asked. */
      bool AskBeforeExit()
      {
        if ((gTestRun && !mAskInTests) || mDocument.GetState() != EdDocument::State::Open || !mDocument.Modified()) {
          return false;
        }
        mGuardProceed = [this] {
          mShell->RequestExit();
        };
        mGuardAsk = true;
        (void)::SetFocus(gPanelWindow);
        return true;
      }

      /** Whether the mouse is over the game's view (its own window, where ImGui doesn't see the mouse). */
      [[nodiscard]] bool MouseOverView() const
      {
        const HWND view = HandleOf(moho::ren_Viewport);
        RECT rect{};
        POINT cursor{};
        return view != nullptr && ::IsWindowVisible(view) && ::GetWindowRect(view, &rect) && ::GetCursorPos(&cursor) &&
          ::PtInRect(&rect, cursor) && ImGui::GetCurrentContext() != nullptr && !ImGui::GetIO().WantCaptureMouse;
      }

      /** F6 while a play runs: the editor's view in front of it, or the game's again. */
      void ToggleEditorView()
      {
        mShell->EditorViewInPlay() = !mShell->EditorViewInPlay();
        gpg::Logf("editor: F6: the %s view", mShell->EditorViewInPlay() ? "editor's" : "game's");
      }
      [[nodiscard]] bool EditorViewOverPlay() const
      {
        return mScene.OverPlay();
      }

    private:
      void SetUpImGui();
      /** Every command of the editor and the title row's menus (design §3: one registry behind menus, keys and
       * palette). */
      void RegisterCommands();
      /** The own title row: Windows draws no caption (`/nativecaption` keeps Windows'), the frame's border dark. */
      void SetUpWindowChrome(HWND frame);
      void UpdateTitle();
      void RenderPanels();
      /** True when it re-made the device's heads (the view changed size): the frame's panels aren't drawn then. */
      bool FitGameView();
      void ReadOpenCommandLine();
      void DriveOpens();

      EdCommands mCommands;
      std::vector<EdMenu> mMenus;
      /** Each command's keys as registered (Settings > Keys resets to them), keys.ini, the Settings window. */
      EdKeyDefaults mKeyDefaults;
      std::filesystem::path mKeysFile;
      bool mShowSettings = false;
      /** Settings' page: 0 General, 1 Appearance, 2 Keys, 3 Viewport, 4 Performance. */
      int mSettingsPage = 0;
      /** settings.ini (`/settingsfile <path>`: another, for test runs), and whether a change is written. */
      EdSettings mSettings;
      std::filesystem::path mSettingsFile;
      bool mSettingsWritable = true;
      bool mSettingsRead = false;
      std::vector<std::string> mSettingsProblems;
      /** What settings.ini said at the start: the title row and renderer change from the next start. */
      std::string mStartTitleBar;
      std::string mStartRenderer;
      std::chrono::steady_clock::time_point mLastBackgroundFrame = std::chrono::steady_clock::now();
      // Autosave and recovery (doc/EdAutosave): where autosaves and backups go (`/autosavefolder`,
      // `/backupfolder` for test runs), every how many seconds (`/autosaveevery`), the clock's marks.
      std::filesystem::path mAutosaveRoot;
      std::filesystem::path mBackupRoot;
      bool mAutosaveOn = false;
      double mAutosaveEvery = 60.0;
      double mLastAutosave = 0.0;
      double mLastInput = 0.0;
      double mModifiedSince = -1.0;
      std::vector<EdAutosaveEntry> mRecoverable;
      bool mShowRecover = false;
      // Looks: the map's own environment while one is tried, the looks read so far, the test switch.
      std::optional<EdDocument::LookEnvironment> mLookOriginal;
      std::string mLookTriedId;
      std::string mLookTriedName;
      std::map<std::string, Look> mLookCache;
      bool mLooksListed = false;
      std::string mLookTestArg; // `/looktest <map>,<sections>,<blend>,apply|revert|keep` (test runs)
      std::string mEnvTestArg;  // `/envtest cubes|sky` (test runs)
      std::string mWaterMaskTestArg; // `/watermasktest foam|flatness|bias,<value>,<radius>[,keep]` (test runs)
      int mWaterMaskTestFrames = 0;
      bool mCamAtDone = false;
      int mScTestStage = 0;
      int mScTestFrames = 0;
      int mInteropTestStage = 0;
      bool mGenerateWired = false;
      bool mLayoutWired = false;
      int mLayoutTestStage = 0;
      int mLayoutTestFrames = 0;
      std::uint64_t mLayoutTestStart = 0;
      int mGenTestStage = 0;
      int mGenTestFrames = 0;
      std::uint64_t mGenTestStart = 0;
      int mInteropTestFrames = 0;
      std::uint64_t mInteropTestStart = 0;
      int mErosionTestStage = 0;
      int mErosionTestFrames = 0;
      int mEnvTestFrames = 0;
      int mLookTestFrames = 0;
      // Find and replace objects: asked (Ctrl+F), the objects and types when it opened, the choices.
      bool mFindAsk = false;
      std::vector<FindObject> mFindObjects;
      std::vector<FindTypeCount> mFindTypes;
      int mFindChoice = 0;
      int mFindScope = 0;
      int mFindReplace = 0;
      std::string mFindMessage;
      std::string mFindTestArg; // `/findtest kind,type,scope,action` (test runs)
      int mFindFrames = 0;
      std::string mFillTestArg; // `/filltest <density>,<spacing>[,keep]` (test runs)
      std::string mModalTestArg; // `/modaltest kind,g|r,keys[,cancel]` (test runs)
      int mModalFrames = 0;
      int mFillFrames = 0;
      std::string mFindOpenArg; // `/findopen <n>` (test runs): the dialog opened on the n-th type
      // The "Save changes?" question: what to do once answered.
      std::function<void()> mGuardProceed;
      bool mGuardAsk = false;
      /** `/askunsaved`: a test run asks the question too (else test runs drop changes without asking). */
      bool mAskInTests = false;
      /** The key whose press ran a command in the view: its release doesn't reach the scene or the game. */
      unsigned mSwallowKeyUp = 0;
      /** The scenario path of each item File > Open Recent shows, by its place. */
      std::vector<std::string> mRecentShown;
      std::wstring mBaseTitle;
      std::wstring mShownTitle;

      CScApp mGame;
      EdLog mLog;
      EdImGuiRenderer mRenderer;
      EdPlay mPlay;
      EdDocument mDocument;
      EdMapScene mScene{mDocument};
      std::chrono::steady_clock::time_point mLastFrame = std::chrono::steady_clock::now();
      EdShell* mShell = nullptr;
      /** Camera bookmarks per map (lower-case path), for this run. */
      std::map<std::string, std::array<std::optional<EdMapScene::CameraPose>, 9>> mBookmarks;
      /** Ids of commands made in a loop (EdCommand keeps its own copy; these keep the c_str()s alive meanwhile). */
      std::vector<std::string> mCommandIds;
      /** A file there while the editor runs: found at the start, the last run didn't end normally. */
      std::filesystem::path mRunMarker;
      // `/openall`: every map opened in turn (the next to open, how many opened, the ones that did not).
      bool mOpenAll = false;
      std::size_t mOpenAllNext = 0;
      int mOpenAllOpened = 0;
      std::vector<std::string> mOpenAllFailed;
      // `/roundtrip <folder>`: with every map opened, the save round trip into that folder.
      std::filesystem::path mRoundTripFolder;
      int mRoundTripOk = 0;
      int mRoundTripSameBytes = 0;
      int mRoundTripDiskFiles = 0;
      bool mRoundTripShown = false;
      // `/saveas <folder>` with `/open`: the drawn map saved as that new folder, then the editor closes.
      std::string mSaveAsFolder;
      // `/symcheck <mode>[x<turns>][:repair]` with `/open`: the symmetry check on the drawn map (mode: the Tools
      // panel's symmetry index), then the copy of the source part when asked; the editor stays open.
      int mSymCheckMode = -1;
      int mSymCheckTurns = 3;
      bool mSymCheckRepair = false;
      int mSymCheckFrames = 0;
      // `/heightexport <file>`, `/heightimport <file>` with `/open`: the drawn map's heights written to or
      // read from that file once, as the Tools panel's buttons do; the editor stays open.
      std::string mHeightExportFile;
      std::string mHeightImportFile;
      int mHeightFileFrames = 0;
      // `/heightdialog` with `/open`: the Import button pressed once (its file dialog), for test runs.
      bool mHeightDialog = false;
      // `/newmap <folder>[,<size index>,<players>,<height>,<sea level or 0>]` (test runs): that new map made
      // in the vault, mounted and opened; the editor stays open.
      std::string mNewMapSpec;
      // `/brush <mode>` and `/stamp <file>` (test runs): the terrain brush's mode and stamp image, set once.
      int mBrushModeArg = -1;
      bool mStampSourceDone = false;
      bool mSymOptionsDone = false;
      bool mMaskOptionsDone = false;
      bool mShaderBrowserDone = false;
      std::string mConvertLayersArg;
      int mConvertLayersFrames = 0;
      std::string mMaskTestArg;
      int mMaskTestFrames = 0;
      // `/masklayer <1-8>` and `/maskrule <layer>,<low>,<high>` (test runs): the Texture tool on that layer;
      // a height rule applied to the whole map once the map has been shown for 120 frames.
      int mMaskLayerArg = -1;
      std::string mMaskRuleArg;
      // `/brushtest <mode>,<x>,<z>[,<seconds>]` (test runs): a scripted stroke of that height brush mode.
      std::string mBrushTestArg;
      int mBrushTestFrames = 0;
      int mMaskRuleFrames = 0;
      std::string mLayerNamesOf;
      // `/layer <slot>,<albedo path>[,<size>]` with `/open` (test runs): one texture slot changed.
      std::string mLayerArg;
      /** The game's view shows nothing while a modal dialog of the panels is open (FitGameView). */
      bool mViewStepsAside = false;
      /** The popups' rectangles (view pixels) the view's window region leaves out, as last set. */
      std::vector<RECT> mViewHoles;
      /** Frames run, for the stall line (the first ones load and are slow on purpose). */
      std::uint64_t mFramesRun = 0;
      /** The game's head copied for the panels (CopyGameView), and its image for the draw lists. */
      void CopyGameView();
      /** The minimap's rectangle of the game's last frame into a target of its own, when it was drawn in that frame. */
      void CopyMiniMap(
        gpg::gal::Device& device,
        moho::CD3DDevice& d3d,
        const boost::shared_ptr<gpg::gal::RenderTarget>& output
      );
      moho::ID3DDeviceResources::RenderTargetHandle mMiniCopy;
      moho::ID3DRenderTarget::SurfaceHandle mMiniSurface;
      int mMiniCopyWidth = 0;
      int mMiniCopyHeight = 0;
      moho::ID3DDeviceResources::RenderTargetHandle mViewCopy;
      moho::ID3DRenderTarget::SurfaceHandle mViewSurface;
      std::uint32_t mViewCopyWidth = 0;
      std::uint32_t mViewCopyHeight = 0;
      std::uint64_t mViewImage = 0;
      /** The holes of the last frames, newest first (FitGameView). */
      std::deque<std::vector<RECT>> mHoleHistory;
      int mBrowseArg = -1;
      // `/shader <name>` with `/open` (test runs): the map's terrain shader changed once it is shown.
      std::string mShaderArg;
      std::string mPlayableAreaArg;
      std::string mMarkerToolArg;
      /** `/framemarker <name>[@distance]` (test runs): the camera goes to that marker once the map is shown. */
      std::string mFrameMarkerArg;
      bool mSelectUnitDone = false;
      int mFocusPanelFrames = 0;
      bool mWaterFilesDone = false;
      bool mLightingFilesDone = false;
      bool mLightingFromDone = false;
      bool mMarkerFilesDone = false;
      bool mUnitFilesDone = false;
      bool mPaintSetDone = false;
      bool mSkyboxFilesDone = false;
      bool mWaveSwitchesDone = false;
      bool mTerrainTypeArgDone = false;
      bool mViewAidArgsDone = false;
      int mUnitTreeFrames = 0;
      bool mUnitGroupArgDone = false;
      bool mArmyEconomyArgDone = false;
      bool mPropEditArgDone = false;
      bool mAdaptiveArgDone = false;
      bool mAirGridArgDone = false;
      /** Pictures of prop models for the Props list and the Properties panel. */
      EdPropThumbnails mPropThumbnails;
      int mRdCaptureFrame = -1;
      int mRdFrames = 0;
      int mReclaimFrames = 0;
      bool mReclaimLogged = false;
      int mLayerFileStep = 0;
      /** `/waterset <on>,<level>,<deep>,<abyss>` (test runs): the sea set as one edit once the map is shown. */
      std::string mWaterSetArg;
      bool mWaterDragging = false;
      WaterState mWaterBefore;
      /** The scenario's water bodies as last read, and the undo step of an edit under way. */
      std::string mBodiesScenario;
      WaterBodiesRead mBodiesRead;
      bool mBodiesDragging = false;
      EdDocument::SaveSnapshot mBodiesBefore;
      bool mBrowserArg = false;
      /** `/faflogin` and `/vaultsearch <text>` (test runs, '+' for spaces). */
      bool mFafLoginArg = false;
      std::string mVaultSearchArg;
      std::string mVaultQueryArg;
      std::filesystem::path mPendingFafTokenFile;
      /** `/thumbdump <name>,<file>` (test runs): a prop thumbnail saved once it is made. */
      std::string mThumbDumpArg;
      int mThumbDumpFrames = 0;
      /** `/openfolder <scenario file>` (test runs): a map opened from a folder anywhere on disk. */
      std::string mOpenFolderArg;
      std::string mBrowserFilterArg;
      std::string mVaultMapArg;
      /** `/waterbody <body>` (test runs, '+' for spaces): a body added as one edit once the map is shown. */
      std::string mWaterBodyArg;
      /** `/waterpick <n>[,seed|outline]` or `/waterpick new` (test runs): a body chosen, and what a click in the view
       * does. */
      std::string mWaterPickArg;
      /** `/unittool <type>,<army>[,select]` (test runs). */
      std::string mUnitToolArg;
      /** `/decaltool <texture>[,select]` (test runs): the Decals tool with this texture. */
      std::string mDecalToolArg;
      /** `/grid`, `/snap`, `/gridstep <units>` (test runs): the toolbar's grid settings, set once the map is shown. */
      bool mGridArgsPending = true;
      /** `/check` (test runs): the Check runs once the map is shown. */
      bool mCheckArgPending = true;
      /**
       * `/uiclicks "x,y;dx,y;..."` (test runs): clicks fed to the panels through ImGui's input queue, in the panels'
       * pixels, `d` for a double-click, one every half second from frame 300. Posted window messages can't do it:
       * ImGui's Win32 backend takes the real cursor's position while the window has focus.
       */
      struct UiClick
      {
        float x;
        float y;
        bool doubleClick;
        /** `^D`: a Ctrl+<key> for the view instead of a click. */
        char key = 0;
        /** `h<x>,<y>`: the pointer moved there, no button (a hover). */
        bool hoverOnly = false;
      };
      std::vector<UiClick> mUiClicks;
      int mUiClickFrame = 0;
      void FeedUiClicks();
      /**
       * Test runs: `/command <id>[,<id>...]` runs those commands once the map is open (each logs what it did, or why
       * it can't run), `/palette <text>` opens the command palette with the text typed, at frame 300.
       */
      void FeedTestCommands()
      {
        static int frame = 0;
        if (++frame != 300) {
          return;
        }
        // `/resizetest <width index>,<depth index>,<canvas|scale>,<anchor>,<folder>` (test runs): Map > Resize.
        if (fa::vector<fa::string> spec; moho::CFG_GetArgOption("/resizetest", 1, &spec) && !spec.empty()) {
          std::vector<std::string> parts;
          const std::string text = spec[0].c_str();
          for (std::size_t at = 0; at <= text.size();) {
            const std::size_t comma = std::min(text.find(',', at), text.size());
            parts.push_back(text.substr(at, comma - at));
            at = comma + 1;
          }
          if (parts.size() >= 5) {
            const MapFacts& facts = mDocument.Facts();
            EdShell::ResizeRequest ask;
            ask.widthIndex = std::clamp(std::atoi(parts[0].c_str()), 0, kNewMapSizeCount - 1);
            ask.depthIndex = std::clamp(std::atoi(parts[1].c_str()), 0, kNewMapSizeCount - 1);
            ask.options.oldWidth = facts.sizeX;
            ask.options.oldDepth = facts.sizeZ;
            ask.options.newWidth = kNewMapSizes[ask.widthIndex].units;
            ask.options.newDepth = kNewMapSizes[ask.depthIndex].units;
            ask.options.mode = parts[2] == "scale" ? ResizeMode::Scale : ResizeMode::Canvas;
            ask.options.anchor = std::atoi(parts[3].c_str());
            ask.folder = parts[4];
            StartResize(ask);
          } else {
            gpg::Warnf("editor: /resizetest wants <width index>,<depth index>,<canvas|scale>,<anchor>,<folder>");
          }
        }
        // `/exportpreview <file>` (test runs): the lobby preview written there.
        if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/exportpreview", 1, &file) && !file.empty()) {
          std::string message;
          const bool ok = mDocument.ExportPreview(file[0].c_str(), message);
          (ok ? gpg::Logf : gpg::Warnf)("editor: %s", message.c_str());
        }
        // `/dropdefaultcube` (test runs): the map's <default> reflection cube taken away first (a save adds it back).
        if (moho::CFG_GetArgOption("/dropdefaultcube", 0, nullptr)) {
          std::vector<std::pair<std::string, std::string>> cubes = mDocument.CubesNow();
          cubes.erase(
            std::remove_if(
              cubes.begin(),
              cubes.end(),
              [](const auto& cube) {
            return cube.first == "<default>";
          }
            ),
            cubes.end()
          );
          mDocument.ApplyCubes(cubes);
          gpg::Logf("editor: test: the <default> reflection cube taken away (%zu cubes left)", cubes.size());
        }
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/command", 1, &value) && !value.empty()) {
          std::string list = value[0].c_str();
          std::size_t start = 0;
          while (start <= list.size()) {
            const std::size_t comma = list.find(',', start);
            const std::string id = list.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            if (!id.empty()) {
              const std::string why = mCommands.WhyNot(id);
              if (why.empty()) {
                gpg::Logf("editor: /command %s", id.c_str());
                (void)mCommands.Run(id);
              } else {
                gpg::Logf("editor: /command %s can't run now: %s", id.c_str(), why.c_str());
              }
            }
            if (comma == std::string::npos) {
              break;
            }
            start = comma + 1;
          }
        }
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/palette", 1, &value) && !value.empty()) {
          OpenCommandPalette(value[0].c_str());
          gpg::Logf("editor: /palette %s", value[0].c_str());
        }
      }
      // `/proptool <mode>,<blueprint>` and `/tool <index>` (test runs).
      std::string mPropToolArg;
      int mToolArg = -1;
      int mBrowseFrames = 0;
      std::string mStampArg;
      /** The Tools panel's height field Import and Export: the file dialog, then the view. */
      void DriveHeightFiles();
      int mRoundTripFrames = 0;
      // `/roundtripframes <n>` (test runs): /roundtrip and /saveas wait this many frames of the drawn map (180).
      int mRoundTripAfter = 180;
      void SaveDocument();
      /**
       * Map > Resize, in two steps: StartResize takes what the map has (heights and masks as images, resized; props,
       * decals, markers, areas and units moved; the look, the layers and the scenario's fields) and makes the new
       * folder; once the new map is open, FinishResize puts it all on it, saves it and opens it again.
       */
      void StartResize(const EdShell::ResizeRequest& request);
      /** Map > Regenerate preview: the lobby picture drawn anew from the heights, the sea and the markers. */
      bool RegeneratePreview(std::string& message);
      void FinishResize();
      struct PendingResize
      {
        std::filesystem::path dir;
        ResizeGeometry geometry;
        ResizeReport report;
        int maskWidth = 0;
        int maskHeight = 0;
        std::string shader;
        std::vector<LayerSettings> layers;
        EdDocument::LookEnvironment look;
        EdDocument::PropSnapshot props;
        EdDocument::DecalSnapshot decals;
        std::string save;
        std::string script;
        std::vector<std::pair<std::string, std::string>> fields;
        std::vector<ScenarioTeam> teams;
        std::vector<std::string> extraArmies;
        SlotFactions factions;
        std::string folder;
        std::string scenario; // the new map's, once it opens
        int frames = 0;
        bool reopened = false;
      };
      std::optional<PendingResize> mResize;
      // `/resizetest <width index>,<depth index>,<canvas|scale>,<anchor>,<folder>` with `/open` (test runs).
      std::string mResizeTestArg;
      /** The material editor's Live Update and Apply, with the open map's slots. */
      void DriveMaterialEditor();
      void ApplyMaterial(const EdMaterialEditor::Bake& bake);
      /** The Layers panel's map-wide textures: its asks, and its rows' states (once a second). */
      void MapTexturesUpdate();
      /** True when it made and set the texture (false with a status message saying why not). */
      bool MakeMapTexture(MapTextureKind kind);
      void ClearMapTexture(MapTextureKind kind);
      /** The Texture tool's Mask generator: starting points, the preview (when the rules change), Write. */
      void MaskGenUpdate();
      /** The rules' context: the heights (and the paint when a rule reads it). False with `error`. */
      bool MaskGenContextOf(const std::vector<MaskGenRule>& rules, MaskGenContext& context, std::string& error);
      int mMaskGenEvaluated = -1;
      int mMaskGenWait = 0;
      std::uint64_t mMaskGenImage = 0;
      std::string mMaskGenArg; // `/maskgen <preset>,<layer>[,add|sub][,free]`
      int mMaskGenFrames = 0;
      /** The Stratum recipes: each layer's kind (once a second while the section is open), Paint the map. */
      void RecipesUpdate();
      int mRecipeFrame = 0;
      int mRecipeArg = -1; // `/recipe <style>` (test runs)
      int mRecipeArgFrames = 0;
      /** The Layers panel's optimal tiles (once a second) and Texture sets (try, keep, back, apply). */
      void TexturesUpdate();
      [[nodiscard]] int TexturePixels(const std::string& path);
      [[nodiscard]] bool GameFileExists(const std::string& path);
      std::map<std::string, int> mTexturePixels;               // lower case path -> width, 0 unreadable
      std::map<std::string, bool> mGameFiles;                  // lower case path -> exists
      std::vector<std::pair<int, LayerSettings>> mThemeBefore; // the layers before a Try
      bool mThemeTrying = false;
      int mTexturesFrame = 0;
      int mThemePreviewFor = -1;
      std::string mThemeShaderFor;
      std::vector<std::string> mThemePreviewLines;
      std::string mThemeArg;   // `/texset <index>[,try|,back]` (test runs)
      std::string mLayerOpArg; // `/layerop <slot>,fill|remove|optimal` (test runs)
      std::string mSlopeViewArg;       // `/slopeview units,<n>[,<limit>]|buildings,<n>,ring|area[,<limit>]` (test runs)
      std::string mTypesFromLayersArg; // `/typesfromlayers[,only]` (test runs)
      std::string mFollowTestArg;      // `/followtest props|markers|units|decals` (test runs)
      std::string mArrangeTestArg;     // `/arrangetest props|markers,<op>[,<step>]` (test runs)
      int mArrangeFrames = 0;
      int mD2gFrames = 0;
      int mLayerOpFrames = 0;
      int mThemeArgFrames = 0;
      /** Export (true) the slot's texture to a .dds, or import one into the map's folder and the slot. */
      void TransferMapTexture(MapTextureKind kind, bool exporting, const std::string& testFile);
      bool mMapTexturesStale[4]{};
      /** The paint's textures: the heights, the masks and the layers' textures in one sum. */
      [[nodiscard]] std::uint64_t PaintChecksum(std::uint64_t heights);
      [[nodiscard]] std::uint64_t HeightsChecksum();
      [[nodiscard]] static std::string LowerPath(std::string path);
      int mMapTextureFrame = 0;
      std::map<std::string, std::uint64_t>
        mMapTexturesMade; // a texture made here, by its game path: the heights' checksum
      std::string mIniPath;
      bool mImGuiReady = false;
    };

    bool EditorApp::Init()
    {
      LoadSettings();
      // Direct3D 12, then Vulkan; /d3d12 or /vulkan alone, else Settings > Viewport's renderer. Nothing older
      // (moho::gAppRenderers).
      using gpg::gal::DeviceApi;
      const std::string renderer = mSettings.Get(EdSettings::kRenderer);
      if (moho::CFG_GetArgOption("/vulkan", 0, nullptr)) {
        moho::gAppRenderers = {DeviceApi::Vulkan};
      } else if (moho::CFG_GetArgOption("/d3d12", 0, nullptr)) {
        moho::gAppRenderers = {DeviceApi::Direct3D12};
      } else if (renderer == "vulkan") {
        moho::gAppRenderers = {DeviceApi::Vulkan, DeviceApi::Direct3D12};
      } else if (renderer == "d3d12") {
        moho::gAppRenderers = {DeviceApi::Direct3D12, DeviceApi::Vulkan};
      } else {
        moho::gAppRenderers = {DeviceApi::Direct3D12, DeviceApi::Vulkan};
      }
      // The hovered prop's outline techniques in mesh.fx (before the device loads its effects; WPE.57).
      moho::ren_EditorMeshOutline = true;
      // One maximized, movable, resizable window, whatever the game's display options say.
      moho::gAppWindowed = true;
      // The panels' window and its head (head 1); the game keeps head 0 for its viewport.
      moho::gAppBeforeDeviceCreate = &AddPanelHead;
      // Plays have cheats on (the whole-map view during play needs them), Game.prefs untouched.
      moho::gSessionCheats = true;
      // Textures saved into maps (the stratum masks) get the classic DDS header, which the retail game's
      // D3D9 texture loader reads; D3DX11's saver would write the DX10 one.
      gpg::gal::imaging::ImageCodec::PreferOwnDds(true);
      // `/memtrace`: every block's call stack, to find what a play leaves behind (slow).
      if (moho::CFG_GetArgOption("/memtrace", 0, nullptr)) {
        memtrace::Start();
      }
      // `/logtimes <file>`: every log line with its time, for timing a play's start.
      // Without it, the same goes to editor_log.txt in the settings folder, so a freeze or a crash a user reports has a
      // log with times to read (a run from the IDE passes no /log).
      if (fa::vector<fa::string> args; moho::CFG_GetArgOption("/logtimes", 1, &args) && !args.empty()) {
        mLog.WriteTimesTo(args[0].c_str());
      } else if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
        mLog.WriteTimesTo((folder / "editor_log.txt").string());
      }
      // Each play's rules (every blueprint) are kept for the next play with the same mods.
      moho::RULE_SetKeepBetweenSessions(true);
      // The editor's loading view in place of the game's movie and "IN TRANSIT" screen.
      moho::gUIBeforeStartGameUI = &InstallLoadingView;

      if (!mGame.Init()) {
        ::MessageBoxW(
          nullptr,
          L"Neither Direct3D 12 nor Vulkan started, or the game data could not be read. See the log.",
          kTitle,
          MB_OK | MB_ICONERROR
        );
        return false;
      }
      // The game starts its first session or the main menu on its first frame (CScApp::Main); the editor
      // starts sessions itself, from Play.
      mGame.initialized = 1;

      const HWND frame = HandleOf(mGame.supcomFrame);
      const HWND viewport = HandleOf(moho::ren_Viewport);
      const gpg::gal::DeviceContext* const context = gpg::gal::Device::GetInstance()->GetDeviceContext();
      if (
        frame == nullptr || viewport == nullptr || gPanelWindow == nullptr ||
        context->GetHeadCount() <= static_cast<int>(kPanelHead)
      ) {
        gpg::Warnf("editor: the game window, its viewport or the panels' window is missing");
        return false;
      }
      const char* const api = context->mDeviceType == DeviceApi::Vulkan ? "Vulkan" : "Direct3D 12";
      mBaseTitle = std::wstring(kTitle) + L" [" + std::wstring(api, api + std::char_traits<char>::length(api)) + L"]";
      ::SetWindowTextW(frame, mBaseTitle.c_str());
      mShownTitle = mBaseTitle;

      gViewportProc = reinterpret_cast<WNDPROC>(
        ::SetWindowLongPtrW(viewport, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&EditorViewportProc))
      );
      gFrameProc = reinterpret_cast<WNDPROC>(
        ::SetWindowLongPtrW(frame, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&EditorFrameProc))
      );

      SetUpImGui();
      if (!mRenderer.Init()) {
        ::MessageBoxW(
          nullptr, L"The editor's panels could not be set up on this device. See the log.", kTitle, MB_OK | MB_ICONERROR
        );
        return false;
      }
      mImGuiReady = true;
      EdImGuiRenderer::SetGameViewSource([]() {
        return gViewSurface;
      });
      // `/playsetups <file>` (test runs) reads and writes the play setups there instead.
      if (fa::vector<fa::string> args; moho::CFG_GetArgOption("/playsetups", 1, &args) && !args.empty()) {
        mPlay.SetSetupsFile(args[0].c_str());
      } else if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
        mPlay.SetSetupsFile((folder / "play_setups.ini").string());
      }
      // `/recentmaps <file>` (test runs) keeps the recent maps there instead.
      if (fa::vector<fa::string> args; moho::CFG_GetArgOption("/recentmaps", 1, &args) && !args.empty()) {
        mDocument.SetRecentMapsFile(args[0].c_str());
      } else if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
        mDocument.SetRecentMapsFile((folder / "recent_maps.txt").string());
      }
      // The FAF login kept between runs (its refresh token, encrypted for this Windows user).
      if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
        mPendingFafTokenFile = folder / "faf_login.bin";
      }
      // The vault: `/vault <folder>` (a test folder); else the FAF client's (fa_path.lua), which the game mounts and
      // the client lists, when this Windows user can write it; else Documents\My Games\..., as init_faf.lua finds
      // it without a client path. Its maps the init file didn't mount are mounted here.
      const std::filesystem::path clientVault = ClientVaultFolder();
      if (fa::vector<fa::string> vault; moho::CFG_GetArgOption("/vault", 1, &vault) && !vault.empty()) {
        mDocument.SetVaultFolder(vault[0].c_str());
      } else if (VaultUsable(clientVault)) {
        mDocument.SetVaultFolder(clientVault);
      } else if (
        PWSTR documents = nullptr; SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &documents))
      ) {
        mDocument.SetVaultFolder(
          std::filesystem::path(documents) / "My Games" / "Gas Powered Games" / "Supreme Commander Forged Alliance"
        );
        ::CoTaskMemFree(documents);
        if (!clientVault.empty()) {
          gpg::Logf(
            "editor: the FAF client's vault %s isn't writable by this Windows user", clientVault.string().c_str()
          );
        }
      }
      gpg::Logf("editor: the vault is %s", mDocument.VaultFolder().string().c_str());
      MountVaultMaps(mDocument.VaultFolder());
      mPlay.FindMaps();
      mPlay.ReadCommandLine();
      mShell = new EdShell(mLog, mPlay, mDocument);
      // The last run's marker still there: it didn't end normally (a crash, or killed).
      if (fa::vector<fa::string> marker; moho::CFG_GetArgOption("/runmarker", 1, &marker) && !marker.empty()) {
        mRunMarker = marker[0].c_str();
      } else if (!IsTestRunCommandLine() && !EditorSettingsFolder().empty()) {
        mRunMarker = EditorSettingsFolder() / "editor_running.txt";
      }
      if (!mRunMarker.empty()) {
        std::error_code ec;
        if (std::filesystem::exists(mRunMarker, ec)) {
          gpg::Warnf(
            "editor: the last run didn't end normally (a crash, or it was stopped); its log is in the logs folder, and "
            "File > Recover offers an autosave when there is one"
          );
          PostStatusMessage("The last run didn't end normally: see the Log, and File > Recover");
        }
        std::ofstream(mRunMarker, std::ios::trunc) << "running\n";
      }
      if (!mPendingFafTokenFile.empty()) {
        mShell->Browser().Faf().SetTokenFile(mPendingFafTokenFile);
        mShell->Browser().Faf().SetPictureCache(mPendingFafTokenFile.parent_path() / "cache" / "maps");
      }
      mDocument.SetBeforeDrop([this] {
        mScene.Detach();
      });
      mScene.SetTools(&mShell->Tools());
      mShell->Tools().SetPropPictures([this](const std::string& blueprint) {
        return mPropThumbnails.Get(blueprint);
      });
      // The prop pictures kept between runs, and the asset browser's favourites and recent: in the settings folder;
      // a test run only with `/thumbcache <folder>` and `/assetmarks <file>`.
      if (fa::vector<fa::string> folder; moho::CFG_GetArgOption("/thumbcache", 1, &folder) && !folder.empty()) {
        mPropThumbnails.SetCacheFolder(folder[0].c_str());
      } else if (!IsTestRunCommandLine() && !EditorSettingsFolder().empty()) {
        mPropThumbnails.SetCacheFolder(EditorSettingsFolder() / "cache" / "props");
      }
      if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/assetmarks", 1, &file) && !file.empty()) {
        mShell->Assets().SetMarksFile(file[0].c_str());
      } else if (!IsTestRunCommandLine() && !EditorSettingsFolder().empty()) {
        mShell->Assets().SetMarksFile(EditorSettingsFolder() / "asset_marks.txt");
      }
      ReadOpenCommandLine();
      gEditorApp = this;
      // The particle editor's own view renders at the start of the game head's frame (moho::gViewportBeforeFrame).
      moho::gViewportBeforeFrame = [](const int head) {
        if (head != 0 || gEditorApp == nullptr || gEditorApp->mShell == nullptr) {
          return;
        }
        gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
        const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
        if (context == nullptr || context->GetHeadCount() < 1) {
          return;
        }
        const gpg::gal::Head& game = context->GetHead(0);
        gEditorApp->mShell->ParticleEditor().Viewport().Render(
          static_cast<int>(game.mWidth),
          static_cast<int>(game.mHeight),
          ImGui::GetCurrentContext() != nullptr ? ImGui::GetIO().DeltaTime : 0.016f
        );
      };
      RegisterCommands();
      LoadKeymap();
      SetUpAutosave();
      // The script debugger's hook installer, before any sim makes its Lua state; `/debugarm` and
      // `/breakpoint <file>:<line>` for test runs.
      EdLuaDebugger::Get().Register();
      EdLuaDebugger::Get().SetArmed(moho::CFG_GetArgOption("/debugarm", 0, nullptr));
      if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/breakpoint", 1, &value) && !value.empty()) {
        const std::string spec = value[0].c_str();
        if (const std::size_t colon = spec.rfind(':'); colon != std::string::npos) {
          EdLuaDebugger::Get().ToggleBreakpoint(spec.substr(0, colon), std::atoi(spec.c_str() + colon + 1));
        }
      }
      mShell->SetCommands(&mCommands, &mMenus);
      // Editor mods: the turned-on ones (settings folder; a test run only with `/editormods <file>`) run now.
      if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/editormods", 1, &file) && !file.empty()) {
        mShell->ModHost().SetEnabledFile(file[0].c_str());
      } else if (!IsTestRunCommandLine() && !EditorSettingsFolder().empty()) {
        mShell->ModHost().SetEnabledFile(EditorSettingsFolder() / "editor_mods.txt");
      }
      if (!mDocument.VaultFolder().empty()) {
        mShell->ModHost().Scan(mDocument.VaultFolder() / "mods");
      }
      SetUpWindowChrome(frame);
      // The game view's ambient occlusion makes its GPU programs on first use, which the editor's own view never
      // is: made now, so the first Play's first frame doesn't wait for them (WPE.15).
      const auto warmStart = std::chrono::steady_clock::now();
      if (moho::AmbientOcclusionRenderer::Get().IsActive()) {
        gpg::Logf(
          "editor: game view's ambient occlusion made ahead in %.2f s",
          std::chrono::duration<double>(std::chrono::steady_clock::now() - warmStart).count()
        );
      }
      gpg::Logf("editor: ready on %s", api);
      return true;
    }

    void EditorApp::SetUpImGui()
    {
      IMGUI_CHECKVERSION();
      ImGui::CreateContext();
      {
        ImGuiSettingsHandler handler;
        handler.TypeName = "FafEditor";
        handler.TypeHash = ImHashStr("FafEditor");
        handler.ReadOpenFn = &UiSettingsOpen;
        handler.ReadLineFn = &UiSettingsLine;
        handler.WriteAllFn = &UiSettingsWrite;
        ImGui::AddSettingsHandler(&handler);
      }
      // A test run (its options) writes back the workspace and panels it read, not the ones it showed.
      gTestRun = IsTestRunCommandLine();
      ImGuiIO& io = ImGui::GetIO();
      io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
      const std::filesystem::path settings = EditorSettingsFolder();
      if (settings.empty()) {
        io.IniFilename = nullptr;
      } else {
        mIniPath = (settings / "layout.ini").string();
        io.IniFilename = mIniPath.c_str();
      }

      // The look is a theme (ui/EdTheme: Lua files, built-in and the user's); the first built-in, FAF Blue, is the
      // mockup's look. The theme in layout.ini replaces it at the first frame.
      mDpiScale = ImGui_ImplWin32_GetDpiScaleForHwnd(gPanelWindow);
      io.ConfigDpiScaleFonts = true;
      LoadThemeList();
      SetTheme(mThemes.empty() ? std::string() : mThemes.front().name);

      // FreeType with light hinting draws the panels' text (imgui_freetype): the stems land on whole pixels as a
      // browser's text does, where ImGui's own rasterizer leaves them soft. `/stbfont` keeps ImGui's for comparison.
      if (!moho::CFG_GetArgOption("/stbfont", 0, nullptr)) {
        io.Fonts->SetFontLoader(ImGuiFreeType::GetFontLoader());
        io.Fonts->FontLoaderFlags = ImGuiFreeTypeLoaderFlags_LightHinting;
      }
      std::error_code error;
      const std::filesystem::path segoe = "C:\\Windows\\Fonts\\segoeui.ttf";
      ImFont* body = nullptr;
      if (std::filesystem::exists(segoe, error)) {
        body = io.Fonts->AddFontFromFileTTF(segoe.string().c_str(), 16.0f);
      }
      if (body == nullptr) {
        body = io.Fonts->AddFontDefault();
      }
      // The icons (ui/EdIconFont.h, the mockup's line icons) are characters of the panels' font, so any label can
      // carry one. At 13.5 of the text's 16 an icon is about 1.1 em of Segoe UI, as the mockup sizes them.
      {
        ImFontConfig icons;
        icons.MergeMode = true;
        icons.FontDataOwnedByAtlas = false;
        icons.GlyphMinAdvanceX = 13.5f;
        // A pixel up: measured beside Segoe UI the icons sat about a pixel below the capitals (the Play button, the
        // start screen's rows; user reports).
        icons.GlyphOffset = ImVec2(0.0f, -1.0f);
        (void)io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(IconFontData()), IconFontSize(), 13.5f, &icons);
      }
      // Headings and codes (the FAF sign-in's): Segoe UI Semibold (the mockup's weight 600; Bold when Windows has no
      // Semibold) and Consolas, when Windows has them.
      for (const char* const name : {"C:\\Windows\\Fonts\\seguisb.ttf", "C:\\Windows\\Fonts\\segoeuib.ttf"}) {
        if (const std::filesystem::path bold = name; gBoldFont == nullptr && std::filesystem::exists(bold, error)) {
          gBoldFont = io.Fonts->AddFontFromFileTTF(bold.string().c_str(), 16.0f);
        }
      }
      if (const std::filesystem::path mono = "C:\\Windows\\Fonts\\consola.ttf"; std::filesystem::exists(mono, error)) {
        gMonoFont = io.Fonts->AddFontFromFileTTF(mono.string().c_str(), 16.0f);
      }
      ImGui_ImplWin32_Init(gPanelWindow);
    }

    void EditorApp::RegisterCommands()
    {
      EdCommands& c = mCommands;
      const auto mapOpen = [this]() -> std::string {
        return mDocument.GetState() == EdDocument::State::Open ? std::string() : std::string("no map is open");
      };
      const auto notBusy = [this]() -> std::string {
        if (mPlay.Active()) {
          return "a play is running (F5 stops it)";
        }
        if (mDocument.GetState() == EdDocument::State::Loading) {
          return "a map is opening";
        }
        return {};
      };
      // The Review workspace only looks: what changes the map says so.
      const auto notReview = []() -> std::string {
        return Workspaces()[static_cast<std::size_t>(ActiveWorkspace())].readOnly ? kReviewOnlyLooks : "";
      };
      const auto canEdit = [mapOpen, notReview]() -> std::string {
        std::string why = notReview();
        return why.empty() ? mapOpen() : why;
      };
      const auto add = [&c](
                         const char* id,
                         const char* title,
                         const char* category,
                         const char* keys,
                         std::function<void()> run,
                         std::function<std::string()> why = {},
                         std::function<bool()> checked = {},
                         const char* description = ""
                       ) {
        c.Add(EdCommand{id, title, category, keys, description, std::move(run), std::move(why), std::move(checked)});
      };
      // A panel shown or hidden: View's entries, ticked while shown.
      const auto panel = [this, &add](const char* id, const char* title, bool& (EdShell::*flag)() noexcept) {
        add(id, title, "View", "", [this, flag] {
          bool& on = (mShell->*flag)();
          on = !on;
        }, {}, [this, flag] {
          return (mShell->*flag)();
        });
      };

      // File
      add("file.home", "Start screen", "File", "", [this] {
        mShell->ShowHome(0);
      }, {}, {}, "New, recent work, your maps and the FAF vault");
      add("new.mission", "New mission...", "File", "", [] {}, [] {
        return std::string("missions come with the Mission tools");
      });
      add("new.mod", "New mod...", "File", "", [] {}, [] {
        return std::string("mods come with the Units and mods tools");
      });
      add("new.effect", "New effect", "File", "", [this] {
        mShell->SwitchWorkspace(6);
        mShell->HideHome();
        mShell->ShowParticleEditor() = true;
        mShell->ParticleEditor().NewEffect();
      }, {}, {}, "A particle effect in the Effects workspace");
      add("new.material", "New material", "File", "", [this] {
        mShell->SwitchWorkspace(8);
        mShell->HideHome();
        mShell->ShowMaterialEditor() = true;
        mShell->MaterialEditor().NewGraph();
      }, {}, {}, "A texture layer's node graph in the Materials workspace");
      add("file.new", "New map...", "File", "Ctrl+N", [this] {
        mShell->OpenNewMap();
      }, notBusy);
      add("file.open", "Open map...", "File", "Ctrl+O", [this] {
        mShell->Browser().Show();
      }, {}, {}, "This computer and the FAF vault");
      add("file.save", "Save", "File", "Ctrl+S", [this] {
        SaveDocument();
      }, mapOpen);
      add("file.exportpreview", "Export the lobby preview (PNG)...", "File", "", [this] {
        wchar_t path[MAX_PATH] = L"";
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = HandleOf(mGame.supcomFrame);
        dialog.lpstrFile = path;
        dialog.nMaxFile = MAX_PATH;
        dialog.lpstrFilter = L"PNG picture (*.png)\0*.png\0";
        dialog.lpstrDefExt = L"png";
        dialog.lpstrTitle = L"Export the lobby preview";
        dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if (::GetSaveFileNameW(&dialog) != FALSE) {
          std::string message;
          const bool ok = mDocument.ExportPreview(path, message);
          (ok ? gpg::Logf : gpg::Warnf)("editor: %s", message.c_str());
          PostStatusMessage(message);
        }
      }, mapOpen, {}, "The map's preview picture, as the lobby shows it, as a PNG");
      add("file.saveas", "Save as new map folder...", "File", "Ctrl+Shift+S", [this] {
        mShell->OpenSaveAs();
      }, mapOpen);
      add(
        "map.preview",
        "Regenerate the lobby preview",
        "Map",
        "",
        [this] {
        std::string message;
        const bool ok = RegeneratePreview(message);
        (ok ? gpg::Logf : gpg::Warnf)("editor: %s", message.c_str());
        PostStatusMessage(message);
      },
        mapOpen,
        {},
        "The preview picture the lobby shows, drawn anew from the heights, the sea, the start positions "
        "and the resources (saved with the map)"
      );
      add("map.resize", "Resize map...", "Map", "", [this] {
        mShell->OpenResize();
      }, mapOpen, {}, "The map made another size in a new folder: cut or added around an anchor, or stretched");
      add("file.package", "Package for the FAF vault...", "File", "", [this] {
        mShell->OpenPackage();
      }, mapOpen);
      add("file.recent.clear", "Clear recently opened", "File", "", [this] {
        mDocument.ClearRecentMaps();
      }, [this]() -> std::string {
        return mDocument.RecentMaps().empty() ? "the list is empty" : "";
      });
      {
        // Open Recent's placeholder: a menu entry only (not in the palette or Settings > Keys).
        EdCommand none{"file.recent.none", "(no maps opened yet)", "File", "", "", [] {}, [] {
          return std::string("no maps opened yet");
        }};
        none.palette = false;
        c.Add(std::move(none));
      }
      for (int i = 0; i < 10; ++i) {
        EdCommand recent{
          "file.recent." + std::to_string(i),
          "Open recent map " + std::to_string(i + 1),
          "File",
          "",
          "",
          [this, i] {
          if (static_cast<std::size_t>(i) >= mRecentShown.size()) {
            return;
          }
          const std::string scenario = mRecentShown[static_cast<std::size_t>(i)];
          const std::vector<std::string>& maps = mPlay.Maps();
          for (std::size_t m = 0; m < maps.size(); ++m) {
            if (maps[m] == scenario) {
              mPlay.Select(static_cast<int>(m));
              (void)mDocument.Open(scenario);
              gpg::Logf("editor: File > Open Recent: %s", scenario.c_str());
            }
          }
        },
          notBusy,
          [this, i] {
          return static_cast<std::size_t>(i) < mRecentShown.size() && mDocument.GetState() == EdDocument::State::Open &&
            _stricmp(mDocument.Path().c_str(), mRecentShown[static_cast<std::size_t>(i)].c_str()) == 0;
        },
        };
        recent.palette = false;
        c.Add(std::move(recent));
      }
      add("file.exit", "Exit", "File", "Alt+F4", [this] {
        if (!AskBeforeExit()) {
          mShell->RequestExit();
        }
      });
      add("file.recover", "Recover an autosaved map...", "File", "", [this] {
        mRecoverable = ListAutosaves(mAutosaveRoot);
        mShowRecover = true;
      }, [this]() -> std::string {
        return mRecoverable.empty() ? "there is no autosaved map" : "";
      }, {}, "Maps the editor autosaved and that weren't saved since");

      // Edit
      add("edit.undo", "Undo", "Edit", "Ctrl+Z", [this] {
        (void)mScene.Undo();
      }, notReview);
      add("edit.redo", "Redo", "Edit", "Ctrl+Y, Ctrl+Shift+Z", [this] {
        (void)mScene.Redo();
      }, notReview);
      add("edit.delete", "Delete selection", "Edit", "Delete", [this] {
        mScene.DeleteSelected();
      }, canEdit);
      add("edit.cut", "Cut", "Edit", "Ctrl+X", [this] {
        mScene.CtrlKey('X');
      }, canEdit, {}, "The tool's selection copied, then deleted");
      add("edit.copy", "Copy", "Edit", "Ctrl+C", [this] {
        mScene.CtrlKey('C');
      }, mapOpen, {}, "The tool's selection");
      add("edit.paste", "Paste at the cursor", "Edit", "Ctrl+V", [this] {
        mScene.CtrlKey('V');
      }, canEdit);
      add("view.shading", "Shading: lit / heights / slope", "View", "", [this] {
        EdTools& tools = mShell->Tools();
        tools.SetShading((tools.Shading() + 1) % 3);
      }, mapOpen, {}, "The view's shading in turn: lit, the ground by height, the ground by slope");
      add(
        "terrain.generate", "Generate (node graph)...", "Terrain", "", [this] {
        mShell->SwitchWorkspace(4);
        mShell->HideHome();
        mShell->ShowGenerate();
      }, mapOpen, {}, "The terrain graph in the Generate workspace: nodes, a preview on the map, Build as one undo step"
      );
      add(
        "terrain.layout", "Layout canvas...", "Terrain", "", [this] {
        mShell->SwitchWorkspace(3);
        mShell->HideHome();
        mShell->ShowLayout();
      }, mapOpen, {}, "The map drawn in layers (hills, mountains, water, bases...) and turned into terrain in one step"
      );
      add("terrain.interop", "Import / Export...", "Terrain", "", [this] {
        mShell->Tools().OpenInterop();
      }, mapOpen, {}, "Heightmaps from and to other tools: mapping, turns and blends, a live link, a sidecar");
      add("terrain.sctools", "SC tools...", "Terrain", "", [this] {
        mShell->Tools().OpenScTools();
      }, mapOpen, {}, "Base pads under the markers, the pathable slope limit, the grade along a route");
      add("terrain.erosion", "Erosion...", "Terrain", "", [this] {
        mShell->Tools().OpenErosion();
      }, mapOpen, {}, "A solver run over the whole map: presets, a preview on the map, Apply as one undo step");
      add("edit.find", "Find and replace objects...", "Edit", "Ctrl+F", [this] {
        mFindAsk = true;
      }, mapOpen, {}, "Every object of one type: select them, delete them or change them to another");
      add("edit.duplicate", "Duplicate beside", "Edit", "Ctrl+D", [this] {
        mScene.CtrlKey('D');
      }, canEdit, {}, "A copy of the selection 8 units beside it");
      for (int i = 0; i < static_cast<int>(ArrangeOp::Count); ++i) {
        const ArrangeOp op = static_cast<ArrangeOp>(i);
        add((std::string("arrange.") + ArrangeId(op)).c_str(), ArrangeTitle(op), "Edit", "", [this, op] {
          mShell->Tools().RequestArrange(op);
        }, canEdit, {}, "The selection, as one undo step (Select tool > Arrange)");
      }

      // Tools: 1 to 8, as the strip lists them; in Review only Select.
      for (int i = 0; i < EdTools::ToolCount(); ++i) {
        const std::string title = std::string(EdTools::ToolName(i)) + " tool";
        const std::string keys = std::to_string(i + 1);
        add(("tool." + std::to_string(i)).c_str(), title.c_str(), "Tools", keys.c_str(), [this, i] {
          mShell->Tools().SetTool(i);
        }, [i]() -> std::string {
          return i != 0 && Workspaces()[static_cast<std::size_t>(ActiveWorkspace())].readOnly ? kReviewOnlyLooks : "";
        }, [this, i] {
          return mShell->Tools().Tool() == i;
        });
      }

      // Workspaces: Alt+1 to Alt+0, and the title row's tabs.
      for (std::size_t i = 0; i < Workspaces().size(); ++i) {
        const EdWorkspace& w = Workspaces()[i];
        add(
          ("workspace." + std::to_string(i)).c_str(),
          (std::string(w.name) + " workspace").c_str(),
          "Workspace",
          w.keys,
          [this, i] {
          mShell->SwitchWorkspace(static_cast<int>(i));
        },
          {},
          [i] {
          return ActiveWorkspace() == static_cast<int>(i);
        },
          w.about
        );
      }

      // View
      panel("view.tools", "Tools", &EdShell::ShowTools);
      panel("view.map", "Map", &EdShell::ShowMap);
      panel("view.info", "Info", &EdShell::ShowInfo);
      panel("view.layers", "Layers", &EdShell::ShowLayers);
      panel("view.markers", "Markers", &EdShell::ShowMarkers);
      panel("view.check", "Check", &EdShell::ShowCheck);
      panel("view.script", "Script", &EdShell::ShowScript);
      panel("view.lighting", "Lighting", &EdShell::ShowLighting);
      panel("view.armies", "Armies", &EdShell::ShowArmies);
      panel("view.properties", "Properties", &EdShell::ShowProperties);
      panel("view.material", "Material Editor", &EdShell::ShowMaterialEditor);
      panel("view.particle", "Particle Editor", &EdShell::ShowParticleEditor);
      panel("view.particlebrowser", "Particle Browser", &EdShell::ShowParticleBrowser);
      panel("view.adaptive", "Adaptive Map", &EdShell::ShowAdaptiveWindow);
      panel("view.log", "Log", &EdShell::ShowLog);
      panel("view.history", "History", &EdShell::ShowHistory);
      panel("view.debugger", "Debugger", &EdShell::ShowDebugger);
      add("view.problems", "Problems", "View", "", [this] {
        if (mShell->ShowProblems()) {
          mShell->ShowProblems() = false;
        } else {
          mShell->OpenProblems();
        }
      }, {}, [this] {
        return mShell->ShowProblems();
      }, "The check's findings and the log's warnings in one list");
      panel("view.panelsplaying", "Panels while playing", &EdShell::PanelsWhilePlaying);
      panel("view.imguidemo", "ImGui demo", &EdShell::ShowDemo);
      add("view.fullhelp", "Full help text", "View", "", [] {
        FullHelpText() = !FullHelpText();
      }, {}, [] {
        return FullHelpText();
      });
      add("view.resetlayout", "Reset this workspace's layout", "View", "", [this] {
        mShell->ResetLayout();
      });
      // Help: F1 the topic of the panel under the mouse (over the map view, the view's).
      add("help.open", "Help", "Help", "F1", [this] {
        mShell->OpenHelp(MouseOverView() ? std::string("view") : mShell->HelpTopicUnderMouse());
      }, {}, {}, "The help topic of the panel under the mouse");
      add("help.tour", "Tour", "Help", "", [this] {
        mShell->StartTour();
      }, {}, {}, "A few steps around the window");
      add("view.palette", "Command palette", "View", "Ctrl+K, Ctrl+Shift+P", [] {
        OpenCommandPalette();
      }, {}, {}, "Find any command by a few of its letters");
      add("view.frame", "Frame the whole map", "View", "Home", [this] {
        mScene.FrameMap();
      }, mapOpen);
      // Q / E: the selected props turn under the Select tool, else the camera (the first that can run takes the key).
      add("object.turnleft", "Turn the selection left", "Object", "Q", [this] {
        (void)mScene.TurnSelectedProps(-0.2617994f);
      }, [this]() -> std::string {
        return mScene.CanTurnSelectedProps() ? std::string() : "no props selected under the Select tool";
      });
      add("object.turnright", "Turn the selection right", "Object", "E", [this] {
        (void)mScene.TurnSelectedProps(0.2617994f);
      }, [this]() -> std::string {
        return mScene.CanTurnSelectedProps() ? std::string() : "no props selected under the Select tool";
      });
      add("view.turnleft", "Turn the camera left", "View", "Q", [this] {
        mScene.StepCamera(-0.2617994f, 1.0f);
      }, mapOpen);
      add("view.turnright", "Turn the camera right", "View", "E", [this] {
        mScene.StepCamera(0.2617994f, 1.0f);
      }, mapOpen);
      add("view.zoomin", "Closer", "View", "PageUp", [this] {
        mScene.StepCamera(0.0f, 0.8f);
      }, mapOpen);
      add("view.zoomout", "Farther", "View", "PageDown", [this] {
        mScene.StepCamera(0.0f, 1.25f);
      }, mapOpen);
      add("view.north", "Face north", "View", "N", [this] {
        mScene.FaceNorth();
      }, mapOpen);
      add("view.down", "Look straight down", "View", "T", [this] {
        mScene.LookDown();
      }, mapOpen);
      // Camera bookmarks: Ctrl+Shift+1..9 keeps the camera, Ctrl+1..9 goes back to it (per map, for this run).
      for (int b = 1; b <= 9; ++b) {
        const std::string n = std::to_string(b);
        mCommandIds.push_back("view.bookmark.save." + n);
        mCommandIds.push_back("view.bookmark.go." + n);
        add(
          mCommandIds[mCommandIds.size() - 2].c_str(),
          ("Keep the camera as bookmark " + n).c_str(),
          "View",
          ("Ctrl+Shift+" + n).c_str(),
          [this, b] {
          mBookmarks[LowerPath(mDocument.Path())][static_cast<std::size_t>(b - 1)] = mScene.GetCameraPose();
          PostStatusMessage("Camera bookmark " + std::to_string(b) + " kept");
        },
          mapOpen
        );
        add(
          mCommandIds.back().c_str(), ("Go to camera bookmark " + n).c_str(), "View", ("Ctrl+" + n).c_str(), [this, b] {
          mScene.SetCameraPose(*mBookmarks[LowerPath(mDocument.Path())][static_cast<std::size_t>(b - 1)]);
        }, [this, mapOpen, b]() -> std::string {
          if (std::string why = mapOpen(); !why.empty()) {
            return why;
          }
          const auto it = mBookmarks.find(LowerPath(mDocument.Path()));
          return it == mBookmarks.end() || !it->second[static_cast<std::size_t>(b - 1)]
            ? "no camera bookmark " + std::to_string(b) + " yet (Ctrl+Shift+" + std::to_string(b) + " keeps one)"
            : std::string();
        }
        );
      }
      add("play.pause", "Pause / resume", "Play", "Pause", [this] {
        moho::CWldSession* const session = moho::WLD_GetActiveSession();
        if (session == nullptr) {
          return;
        }
        // As SessionIsPaused reads it (UserLuaSession.cpp).
        const bool paused =
          session->mRequestingPauseState != 0U ? session->mRequestingPause != 0 : session->mSessionPauseStateA != 0;
        if (paused) {
          session->Resume();
        } else {
          session->RequestPause();
        }
        gpg::Logf("editor: play %s", paused ? "resumed" : "paused");
      }, [this]() -> std::string {
        return mPlay.Active() && moho::WLD_GetActiveSession() != nullptr ? std::string() : "no play running";
      });
      add("view.focus", "Focus selection", "View", "F", [this] {
        if (!mScene.FrameSelection()) {
          PostStatusMessage("Nothing selected to focus on");
        }
      }, mapOpen, {}, "The camera over the selection, far enough to see all of it");
      // Select: over what the active tool selects (the Select tool's props, Markers, Units, Decals).
      const auto selectWhy = [this, mapOpen]() -> std::string {
        if (std::string why = mapOpen(); !why.empty()) {
          return why;
        }
        return *mScene.SelectableKind() == '\0'
          ? "the active tool selects nothing: use Select, Markers, Units or Decals"
          : std::string();
      };
      const auto selectCommand =
        [this, &add, selectWhy](
          const char* id, const char* title, const char* keys, const SelectMode mode, const char* description
        ) {
        add(id, title, "Select", keys, [this, mode] {
          const int count = mScene.SelectWhole(mode);
          PostStatusMessage(
            std::string(SelectModeName(mode)) + ": " + std::to_string(std::max(count, 0)) + " " +
            mScene.SelectableKind()
          );
        }, selectWhy, {}, description);
      };
      selectCommand("select.all", "All", "Ctrl+A", SelectMode::All, "Selects every object the active tool selects");
      selectCommand("select.none", "None", "Alt+A", SelectMode::None, "Selects nothing");
      selectCommand("select.invert", "Invert", "Ctrl+I", SelectMode::Invert, "The unselected ones selected instead");
      selectCommand(
        "select.same",
        "Same type",
        "Shift+G",
        SelectMode::Same,
        "Every one with a selected one's blueprint, marker type or decal texture"
      );
      // Window: any panel by its id (the panels without a View entry of their own too).
      const auto windowPanel = [this, &add](const char* id, const char* title, const char* panelId) {
        add(id, title, "Window", "", [this, panelId] {
          if (bool* const shown = mShell->PanelShown(panelId); shown != nullptr) {
            *shown = !*shown;
          }
        }, {}, [this, panelId] {
          const bool* const shown = mShell->PanelShown(panelId);
          return shown != nullptr && *shown;
        });
      };
      windowPanel("window.stages", "Stages", "MissionStages");
      windowPanel("window.strings", "Strings", "MissionStrings");
      windowPanel("window.bases", "Bases", "MissionBases");
      windowPanel("window.platoons", "Platoons", "MissionPlatoons");
      windowPanel("window.run", "Run", "MissionRun");
      windowPanel("window.unitlab", "Unit lab", "UnitLab");
      windowPanel("window.unitviewer", "Unit viewer", "UnitViewer");
      windowPanel("window.modproject", "Mod project", "ModProject");
      windowPanel("window.editormods", "Editor mods", "EditorMods");
      windowPanel("window.assets", "Asset browser", "AssetBrowser");
      if (EdCommand* const assets = const_cast<EdCommand*>(c.Find("window.assets")); assets != nullptr) {
        (void)c.SetKeys("window.assets", "Ctrl+Alt+A");
      }
      add("view.uiscale.up", "Larger panels and text", "View", "Ctrl+=", [this] {
        mShell->StepUiScale(1);
      });
      add("view.uiscale.down", "Smaller panels and text", "View", "Ctrl+-", [this] {
        mShell->StepUiScale(-1);
      });
      add("view.uiscale.reset", "Panels at 100 %", "View", "Ctrl+0", [this] {
        mShell->StepUiScale(0);
      });
      add("settings.open", "Settings...", "File", "", [this] {
        mShowSettings = true;
      });
      add("settings.keys", "Keyboard shortcuts...", "View", "", [this] {
        mShowSettings = true;
        mSettingsPage = 2;
      }, {}, {}, "Every command's keys, to change");
      {
        static constexpr const char* kPageIds[] = {"general", "appearance", "keys", "viewport", "performance"};
        static constexpr const char* kPageTitles[] = {
          "Settings: General", "Settings: Appearance", "Settings: Keys", "Settings: Viewport", "Settings: Performance"
        };
        for (int i = 0; i < 5; ++i) {
          add((std::string("settings.") + kPageIds[i]).c_str(), kPageTitles[i], "Settings", "", [this, i] {
            mShowSettings = true;
            mSettingsPage = i;
          });
        }
      }
      RegisterThemeCommands();

      // Play
      add("play.editorview", "Editor's view during a play", "Play", "F6", [this] {
        ToggleEditorView();
      }, [this]() -> std::string {
        return mPlay.Active() ? "" : "no play is running";
      }, [this] {
        return mPlay.Active() && mShell->EditorViewInPlay();
      });
      add("play.toggle", "Play", "Play", "F5", [this] {
        if (mPlay.Active()) {
          mPlay.Stop();
        } else if (mPlay.CanPlay()) {
          mPlay.Play();
        }
      }, [this]() -> std::string {
        if (mPlay.Active() || mPlay.CanPlay()) {
          return {};
        }
        return mPlay.Maps().empty() ? "the game lists no maps to play" : "a session is still loading";
      });
      for (std::size_t i = 0; i < mPlay.Maps().size(); ++i) {
        EdCommand map{
          "play.map." + std::to_string(i),
          mPlay.Titles()[i] + "  (" + MapDisplayName(mPlay.Maps()[i]) + ")",
          "Play",
          "",
          "",
          [this, i] {
          mPlay.Select(static_cast<int>(i));
        },
          [this]() -> std::string {
          return mPlay.Active() ? "a play is running" : "";
        },
          [this, i] {
          return mPlay.Selected() == static_cast<int>(i);
        },
        };
        map.palette = false;
        c.Add(std::move(map));
      }

      // The title row's menus.
      const auto cmd = [](const char* id) {
        EdMenuItem item;
        item.command = id;
        return item;
      };
      const auto sep = [] {
        EdMenuItem item;
        item.separator = true;
        return item;
      };
      EdMenuItem recent;
      recent.label = "Open &Recent";
      recent.provider = [this] {
        // The recent maps the game still lists, with their titles; filled each time the menu opens.
        mRecentShown.clear();
        std::vector<EdMenuItem> items;
        for (const std::string& scenario : mDocument.RecentMaps()) {
          const std::vector<std::string>& maps = mPlay.Maps();
          for (std::size_t i = 0; i < maps.size() && mRecentShown.size() < 10; ++i) {
            if (_stricmp(maps[i].c_str(), scenario.c_str()) != 0) {
              continue;
            }
            EdMenuItem item;
            item.command = "file.recent." + std::to_string(mRecentShown.size());
            item.label = std::to_string(mRecentShown.size() + 1) + "  " + mPlay.Titles()[i] + "  (" +
              MapDisplayName(maps[i]) + ")";
            items.push_back(std::move(item));
            mRecentShown.push_back(maps[i]);
            break;
          }
        }
        if (items.empty()) {
          EdMenuItem none;
          none.command = "file.recent.none";
          items.push_back(std::move(none));
        } else {
          EdMenuItem line;
          line.separator = true;
          items.push_back(std::move(line));
          EdMenuItem clear;
          clear.command = "file.recent.clear";
          items.push_back(std::move(clear));
        }
        return items;
      };
      EdMenuItem workspaces;
      workspaces.label = "&Workspace";
      for (std::size_t i = 0; i < Workspaces().size(); ++i) {
        workspaces.items.push_back(cmd(("workspace." + std::to_string(i)).c_str()));
      }
      // View > World: every environment panel in one place (the design's Window > World).
      EdMenuItem world;
      world.label = "&World";
      world.provider = [cmd] {
        return std::vector<EdMenuItem>{cmd("view.lighting"), cmd("tool.3")};
      };
      EdMenuItem arrange;
      arrange.label = "&Arrange";
      arrange.provider = [] {
        std::vector<EdMenuItem> items;
        for (int i = 0; i < static_cast<int>(ArrangeOp::Count); ++i) {
          const ArrangeOp op = static_cast<ArrangeOp>(i);
          if (op == ArrangeOp::DistributeX || op == ArrangeOp::Snap || op == ArrangeOp::MirrorX) {
            EdMenuItem line;
            line.separator = true;
            items.push_back(std::move(line));
          }
          EdMenuItem item;
          item.command = std::string("arrange.") + ArrangeId(op);
          item.label = ArrangeTitle(op);
          items.push_back(std::move(item));
        }
        return items;
      };
      EdMenuItem themes;
      themes.label = "&Theme";
      themes.provider = [this] {
        std::vector<EdMenuItem> items;
        for (std::size_t i = 0; i < mThemes.size(); ++i) {
          EdMenuItem item;
          item.command = "view.theme." + std::to_string(i);
          item.label = mThemes[i].name;
          items.push_back(std::move(item));
        }
        EdMenuItem line;
        line.separator = true;
        items.push_back(std::move(line));
        for (const char* const id : {"view.theme.reload", "view.theme.folder"}) {
          EdMenuItem item;
          item.command = id;
          items.push_back(std::move(item));
        }
        return items;
      };
      EdMenuItem playMaps;
      playMaps.label = "&Map";
      playMaps.provider = [this] {
        std::vector<EdMenuItem> items;
        for (std::size_t i = 0; i < mPlay.Maps().size(); ++i) {
          EdMenuItem item;
          item.command = "play.map." + std::to_string(i);
          items.push_back(std::move(item));
        }
        return items;
      };
      mMenus = {
        EdMenu{
          "&File",
          {cmd("file.home"),
           sep(),
           cmd("file.new"),
           cmd("new.effect"),
           cmd("new.material"),
           cmd("file.open"),
           recent,
           sep(),
           cmd("file.save"),
           cmd("file.saveas"),
           cmd("file.package"),
           cmd("file.exportpreview"),
           sep(),
           cmd("file.recover"),
           cmd("settings.open"),
           sep(),
           cmd("file.exit")}
        },
        EdMenu{
          "&Edit",
          {cmd("edit.undo"),
           cmd("edit.redo"),
           sep(),
           cmd("edit.cut"),
           cmd("edit.copy"),
           cmd("edit.paste"),
           cmd("edit.duplicate"),
           cmd("edit.delete"),
           sep(),
           cmd("edit.find"),
           arrange}
        },
        EdMenu{
          "&Terrain",
          {cmd("terrain.generate"),
           cmd("terrain.layout"),
           cmd("terrain.interop"),
           cmd("terrain.erosion"),
           cmd("terrain.sctools")}
        },
        EdMenu{
          "&Select",
          {cmd("select.all"), cmd("select.none"), cmd("select.invert"), cmd("select.same"), sep(), cmd("view.focus")}
        },
        EdMenu{
          "&View",
          {EdMenuItem{
             "",
             "Camera",
             false,
             {cmd("view.frame"),
              cmd("view.focus"),
              cmd("view.north"),
              cmd("view.down"),
              cmd("view.turnleft"),
              cmd("view.turnright"),
              cmd("view.zoomin"),
              cmd("view.zoomout")}
           },
           world,
           sep(),
           cmd("view.palette"),
           cmd("settings.keys"),
           themes,
           sep(),
           cmd("view.fullhelp"),
           cmd("view.panelsplaying"),
           sep(),
           workspaces,
           cmd("view.resetlayout")}
        },
        EdMenu{
          "&Map",
          {cmd("view.info"),
           cmd("view.armies"),
           cmd("view.markers"),
           cmd("view.check"),
           sep(),
           cmd("view.script"),
           cmd("view.adaptive"),
           cmd("view.lighting"),
           sep(),
           cmd("map.preview"),
           cmd("map.resize")}
        },
        EdMenu{
          "&Window",
          {EdMenuItem{
             "",
             "General",
             false,
             {cmd("view.tools"),
              cmd("view.properties"),
              cmd("view.map"),
              cmd("view.info"),
              cmd("view.problems"),
              cmd("view.log"),
              cmd("view.history"),
              cmd("view.debugger")}
           },
           EdMenuItem{
             "",
             "Mission",
             false,
             {cmd("window.stages"),
              cmd("window.strings"),
              cmd("window.bases"),
              cmd("window.platoons"),
              cmd("window.run")}
           },
           EdMenuItem{
             "",
             "Mod and effects",
             false,
             {cmd("view.particle"),
              cmd("view.particlebrowser"),
              cmd("view.material"),
              cmd("window.unitlab"),
              cmd("window.unitviewer"),
              cmd("window.modproject"),
              cmd("window.editormods")}
           },
           cmd("window.assets"),
           cmd("view.script")}
        },
        EdMenu{"&Play", {cmd("play.toggle"), cmd("play.pause"), cmd("play.editorview"), playMaps}},
        EdMenu{"&Help", {cmd("help.open"), cmd("help.tour"), sep(), cmd("view.palette"), cmd("settings.keys")}},
      };
      const auto clashes = c.Clashes();
      for (const auto& [a, b] : clashes) {
        gpg::Warnf("editor: commands %s and %s share a key", a.c_str(), b.c_str());
      }
      gpg::Logf("editor: %zu commands, %zu menus", c.All().size(), mMenus.size());
    }

    void EditorApp::SetUpWindowChrome(
      const HWND frame
    )
    {
      EdWindowChrome& chrome = WindowChrome();
      chrome.own =
        !moho::CFG_GetArgOption("/nativecaption", 0, nullptr) && mSettings.Get(EdSettings::kTitleBar) != "windows";
      // The frame's border and (with Windows' caption) its caption dark, as the panels are.
      const BOOL dark = TRUE;
      (void)::DwmSetWindowAttribute(frame, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));
      chrome.maximised = ::IsZoomed(frame) != FALSE;
      const LONG_PTR style = ::GetWindowLongPtrW(frame, GWL_STYLE);
      gpg::Logf(
        "editor: title row %s (window style 0x%08llx%s)",
        chrome.own ? "drawn by the editor" : "Windows'",
        static_cast<unsigned long long>(style),
        (style & WS_THICKFRAME) != 0 ? ", resizable" : ", fixed size"
      );
      // The frame's client area changes (WM_NCCALCSIZE): the game's frame resizes its viewport and device to it.
      ::SetWindowPos(
        frame, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED
      );
    }

    void EditorApp::FeedUiClicks()
    {
      if (mUiClicks.empty()) {
        return;
      }
      // Frame by frame from frame 300: the position, down, up (down and up again for a double-click), then a pause.
      constexpr int kStart = 300;
      constexpr int kEach = 30;
      const int frame = mUiClickFrame++ - kStart;
      if (frame < 0) {
        return;
      }
      const std::size_t index = static_cast<std::size_t>(frame / kEach);
      if (index >= mUiClicks.size()) {
        mUiClicks.clear();
        return;
      }
      const UiClick& click = mUiClicks[index];
      const int step = frame % kEach;
      if (click.key != 0) {
        if (step == 1) {
          gpg::Logf("editor: test key Ctrl+%c", click.key);
          mScene.CtrlKey(click.key);
        }
        return;
      }
      if (click.x < 0.0f) {
        return;
      }
      ImGuiIO& io = ImGui::GetIO();
      io.AddMousePosEvent(click.x, click.y);
      if (click.hoverOnly) {
        if (step == 1) {
          gpg::Logf("editor: test pointer at %.0f,%.0f", click.x, click.y);
        }
        return;
      }
      if (step == 1 || (click.doubleClick && step == 3)) {
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, true);
        gpg::Logf(
          "editor: test click at %.0f,%.0f%s", click.x, click.y, click.doubleClick && step == 3 ? " (second)" : ""
        );
      } else if (step == 2 || (click.doubleClick && step == 4)) {
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
      }
    }

    void EditorApp::HandleMenuCommand(
      const UINT command
    )
    {
      // The old menu ids (test runs post them) and the commands they ran.
      static const std::pair<UINT, const char*> kIds[] = {
        {kMenuExit, "file.exit"},
        {kMenuTools, "view.tools"},
        {kMenuMap, "view.map"},
        {kMenuLog, "view.log"},
        {kMenuInfo, "view.info"},
        {kMenuMarkers, "view.markers"},
        {kMenuCheck, "view.check"},
        {kMenuScript, "view.script"},
        {kMenuLighting, "view.lighting"},
        {kMenuFullHelp, "view.fullhelp"},
        {kMenuArmies, "view.armies"},
        {kMenuProperties, "view.properties"},
        {kMenuMaterialEditor, "view.material"},
        {kMenuParticleEditor, "view.particle"},
        {kMenuParticleBrowser, "view.particlebrowser"},
        {kMenuAdaptiveWindow, "view.adaptive"},
        {kMenuPanelsWhilePlaying, "view.panelsplaying"},
        {kMenuResetLayout, "view.resetlayout"},
        {kMenuImGuiDemo, "view.imguidemo"},
        {kMenuPlayStop, "play.toggle"},
        {kMenuSave, "file.save"},
        {kMenuSaveAs, "file.saveas"},
        {kMenuNew, "file.new"},
        {kMenuPackage, "file.package"},
        {kMenuOpen, "file.open"},
        {kMenuClearRecent, "file.recent.clear"},
        {kMenuUndo, "edit.undo"},
        {kMenuRedo, "edit.redo"},
        {kMenuDelete, "edit.delete"},
      };
      std::string id;
      for (const auto& [menuId, commandId] : kIds) {
        if (menuId == command) {
          id = commandId;
        }
      }
      if (id.empty() && command >= kMenuFirstRecent && command < kMenuFirstRecent + 10) {
        id = "file.recent." + std::to_string(command - kMenuFirstRecent);
      } else if (id.empty() && command >= kMenuFirstMap && command < kMenuFirstMap + mPlay.Maps().size()) {
        id = "play.map." + std::to_string(command - kMenuFirstMap);
      }
      if (id.empty()) {
        return;
      }
      const std::string why = mCommands.WhyNot(id);
      if (!why.empty()) {
        gpg::Logf("editor: %s can't run now: %s", id.c_str(), why.c_str());
        return;
      }
      (void)mCommands.Run(id);
    }

    void EditorApp::UpdateTitle()
    {
      mCommands.SetTitle("play.toggle", mPlay.Active() ? "Stop" : "Play");
      // Undo and Redo name their step (design §5); the status bar counts the selection.
      const char* const undo = mDocument.UndoStepName();
      const char* const redo = mDocument.RedoStepName();
      mCommands.SetTitle("edit.undo", undo != nullptr ? std::string("Undo ") + undo : std::string("Undo"));
      mCommands.SetTitle("edit.redo", redo != nullptr ? std::string("Redo ") + redo : std::string("Redo"));
      if (mShell != nullptr) {
        mShell->SetStatusSelection(mScene.Attached() ? mScene.SelectionText() : std::string());
      }
      std::wstring title = mBaseTitle;
      if (mPlay.Active() && !mPlay.Maps().empty()) {
        const std::size_t at = static_cast<std::size_t>(mPlay.Selected());
        title += L" - " + Widen(mPlay.StateText()) + L" " + Widen(mPlay.Titles()[at]) + L" (" +
          Widen(MapDisplayName(mPlay.Maps()[at])) + L")";
      }
      if (title != mShownTitle) {
        mShownTitle = title;
        ::SetWindowTextW(HandleOf(mGame.supcomFrame), title.c_str());
      }
    }

    bool OnViewportMessage(
      const HWND window,
      const UINT message,
      const WPARAM wParam,
      const LPARAM lParam
    )
    {
      return gEditorApp != nullptr && gEditorApp->HandleViewportMessage(window, message, wParam, lParam);
    }

    bool EditorViewOverPlay()
    {
      return gEditorApp != nullptr && gEditorApp->EditorViewOverPlay();
    }

    bool AskBeforeExit()
    {
      return gEditorApp != nullptr && gEditorApp->AskBeforeExit();
    }

    void OnMenuCommand(
      const UINT command
    )
    {
      if (gEditorApp != nullptr) {
        gEditorApp->HandleMenuCommand(command);
      }
    }

    int MenuIndexForKey(
      const char key
    )
    {
      return gEditorApp != nullptr ? gEditorApp->MenuForKey(key) : -1;
    }

    bool SessionActive()
    {
      return gEditorApp != nullptr && gEditorApp->SessionActive();
    }

    void EditorApp::Main()
    {
      UpdateTitle();
      // Stop, and the game's own way out of a session (its menu's exit, a defeat screen's "exit"), end the
      // session here, before CScApp::Main runs WLD_Frame: the game would go on to its main menu.
      mPlay.BeforeGameFrame();
      DriveOpens();
      // The opened map in the viewport while no play runs (a play's start sets the state off Inactive at once).
      const auto now = std::chrono::steady_clock::now();
      const float frameSeconds = std::chrono::duration<float>(now - mLastFrame).count();
      // A stall: the lines before this one in the log say what the editor was doing.
      if (frameSeconds > 0.33f && mFramesRun > 120) {
        gpg::Warnf(
          "editor: the editor stopped for %.2f s (frame %llu)",
          static_cast<double>(frameSeconds),
          static_cast<unsigned long long>(mFramesRun)
        );
      }
      ++mFramesRun;
      mLastFrame = now;
      // The editor's view in front of a running play, when asked for (F6 / the toolbar); a new play starts in the
      // game's.
      const bool playIdle = moho::WLD_GetFrameAction() == moho::EWldFrameAction::Inactive;
      if (playIdle) {
        mShell->EditorViewInPlay() = false;
      }
      // `/playeditorview <on>,<off>` (test runs, with /play): the editor's view that many seconds into the play, the
      // game's again at the second time (0: stays).
      {
        static double playingSince = -1.0;
        static bool onDone = false;
        static bool offDone = false;
        static bool againDone = false;
        const double now = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
        if (moho::WLD_GetFrameAction() == moho::EWldFrameAction::Playing) {
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/playeditorview", 1, &value) && !value.empty()) {
            playingSince = playingSince < 0.0 ? now : playingSince;
            double on = 0.0;
            double off = 0.0;
            double again = 0.0;
            (void)std::sscanf(value[0].c_str(), "%lf,%lf,%lf", &on, &off, &again);
            // The game's camera at each switch (it should be where it was left when the game's view comes back).
            const auto logGameCamera = [](const char* const when) {
              if (
                moho::CameraImpl* const camera = moho::CAM_GetManager()->GetCamera("WorldCamera"); camera != nullptr
              ) {
                const Wm3::Vector3f at = camera->GetTargetPosition();
                gpg::Logf(
                  "editor: the game's camera %s: at %.1f,%.1f, zoom %.1f",
                  when,
                  static_cast<double>(at.x),
                  static_cast<double>(at.z),
                  static_cast<double>(camera->CameraGetTargetZoom())
                );
              }
            };
            if (!onDone && now - playingSince >= on) {
              onDone = true;
              logGameCamera("before the editor's view");
              mShell->EditorViewInPlay() = true;
            }
            if (!offDone && off > 0.0 && now - playingSince >= off) {
              offDone = true;
              mShell->EditorViewInPlay() = false;
            }
            if (offDone && !againDone && again > 0.0 && now - playingSince >= again) {
              againDone = true;
              logGameCamera("back in the game's view");
              mShell->EditorViewInPlay() = true;
            }
          }
          // `/playlivetest` (test runs, with /playeditorview): in the editor's view, the commander selected, its state
          // logged as the Properties panel reads it, then an enhancement added, its health halved and a warp, and the
          // state logged again (WPE.43).
          if (moho::CFG_GetArgOption("/playlivetest", 0, nullptr) && mScene.OverPlay()) {
            static int step = 0;
            static double stepAt = 0.0;
            static std::uint32_t unitId = 0;
            const auto logInfo = [&](const char* const when) {
              LiveUnitInfo info;
              try {
                info = ReadLiveUnit(unitId);
              } catch (const std::exception& error) {
                gpg::Warnf("editor: live test: reading unit %u threw: %s", unitId, error.what());
              } catch (...) {
                gpg::Warnf("editor: live test: reading unit %u threw", unitId);
              }
              std::string toggles;
              for (const LiveUnitInfo::Toggle& t : info.toggles) {
                toggles += " " + ToggleName(t.cap) + "=" + (t.on ? "set" : "clear");
              }
              std::string has;
              for (const LiveUnitInfo::Enhancement& e : info.enhancements) {
                has += e.has ? " " + e.name : std::string();
              }
              float x = 0.0f, z = 0.0f;
              for (const LiveUnit& u : LiveUnits()) {
                if (u.id == unitId) {
                  x = u.x;
                  z = u.z;
                }
              }
              gpg::Logf(
                "editor: live test %s: %s %s army %d health %.0f/%.0f at %.1f,%.1f; %zu enhancements, has:%s; "
                "toggles:%s",
                when,
                info.blueprint.c_str(),
                info.name.c_str(),
                info.army,
                static_cast<double>(info.health),
                static_cast<double>(info.maxHealth),
                static_cast<double>(x),
                static_cast<double>(z),
                info.enhancements.size(),
                has.empty() ? " none" : has.c_str(),
                toggles.empty() ? " none" : toggles.c_str()
              );
              return info;
            };
            if (step == 0) {
              static bool listed = false;
              if (!listed) {
                listed = true;
                gpg::Logf(
                  "editor: live test: %zu units, the first %s",
                  mScene.LiveNow().size(),
                  mScene.LiveNow().empty() ? "-" : mScene.LiveNow().front().blueprint.c_str()
                );
              }
              bool found = false;
              for (const LiveUnit& u : mScene.LiveNow()) {
                // A commander (its blueprint ...0001); its entity id may well be 0 (army 0's first unit).
                if (u.blueprint.find("0001") != std::string::npos && !found) {
                  unitId = u.id;
                  found = true;
                }
              }
              if (found) {
                mScene.SelectLive({unitId});
                step = 1;
                stepAt = now + 1.0;
              }
            } else if (step == 1 && now >= stepAt) {
              gpg::Logf("editor: live test: reading unit %u", unitId);
              const LiveUnitInfo info = logInfo("before");
              for (const LiveUnitInfo::Enhancement& e : info.enhancements) {
                if (!e.has && e.prerequisite.empty()) {
                  LiveUnitDo(unitId, "u:CreateEnhancement('" + e.name + "')");
                  break;
                }
              }
              LiveUnitDo(unitId, "u:SetHealth(u, u:GetMaxHealth() * 0.5)");
              for (const LiveUnit& u : LiveUnits()) {
                if (u.id == unitId) {
                  LiveUnitWarp(unitId, u.x + 20.0f, u.z);
                }
              }
              step = 2;
              stepAt = now + 2.0;
            } else if (step == 2 && now >= stepAt) {
              (void)logInfo("after");
              step = 3;
            }
          }
          // `/playdecaltest` (test runs, with /playeditorview): in the editor's view, the map's first decal copied
          // beside the first commander, then the map's last decal moved 40 units, then both taken back as undo does;
          // the play's decals counted and looked up after each (WPE.49).
          if (
            moho::CFG_GetArgOption("/playdecaltest", 0, nullptr) && mScene.OverPlay() &&
            mScene.SessionMap() != nullptr && mDocument.Decals() != nullptr
          ) {
            static int step = 0;
            static EdDocument::DecalSnapshot original;
            static DecalState added;
            static DecalState moved;
            moho::IDecalManager* const play = mScene.SessionMap()->mTerrainRes->GetDecalManager();
            const auto inPlay = [play](const DecalState& state) {
              const std::string key = DecalKey(state);
              for (const DecalState& d : CaptureDecals(*play)) {
                if (DecalKey(d) == key) {
                  return true;
                }
              }
              return false;
            };
            if (step == 0 && play != nullptr) {
              for (const LiveUnit& u : mScene.LiveNow()) {
                if (u.blueprint.find("0001") != std::string::npos && step == 0) {
                  original = mDocument.DecalsNow();
                  if (original.empty()) {
                    step = 9;
                    gpg::Warnf("editor: decal test: the map has no decals");
                    break;
                  }
                  gpg::Logf(
                    "editor: decal test: %zu decals in the editor, %d in the play",
                    original.size(),
                    play->GetDecalCount()
                  );
                  added = original.front();
                  added.position[0] = u.x + 20.0f;
                  added.position[2] = u.z;
                  (void)AddDecal(*mDocument.Decals(), added);
                  mDocument.DecalsEdited(original);
                  const EdDocument::DecalSnapshot now = mDocument.DecalsNow();
                  added = now.back();
                  gpg::Logf(
                    "editor: decal test: one added at %.0f,%.0f: %d in the play, the new one there: %s",
                    static_cast<double>(added.position[0]),
                    static_cast<double>(added.position[2]),
                    play->GetDecalCount(),
                    inPlay(added) ? "yes" : "no"
                  );
                  step = 1;
                }
              }
            } else if (step == 1 && play != nullptr) {
              const EdDocument::DecalSnapshot before = mDocument.DecalsNow();
              EdDocument::DecalSnapshot after = before;
              DecalState& last = after[after.size() - 2]; // the map's own last decal (the test's is after it)
              const DecalState was = last;
              last.position[0] += 40.0f;
              moved = last;
              // As the editor's own decal moves do it: the decals set, then the edit recorded (which sends it to the
              // play).
              RestoreDecals(*mDocument.Decals(), after);
              mDocument.DecalsEdited(before);
              gpg::Logf(
                "editor: decal test: the map's decal %s moved 40: %d in the play, there at the old place: %s, at the "
                "new: %s",
                was.names[0].c_str(),
                play->GetDecalCount(),
                inPlay(was) ? "yes" : "no",
                inPlay(moved) ? "yes" : "no"
              );
              step = 2;
            } else if (step == 2 && play != nullptr) {
              mDocument.RestoreDecals(original);
              gpg::Logf(
                "editor: decal test: back to the map's own (undo's way): %d in the play, the added one there: %s, the "
                "moved one at "
                "its new place: %s",
                play->GetDecalCount(),
                inPlay(added) ? "yes" : "no",
                inPlay(moved) ? "yes" : "no"
              );
              step = 3;
            }
          }
          // `/playlooktest` (test runs, with /playeditorview): in the editor's view, the sun's colour made red, the
          // water raised 6 and stratum 4 painted beside the first commander; each read back from the play's map, and
          // the water from its sim (WPE.41).
          if (
            moho::CFG_GetArgOption("/playlooktest", 0, nullptr) && mScene.OverPlay() && mScene.SessionMap() != nullptr
          ) {
            static int step = 0;
            static double stepAt = 0.0;
            static std::uint32_t unitId = 0;
            static float x = 0.0f;
            static float z = 0.0f;
            moho::IWldTerrainRes* const play = mScene.SessionMap()->mTerrainRes;
            if (step == 0) {
              for (const LiveUnit& u : mScene.LiveNow()) {
                if (u.blueprint.find("0001") != std::string::npos && step == 0) {
                  unitId = u.id;
                  x = u.x + 30.0f;
                  z = u.z;
                  step = 1;
                  stepAt = now + 1.0;
                }
              }
            } else if (step == 1 && now >= stepAt && play != nullptr) {
              const Wm3::Vector3f sunBefore = play->GetSunColor();
              LightingState lighting = mDocument.LightingNow();
              lighting.sunColor[0] = 2.0f;
              lighting.sunColor[1] = 0.4f;
              lighting.sunColor[2] = 0.3f;
              mDocument.ApplyLighting(lighting);
              const Wm3::Vector3f sun = play->GetSunColor();
              gpg::Logf(
                "editor: look test: the play's sun colour %.2f,%.2f,%.2f -> %.2f,%.2f,%.2f",
                static_cast<double>(sunBefore.x),
                static_cast<double>(sunBefore.y),
                static_cast<double>(sunBefore.z),
                static_cast<double>(sun.x),
                static_cast<double>(sun.y),
                static_cast<double>(sun.z)
              );
              const float levelBefore = play->mMap != nullptr ? play->mMap->mWaterElevation : 0.0f;
              WaterState water = mDocument.WaterNow();
              water.elevation += 6.0f;
              water.deep += 6.0f;
              water.abyss += 6.0f;
              mDocument.ApplyWater(water);
              gpg::Logf(
                "editor: look test: the play's drawn water level %.2f -> %.2f",
                static_cast<double>(levelBefore),
                static_cast<double>(play->mMap != nullptr ? play->mMap->mWaterElevation : 0.0f)
              );
              mScene.TestLiveMask(x, z);
              step = 2;
              stepAt = now + 2.0;
            } else if (step == 2 && now >= stepAt) {
              // A point of open water on Seton's Clutch: the surface there is the water's level.
              LiveUnitDo(
                unitId,
                "LOG('editor: look test: the sim surface at 150,150 ' .. GetSurfaceHeight(150, 150) .. ', ground ' .. "
                "GetTerrainHeight(150, 150))"
              );
              step = 3;
            }
          }
          // `/playridgetest` (test runs, with /playeditorview; `/playnopathdirty` to compare): in the editor's view, a
          // steep ridge raised 35 units east of the first commander, 70 units long north to south; then the commander
          // ordered to a point 70 units east, and where it is logged every 2 s (WPE.47: the path clusters redone over
          // new ground).
          if (moho::CFG_GetArgOption("/playridgetest", 0, nullptr) && mScene.OverPlay()) {
            SetLiveHeightsNoPathDirty(moho::CFG_GetArgOption("/playnopathdirty", 0, nullptr));
            static int step = 0;
            static double stepAt = 0.0;
            static float x = 0.0f;
            static float z = 0.0f;
            static std::uint32_t unitId = 0;
            if (step == 0) {
              for (const LiveUnit& u : mScene.LiveNow()) {
                if (u.blueprint.find("0001") != std::string::npos && step == 0) {
                  unitId = u.id;
                  x = u.x;
                  z = u.z;
                  step = 1;
                  stepAt = now + 1.0;
                }
              }
            } else if (step == 1 && now >= stepAt) {
              // `/playridgeoff`: no ridge, the route the commander takes over the map as it is (the control).
              for (int k = -4; k <= 4 && !moho::CFG_GetArgOption("/playridgeoff", 0, nullptr); ++k) {
                (void)mScene.TestRaise(x + 35.0f, z + static_cast<float>(k) * 8.0f, 1.5f);
              }
              gpg::Logf(
                "editor: ridge test: a ridge at x %.0f from z %.0f to %.0f (path clusters %s)",
                static_cast<double>(x + 35.0f),
                static_cast<double>(z - 32.0f),
                static_cast<double>(z + 32.0f),
                moho::CFG_GetArgOption("/playnopathdirty", 0, nullptr) ? "left as they were" : "redone"
              );
              step = 2;
              stepAt = now + 2.0;
            } else if (step == 2 && now >= stepAt) {
              char lua[200];
              std::snprintf(
                lua,
                sizeof(lua),
                "IssueClearCommands({u}) IssueMove({u}, {%.1f, GetTerrainHeight(%.1f, %.1f), %.1f})",
                static_cast<double>(x + 70.0f),
                static_cast<double>(x + 70.0f),
                static_cast<double>(z),
                static_cast<double>(z)
              );
              LiveUnitDo(unitId, lua);
              step = 3;
              stepAt = now + 2.0;
            } else if (step >= 3 && step < 18 && now >= stepAt) {
              for (const LiveUnit& u : LiveUnits()) {
                if (u.id == unitId) {
                  gpg::Logf(
                    "editor: ridge test: %.0f s: the commander at %.1f,%.1f (%.1f east, %.1f off the line; target %.1f "
                    "east)",
                    static_cast<double>((step - 2) * 2),
                    static_cast<double>(u.x),
                    static_cast<double>(u.z),
                    static_cast<double>(u.x - x),
                    static_cast<double>(u.z - z),
                    70.0
                  );
                }
              }
              ++step;
              stepAt = now + 2.0;
            }
          }
          // `/playheighttest` (test runs, with /playeditorview): in the editor's view, a raise under the first
          // commander, then the sim's own terrain height there and the commander's height read through its Lua (WPE.40:
          // the play's sim takes it; WPE.47: the commander stands on the new ground).
          if (moho::CFG_GetArgOption("/playheighttest", 0, nullptr) && mScene.OverPlay()) {
            SetLiveHeightsNoReseat(moho::CFG_GetArgOption("/playnoreseat", 0, nullptr));
            static int step = 0;
            static double stepAt = 0.0;
            static float x = 0.0f;
            static float z = 0.0f;
            static std::uint32_t unitId = 0;
            if (step == 0) {
              for (const LiveUnit& u : mScene.LiveNow()) {
                if (u.blueprint.find("0001") != std::string::npos && step == 0) {
                  unitId = u.id;
                  x = u.x;
                  z = u.z;
                  step = 1;
                  stepAt = now + 1.0;
                }
              }
            } else if (step == 1 && now >= stepAt) {
              const moho::CHeightField* const edited =
                mDocument.Map() != nullptr ? mDocument.Map()->mTerrainRes->GetHeightField() : nullptr;
              const float before = edited != nullptr ? edited->GetElevation(x, z) : 0.0f;
              const bool raised = mScene.TestRaise(x, z, 1.0f);
              gpg::Logf(
                "editor: height test: raise at %.0f,%.0f %s; the editor's height %.2f -> %.2f",
                static_cast<double>(x),
                static_cast<double>(z),
                raised ? "made" : "changed nothing",
                static_cast<double>(before),
                static_cast<double>(edited != nullptr ? edited->GetElevation(x, z) : 0.0f)
              );
              step = 2;
              stepAt = now + 2.0;
            } else if (step == 2 && now >= stepAt) {
              char lua[160];
              std::snprintf(
                lua,
                sizeof(lua),
                "LOG(string.format('editor: height test: the sim reads %%.2f at %.0f,%.0f', GetTerrainHeight(%.1f, "
                "%.1f)))",
                static_cast<double>(x),
                static_cast<double>(z),
                static_cast<double>(x),
                static_cast<double>(z)
              );
              LiveUnitDo(unitId, lua);
              LiveUnitDo(
                unitId,
                "local p = u:GetPosition() LOG('editor: height test: the commander at y ' .. p[2] .. ', ground ' .. "
                "GetTerrainHeight(p[1], p[3]))"
              );
              step = 3;
            }
          }
        } else if (playIdle) {
          // Armed again only once the play is over (a play's other phases aren't its end).
          playingSince = -1.0;
          onDone = false;
          offDone = false;
          againDone = false;
        }
      }
      mScene.SetCursorInView(MouseOverView());
      {
        // FAF_GPU_PROFILE=<frames> lists the editor's own frame stages beside the render passes.
        const gpg::gal::RenderProfileScope profileScene("EdSceneUpdate");
        mScene.Update(
          frameSeconds,
          playIdle,
          mShell->EditorViewInPlay() && moho::WLD_GetFrameAction() == moho::EWldFrameAction::Playing
        );
      }
      KeepViewState();
      KeepSoundToFocus();
      mShell->Tools().SetModelsLoading(mScene.ModelsPending());

      if (mImGuiReady) {
        ApplyUiScale();
        ImGui_ImplWin32_NewFrame();
        FeedUiClicks();
        ImGui::NewFrame();
        FeedTestCommands();
        // `/browser`, `/vaultmap <name>` (test runs), with or without a map open.
        if (mBrowserArg) {
          mBrowserArg = false;
          mShell->Browser().Show();
          mShell->Browser().SetFilter(mBrowserFilterArg);
        }
        if (!mVaultMapArg.empty()) {
          mShell->Browser().Download(mVaultMapArg);
          mVaultMapArg.clear();
        }
        if (!mThumbDumpArg.empty() && ++mThumbDumpFrames % 30 == 0) {
          const std::size_t comma = mThumbDumpArg.find(',');
          std::string blueprint;
          if (
            comma != std::string::npos &&
            mPropThumbnails.Save(mThumbDumpArg.substr(0, comma), mThumbDumpArg.substr(comma + 1), blueprint)
          ) {
            gpg::Logf(
              "editor: thumbnail of %s saved to %s", blueprint.c_str(), mThumbDumpArg.substr(comma + 1).c_str()
            );
            mThumbDumpArg.clear();
          }
        }
        if (mFafLoginArg) {
          mFafLoginArg = false;
          mShell->Browser().ShowVault();
          mShell->Browser().Faf().Resume();
          if (mShell->Browser().Faf().GetState() == EdFafSession::State::LoggedOut) {
            mShell->Browser().Faf().StartLogin();
          }
        }
        if (!mVaultQueryArg.empty()) {
          int values[4] = {0, 0, 0, 0};
          std::size_t at = 0;
          for (int i = 0; i < 4 && at <= mVaultQueryArg.size(); ++i) {
            const std::size_t comma = mVaultQueryArg.find(',', at);
            values[i] = std::atoi(mVaultQueryArg.substr(at, comma - at).c_str());
            at = comma == std::string::npos ? mVaultQueryArg.size() + 1 : comma + 1;
          }
          mShell->Browser().SetFilters(values[0], values[1], values[2], values[3] != 0);
          mVaultQueryArg.clear();
        }
        if (!mVaultSearchArg.empty()) {
          mShell->Browser().AskSearch(mVaultSearchArg);
          mVaultSearchArg.clear();
        }
        if (!mOpenFolderArg.empty()) {
          mShell->Browser().OpenFromDisk(PathFromUtf8(mOpenFolderArg));
          mOpenFolderArg.clear();
        }
        if (mShell->Browser().TakeOpenFileAsk()) {
          const std::filesystem::path file = AskFile(
            HandleOf(mGame.supcomFrame),
            false,
            L"Map scenario (*_scenario.lua)\0*_scenario.lua\0",
            L"lua",
            L"Open a map from a folder: pick its _scenario.lua"
          );
          if (!file.empty()) {
            mShell->Browser().OpenFromDisk(file);
          }
        }
        // `/materialeditor` (test runs): the material editor open from the start.
        if (static bool asked = false; !asked) {
          asked = true;
          if (moho::CFG_GetArgOption("/materialeditor", 0, nullptr)) {
            mShell->ShowMaterialEditor() = true;
          }
          if (
            fa::vector<fa::string> filter; moho::CFG_GetArgOption("/particlebrowser", 1, &filter) && !filter.empty()
          ) {
            // `/particlebrowser <search>` (test runs): the browser open, its search set, the first match played.
            mShell->ShowParticleBrowser() = true;
            mShell->ParticleEditor().TestBrowse(filter[0].c_str());
          }
          if (fa::vector<fa::string> name; moho::CFG_GetArgOption("/particletemplate", 1, &name) && !name.empty()) {
            // `/particletemplate <name>` (test runs): one of FAF's effect templates opened as a graph.
            mShell->ShowParticleEditor() = true;
            (void)mShell->ParticleEditor().TestTemplate(name[0].c_str());
          }
          if (fa::vector<fa::string> kind; moho::CFG_GetArgOption("/particlenew", 1, &kind) && !kind.empty()) {
            mShell->ShowParticleEditor() = true;
            mShell->ParticleEditor().TestNew(kind[0].c_str());
          }
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/particleopen", 1, &file) && !file.empty()) {
            // `/particleopen <game path>` (test runs): the particle editor open on a game emitter.
            mShell->ShowParticleEditor() = true;
            (void)mShell->ParticleEditor().OpenGameEmitter(file[0].c_str());
          }
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/materialopen", 1, &file) && !file.empty()) {
            mShell->ShowMaterialEditor() = true;
            (void)mShell->MaterialEditor().OpenFile(std::filesystem::path(file[0].c_str()));
          }
          if (fa::vector<fa::string> type; moho::CFG_GetArgOption("/materialselect", 1, &type) && !type.empty()) {
            mShell->ShowMaterialEditor() = true;
            mShell->MaterialEditor().SelectFirst(type[0].c_str());
          }
          mShell->MaterialEditor().SetTerrainSource([this] {
            return mScene.TerrainHeights();
          });
        }
        {
          // A vault map's own folder keeps its graphs; the game's own maps (in its install folder) don't get any.
          const std::filesystem::path scmap = mDocument.MapDiskFile();
          const std::string vault = mDocument.VaultFolder().lexically_normal().string();
          const std::string folder = scmap.parent_path().lexically_normal().string();
          const bool inVault = !scmap.empty() && !vault.empty() && folder.size() > vault.size() &&
            _strnicmp(folder.c_str(), vault.c_str(), vault.size()) == 0;
          mShell->MaterialEditor().SetMapFolder(inVault ? scmap.parent_path() : std::filesystem::path());
          mShell->ParticleEditor().SetMapFolder(
            inVault ? scmap.parent_path() : std::filesystem::path(), inVault ? mDocument.FolderName() : std::string()
          );
          // The particle editor's effect plays in its own view (EdParticleViewport) while its windows show.
          mShell->ParticleEditor().Frame(mShell->ShowParticleEditor() || mShell->ShowParticleBrowser());
          if (std::string effect; mShell->ParticleEditor().TakePlaceAsk(effect) && mScene.Attached()) {
            mScene.PlaceEffect(effect);
          }
        }
        {
          const gpg::gal::RenderProfileScope profileShell("EdPanels");
          mShell->Draw();
        }
        SyncSettings();
        DrawSettings();
        DrawRecover();
        DrawUnsavedQuestion();
        DrawFind();
        DriveAutosave();
        // `/focuspanel <window>` (test runs): that panel in front, a while after the map opened (opening fronts Info).
        if (mFocusPanelFrames < 90 && mDocument.GetState() == EdDocument::State::Open) {
          if (
            fa::vector<fa::string> panel;
            ++mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/focuspanel", 1, &panel) && !panel.empty()
          ) {
            ImGui::SetWindowFocus(panel[0].c_str());
            gpg::Logf("editor: /focuspanel %s", panel[0].c_str());
          }
          // `/materiallive <slot>` and `/materialapply <slot>` (test runs): the material editor's result into a slot.
          if (
            fa::vector<fa::string> slot;
            mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/materiallive", 1, &slot) && !slot.empty()
          ) {
            mShell->MaterialEditor().TestLive(std::atoi(slot[0].c_str()));
          }
          if (
            fa::vector<fa::string> file;
            mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/particleswitch", 1, &file) && !file.empty()
          ) {
            // `/particleswitch <game path>` (test runs): the open effect taken as edited, then another opened (it asks
            // first).
            mShell->ShowParticleEditor() = true;
            mShell->ParticleEditor().TestOpenEdited(file[0].c_str());
          }
          if (
            fa::vector<fa::string> key;
            mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/adaptivewindow", 1, &key) && !key.empty()
          ) {
            // `/adaptivewindow <option key>` (test runs): the Adaptive Map window on that option.
            mShell->OpenAdaptiveWindow(key[0].c_str());
          }
          if (
            fa::vector<fa::string> spec;
            mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/adaptivepreview", 1, &spec) && !spec.empty()
          ) {
            // `/adaptivepreview <key>=<choice>,...[;<players>]` (test runs): the window's preview of a game on.
            mShell->TestAdaptivePreview(spec[0].c_str());
          }
          if (mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/texturepicker", 0, nullptr)) {
            // `/texturepicker` (test runs): the particle editor's next texture input opens its browser.
            mShell->ParticleEditor().TestTexturePicker();
          }
          if (
            fa::vector<fa::string> effect;
            mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/placeeffect", 1, &effect) && !effect.empty()
          ) {
            // `/placeeffect <game path>` (test runs): an effect decoration at the view's centre.
            mScene.PlaceEffect(effect[0].c_str());
          }
          if (
            fa::vector<fa::string> distance;
            mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/particleframe", 1, &distance) && !distance.empty()
          ) {
            // `/particleframe <distance>` (test runs): the view this close to its centre, where the particle preview
            // emits.
            float x = 0.0f;
            float y = 0.0f;
            float z = 0.0f;
            mScene.ViewTarget(x, y, z);
            mScene.FramePoint(x, z, static_cast<float>(std::atof(distance[0].c_str())));
          }
          if (
            fa::vector<fa::string> slot;
            mFocusPanelFrames == 80 && moho::CFG_GetArgOption("/materialapply", 1, &slot) && !slot.empty()
          ) {
            mShell->MaterialEditor().TestApply(std::atoi(slot[0].c_str()));
          }
        }
        switch (mShell->TakeCommand()) {
        case EdShell::Command::Save:
          SaveDocument();
          break;
        case EdShell::Command::Undo:
          (void)mScene.Undo();
          break;
        case EdShell::Command::Redo:
          (void)mScene.Redo();
          break;
        case EdShell::Command::None:
          break;
        }
        // The panels' keys run their commands too (the view's reach HandleViewportMessage): not the ones a text field
        // or the panels' keyboard navigation use themselves, and not in the material editor, which keeps its own.
        if (!mShell->MaterialEditor().Focused() && !mScene.ModalOn()) {
          if (
            const std::string chord = PanelChordPressed();
            !chord.empty() && !PanelsKeepChord(chord, ImGui::GetIO().WantTextInput)
          ) {
            (void)RunChord(chord, false);
          }
        }
        if (gComposite && mViewImage != 0) {
          const ImVec2 from(static_cast<float>(gViewRect.left), static_cast<float>(gViewRect.top));
          const ImVec2 to(static_cast<float>(gViewRect.right), static_cast<float>(gViewRect.bottom));
          ImGui::GetBackgroundDrawList()->AddImage(static_cast<ImTextureID>(EdImGuiRenderer::kGameViewImage), from, to);
        }
        {
          const gpg::gal::RenderProfileScope profilePanels("EdPanelsRender");
          ImGui::Render();
          // A frame whose heads were re-made isn't drawn: its draw lists hold the view's and the minimap's copies,
          // which the re-made context freed.
          if (!FitGameView()) {
            RenderPanels();
          }
        }
      }

      {
        const gpg::gal::RenderProfileScope profileGame("GameMain");
        mGame.Main();
      }
      CapBackgroundFrames();

      // Lua asked the app to quit (ExitApplication from a game menu) while the window stays open: that ends the
      // session, not the editor.
      if (!ShellGetApp().KeepGoing() && !gWindowClosing && !mShell->ExitRequested() && !mPlay.QuitRequested()) {
        ShellGetApp().SetKeepGoing();
        mPlay.Stop();
      }
      // Leaving: a sim held by the script debugger goes on, so it can end.
      if (gWindowClosing || mShell->ExitRequested()) {
        EdLuaDebugger::Get().Release();
      }
      if ((mShell->ExitRequested() || mPlay.QuitRequested()) && ShellGetApp().KeepGoing()) {
        gShellApp->ExitMainLoop();
      }
    }

    void EditorApp::ReadOpenCommandLine()
    {
      // `/roundtrip <folder>` (test runs): as /openall, and each map's save round trip into that folder.
      if (fa::vector<fa::string> folder; moho::CFG_GetArgOption("/roundtrip", 1, &folder) && !folder.empty()) {
        mRoundTripFolder = folder[0].c_str();
      }
      if (fa::vector<fa::string> folder; moho::CFG_GetArgOption("/saveas", 1, &folder) && !folder.empty()) {
        mSaveAsFolder = folder[0].c_str();
      }
      if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/heightexport", 1, &file) && !file.empty()) {
        mHeightExportFile = file[0].c_str();
      }
      mHeightDialog = moho::CFG_GetArgOption("/heightdialog", 0, nullptr);
      if (fa::vector<fa::string> layer; moho::CFG_GetArgOption("/masklayer", 1, &layer) && !layer.empty()) {
        mMaskLayerArg = std::atoi(layer[0].c_str()) - 1;
      }
      if (fa::vector<fa::string> frames; moho::CFG_GetArgOption("/roundtripframes", 1, &frames) && !frames.empty()) {
        mRoundTripAfter = std::max(1, std::atoi(frames[0].c_str()));
      }
      if (fa::vector<fa::string> prop; moho::CFG_GetArgOption("/proptool", 1, &prop) && !prop.empty()) {
        mPropToolArg = prop[0].c_str();
      }
      if (fa::vector<fa::string> tool; moho::CFG_GetArgOption("/tool", 1, &tool) && !tool.empty()) {
        mToolArg = std::atoi(tool[0].c_str());
      }
      if (fa::vector<fa::string> clicks; moho::CFG_GetArgOption("/uiclicks", 1, &clicks) && !clicks.empty()) {
        const std::string list = clicks[0].c_str();
        std::size_t at = 0;
        while (at < list.size()) {
          const std::size_t end = std::min(list.find(';', at), list.size());
          std::string point = list.substr(at, end - at);
          at = end + 1;
          // "w": a slot with no click, to wait half a second.
          if (point == "w") {
            mUiClicks.push_back({-1.0f, -1.0f, false});
            continue;
          }
          if (point.size() == 2 && point[0] == '^') {
            mUiClicks.push_back(
              {-1.0f, -1.0f, false, static_cast<char>(std::toupper(static_cast<unsigned char>(point[1])))}
            );
            continue;
          }
          const bool twice = !point.empty() && point[0] == 'd';
          const bool hover = !point.empty() && point[0] == 'h';
          if (twice || hover) {
            point.erase(0, 1);
          }
          const std::size_t comma = point.find(',');
          if (comma != std::string::npos) {
            UiClick click{
              static_cast<float>(std::atof(point.c_str())),
              static_cast<float>(std::atof(point.c_str() + comma + 1)),
              twice
            };
            click.hoverOnly = hover;
            mUiClicks.push_back(click);
          }
        }
      }
      if (fa::vector<fa::string> decal; moho::CFG_GetArgOption("/decaltool", 1, &decal) && !decal.empty()) {
        mDecalToolArg = decal[0].c_str();
      }
      if (fa::vector<fa::string> unit; moho::CFG_GetArgOption("/unittool", 1, &unit) && !unit.empty()) {
        mUnitToolArg = unit[0].c_str();
      }
      if (fa::vector<fa::string> water; moho::CFG_GetArgOption("/waterset", 1, &water) && !water.empty()) {
        mWaterSetArg = water[0].c_str();
      }
      if (fa::vector<fa::string> pick; moho::CFG_GetArgOption("/waterpick", 1, &pick) && !pick.empty()) {
        mWaterPickArg = pick[0].c_str();
      }
      // `/browser` shows the map browser; `/vaultmap <name>` downloads a vault map and opens it (test runs).
      if (moho::CFG_GetArgOption("/browser", 0, nullptr)) {
        mBrowserArg = true;
      }
      if (moho::CFG_GetArgOption("/nocomposite", 0, nullptr)) {
        gComposite = false;
        gpg::Logf("editor: /nocomposite: the 3D view shows through its own window");
      }
      // Composited, the cursor is never over the viewport's own window: the keys stay the view's when the game
      // thinks the mouse left it (user report: WASD didn't move the camera).
      moho::gViewportLeaveKeepsFocus = gComposite;
      mFafLoginArg = moho::CFG_GetArgOption("/faflogin", 0, nullptr);
      if (fa::vector<fa::string> query; moho::CFG_GetArgOption("/vaultquery", 1, &query) && !query.empty()) {
        mVaultQueryArg = query[0].c_str();
      }
      if (fa::vector<fa::string> search; moho::CFG_GetArgOption("/vaultsearch", 1, &search) && !search.empty()) {
        mVaultSearchArg = search[0].c_str();
        std::replace(mVaultSearchArg.begin(), mVaultSearchArg.end(), '+', ' ');
      }
      if (fa::vector<fa::string> dump; moho::CFG_GetArgOption("/thumbdump", 1, &dump) && !dump.empty()) {
        mThumbDumpArg = dump[0].c_str();
      }
      if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/openfolder", 1, &file) && !file.empty()) {
        mOpenFolderArg = file[0].c_str();
        std::replace(mOpenFolderArg.begin(), mOpenFolderArg.end(), '+', ' ');
      }
      if (fa::vector<fa::string> filter; moho::CFG_GetArgOption("/browserfilter", 1, &filter) && !filter.empty()) {
        mBrowserArg = true;
        mBrowserFilterArg = filter[0].c_str();
      }
      if (fa::vector<fa::string> vaultMap; moho::CFG_GetArgOption("/vaultmap", 1, &vaultMap) && !vaultMap.empty()) {
        mVaultMapArg = vaultMap[0].c_str();
      }
      if (fa::vector<fa::string> body; moho::CFG_GetArgOption("/waterbody", 1, &body) && !body.empty()) {
        mWaterBodyArg = body[0].c_str();
        std::replace(mWaterBodyArg.begin(), mWaterBodyArg.end(), '+', ' ');
      }
      if (fa::vector<fa::string> marker; moho::CFG_GetArgOption("/framemarker", 1, &marker) && !marker.empty()) {
        mFrameMarkerArg = marker[0].c_str();
        std::replace(mFrameMarkerArg.begin(), mFrameMarkerArg.end(), '+', ' '); // "Mass+08" for "Mass 08"
      }
      if (fa::vector<fa::string> type; moho::CFG_GetArgOption("/markertool", 1, &type) && !type.empty()) {
        mMarkerToolArg = type[0].c_str();
      }
      if (fa::vector<fa::string> area; moho::CFG_GetArgOption("/playablearea", 1, &area) && !area.empty()) {
        mPlayableAreaArg = area[0].c_str();
      }
      if (fa::vector<fa::string> shader; moho::CFG_GetArgOption("/shader", 1, &shader) && !shader.empty()) {
        mShaderArg = shader[0].c_str();
      }
      if (fa::vector<fa::string> slot; moho::CFG_GetArgOption("/browse", 1, &slot) && !slot.empty()) {
        mBrowseArg = std::atoi(slot[0].c_str());
      }
      if (fa::vector<fa::string> layer; moho::CFG_GetArgOption("/layer", 1, &layer) && !layer.empty()) {
        mLayerArg = layer[0].c_str();
      }
      if (fa::vector<fa::string> convert; moho::CFG_GetArgOption("/convertlayers", 1, &convert) && !convert.empty()) {
        mConvertLayersArg = convert[0].c_str();
      }
      if (fa::vector<fa::string> mask; moho::CFG_GetArgOption("/masktest", 1, &mask) && !mask.empty()) {
        mMaskTestArg = mask[0].c_str();
      }
      if (fa::vector<fa::string> test; moho::CFG_GetArgOption("/brushtest", 1, &test) && !test.empty()) {
        mBrushTestArg = test[0].c_str();
      }
      if (fa::vector<fa::string> follow; moho::CFG_GetArgOption("/followtest", 1, &follow) && !follow.empty()) {
        mFollowTestArg = follow[0].c_str();
      }
      if (fa::vector<fa::string> arrange; moho::CFG_GetArgOption("/arrangetest", 1, &arrange) && !arrange.empty()) {
        mArrangeTestArg = arrange[0].c_str();
      }
      if (fa::vector<fa::string> find; moho::CFG_GetArgOption("/findtest", 1, &find) && !find.empty()) {
        mFindTestArg = find[0].c_str();
      }
      if (fa::vector<fa::string> modal; moho::CFG_GetArgOption("/modaltest", 1, &modal) && !modal.empty()) {
        mModalTestArg = modal[0].c_str();
      }
      // Lake shores drawn from the ground's own height (the engine's finer water map), unless `/nowaterhires`.
      moho::CON_Execute(moho::CFG_GetArgOption("/nowaterhires", 0, nullptr) ? "ren_WaterHiRes 0" : "ren_WaterHiRes 2");
      if (fa::vector<fa::string> mask; moho::CFG_GetArgOption("/watermasktest", 1, &mask) && !mask.empty()) {
        mWaterMaskTestArg = mask[0].c_str();
      }
      if (fa::vector<fa::string> env; moho::CFG_GetArgOption("/envtest", 1, &env) && !env.empty()) {
        mEnvTestArg = env[0].c_str();
      }
      if (fa::vector<fa::string> look; moho::CFG_GetArgOption("/looktest", 1, &look) && !look.empty()) {
        mLookTestArg = look[0].c_str();
      }
      if (fa::vector<fa::string> fill; moho::CFG_GetArgOption("/filltest", 1, &fill) && !fill.empty()) {
        mFillTestArg = fill[0].c_str();
      }
      if (fa::vector<fa::string> open; moho::CFG_GetArgOption("/findopen", 1, &open) && !open.empty()) {
        mFindOpenArg = open[0].c_str();
      }
      if (fa::vector<fa::string> slope; moho::CFG_GetArgOption("/slopeview", 1, &slope) && !slope.empty()) {
        mSlopeViewArg = slope[0].c_str();
      }
      if (moho::CFG_GetArgOption("/typesfromlayers", 0, nullptr)) {
        fa::vector<fa::string> value;
        mTypesFromLayersArg = moho::CFG_GetArgOption("/typesfromlayers", 1, &value) && !value.empty()
          ? std::string(value[0].c_str())
          : std::string("all");
      }
      if (fa::vector<fa::string> op; moho::CFG_GetArgOption("/layerop", 1, &op) && !op.empty()) {
        mLayerOpArg = op[0].c_str();
      }
      if (fa::vector<fa::string> theme; moho::CFG_GetArgOption("/texset", 1, &theme) && !theme.empty()) {
        mThemeArg = theme[0].c_str();
      }
      if (fa::vector<fa::string> recipe; moho::CFG_GetArgOption("/recipe", 1, &recipe) && !recipe.empty()) {
        mRecipeArg = std::max(0, std::atoi(recipe[0].c_str()));
      }
      if (fa::vector<fa::string> gen; moho::CFG_GetArgOption("/maskgen", 1, &gen) && !gen.empty()) {
        mMaskGenArg = gen[0].c_str();
      }
      if (fa::vector<fa::string> rule; moho::CFG_GetArgOption("/maskrule", 1, &rule) && !rule.empty()) {
        mMaskRuleArg = rule[0].c_str();
      }
      if (fa::vector<fa::string> mode; moho::CFG_GetArgOption("/brush", 1, &mode) && !mode.empty()) {
        mBrushModeArg = std::atoi(mode[0].c_str());
      }
      if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/stamp", 1, &file) && !file.empty()) {
        mStampArg = file[0].c_str();
      }
      if (fa::vector<fa::string> spec; moho::CFG_GetArgOption("/newmap", 1, &spec) && !spec.empty()) {
        mNewMapSpec = spec[0].c_str();
      }
      if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/heightimport", 1, &file) && !file.empty()) {
        mHeightImportFile = file[0].c_str();
      }
      if (fa::vector<fa::string> check; moho::CFG_GetArgOption("/symcheck", 1, &check) && !check.empty()) {
        // `<mode>[x<turns>][:repair]`, one argument (the option reader takes whatever follows it).
        const std::string spec = check[0].c_str();
        mSymCheckMode = std::atoi(spec.c_str());
        if (const std::size_t x = spec.find('x'); x != std::string::npos) {
          mSymCheckTurns = std::max(2, std::atoi(spec.c_str() + x + 1));
        }
        mSymCheckRepair = spec.find(":repair") != std::string::npos;
      }
      // With `/open`, the round trip runs on that one map once it has been drawn for a while (its terrain
      // finalized, normal map built), then the editor closes.
      if (!mRoundTripFolder.empty() && moho::CFG_GetArgOption("/open", 1, nullptr)) {
        mRoundTripShown = true;
      }
      // `/openall` (test runs): every map opened in turn, then a summary, then the editor closes.
      if (moho::CFG_GetArgOption("/openall", 0, nullptr) || (!mRoundTripFolder.empty() && !mRoundTripShown)) {
        mOpenAll = true;
        gpg::Logf("editor: opening all %zu maps", mPlay.Maps().size());
        return;
      }
      // `/open <map folder>`: that map opened at start.
      fa::vector<fa::string> args;
      if (!moho::CFG_GetArgOption("/open", 1, &args) || args.empty()) {
        return;
      }
      std::string wanted = args[0].c_str();
      std::transform(wanted.begin(), wanted.end(), wanted.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      const std::vector<std::string>& maps = mPlay.Maps();
      for (std::size_t i = 0; i < maps.size(); ++i) {
        std::string folder = MapDisplayName(maps[i]);
        std::transform(folder.begin(), folder.end(), folder.begin(), [](const unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
        if (folder == wanted) {
          mPlay.Select(static_cast<int>(i));
          const bool started = mDocument.Open(maps[i]);
          (started ? gpg::Logf : gpg::Warnf)(
            "editor: /open %s: %s %s", args[0].c_str(), started ? "opening" : "can't open", maps[i].c_str()
          );
          return;
        }
      }
      gpg::Warnf("editor: /open %s: no such map", args[0].c_str());
    }

    void EditorApp::DriveMaterialEditor()
    {
      EdMaterialEditor& material = mShell->MaterialEditor();
      if (!mScene.Attached()) {
        material.SetSlotNames({});
        return;
      }
      static const char* const kSlotLabels[10] = {
        "Lower",
        "Stratum 1",
        "Stratum 2",
        "Stratum 3",
        "Stratum 4",
        "Stratum 5",
        "Stratum 6",
        "Stratum 7",
        "Stratum 8",
        "Upper"
      };
      std::vector<std::string> names;
      const std::vector<EdTools::LayerSlot> slots = mScene.LayerSlots();
      for (std::size_t s = 0; s < slots.size() && s < 10; ++s) {
        names.push_back(std::string(kSlotLabels[s]) + "  " + LayerTextureName(slots[s].albedo));
      }
      material.SetSlotNames(std::move(names));
      for (int slot = -1; material.TakeRestore(slot);) {
        mScene.RestoreLayerSlot(slot);
      }
      if (EdMaterialEditor::LiveImage live; material.TakeLive(live)) {
        mScene.PreviewLayerSlot(live.slot, live.albedo, live.normals, 10.0f);
      }
      if (EdMaterialEditor::Bake bake; material.TakeApply(bake)) {
        ApplyMaterial(bake);
      }
    }

    void EditorApp::MapTexturesUpdate()
    {
      EdTools& tools = mShell->Tools();
      const std::vector<EdTools::LayerSlot> slots = mScene.LayerSlots();
      if (slots.size() != 10) {
        return;
      }
      int askedKind = 0;
      EdTools::MapTextureOp op = EdTools::MapTextureOp::None;
      if (tools.TakeMapTextureAsk(askedKind, op)) {
        const int kind = askedKind;
        const MapTextureKind which = static_cast<MapTextureKind>(std::clamp(kind, 0, kMapTextureKinds - 1));
        if (op == EdTools::MapTextureOp::Make) {
          MakeMapTexture(which);
          // `/mapwide <kind>,stale` (test runs): the ground raised after it, so the row goes out of date.
          if (tools.MapTextureRaiseAfter()) {
            const float middle = static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ)) * 0.5f;
            gpg::Logf(
              "editor: /mapwide: the ground raised after Make: %s",
              mScene.TestRaise(middle, middle, 1.0f) ? "done" : "not done"
            );
          }
          // `/mapwide <kind>,make,export=<file>` (test runs): the texture just made, exported.
          if (!tools.MapTextureFile().empty()) {
            TransferMapTexture(which, true, tools.MapTextureFile());
          }
        } else if (op == EdTools::MapTextureOp::Clear) {
          ClearMapTexture(which);
        } else {
          TransferMapTexture(which, op == EdTools::MapTextureOp::Export, tools.MapTextureFile());
        }
        mMapTextureFrame = 0; // the rows at once
      }
      // The rows, once a second (the heights' checksum is the costly part, and only when one was made here).
      if (mMapTextureFrame++ % 60 != 0) {
        return;
      }
      const std::string shader = mScene.TerrainShader();
      const float mapSize = static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ));
      std::uint64_t sum = 0;
      bool summed = false;
      for (int kind = 0; kind < kMapTextureKinds; ++kind) {
        const bool fromPaint = kind >= 2;
        const MapTextureTarget target = MapTextureTargetOf(shader, static_cast<MapTextureKind>(kind));
        EdTools::MapTextureRow& row = tools.MapTextureState(kind);
        row = {};
        row.available = target.Valid();
        row.shared = target.pack == MapTexturePack::Light301;
        if (!row.available) {
          continue;
        }
        const EdTools::LayerSlot& slot = slots[static_cast<std::size_t>(target.slot)];
        const std::string& path = target.normalsPath ? slot.normals : slot.albedo;
        row.present = !path.empty() && MapWideOn(slot.albedoSize, mapSize);
        const auto made = mMapTexturesMade.find(LowerPath(path));
        row.made = row.present && made != mMapTexturesMade.end();
        if (row.made) {
          if (!summed) {
            sum = HeightsChecksum();
            summed = true;
          }
          row.stale = (fromPaint ? PaintChecksum(sum) : sum) != made->second;
          if (row.stale && !mMapTexturesStale[kind]) {
            gpg::Logf(
              "editor: map-wide texture %s is out of date: the %s changed since it was made",
              path.c_str(),
              fromPaint ? "heights or the paint" : "heights"
            );
          }
        }
        mMapTexturesStale[kind] = row.stale;
        const std::size_t slash = path.find_last_of('/');
        const std::string leaf = slash == std::string::npos ? path : path.substr(slash + 1);
        row.state = !row.present
          ? (path.empty() ? std::string(
                              fromPaint ? "Not made: Make draws it from the paint."
                                        : "Not made: Make draws it from the heights, the sun and the sea."
                            )
                          : "Off: " + leaf + " is in the slot, but its size isn't above the map's.")
          : row.stale ? std::string(
                          fromPaint ? "Out of date: the heights or the paint changed since it was made. Remake it."
                                    : "Out of date: the heights changed since it was made. Remake it."
                        )
          : row.made
          ? std::string(fromPaint ? "From the paint \xC2\xB7 up to date" : "From the heights \xC2\xB7 up to date")
          : "Made elsewhere: " + leaf;
      }
    }

    std::uint64_t EditorApp::HeightsChecksum()
    {
      const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
      std::uint64_t hash = 1469598103934665603ULL;
      if (terrain != nullptr) {
        for (const float h : terrain->heights) {
          std::uint32_t bits = 0;
          std::memcpy(&bits, &h, sizeof(bits));
          hash = (hash ^ bits) * 1099511628211ULL;
        }
      }
      return hash;
    }

    std::uint64_t EditorApp::PaintChecksum(
      const std::uint64_t heights
    )
    {
      std::uint64_t hash = heights;
      const EdDocument::MaskGrid& masks = mDocument.Masks();
      for (const std::uint64_t texel : masks.texels) {
        hash = (hash ^ texel) * 1099511628211ULL;
      }
      for (const EdTools::LayerSlot& slot : mScene.LayerSlots()) {
        for (const char c : slot.albedo) {
          hash = (hash ^ static_cast<unsigned char>(c)) * 1099511628211ULL;
        }
      }
      return hash;
    }

    std::string EditorApp::LowerPath(
      std::string path
    )
    {
      for (char& c : path) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return path;
    }

    bool EditorApp::MakeMapTexture(
      const MapTextureKind kind
    )
    {
      const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
      const std::filesystem::path scmap = mDocument.MapDiskFile();
      const MapTextureTarget target = MapTextureTargetOf(mScene.TerrainShader(), kind);
      if (terrain == nullptr || scmap.empty() || !target.Valid()) {
        PostStatusMessage(
          target.Valid() ? "No map folder to write the texture into" : "This shader draws no map-wide textures"
        );
        return false;
      }
      // The map's own sun and sea.
      MapTextureOptions options;
      const LightingState lighting = mDocument.LightingNow();
      SunAnglesOf(lighting.sunDirection, options.azimuth, options.altitude);
      options.altitude = std::clamp(options.altitude, 5.0f, 85.0f);
      const WaterState water = mDocument.WaterNow();
      options.waterOn = water.enabled;
      options.waterElevation = water.elevation;
      options.abyss = water.abyss;
      const int mapSize = std::max(terrain->width, terrain->height) - 1;
      const int size = std::clamp(mapSize, 64, 1024);
      const auto started = std::chrono::steady_clock::now();
      std::vector<float> rgba;
      std::string error;
      const bool fromPaint = target.pack == MapTexturePack::Specular || target.pack == MapTexturePack::Macro;
      std::string kinds;
      bool made = false;
      if (fromPaint) {
        // The paint: what each layer shows, its colour and its kind of ground.
        const EdDocument::MaskGrid& masks = mScene.ReadMasks();
        const std::vector<EdTools::LayerSlot> slots = mScene.LayerSlots();
        const ShaderProfile profile = ShaderProfileOf(mScene.TerrainShader());
        MapPaint paint;
        EdTextureLibrary& library = mShell->Tools().Library();
        for (int layer = 0; layer <= 8 && layer < static_cast<int>(slots.size()); ++layer) {
          MapPaintLayer& entry = paint.layers[static_cast<std::size_t>(layer)];
          const std::string& albedo = slots[static_cast<std::size_t>(layer)].albedo;
          entry.textured = !albedo.empty();
          if (!entry.textured) {
            continue;
          }
          float rgb[3] = {0.4f, 0.4f, 0.4f};
          const bool read = library.AverageColour(albedo, rgb);
          entry.colour = {rgb[0], rgb[1], rgb[2]};
          entry.kind = GroundKindOf(albedo, read ? rgb : nullptr).kind;
          kinds += (kinds.empty() ? "" : ", ") + std::to_string(layer) + " " + GroundKindName(entry.kind);
        }
        if (masks.texels.empty()) {
          error = "the map's masks couldn't be read";
        } else {
          VisibleWeights(masks.texels.data(), masks.width, masks.height, profile.painted, profile.remapped, paint);
          made = MakePaintTexture(
            terrain->heights,
            terrain->width,
            terrain->height,
            paint,
            target,
            options,
            MapPaintOptions{},
            size,
            rgba,
            error
          );
        }
      } else {
        made = faf::editor::MakeMapTexture(
          terrain->heights, terrain->width, terrain->height, target, options, size, rgba, error
        );
      }
      if (!made) {
        PostStatusMessage("The map-wide texture wasn't made: " + error);
        gpg::Warnf("editor: map-wide texture: %s", error.c_str());
        return false;
      }
      TexImage image;
      image.Reset(size, 4, 0.0f);
      image.data = std::move(rgba);
      std::vector<std::uint8_t> dds;
      if (!EncodeDds(image, DdsKind::Bgra, dds, error)) {
        PostStatusMessage("The map-wide texture wasn't encoded: " + error);
        return false;
      }
      const char* const file = target.pack == MapTexturePack::Normal7 ? "map_normals.dds"
        : target.pack == MapTexturePack::Info7                        ? "map_lighting.dds"
        : target.pack == MapTexturePack::Specular                     ? "map_specular.dds"
        : target.pack == MapTexturePack::Macro                        ? "map_macro.dds"
                                                                      : "map_normals_lighting.dds";
      const std::filesystem::path folder = scmap.parent_path() / "env" / "layers";
      std::error_code ec;
      std::filesystem::create_directories(folder, ec);
      {
        std::ofstream out(folder / file, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(dds.data()), static_cast<std::streamsize>(dds.size()));
        if (!out) {
          PostStatusMessage("Can't write " + (folder / file).string());
          return false;
        }
      }
      const std::string game = "/maps/" + mDocument.FolderName() + "/env/layers/" + file;
      EdTools::LayerSlot value = mScene.LayerSlots()[static_cast<std::size_t>(target.slot)];
      if (target.normalsPath) {
        value.normals = game;
      } else {
        value.albedo = game;
      }
      // Above the map's size: the shader reads the slot as map-wide data.
      value.albedoSize = static_cast<float>(mapSize + 1);
      value.normalsSize = static_cast<float>(mapSize + 1);
      mScene.ChangeLayerSlot(target.slot, value);
      mMapTexturesMade[LowerPath(game)] = fromPaint ? PaintChecksum(HeightsChecksum()) : HeightsChecksum();
      std::string read;
      const bool seen = ReadGameFile(game, read) && read.size() == dds.size();
      const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
      gpg::Logf(
        "editor: map-wide texture %s made in %.1f s: %dx%d, sun %.0f / %.0f, slot %d%s%s",
        game.c_str(),
        seconds,
        size,
        size,
        static_cast<double>(options.azimuth),
        static_cast<double>(options.altitude),
        target.slot,
        target.normalsPath ? " (its normal map)" : "",
        seen ? "" : "; the game's files don't see it yet"
      );
      if (fromPaint) {
        gpg::Logf("editor: map-wide texture %s: the layers' kinds of ground: %s", game.c_str(), kinds.c_str());
      }
      PostStatusMessage(std::string("Made ") + file + (fromPaint ? " from the paint" : " from the heights"));
      return true;
    }

    bool EditorApp::MaskGenContextOf(
      const std::vector<MaskGenRule>& rules,
      MaskGenContext& context,
      std::string& error
    )
    {
      const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
      if (terrain == nullptr || terrain->width < 2) {
        error = "no terrain";
        return false;
      }
      context.heights = std::make_shared<field::Grid>(terrain->width, terrain->height, 1.0f, 0.0f, 0.0f);
      context.heights->v = terrain->heights;
      const WaterState water = mDocument.WaterNow();
      context.water = water.elevation;
      const bool readsPaint = std::any_of(rules.begin(), rules.end(), [](const MaskGenRule& rule) {
        return rule.enabled && (rule.type == "layer" || rule.type == "free_above" || rule.type == "near_layer");
      });
      if (readsPaint) {
        const EdDocument::MaskGrid& masks = mScene.ReadMasks();
        if (!masks.texels.empty()) {
          MaskLayerFields(
            masks.texels.data(),
            masks.width,
            masks.height,
            static_cast<float>(terrain->width - 1),
            RemappedStrata(mScene.TerrainShader()),
            context
          );
        }
      }
      return true;
    }

    void EditorApp::MaskGenUpdate()
    {
      EdTools& tools = mShell->Tools();
      const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
      // `/maskgen <preset>,<layer>[,add|sub][,free]` (test runs): that starting point written into the layer.
      if (!mMaskGenArg.empty() && terrain != nullptr && ++mMaskGenFrames == 150) {
        const std::string arg = std::exchange(mMaskGenArg, {});
        const std::size_t comma = arg.find(',');
        tools.AskGenPreset(arg.substr(0, comma));
        EdTools::MaskGenTarget& target = tools.GenTarget();
        target.layer = comma == std::string::npos ? 1 : std::clamp(std::atoi(arg.c_str() + comma + 1), 1, 8);
        target.mode = arg.find(",add") != std::string::npos ? MaskWriteMode::AddTo
          : arg.find(",sub") != std::string::npos           ? MaskWriteMode::SubtractFrom
                                                            : MaskWriteMode::Replace;
        target.takeAway = arg.find(",free") != std::string::npos;
        tools.AskGenApply();
      }
      if (std::string id; tools.TakeGenPresetAsk(id) && terrain != nullptr && !terrain->heights.empty()) {
        const auto [low, high] = std::minmax_element(terrain->heights.begin(), terrain->heights.end());
        tools.SetGenRules(MaskPresetRules(id, *low, *high));
        gpg::Logf("editor: mask generator: starting point %s, %zu rules", id.c_str(), tools.GenRules().size());
      }
      if (tools.TakeGenApply()) {
        const EdTools::MaskGenTarget target = tools.GenTarget();
        MaskGenContext context;
        field::Grid mask;
        std::string error;
        const auto started = std::chrono::steady_clock::now();
        if (
          !MaskGenContextOf(tools.GenRules(), context, error) ||
          !EvaluateMaskRules(context, tools.GenRules(), mask, error)
        ) {
          PostStatusMessage("The mask wasn't made: " + error);
          gpg::Warnf("editor: mask generator: %s", error.c_str());
        } else {
          float before[8] = {};
          (void)mScene.MaskCoverage(before);
          std::string message;
          const int changed =
            mScene.WriteGeneratedMask(mask, target.layer, target.mode, target.strength, target.takeAway, message);
          float after[8] = {};
          (void)mScene.MaskCoverage(after);
          PostStatusMessage(message);
          gpg::Logf(
            "editor: mask generator: %s in %.2f s; layer %d covers %.1f %% (was %.1f %%)",
            message.c_str(),
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count(),
            target.layer,
            static_cast<double>(after[target.layer - 1] * 100.0f),
            static_cast<double>(before[target.layer - 1] * 100.0f)
          );
          (void)changed;
        }
      }
      // The preview: when the rules changed and the section is open, a moment after the last change.
      if (!tools.GenSectionOpen() || tools.GenRevision() == mMaskGenEvaluated) {
        mMaskGenWait = 0;
        return;
      }
      if (++mMaskGenWait < 8 || ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        return;
      }
      mMaskGenWait = 0;
      mMaskGenEvaluated = tools.GenRevision();
      if (mMaskGenImage != 0) {
        EdImGuiRenderer::DestroyImage(mMaskGenImage);
        mMaskGenImage = 0;
      }
      if (tools.GenRules().empty()) {
        tools.SetGenPreview(0, 0.0f, "Pick a starting point or add a rule.");
        return;
      }
      MaskGenContext context;
      field::Grid mask;
      std::string error;
      if (
        !MaskGenContextOf(tools.GenRules(), context, error) ||
        !EvaluateMaskRules(context, tools.GenRules(), mask, error)
      ) {
        tools.SetGenPreview(0, 0.0f, error);
        return;
      }
      // A small picture: the mask in red over a dark ground, as the map shows it from above.
      constexpr int kSide = 160;
      std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kSide) * kSide);
      const float span = static_cast<float>(context.heights->w - 1);
      double sum = 0.0;
      for (const float value : mask.v) {
        sum += std::clamp(value, 0.0f, 1.0f);
      }
      for (int y = 0; y < kSide; ++y) {
        for (int x = 0; x < kSide; ++x) {
          const float m = std::clamp(
            SampleField(
              mask, (static_cast<float>(x) + 0.5f) / kSide * span, (static_cast<float>(y) + 0.5f) / kSide * span
            ),
            0.0f,
            1.0f
          );
          const auto lerp = [m](const int from, const int to) {
            return static_cast<std::uint32_t>(static_cast<float>(from) + (static_cast<float>(to - from)) * m);
          };
          // BGRA: from the panel's dark grey to red.
          pixels[static_cast<std::size_t>(y) * kSide + static_cast<std::size_t>(x)] =
            0xFF000000u | (lerp(0x2A, 0xF0) << 16) | (lerp(0x2E, 0x40) << 8) | lerp(0x34, 0x40);
        }
      }
      mMaskGenImage = EdImGuiRenderer::CreateImage(kSide, kSide, pixels.data());
      tools.SetGenPreview(
        mMaskGenImage, mask.v.empty() ? 0.0f : static_cast<float>(sum / static_cast<double>(mask.v.size())), {}
      );
    }

    int EditorApp::TexturePixels(
      const std::string& path
    )
    {
      const std::string key = LowerPath(path);
      if (const auto found = mTexturePixels.find(key); found != mTexturePixels.end()) {
        return found->second;
      }
      std::string bytes;
      const int width = !path.empty() && ReadGameFile(path, bytes) ? DdsWidth(bytes.data(), bytes.size()) : 0;
      mTexturePixels[key] = width;
      if (width > 0) {
        mGameFiles[key] = true;
      }
      return width;
    }

    bool EditorApp::GameFileExists(
      const std::string& path
    )
    {
      const std::string key = LowerPath(path);
      if (const auto found = mGameFiles.find(key); found != mGameFiles.end()) {
        return found->second;
      }
      std::string bytes;
      const bool exists = ReadGameFile(path, bytes);
      mGameFiles[key] = exists;
      if (exists) {
        mTexturePixels[key] = DdsWidth(bytes.data(), bytes.size());
      }
      return exists;
    }

    void EditorApp::TexturesUpdate()
    {
      EdTools& tools = mShell->Tools();
      if (mScene.TerrainHeights() == nullptr) {
        return;
      }
      // `/texset <index>[,try|,back]` (test runs): that set applied (or tried, or tried and taken back).
      if (!mThemeArg.empty() && ++mThemeArgFrames == 150) {
        tools.SetThemeIndex(std::clamp(std::atoi(mThemeArg.c_str()), 0, static_cast<int>(TextureThemes().size()) - 1));
        tools.AskTheme(
          mThemeArg.find(",try") != std::string::npos || mThemeArg.find(",back") != std::string::npos
            ? EdTools::ThemeOp::Try
            : EdTools::ThemeOp::Apply
        );
      }
      if (!mThemeArg.empty() && mThemeArgFrames == 240 && mThemeArg.find(",back") != std::string::npos) {
        tools.AskTheme(EdTools::ThemeOp::Back);
        mThemeArg.clear();
      }
      // `/slopeview ...` and `/typesfromlayers` (test runs).
      if (!mFollowTestArg.empty() && !mScene.ModelsPending() && ++mD2gFrames >= 150) {
        mScene.TestFollow(std::exchange(mFollowTestArg, {}));
      }
      if (!mArrangeTestArg.empty() && !mScene.ModelsPending() && ++mArrangeFrames >= 150) {
        mScene.TestArrange(std::exchange(mArrangeTestArg, {}));
      }
      if (!mModalTestArg.empty() && !mScene.ModelsPending() && ++mModalFrames >= 150) {
        mScene.TestModal(std::exchange(mModalTestArg, {}));
      }
      if (!mFillTestArg.empty() && !mScene.ModelsPending() && ++mFillFrames >= 150) {
        mScene.TestFill(std::exchange(mFillTestArg, {}));
      }
      if (!mFindTestArg.empty() && !mScene.ModelsPending() && ++mFindFrames >= 150) {
        mScene.TestFind(std::exchange(mFindTestArg, {}));
      }
      if (!mFindOpenArg.empty() && !mScene.ModelsPending() && ++mFindFrames >= 150) {
        mFindChoice = std::atoi(std::exchange(mFindOpenArg, {}).c_str());
        mFindAsk = true;
      }
      if ((!mSlopeViewArg.empty() || !mTypesFromLayersArg.empty()) && ++mD2gFrames == 120) {
        if (!mSlopeViewArg.empty()) {
          EdTools::SlopeView& slope = tools.SlopeSettings();
          std::vector<std::string> parts;
          for (std::size_t at = 0; at <= mSlopeViewArg.size();) {
            const std::size_t comma = std::min(mSlopeViewArg.find(',', at), mSlopeViewArg.size());
            parts.push_back(mSlopeViewArg.substr(at, comma - at));
            at = comma + 1;
          }
          slope.buildings = !parts.empty() && parts[0] == "buildings";
          if (parts.size() > 1) {
            (slope.buildings ? slope.skirt : slope.footprint) = std::clamp(std::atoi(parts[1].c_str()), 1, 16);
          }
          std::size_t limitAt = 2;
          if (slope.buildings && parts.size() > 2 && (parts[2] == "ring" || parts[2] == "area")) {
            slope.ring = parts[2] == "ring";
            limitAt = 3;
          }
          if (parts.size() > limitAt) {
            (!slope.buildings ? slope.unitLimit
               : slope.ring   ? slope.ringLimit
                              : slope.areaLimit) = static_cast<float>(std::atof(parts[limitAt].c_str()));
          }
          tools.SetShowSlope(true);
          mSlopeViewArg.clear();
        }
        if (!mTypesFromLayersArg.empty()) {
          tools.AskTypesFromLayers(mTypesFromLayersArg.find("only") != std::string::npos);
          mTypesFromLayersArg.clear();
        }
      }
      std::array<int, 9> layerTypes{};
      bool onlyDefault = false;
      if (tools.TakeTypesFromLayers(layerTypes, onlyDefault)) {
        const std::array<int, 9>& types = layerTypes;
        std::string message;
        const int changed = mScene.TerrainTypesFromTextures(types, onlyDefault, message);
        PostStatusMessage(changed < 0 ? message : "Terrain types from the textures: " + message);
        std::string list;
        for (std::size_t layer = 0; layer < types.size(); ++layer) {
          list += (layer == 0 ? "" : " ") + std::to_string(types[layer]);
        }
        gpg::Logf(
          "editor: terrain types from the textures (layer types %s%s): %s",
          list.c_str(),
          onlyDefault ? ", Default cells only" : "",
          message.c_str()
        );
      }
      // `/layerop <slot>,<item>` (test runs): after the optimal tiles are known (a second in).
      if (!mLayerOpArg.empty() && ++mLayerOpFrames == 120) {
        const std::size_t comma = mLayerOpArg.find(',');
        const int slot = std::atoi(mLayerOpArg.c_str());
        const std::string item = comma == std::string::npos ? std::string() : mLayerOpArg.substr(comma + 1);
        float before[8] = {};
        (void)mScene.MaskCoverage(before);
        gpg::Logf(
          "editor: /layerop %s: %s (layer %d covered %.1f %%)",
          mLayerOpArg.c_str(),
          tools.RunLayerMenuItem(slot, item) ? "asked" : "refused",
          slot,
          slot >= 1 && slot <= 8 ? static_cast<double>(before[slot - 1] * 100.0f) : 0.0
        );
        mLayerOpArg.clear();
      }
      const std::vector<EdTools::LayerSlot> slots = mScene.LayerSlots();
      const ShaderProfile profile = ShaderProfileOf(mScene.TerrainShader());
      const bool biplanar = profile.summary.find("biplanar") != std::string::npos;
      // The Upper layer takes a macrotexture only where the shader lays it over the ground.
      const bool upperOverlay = MapTextureTargetOf(mScene.TerrainShader(), MapTextureKind::Macro).Valid();
      const TextureTheme& theme = TextureThemes()[static_cast<std::size_t>(
        std::clamp(tools.ThemeIndex(), 0, static_cast<int>(TextureThemes().size()) - 1)
      )];
      const auto themeSlots = [&] {
        return ThemeSlots(theme, profile.painted, biplanar, upperOverlay, [this](const std::string& path) {
          return GameFileExists(path);
        }, [this](const std::string& path) {
          return TexturePixels(path);
        });
      };
      const EdTools::ThemeOp op = tools.TakeThemeOp();
      switch (op) {
      case EdTools::ThemeOp::Try:
      case EdTools::ThemeOp::Apply: {
        const bool trying = op == EdTools::ThemeOp::Try;
        std::vector<std::pair<int, LayerSettings>> layers;
        std::vector<std::pair<int, LayerSettings>> before;
        EdTextureLibrary& library = tools.Library();
        for (const ThemeSlot& s : themeSlots()) {
          // The normal map that pairs with the texture in the library.
          std::string normals;
          for (const LayerTexture& t : library.Textures()) {
            if (LowerPath(t.path) == LowerPath(s.albedo)) {
              normals = t.normals;
              break;
            }
          }
          layers.push_back({s.slot, LayerSettings{s.albedo, normals, s.size, s.size}});
          if (static_cast<std::size_t>(s.slot) < slots.size()) {
            const EdTools::LayerSlot& now = slots[static_cast<std::size_t>(s.slot)];
            before.push_back({s.slot, LayerSettings{now.albedo, now.normals, now.albedoSize, now.normalsSize}});
          }
        }
        const int changed = mScene.ApplyLayerSettings({}, layers);
        if (trying) {
          mThemeBefore = std::move(before);
        }
        // Apply keeps at once; Try keeps the layers before until Keep or Back.
        mThemeTrying = trying && changed > 0;
        gpg::Logf("editor: texture set %s: %d layers changed (%zu given)", theme.id, changed, layers.size());
        PostStatusMessage(std::string("Texture set ") + theme.label + ": " + std::to_string(changed) + " layers");
        mThemePreviewFor = -1;
        break;
      }
      case EdTools::ThemeOp::Keep:
        mThemeTrying = false;
        mThemeBefore.clear();
        gpg::Logf("editor: texture set kept");
        break;
      case EdTools::ThemeOp::Back: {
        const int changed = mScene.ApplyLayerSettings({}, mThemeBefore);
        mThemeTrying = false;
        mThemeBefore.clear();
        gpg::Logf("editor: texture set taken back: %d layers as before", changed);
        PostStatusMessage("Back to the textures before");
        break;
      }
      case EdTools::ThemeOp::None:
        break;
      }
      // Once a second while the Layers panel is shown: each slot's optimal tile, and what the picked set gives.
      if (!tools.LayersPanelShown() || mTexturesFrame++ % 60 != 0) {
        return;
      }
      const auto measured = std::chrono::steady_clock::now();
      std::array<float, 10> tiles{};
      for (std::size_t slot = 0; slot < slots.size() && slot < tiles.size(); ++slot) {
        const std::string& albedo = slots[slot].albedo;
        if (!albedo.empty()) {
          tiles[slot] = TileForPixels(TexturePixels(albedo));
        }
      }
      tools.SetOptimalTiles(tiles);
      if (mThemePreviewFor != tools.ThemeIndex() || mThemeShaderFor != mScene.TerrainShader()) {
        mThemePreviewFor = tools.ThemeIndex();
        mThemeShaderFor = mScene.TerrainShader();
        std::vector<std::string> preview;
        for (const ThemeSlot& s : themeSlots()) {
          char line[160];
          std::snprintf(
            line,
            sizeof(line),
            "%s\t%s\t%s\t%.1f",
            s.slot == 0     ? "Base"
              : s.slot == 9 ? "Upper"
                            : std::to_string(s.slot).c_str(),
            s.slot == 0     ? "base"
              : s.slot == 9 ? "macro"
                            : GroundKindName(s.kind),
            LayerTextureName(s.albedo).c_str(),
            static_cast<double>(s.size)
          );
          preview.emplace_back(line);
        }
        mThemePreviewLines = std::move(preview);
      }
      tools.SetThemeState(mThemeTrying, mThemePreviewLines);
      // The widths are read once per texture (whole files from the game's archives); say so when that takes long.
      if (
        const double took = std::chrono::duration<double>(std::chrono::steady_clock::now() - measured).count();
        took > 0.2
      ) {
        gpg::Logf(
          "editor: texture widths and the set's preview took %.2f s (%zu textures known)", took, mTexturePixels.size()
        );
      }
    }

    void EditorApp::RecipesUpdate()
    {
      EdTools& tools = mShell->Tools();
      const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
      if (terrain == nullptr) {
        return;
      }
      // `/recipe <style>` (test runs): that style painted over the map.
      if (mRecipeArg >= 0 && ++mRecipeArgFrames == 150) {
        tools.SetRecipeStyle(std::exchange(mRecipeArg, -1));
        tools.AskRecipeApply();
        mRecipeFrame = 0;
      }
      const bool apply = tools.TakeRecipeApply();
      if (!apply && (!tools.RecipesOpen() || mRecipeFrame++ % 60 != 0)) {
        return;
      }
      // Each layer's kind: its texture's name and average colour, or what the panel chose.
      const std::vector<EdTools::LayerSlot> slots = mScene.LayerSlots();
      const ShaderProfile profile = ShaderProfileOf(mScene.TerrainShader());
      std::array<GroundKind, 9> detected{};
      std::array<std::string, 9> names;
      std::array<bool, 9> textured{};
      EdTextureLibrary& library = tools.Library();
      for (int layer = 0; layer <= 8 && layer < static_cast<int>(slots.size()); ++layer) {
        const std::string& albedo = slots[static_cast<std::size_t>(layer)].albedo;
        if (albedo.empty()) {
          continue;
        }
        textured[static_cast<std::size_t>(layer)] = true;
        names[static_cast<std::size_t>(layer)] = LayerTextureName(albedo);
        float rgb[3] = {};
        detected[static_cast<std::size_t>(layer)] =
          GroundKindOf(albedo, library.AverageColour(albedo, rgb) ? rgb : nullptr).kind;
      }
      tools.SetRecipeDetected(detected, names, profile.painted);
      if (!apply) {
        return;
      }
      const auto started = std::chrono::steady_clock::now();
      std::array<GroundKind, 9> kinds = detected;
      for (std::size_t layer = 0; layer < kinds.size(); ++layer) {
        const int chosen = tools.RecipeOverrides()[layer];
        if (chosen >= 0) {
          kinds[layer] = static_cast<GroundKind>(chosen);
        }
      }
      const RecipePlan plan =
        PlanRecipe(kinds, textured, profile.painted, profile.summary.find("biplanar") != std::string::npos);
      MaskGenContext context;
      std::string error;
      if (!MaskGenContextOf({}, context, error)) {
        PostStatusMessage("The recipe wasn't painted: " + error);
        return;
      }
      const WaterState water = mDocument.WaterNow();
      const RecipeStats stats = RecipeStatsOf(terrain->heights, water.elevation, water.enabled);
      std::vector<RecipeRole> roles;
      std::map<int, field::Grid> target;
      std::array<float, 9> shares{};
      std::string message;
      if (
        !RecipeRoles(context, plan, stats, tools.RecipeSettings(), tools.RecipeStyle(), roles, error) ||
        !ResolveRecipe(context, plan, roles, tools.RecipeSettings(), tools.RecipeStyle(), target, error) ||
        mScene.WriteRecipeMasks(target, textured, plan.cap, shares, message) < 0
      ) {
        const std::string why = error.empty() ? message : error;
        PostStatusMessage("The recipe wasn't painted: " + why);
        gpg::Warnf("editor: stratum recipe: %s", why.c_str());
        return;
      }
      // What each kind shows now.
      std::string summary;
      for (const GroundKind kind : RecipeOrder()) {
        float share = 0.0f;
        for (const int layer : plan.byKind[static_cast<std::size_t>(kind)]) {
          share += shares[static_cast<std::size_t>(layer)];
        }
        if (!plan.byKind[static_cast<std::size_t>(kind)].empty()) {
          char part[64];
          std::snprintf(
            part,
            sizeof(part),
            "%s%s %.0f %%",
            summary.empty() ? "" : ", ",
            GroundKindName(kind),
            static_cast<double>(share * 100.0f)
          );
          summary += part;
        }
      }
      const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
      const std::string style = RecipeStyles()[static_cast<std::size_t>(tools.RecipeStyle())].name;
      tools.SetRecipeResult("Painted (" + style + "): " + summary + ". " + message + ".");
      PostStatusMessage("Painted the map with the recipe: " + message);
      gpg::Logf(
        "editor: stratum recipe %s in %.2f s: %s; %s; layers outside the recipe %zu, beyond the shader %zu",
        style.c_str(),
        seconds,
        summary.c_str(),
        message.c_str(),
        plan.unknown.size(),
        plan.beyond.size()
      );
    }

    void EditorApp::TransferMapTexture(
      const MapTextureKind kind,
      const bool exporting,
      const std::string& testFile
    )
    {
      const MapTextureTarget target = MapTextureTargetOf(mScene.TerrainShader(), kind);
      const std::filesystem::path scmap = mDocument.MapDiskFile();
      if (!target.Valid() || scmap.empty()) {
        PostStatusMessage("No map-wide slot or no map folder");
        gpg::Warnf("editor: map-wide texture: no slot for this shader or no map folder");
        return;
      }
      EdTools::LayerSlot value = mScene.LayerSlots()[static_cast<std::size_t>(target.slot)];
      const std::string current = target.normalsPath ? value.normals : value.albedo;
      const wchar_t* const filter = L"DirectDraw surface (*.dds)\0*.dds\0All files\0*.*\0";
      std::filesystem::path file = testFile.empty()
        ? AskFile(
            HandleOf(mGame.supcomFrame),
            exporting,
            filter,
            L"dds",
            exporting ? L"Export the map-wide texture" : L"Import a map-wide texture"
          )
        : PathFromUtf8(testFile);
      if (file.empty()) {
        return;
      }
      if (exporting) {
        std::string bytes;
        if (current.empty() || !ReadGameFile(current, bytes)) {
          PostStatusMessage("The slot has no texture to export");
          gpg::Warnf("editor: map-wide texture: slot %d has no texture to export", target.slot);
          return;
        }
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        gpg::Logf(
          "editor: map-wide texture %s exported to %s (%zu bytes)", current.c_str(), file.string().c_str(), bytes.size()
        );
        PostStatusMessage(out ? "Exported " + file.filename().string() : "Can't write " + file.string());
        return;
      }
      // Import: a DDS as it is (its packing is the shader's), copied into the map's folder.
      std::ifstream in(file, std::ios::binary);
      const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      if (bytes.size() < 128 || bytes.compare(0, 4, "DDS ") != 0) {
        PostStatusMessage(file.filename().string() + " isn't a DDS file");
        gpg::Warnf("editor: map-wide texture: %s isn't a DDS file (%zu bytes)", file.string().c_str(), bytes.size());
        return;
      }
      const std::filesystem::path folder = scmap.parent_path() / "env" / "layers";
      std::error_code ec;
      std::filesystem::create_directories(folder, ec);
      std::string name = file.filename().string();
      {
        std::ofstream out(folder / name, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (!out) {
          PostStatusMessage("Can't write " + (folder / name).string());
          return;
        }
      }
      const std::string game = "/maps/" + mDocument.FolderName() + "/env/layers/" + name;
      if (target.normalsPath) {
        value.normals = game;
      } else {
        value.albedo = game;
      }
      const float mapSize = static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ));
      value.albedoSize = mapSize + 1.0f;
      value.normalsSize = mapSize + 1.0f;
      mScene.ChangeLayerSlot(target.slot, value);
      mMapTexturesMade.erase(LowerPath(game));
      mMapTextureFrame = 0;
      gpg::Logf(
        "editor: map-wide texture imported from %s as %s (slot %d)", file.string().c_str(), game.c_str(), target.slot
      );
      PostStatusMessage("Imported " + name);
    }

    void EditorApp::ClearMapTexture(
      const MapTextureKind kind
    )
    {
      const MapTextureTarget target = MapTextureTargetOf(mScene.TerrainShader(), kind);
      if (!target.Valid()) {
        return;
      }
      EdTools::LayerSlot value = mScene.LayerSlots()[static_cast<std::size_t>(target.slot)];
      if (target.normalsPath) {
        value.normals.clear();
      } else {
        value.albedo.clear();
      }
      value.albedoSize = 4.0f;
      value.normalsSize = 4.0f;
      mScene.ChangeLayerSlot(target.slot, value);
      gpg::Logf(
        "editor: map-wide texture cleared from slot %d%s", target.slot, target.normalsPath ? " (its normal map)" : ""
      );
    }

    void EditorApp::ApplyMaterial(
      const EdMaterialEditor::Bake& bake
    )
    {
      EdMaterialEditor& material = mShell->MaterialEditor();
      const std::filesystem::path scmap = mDocument.MapDiskFile();
      if (scmap.empty() || bake.slot < 0 || bake.slot > 9) {
        material.SetStatus("Apply: no map folder to write into.");
        return;
      }
      // <map>/env/layers/<graph>_albedo.dds (and _normals.dds), named in the game's files under the map's folder.
      std::string base;
      for (const char c : bake.name) {
        base += (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '-')
          ? static_cast<char>(std::tolower(static_cast<unsigned char>(c)))
          : '_';
      }
      const std::filesystem::path folder = scmap.parent_path() / "env" / "layers";
      std::error_code ec;
      std::filesystem::create_directories(folder, ec);
      const auto write = [&](const std::string& file, const std::vector<std::uint8_t>& bytes) {
        std::ofstream out(folder / file, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        return static_cast<bool>(out);
      };
      const std::string gameFolder = "/maps/" + mDocument.FolderName() + "/env/layers/";
      EdTools::LayerSlot value = mScene.LayerSlots()[static_cast<std::size_t>(bake.slot)];
      if (!write(base + "_albedo.dds", bake.albedo)) {
        material.SetStatus("Apply: can't write " + (folder / (base + "_albedo.dds")).string());
        return;
      }
      value.albedo = gameFolder + base + "_albedo.dds";
      if (!bake.normals.empty()) {
        if (!write(base + "_normals.dds", bake.normals)) {
          material.SetStatus("Apply: can't write " + (folder / (base + "_normals.dds")).string());
          return;
        }
        value.normals = gameFolder + base + "_normals.dds";
      }
      if (value.albedoSize <= 1.0f) {
        value.albedoSize = 10.0f;
        value.normalsSize = 10.0f;
      }
      mScene.RestoreLayerSlot(bake.slot);
      mScene.ChangeLayerSlot(bake.slot, value);
      // The game's files must see the new file for the terrain (and Play) to load it.
      std::string read;
      const bool seen = ReadGameFile(value.albedo, read) && read.size() == bake.albedo.size();
      gpg::Logf(
        "editor: material %s applied to slot %d: %s (%zu bytes)%s",
        bake.name.c_str(),
        bake.slot,
        value.albedo.c_str(),
        bake.albedo.size(),
        seen ? "" : "; the game's files don't see it yet"
      );
      if (!seen) {
        mScene.PreviewLayerSlot(bake.slot, bake.albedo, bake.normals, 10.0f);
      }
      std::string status = "Applied to the slot: " + value.albedo;
      if (bake.mask != nullptr && bake.slot >= 1 && bake.slot <= 8) {
        std::string message;
        status +=
          mScene.SetMaskLayer(bake.slot - 1, *bake.mask, message) ? "; the stratum's mask painted" : "; " + message;
      }
      material.SetStatus(status);
    }

    void EditorApp::SaveDocument()
    {
      std::string message;
      // A look being tried isn't saved: the map's own is written, then the tried one put back on the map.
      std::optional<EdDocument::LookEnvironment> tried;
      if (mLookOriginal.has_value()) {
        tried = mDocument.LookEnvironmentNow();
        mDocument.ApplyLookEnvironment(*mLookOriginal);
        gpg::Logf("editor: saving without the look being tried (%s)", mLookTriedName.c_str());
      }
      const bool saved = mDocument.Save(message);
      if (tried.has_value()) {
        mDocument.ApplyLookEnvironment(*tried);
      }
      if (saved) {
        gpg::Logf("editor: %s", message.c_str());
        PostStatusMessage("Saved " + mDocument.FolderName());
        // Saved: its autosave is behind it now.
        if (!mAutosaveRoot.empty()) {
          RemoveAutosave(mAutosaveRoot / mDocument.FolderName());
          mRecoverable = ListAutosaves(mAutosaveRoot);
        }
      } else {
        gpg::Warnf("editor: %s", message.c_str());
      }
    }

    void EditorApp::StartResize(
      const EdShell::ResizeRequest& request
    )
    {
      const auto fail = [this](const std::string& why) {
        gpg::Warnf("editor: resize: %s", why.c_str());
        PostStatusMessage("Resize: " + why);
        mResize.reset();
      };
      if (mResize.has_value()) {
        fail("a resize is still going");
        return;
      }
      if (mDocument.GetState() != EdDocument::State::Open || !mScene.Attached()) {
        fail("open a map first");
        return;
      }
      PendingResize r;
      const ResizeOptions& o = request.options;
      r.geometry = MakeResizeGeometry(o);
      std::error_code ec;
      r.dir = std::filesystem::temp_directory_path(ec) / "FafEditor" / "resize";
      std::filesystem::create_directories(r.dir, ec);
      std::string message;
      std::string error;
      // The heights: written, read, resized, written again for the new map to read.
      HeightImage image;
      if (
        !mScene.ExportHeights(r.dir / "heights_old.png", 0, 1.0f, message) ||
        !ReadHeightImage(r.dir / "heights_old.png", 0, 0, image, error)
      ) {
        fail("the heights couldn't be read: " + message + error);
        return;
      }
      const auto pad = static_cast<std::uint16_t>(std::clamp(std::lround(o.padLevel * 128.0f), 0L, 65535L));
      const HeightImage heights = ResizeImage(image, r.geometry, o.newWidth + 1, o.newDepth + 1, o.padEdge, pad);
      if (!WriteHeightImage(r.dir / "heights.png", heights, error)) {
        fail("the heights couldn't be written: " + error);
        return;
      }
      // The eight strata's masks alike (the mask grid at its own scale, padded with the edge or nothing).
      for (int layer = 0; layer < 8; ++layer) {
        const std::filesystem::path old = r.dir / ("mask" + std::to_string(layer) + "_old.png");
        HeightImage mask;
        if (!mScene.ExportMaskLayer(layer, old, message) || !ReadHeightImage(old, 0, 0, mask, error)) {
          continue; // (a map without masks yet)
        }
        r.maskWidth =
          std::max(2, static_cast<int>(std::lround(static_cast<double>(mask.width) * o.newWidth / o.oldWidth)));
        r.maskHeight =
          std::max(2, static_cast<int>(std::lround(static_cast<double>(mask.height) * o.newDepth / o.oldDepth)));
        const HeightImage resized = ResizeImage(mask, r.geometry, r.maskWidth, r.maskHeight, o.padEdge, 0);
        (void)WriteHeightImage(r.dir / ("mask" + std::to_string(layer) + ".png"), resized, error);
      }
      r.shader = mScene.TerrainShader();
      r.layers = mScene.LayerSettingsNow();
      r.look = mDocument.LookEnvironmentNow();
      // Props moved (the file's record anew, its scale kept), those outside dropped.
      const EdDocument::PropSnapshot props = mDocument.PropsNow();
      for (std::size_t i = 0; i < props.entries.size(); ++i) {
        moho::CWldPropEntry entry = props.entries[i];
        float nx = 0.0f;
        float nz = 0.0f;
        if (!ResizePoint(r.geometry, entry.mTransform.pos_.x, entry.mTransform.pos_.z, nx, nz)) {
          ++r.report.propsDropped;
          continue;
        }
        entry.mTransform.pos_.x = nx;
        entry.mTransform.pos_.z = nz;
        PropRecord record = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
        if (i < props.records.size()) {
          for (int k = 12; k < 15; ++k) {
            record.values[k] = props.records[i].values[k];
          }
        }
        entry.mTransform = record.loaded;
        r.props.entries.push_back(entry);
        r.props.records.push_back(record);
        ++r.report.propsKept;
      }
      // Decals moved (and stretched with a scale), those outside dropped.
      for (DecalState decal : mDocument.DecalsNow()) {
        float nx = 0.0f;
        float nz = 0.0f;
        if (!ResizePoint(r.geometry, decal.position[0], decal.position[2], nx, nz)) {
          ++r.report.decalsDropped;
          continue;
        }
        decal.position[0] = nx;
        decal.position[2] = nz;
        decal.scale[0] *= r.geometry.fx;
        decal.scale[2] *= r.geometry.fz;
        decal.index = -1;
        r.decals.push_back(decal);
        ++r.report.decalsKept;
      }
      r.save = ResizeSaveText(mDocument.SaveData().Text(), r.geometry, r.report, error);
      if (r.save.empty()) {
        fail("the save file couldn't be read: " + error);
        return;
      }
      r.script = mDocument.Script();
      for (const ScenarioField& field : ScenarioFields()) {
        std::string value;
        if (ReadScenarioField(mDocument.Scenario(), field.key, value)) {
          r.fields.emplace_back(field.key, value);
        }
      }
      r.teams = mDocument.Teams();
      r.extraArmies = mDocument.ExtraArmies();
      r.factions = ReadSlotFactions(mDocument.Scenario());
      // The new folder: the engine's empty map of the new size, its start positions replaced in FinishResize.
      NewMapSettings settings;
      settings.folder = request.folder;
      settings.title = request.folder;
      settings.size = request.widthIndex;
      settings.sizeZ = request.depthIndex == request.widthIndex ? -1 : request.depthIndex;
      settings.players = std::clamp(static_cast<int>(mDocument.Armies().size()), 1, 16);
      if (!mDocument.CreateNew(settings, message)) {
        fail(message);
        return;
      }
      gpg::Logf(
        "editor: resize to %d x %d (%s) into %s: %s",
        o.newWidth,
        o.newDepth,
        o.mode == ResizeMode::Scale ? "scale" : "canvas",
        request.folder.c_str(),
        r.report.Text().c_str()
      );
      r.folder = request.folder;
      mResize = std::move(r);
    }

    bool EditorApp::RegeneratePreview(
      std::string& message
    )
    {
      if (mDocument.GetState() != EdDocument::State::Open || !mScene.Attached()) {
        message = "Open a map first.";
        return false;
      }
      std::error_code ec;
      const std::filesystem::path dir = std::filesystem::temp_directory_path(ec) / "FafEditor";
      std::filesystem::create_directories(dir, ec);
      const std::filesystem::path file = dir / "preview_heights.png";
      HeightImage heights;
      std::string error;
      if (!mScene.ExportHeights(file, 0, 1.0f, message) || !ReadHeightImage(file, 0, 0, heights, error)) {
        message = "The preview needs the heights: " + message + error;
        return false;
      }
      PreviewOptions options;
      const EdDocument::LookEnvironment look = mDocument.LookEnvironmentNow();
      options.water = look.water.enabled;
      options.waterLevel = look.water.elevation;
      // Resources first, start positions on top (as the lobby draws them).
      for (int pass = 0; pass < 2; ++pass) {
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          float x = 0.0f;
          float y = 0.0f;
          float z = 0.0f;
          if (!MarkerPosition(marker, x, y, z)) {
            continue;
          }
          const std::string type = MarkerTypeOf(marker);
          const bool start = marker.name.rfind("ARMY_", 0) == 0;
          if (pass == 0 && type == "Mass") {
            options.dots.push_back({x, z, 0xFF7CE03Cu, 1.5f});
          } else if (pass == 0 && type == "Hydrocarbon") {
            options.dots.push_back({x, z, 0xFFFFC832u, 2.5f});
          } else if (pass == 1 && start) {
            options.dots.push_back({x, z, 0xFFFFFFFFu, 3.0f});
          }
        }
      }
      const MapFacts& facts = mDocument.Facts();
      const float width = static_cast<float>(facts.sizeX > 0 ? facts.sizeX : heights.width - 1);
      const float depth = static_cast<float>(facts.sizeZ > 0 ? facts.sizeZ : heights.height - 1);
      mDocument.SetPreviewRecord(PreviewRecord(width, depth, PreviewPixels(heights, width, depth, options)));
      message = "Drew the lobby preview anew (" + std::to_string(options.dots.size()) +
        " start positions and resources on it); saving the map writes it";
      return true;
    }

    void EditorApp::FinishResize()
    {
      PendingResize& r = *mResize;
      std::string message;
      if (!mScene.ImportHeights(r.dir / "heights.png", 1.0f, message)) {
        gpg::Warnf("editor: resize: %s", message.c_str());
      }
      for (int layer = 0; layer < 8; ++layer) {
        const std::filesystem::path mask = r.dir / ("mask" + std::to_string(layer) + ".png");
        std::error_code ec;
        if (std::filesystem::exists(mask, ec) && !mScene.ImportMaskLayer(layer, mask, message)) {
          gpg::Warnf("editor: resize: %s", message.c_str());
        }
      }
      std::vector<std::pair<int, LayerSettings>> layers;
      for (std::size_t i = 0; i < r.layers.size(); ++i) {
        layers.emplace_back(static_cast<int>(i), r.layers[i]);
      }
      (void)mScene.ApplyLayerSettings(r.shader, layers);
      mDocument.ApplyLookEnvironment(r.look);
      mDocument.RestoreProps(r.props); // (the scene shows them once the map opens again below)
      mDocument.RestoreDecals(r.decals);
      mDocument.Script() = r.script;
      mDocument.SetTeams(r.teams);
      mDocument.SetExtraArmies(r.extraArmies);
      for (const auto& [key, value] : r.fields) {
        bool text = true;
        for (const ScenarioField& field : ScenarioFields()) {
          if (key == field.key) {
            text = field.text;
          }
        }
        (void)mDocument.SetScenarioField(key, value, text);
      }
      if (!r.factions.empty()) {
        (void)mDocument.SetSlotFactions(r.factions);
      }
      mDocument.SetModified(true);
      if (std::string why; !RegeneratePreview(why)) {
        gpg::Warnf("editor: resize: %s", why.c_str());
      }
      SaveDocument();
      // The moved markers, areas and units: the save file written over the new map's (its own start positions).
      if (const std::string& savePath = mDocument.Facts().savePath; !savePath.empty()) {
        const std::filesystem::path file =
          mDocument.VaultFolder() / "maps" / r.folder / savePath.substr(savePath.find_last_of('/') + 1);
        std::ofstream out(file, std::ios::binary);
        out.write(r.save.data(), static_cast<std::streamsize>(r.save.size()));
        if (!out) {
          gpg::Warnf("editor: resize: can't write %s", file.string().c_str());
        }
      }
      const std::string scenario = r.scenario;
      const std::string report = r.report.Text();
      mResize.reset();
      // Opened again from its files: everything as the game will read it.
      (void)mDocument.Open(scenario);
      gpg::Logf("editor: resized: %s", report.c_str());
      PostStatusMessage("Resized: " + report);
    }

    namespace
    {
      /** A Windows file dialog for one kind of file; empty when cancelled. */
      std::filesystem::path AskFile(
        const HWND owner,
        const bool save,
        const wchar_t* const filter,
        const wchar_t* const extension,
        const wchar_t* const title
      )
      {
        wchar_t path[MAX_PATH] = L"";
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = owner;
        dialog.lpstrFile = path;
        dialog.nMaxFile = MAX_PATH;
        dialog.lpstrFilter = filter;
        dialog.lpstrDefExt = extension;
        dialog.lpstrTitle = title;
        dialog.Flags = save ? (OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR)
                            : (OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR);
        const BOOL chosen = save ? ::GetSaveFileNameW(&dialog) : ::GetOpenFileNameW(&dialog);
        return chosen != FALSE ? std::filesystem::path(path) : std::filesystem::path{};
      }

      /** The Windows file dialog for a height image; empty when cancelled. */
      std::filesystem::path AskHeightFile(
        const HWND owner,
        const bool save
      )
      {
        wchar_t path[MAX_PATH] = L"";
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = owner;
        dialog.lpstrFile = path;
        dialog.nMaxFile = MAX_PATH;
        if (save) {
          dialog.lpstrFilter =
            L"16-bit grey PNG (*.png)\0*.png\0Raw 16-bit (*.raw)\0*.raw\0World Machine (*.r16)\0*.r16\0";
          dialog.lpstrDefExt = L"png";
          dialog.lpstrTitle = L"Export the height field";
          dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
          return ::GetSaveFileNameW(&dialog) != FALSE ? std::filesystem::path(path) : std::filesystem::path{};
        }
        dialog.lpstrFilter =
          L"Height images (*.png;*.raw;*.r16;*.bmp;*.tif;*.tiff)\0*.png;*.raw;*.r16;*.bmp;*.tif;*.tiff\0All "
          L"files\0*.*\0";
        dialog.lpstrTitle = L"Import a height field";
        dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        return ::GetOpenFileNameW(&dialog) != FALSE ? std::filesystem::path(path) : std::filesystem::path{};
      }
    } // namespace

    void EditorApp::DriveHeightFiles()
    {
      EdTools& tools = mShell->Tools();
      const auto report = [](const bool ok, const std::string& message) {
        if (ok) {
          gpg::Logf("editor: %s", message.c_str());
        } else {
          gpg::Warnf("editor: %s", message.c_str());
        }
      };
      // The unit list, once the kept rules are built: id, and the name without its <LOC> tag.
      if (!tools.HasUnitTypes()) {
        if (moho::RRuleGameRules* const rules = moho::RULE_PeekKept(); rules != nullptr) {
          std::vector<std::pair<std::string, std::string>> types;
          std::vector<EdUnitInfo> infos;
          for (const auto& [id, entry] : rules->GetUnitBlueprints()) {
            moho::RResId resId{};
            resId.name.assign(id.c_str());
            const moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(resId);
            std::string name = blueprint != nullptr ? blueprint->mDescription.c_str() : "";
            if (name.rfind("<LOC", 0) == 0) {
              const std::size_t close = name.find('>');
              name = close == std::string::npos ? std::string() : name.substr(close + 1);
            }
            types.emplace_back(id.c_str(), name);
            // Its faction, kind and tech for the unit browser, from its categories.
            std::vector<std::string> categories;
            if (blueprint != nullptr) {
              for (const fa::string& category : blueprint->mCategories) {
                categories.emplace_back(category.c_str());
              }
            }
            infos.push_back(UnitInfoFrom(id.c_str(), name, categories));
          }
          std::sort(types.begin(), types.end());
          tools.SetUnitTypes(std::move(types));
          tools.SetUnitInfos(std::move(infos));
        }
      }
      // The prop palette, once the kept rules are built.
      if (!tools.HasPropBlueprints()) {
        if (moho::RRuleGameRules* const rules = moho::RULE_PeekKept(); rules != nullptr) {
          std::vector<std::string> blueprints;
          for (const auto& [id, blueprint] : rules->GetPropBlueprints()) {
            blueprints.emplace_back(id.c_str());
          }
          tools.SetPropBlueprints(std::move(blueprints));
        }
      }
      if (!mPropToolArg.empty() && tools.HasPropBlueprints()) {
        // `/proptool <mode>,<blueprint>` (test runs): 0 Single, 1 Scatter, 2 Erase.
        const std::size_t comma = mPropToolArg.find(',');
        tools.SetPropTool(
          comma == std::string::npos ? std::string{} : mPropToolArg.substr(comma + 1), std::atoi(mPropToolArg.c_str())
        );
        mPropToolArg.clear();
      }
      if (mToolArg >= 0) {
        tools.SetTool(mToolArg);
        mToolArg = -1;
      }
      // The open map's layers for the Texture tool's list.
      if (mDocument.GetState() == EdDocument::State::Open && mLayerNamesOf != mDocument.Path()) {
        mLayerNamesOf = mDocument.Path();
        tools.SetLayerNames(mDocument.Facts().layers);
      }
      // The texture slots as the terrain has them, and a change the panel asked for.
      if (mScene.Attached()) {
        int slot = -1;
        EdTools::LayerSlot value;
        if (tools.TakeLayerChange(slot, value)) {
          mScene.ChangeLayerSlot(slot, value);
        }
        tools.SetLayerSlots(mScene.LayerSlots());
        MapTexturesUpdate();
        MaskGenUpdate();
        RecipesUpdate();
        TexturesUpdate();
        DriveMaterialEditor();
        tools.SetMapSizeUnits(static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ)));
        {
          std::vector<std::string> names;
          bool add = false;
          if (tools.TakeMarkerSelect(names, add)) {
            mScene.SelectMarkers(names, add);
          }
        }
        if (std::string name; tools.TakeMarkerFrame(name)) {
          mScene.FrameMarker(name);
        }
        if (float x = 0.0f, z = 0.0f; tools.TakePointFrame(x, z)) {
          mScene.FramePoint(x, z);
        }
        tools.SetDecalSelectionCount(mScene.DecalSelectionCount());
        // `/mapinfotest <name>` (test runs): the map's name set (an undo step), undone and redone, logged each time.
        if (
          fa::vector<fa::string> name;
          !mMapInfoTested && mScene.Attached() && moho::CFG_GetArgOption("/mapinfotest", 1, &name) && !name.empty()
        ) {
          mMapInfoTested = true;
          const std::string before = mDocument.Facts().name;
          const bool set = mDocument.SetScenarioField("name", name[0].c_str(), true);
          const bool added = mDocument.SetScenarioField("norushradius", "75", false);
          gpg::Logf(
            "editor: map info test: name %s -> %s (%s), no-rush added %s; undo step: %s",
            before.c_str(),
            mDocument.Facts().name.c_str(),
            set ? "set" : "unchanged",
            added ? "yes" : "no",
            mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
          );
          (void)mScene.Undo();
          std::string radius;
          gpg::Logf(
            "editor: map info test: undo: no-rush %s",
            ReadScenarioField(mDocument.Scenario(), "norushradius", radius) ? radius.c_str() : "gone"
          );
          (void)mScene.Undo();
          gpg::Logf(
            "editor: map info test: undo: name %s, modified %s",
            mDocument.Facts().name.c_str(),
            mDocument.Modified() ? "yes" : "no"
          );
          (void)mScene.Redo();
          gpg::Logf("editor: map info test: redo: name %s", mDocument.Facts().name.c_str());
        }
        if (bool selection = false; mScene.TakeContextMenuAsk(selection)) {
          mShell->OpenViewMenu(selection);
        }
        // `/viewmenu` (test runs): the menu as a right click would open it, once the map is shown.
        if (
          !mViewMenuTested && mScene.Attached() && moho::CFG_GetArgOption("/viewmenu", 0, nullptr) &&
          ++mViewMenuFrames > 120
        ) {
          mViewMenuTested = true;
          mScene.AskContextMenu();
        }
        mPropThumbnails.Pump(3);
        // `/rdcapture <frame>`: run under RenderDoc (renderdoccmd capture ...), that frame of the editor is captured,
        // through RenderDoc's in-app API (RENDERDOC_GetAPI, version 1.0.0; TriggerCapture is its table's 16th entry).
        if (mRdCaptureFrame < 0) {
          fa::vector<fa::string> value;
          mRdCaptureFrame =
            moho::CFG_GetArgOption("/rdcapture", 1, &value) && !value.empty() ? std::atoi(value[0].c_str()) : 0;
        }
        if (mRdCaptureFrame > 0 && ++mRdFrames == mRdCaptureFrame) {
          if (const HMODULE renderDoc = ::GetModuleHandleA("renderdoc.dll"); renderDoc != nullptr) {
            using GetApi = int(__cdecl*)(int, void**);
            if (
              const auto getApi = reinterpret_cast<GetApi>(::GetProcAddress(renderDoc, "RENDERDOC_GetAPI"));
              getApi != nullptr
            ) {
              void** api = nullptr;
              // Version 1.1.0 for TriggerMultiFrameCapture (the table's 23rd entry): three frames, and the prop
              // pictures asked for again, so the frames hold thumbnail passes.
              if (getApi(10100, reinterpret_cast<void**>(&api)) == 1 && api != nullptr) {
                using TriggerFrames = void(__cdecl*)(std::uint32_t);
                reinterpret_cast<TriggerFrames>(api[22])(3U);
                mPropThumbnails.Clear();
                gpg::Logf("editor: RenderDoc capture of 3 frames asked at frame %d", mRdFrames);
              }
            }
          } else {
            gpg::Warnf("editor: /rdcapture: not running under RenderDoc");
          }
        }
        tools.SetSelectionProperties(mScene.SelectionPropertiesNow());
        // The Markers tool's air node grid; `/airgrid <n>[,keep]` for test runs.
        if (!mAirGridArgDone) {
          mAirGridArgDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/airgrid", 1, &value) && !value.empty()) {
            const std::string text = value[0].c_str();
            tools.AskAirGrid(std::atoi(text.c_str()), text.find("keep") == std::string::npos);
          }
        }
        if (int count = 0; true) {
          bool replace = true;
          if (tools.TakeAirGrid(count, replace)) {
            mScene.FillAirGrid(count, replace);
          }
        }
        // `/adaptive <marker>,<army>` (test runs): ties a mass or hydrocarbon marker to an army in the adaptive tables,
        // once (the map becomes adaptive first when it isn't).
        if (!mAdaptiveArgDone) {
          mAdaptiveArgDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/adaptive", 1, &value) && !value.empty()) {
            std::string text = value[0].c_str();
            std::replace(text.begin(), text.end(), '+', ' '); // "Mass+08,1": the command line splits at spaces
            const std::size_t comma = text.find_last_of(',');
            const std::string marker = text.substr(0, comma);
            const int army = comma == std::string::npos ? 0 : std::atoi(text.c_str() + comma + 1);
            AdaptiveTables tables;
            std::string error;
            if (mDocument.Adaptive()) {
              (void)ParseAdaptiveTables(mDocument.TablesText(), tables, error);
            }
            const std::vector<ScenarioTeam> teams = mDocument.Teams();
            const int slots = teams.empty() ? 1 : static_cast<int>(teams.front().armies.size());
            tables.maxPlayers = mDocument.Adaptive() ? std::max(tables.maxPlayers, slots) : slots;
            std::vector<std::vector<std::string>>& byArmy =
              marker.rfind("Hydrocarbon", 0) == 0 ? tables.hydroArmy : tables.mexArmy;
            if (army >= 1) {
              byArmy.resize(std::max(byArmy.size(), static_cast<std::size_t>(army)));
              byArmy[static_cast<std::size_t>(army - 1)].push_back(marker);
            }
            mDocument.SetTablesText(WithAdaptiveTables(mDocument.TablesText(), tables));
            gpg::Logf(
              "editor: adaptive: %s spawns with ARMY_%d (tables %s)",
              marker.c_str(),
              army,
              mDocument.Facts().tablesPath.c_str()
            );
          }
        }
        // `/propedit <position|heading|size>,<a>[,<b>,<c>]` (test runs): one edit of the selection, once it has one.
        if (!mPropEditArgDone && tools.SelectionPropertiesNow().kind != SelectionProperties::Kind::None) {
          mPropEditArgDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/propedit", 1, &value) && !value.empty()) {
            const std::string text = value[0].c_str();
            PropertyEdit asked;
            asked.what = text.rfind("position", 0) == 0 ? PropertyEdit::What::Position
              : text.rfind("heading", 0) == 0           ? PropertyEdit::What::Heading
              : text.rfind("size", 0) == 0              ? PropertyEdit::What::Size
                                                        : PropertyEdit::What::None;
            std::size_t at = text.find(',');
            for (int i = 0; i < 3 && at != std::string::npos; ++i) {
              asked.values[i] = static_cast<float>(std::atof(text.c_str() + at + 1));
              at = text.find(',', at + 1);
            }
            tools.AskPropertyEdit(asked);
          }
        }
        if (PropertyEdit edit; tools.TakePropertyEdit(edit)) {
          mScene.ApplyPropertyEdit(edit);
          // `/propswapundo` (test runs, with /propswap): the swap undone a second on, the prop's blueprint logged.
          static double undoAt = 0.0;
          if (
            edit.what == PropertyEdit::What::Blueprint && moho::CFG_GetArgOption("/propswapundo", 0, nullptr) &&
            undoAt == 0.0
          ) {
            undoAt = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count() + 1.0;
          }
          mPropSwapUndoAt = undoAt;
        }
        if (
          mPropSwapUndoAt > 0.0 &&
          std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count() >= mPropSwapUndoAt
        ) {
          mPropSwapUndoAt = -1.0;
          mScene.TestUndoPropSwap();
        }
        // The Water panel: its change on the map at once, one undo step when the drag ends.
        tools.SetWater(mDocument.WaterNow());
        if (WaterState water; true) {
          bool final = false;
          if (tools.TakeWaterTakeLightingSun()) {
            const WaterState before = mDocument.WaterNow();
            WaterState taken = before;
            const LightingState lighting = mDocument.LightingNow();
            for (int i = 0; i < 3; ++i) {
              taken.shader.mSunDirection[i] = -lighting.sunDirection[i];
            }
            mDocument.ApplyWater(taken);
            mDocument.WaterEdited(before);
            gpg::Logf(
              "editor: the water's sun takes the lighting sun: %.3f %.3f %.3f",
              static_cast<double>(taken.shader.mSunDirection[0]),
              static_cast<double>(taken.shader.mSunDirection[1]),
              static_cast<double>(taken.shader.mSunDirection[2])
            );
          }
          if (tools.TakeWaterChange(water, final)) {
            if (!mWaterDragging) {
              mWaterBefore = mDocument.WaterNow();
              mWaterDragging = true;
            }
            mDocument.ApplyWater(water);
            if (final) {
              mWaterDragging = false;
              if (!(mWaterBefore == mDocument.WaterNow())) {
                mDocument.WaterEdited(mWaterBefore);
                gpg::Logf(
                  "editor: water: %s, level %.2f, deep %.2f, abyss %.2f",
                  water.enabled ? "on" : "off",
                  static_cast<double>(water.elevation),
                  static_cast<double>(water.deep),
                  static_cast<double>(water.abyss)
                );
              }
            }
          }
        }
        // Its water bodies: the scenario's text changed at once, one undo step when the edit ends.
        if (std::vector<WaterBody> bodies; true) {
          bool final = false;
          if (tools.TakeWaterBodiesChange(bodies, final)) {
            if (!mBodiesDragging) {
              mBodiesBefore = mDocument.SaveDataNow();
              mBodiesDragging = true;
            }
            mDocument.ApplyWaterBodies(bodies);
            if (final) {
              mBodiesDragging = false;
              if (mBodiesBefore.scenario != mDocument.Scenario()) {
                mDocument.SaveDataEdited(std::move(mBodiesBefore));
                gpg::Logf("editor: water bodies: %zu", bodies.size());
              }
            }
          }
        }
        if (!mWaterBodyArg.empty() && mScene.Attached()) {
          const WaterBodiesRead asked = ReadWaterBodies("ScenarioInfo = { WaterBodies = { " + mWaterBodyArg + " } }");
          if (asked.bodies.empty()) {
            gpg::Warnf("editor: /waterbody %s doesn't read", mWaterBodyArg.c_str());
          } else {
            std::vector<WaterBody> bodies = ReadWaterBodies(mDocument.Scenario()).bodies;
            bodies.insert(bodies.end(), asked.bodies.begin(), asked.bodies.end());
            EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
            mDocument.ApplyWaterBodies(bodies);
            mDocument.SaveDataEdited(std::move(before));
            gpg::Logf("editor: water bodies: %zu (added %s)", bodies.size(), mWaterBodyArg.c_str());
          }
          mWaterBodyArg.clear();
        }
        if (mBodiesScenario != mDocument.Scenario()) {
          mBodiesScenario = mDocument.Scenario();
          mBodiesRead = ReadWaterBodies(mBodiesScenario);
        }
        tools.SetWaterBodies(mBodiesRead.bodies, mBodiesRead.error);
        if (!mWaterPickArg.empty() && mScene.Attached()) {
          if (mWaterPickArg == "new") {
            tools.AddWaterBody();
          } else {
            tools.SelectWaterBody(std::atoi(mWaterPickArg.c_str()) - 1);
            const std::size_t comma = mWaterPickArg.find(',');
            const std::string mode = comma == std::string::npos ? std::string() : mWaterPickArg.substr(comma + 1);
            tools.WaterBodyPick() = mode == "seed" ? EdTools::WaterPick::Seed
              : mode == "outline"                  ? EdTools::WaterPick::Outline
                                                   : EdTools::WaterPick::None;
          }
          gpg::Logf("editor: /waterpick %s", mWaterPickArg.c_str());
          mWaterPickArg.clear();
        }
        if (!mWaterSetArg.empty()) {
          WaterState water = mDocument.WaterNow();
          float values[4] = {water.enabled ? 1.0f : 0.0f, water.elevation, water.deep, water.abyss};
          std::size_t at = 0;
          for (int i = 0; i < 4 && at <= mWaterSetArg.size(); ++i) {
            const std::size_t comma = mWaterSetArg.find(',', at);
            values[i] = static_cast<float>(std::atof(mWaterSetArg.substr(at, comma - at).c_str()));
            at = comma == std::string::npos ? mWaterSetArg.size() + 1 : comma + 1;
          }
          const WaterState before = water;
          water.enabled = values[0] != 0.0f;
          water.elevation = values[1];
          water.deep = values[2];
          water.abyss = values[3];
          mDocument.ApplyWater(water);
          mDocument.WaterEdited(before);
          gpg::Logf(
            "editor: water set: %s, level %.2f, deep %.2f, abyss %.2f",
            water.enabled ? "on" : "off",
            static_cast<double>(water.elevation),
            static_cast<double>(water.deep),
            static_cast<double>(water.abyss)
          );
          mWaterSetArg.clear();
        }
        tools.SetUnitSelectionCount(mScene.UnitSelectionCount());
        tools.SetUnitSelection(mScene.UnitSelection());
        if (!mUnitToolArg.empty()) {
          const std::size_t first = mUnitToolArg.find(',');
          const std::size_t second = first == std::string::npos ? std::string::npos : mUnitToolArg.find(',', first + 1);
          tools.SetUnitTool(
            mUnitToolArg.substr(0, first),
            first == std::string::npos ? std::string() : mUnitToolArg.substr(first + 1, second - first - 1),
            second != std::string::npos && mUnitToolArg.substr(second + 1) == "select"
          );
          mUnitToolArg.clear();
        }
        if (tools.PropsToolActive()) {
          tools.SetPropDetails(mScene.PropDetails(tools.PropBlueprint()));
          // The map's reclaim, counted twice a second while the Props tool shows.
          if (++mReclaimFrames % 30 == 1) {
            const EdDocument::ReclaimTotals reclaim = mDocument.PropReclaim();
            // The units that become wrecks count too: from the start (WRECKAGE), and those the script's groups add.
            const UnitWreckTotals wrecks = MapUnitWrecks(mDocument);
            if (reclaim.props > 0 || !reclaim.rows.empty() || wrecks.startCount > 0 || wrecks.scriptCount > 0) {
              char summary[480];
              int used = std::snprintf(
                summary,
                sizeof(summary),
                "%d props: %.0f mass, %.0f energy. %d give none, %d have no blueprint.",
                reclaim.props,
                reclaim.mass,
                reclaim.energy,
                reclaim.none,
                reclaim.unknown
              );
              if (wrecks.startCount > 0 && used > 0 && used < static_cast<int>(sizeof(summary))) {
                used += std::snprintf(
                  summary + used,
                  sizeof(summary) - static_cast<std::size_t>(used),
                  " Unit wrecks from the start: %d, %.0f mass, %.0f energy.",
                  wrecks.startCount,
                  wrecks.startMass,
                  wrecks.startEnergy
                );
              }
              if (wrecks.scriptCount > 0 && used > 0 && used < static_cast<int>(sizeof(summary))) {
                (void)std::snprintf(
                  summary + used,
                  sizeof(summary) - static_cast<std::size_t>(used),
                  " The script's wreck groups, all on: %d more, %.0f mass, %.0f energy (lobby options decide).",
                  wrecks.scriptCount,
                  wrecks.scriptMass,
                  wrecks.scriptEnergy
                );
              }
              std::vector<std::string> rows;
              for (std::size_t i = 0; i < reclaim.rows.size() && i < 8; ++i) {
                const EdDocument::ReclaimRow& row = reclaim.rows[i];
                std::string name = row.blueprint.substr(row.blueprint.find_last_of('/') + 1);
                if (name.size() > 8 && name.compare(name.size() - 8, 8, "_prop.bp") == 0) {
                  name.resize(name.size() - 8);
                }
                char line[200];
                // The mass first, so a narrow panel cuts the name, not the number.
                (void)std::snprintf(
                  line,
                  sizeof(line),
                  "%.0f  %d x %s",
                  static_cast<double>(row.mass * static_cast<float>(row.count)),
                  row.count,
                  name.c_str()
                );
                rows.emplace_back(line);
              }
              if (!mReclaimLogged) {
                mReclaimLogged = true;
                gpg::Logf("editor: map reclaim: %s", summary);
              }
              tools.SetPropReclaim(summary, std::move(rows));
            }
          }
        }
        tools.SetDecalPathInfo(mScene.DecalPathPointCount(), mScene.DecalPathDecalCount());
        switch (tools.TakeDecalPathAction()) {
        case EdTools::DecalPathAction::Place:
          mScene.PlaceDecalPath();
          break;
        case EdTools::DecalPathAction::RemoveLast:
          mScene.RemoveLastDecalPathPoint();
          break;
        case EdTools::DecalPathAction::Clear:
          mScene.ClearDecalPath();
          break;
        case EdTools::DecalPathAction::None:
          break;
        }
        if (!mDecalToolArg.empty()) {
          const std::size_t comma = mDecalToolArg.find(',');
          const std::string mode = comma == std::string::npos ? std::string() : mDecalToolArg.substr(comma + 1);
          tools.SetDecalTool(mDecalToolArg.substr(0, comma), mode == "select" ? 1 : mode == "path" ? 2 : 0);
          mDecalToolArg.clear();
        }
        if (mCheckArgPending) {
          mCheckArgPending = false;
          // `/breakscript` (test runs): a syntax error added to the script's end first.
          if (moho::CFG_GetArgOption("/breakscript", 0, nullptr)) {
            mDocument.Script() += "\nfunction Broken(\n";
          }
          if (moho::CFG_GetArgOption("/check", 0, nullptr)) {
            mShell->RequestCheck();
          }
          if (moho::CFG_GetArgOption("/testrun", 0, nullptr)) {
            mShell->RequestTestRun();
          }
          // `/package` (test runs): the open map packaged for the vault, as the dialog's Package does.
          if (moho::CFG_GetArgOption("/package", 0, nullptr)) {
            const PackagePlan plan = mDocument.PlanPackage();
            for (const std::string& error : plan.errors) {
              gpg::Warnf("editor: package error: %s", error.c_str());
            }
            for (const std::string& warning : plan.warnings) {
              gpg::Logf("editor: package warning: %s", warning.c_str());
            }
            std::filesystem::path written;
            std::string message;
            const bool ok = mDocument.WritePackage(plan, written, message);
            (ok ? gpg::Logf : gpg::Warnf)("editor: %s", message.c_str());
          }
          if (fa::vector<fa::string> layer; moho::CFG_GetArgOption("/pathing", 1, &layer)) {
            mShell->Tools().ShowPathing() = true;
            mShell->Tools().PathingLayer() = !layer.empty() && std::string(layer[0].c_str()) == "ships" ? 1 : 0;
          } else if (moho::CFG_GetArgOption("/pathing", 0, nullptr)) {
            mShell->Tools().ShowPathing() = true;
          }
        }
        if (mGridArgsPending) {
          mGridArgsPending = false;
          if (moho::CFG_GetArgOption("/grid", 0, nullptr)) {
            tools.SetShowGrid(true);
          }
          if (moho::CFG_GetArgOption("/snap", 0, nullptr)) {
            tools.SetSnapToGrid(true);
          }
          if (fa::vector<fa::string> step; moho::CFG_GetArgOption("/gridstep", 1, &step) && !step.empty()) {
            tools.SetGridStep(static_cast<float>(std::atof(step[0].c_str())));
          }
        }
        // `/hoverprop <index or part of a blueprint path>` (test runs): the Select tool's cursor kept on that prop
        // (WPE.54).
        static bool hoverPropArmed = false;
        if (
          fa::vector<fa::string> prop;
          !hoverPropArmed && moho::CFG_GetArgOption("/hoverprop", 1, &prop) && !prop.empty()
        ) {
          const std::string wanted = prop[0].c_str();
          int index = std::isdigit(static_cast<unsigned char>(wanted.front())) != 0 ? std::atoi(wanted.c_str()) : -1;
          if (const moho::CWldMap* const map = mDocument.Map(); index < 0 && map != nullptr && map->mProps != nullptr) {
            for (std::size_t i = 0; i < map->mProps->mEntries.size() && index < 0; ++i) {
              if (std::string(map->mProps->mEntries[i].mBlueprintPath.c_str()).find(wanted) != std::string::npos) {
                index = static_cast<int>(i);
              }
            }
          }
          // `/propswap <part of a blueprint path>` too: that prop selected, the Properties panel's prop browser opened
          // on that filter and its first tile clicked (WPE.55).
          fa::vector<fa::string> swap;
          const bool swapping = moho::CFG_GetArgOption("/propswap", 1, &swap) && !swap.empty();
          hoverPropArmed = index >= 0; // once, when the map's props are there to find it in
          // `/selectprops <n>` too: that prop and the nearest others selected (n in all), the cursor clear of them.
          fa::vector<fa::string> select;
          const int selectNearest =
            moho::CFG_GetArgOption("/selectprops", 1, &select) && !select.empty() ? std::atoi(select[0].c_str()) : 0;
          mScene.TestHoverProp(index, swapping, selectNearest);
          if (swapping) {
            mShell->TestPropSwap(swap[0].c_str());
          }
        }
        if (
          fa::vector<fa::string> hover;
          !mFrameMarkerArg.empty() && moho::CFG_GetArgOption("/hovermarker", 1, &hover) && !hover.empty()
        ) {
          // `/hovermarker <name>` (test runs, with /framemarker): the cursor kept on that marker ("Mass+08" for "Mass
          // 08").
          std::string name = hover[0].c_str();
          std::replace(name.begin(), name.end(), '+', ' ');
          mScene.TestHoverMarker(name);
        }
        if (!mFrameMarkerArg.empty()) {
          const std::size_t at = mFrameMarkerArg.find('@');
          mScene.FrameMarker(
            mFrameMarkerArg.substr(0, at),
            at == std::string::npos ? 140.0f : static_cast<float>(std::atof(mFrameMarkerArg.c_str() + at + 1))
          );
          mFrameMarkerArg.clear();
        }
        // `/selectunit <army>,<unit>` (test runs), once the units are drawn.
        if (!mSelectUnitDone && mScene.UnitsReady()) {
          mSelectUnitDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/selectunit", 1, &value) && !value.empty()) {
            const std::string text = value[0].c_str();
            const std::size_t comma = text.find(',');
            if (comma != std::string::npos) {
              mScene.SelectUnit(text.substr(0, comma), text.substr(comma + 1));
            }
            // `/unitspawn <group>` (test runs): its Properties' Spawns choice set to that group.
            if (fa::vector<fa::string> group; moho::CFG_GetArgOption("/unitspawn", 1, &group) && !group.empty()) {
              mShell->TestUnitSpawn(group[0].c_str());
            }
          }
        }
        tools.SetMarkerSelection(mScene.SelectedMarkers());
        tools.SetArmies(mDocument.Armies(), mDocument.ExtraArmies());
        {
          // `/armyeconomy <army>,<mass>,<energy>` (test runs): that army's starting resources, once.
          if (!mArmyEconomyArgDone) {
            mArmyEconomyArgDone = true;
            if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/armyeconomy", 1, &value) && !value.empty()) {
              const std::string text = value[0].c_str();
              const std::size_t first = text.find(',');
              const std::size_t second = first == std::string::npos ? std::string::npos : text.find(',', first + 1);
              const std::string name = text.substr(0, first);
              for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
                if (entry.name == name && second != std::string::npos) {
                  ArmySettings settings = ReadArmySettings(entry);
                  settings.mass = std::atof(text.c_str() + first + 1);
                  settings.energy = std::atof(text.c_str() + second + 1);
                  mScene.ChangeArmySettings(name, settings);
                }
              }
            }
          }
        }
        tools.SetTeams(mDocument.Teams());
        if (std::vector<ScenarioTeam> teams; tools.TakeTeamsChange(teams)) {
          mScene.ChangeTeams(teams);
        }
        if (std::string extra; tools.TakeExtraArmiesChange(extra)) {
          mScene.ChangeExtraArmies(extra);
        }
        if (std::string marker, key, value; tools.TakeMarkerEdit(marker, key, value)) {
          mScene.EditMarker(marker, key, value);
        }
        if (!mMarkerToolArg.empty()) {
          // `/markertool <type>` (test runs), `/connectnodes` with it for the connect mode.
          tools.SetMarkerTool(mMarkerToolArg);
          tools.SetConnectPathNodes(moho::CFG_GetArgOption("/connectnodes", 0, nullptr));
          mMarkerToolArg.clear();
        }
        // The playable area: the panel shows it and asks for changes; `/playablearea x0,z0,x1,z1` (or `none`) for test
        // runs.
        if (const moho::CHeightField* const field = mDocument.Map()->mTerrainRes->GetHeightField(); field != nullptr) {
          const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea();
          tools.SetPlayableArea(
            area ? std::optional<std::array<int, 4>>(std::array<int, 4>{area->x0, area->z0, area->x1, area->z1})
                 : std::nullopt,
            field->width - 1,
            field->height - 1
          );
        }
        if (std::optional<std::array<int, 4>> change; tools.TakePlayableAreaChange(change)) {
          mScene.ChangePlayableArea(
            change ? std::optional<EdDocument::PlayableRect>(
                       EdDocument::PlayableRect{(*change)[0], (*change)[1], (*change)[2], (*change)[3]}
                     )
                   : std::nullopt
          );
        }
        if (!mPlayableAreaArg.empty()) {
          int x0 = 0, z0 = 0, x1 = 0, z1 = 0;
          if (mPlayableAreaArg == "none") {
            mScene.ChangePlayableArea(std::nullopt);
          } else if (std::sscanf(mPlayableAreaArg.c_str(), "%d,%d,%d,%d", &x0, &z0, &x1, &z1) == 4) {
            mScene.ChangePlayableArea(EdDocument::PlayableRect{x0, z0, x1, z1});
          }
          mPlayableAreaArg.clear();
        }
        if (float coverage[8]; mScene.MaskCoverage(coverage)) {
          tools.SetCoverage(coverage);
        }
        // The Texture tool and the Layers panel show the shader (the panel with any tool).
        if (tools.TextureToolActive() || mShell->ShowLayers()) {
          tools.SetShaders(mScene.TerrainShaders(), mScene.TerrainShader());
        }
        if (!mShaderArg.empty()) {
          mScene.ChangeTerrainShader(std::exchange(mShaderArg, {}));
        }
        if (std::string shader; tools.TakeShaderChange(shader)) {
          mScene.ChangeTerrainShader(shader);
        }
        // The shader browser's Convert section.
        {
          std::string shader;
          LayerConvertOptions options;
          if (tools.TakeConversionPlanRequest(shader, options)) {
            tools.SetConversionPlan(mScene.PlanConversion(shader, options));
          }
          if (tools.TakeConversionRequest(shader, options)) {
            std::vector<std::string> report;
            (void)mScene.ConvertLayers(shader, options, report);
            tools.SetConversionReport(std::move(report));
          }
        }
        // `/convertlayers <shader>[,move|merge|drop][,undo]` (test runs): a conversion, logged; with undo, Undo and
        // Redo checked against the masks and shader before and after.
        if (!mConvertLayersArg.empty() && mScene.Attached() && ++mConvertLayersFrames == 140) {
          const std::string arg = std::exchange(mConvertLayersArg, {});
          const std::string shader = arg.substr(0, arg.find(','));
          LayerConvertOptions options;
          options.lost = arg.find(",merge") != std::string::npos ? LostLayers::Merge
            : arg.find(",drop") != std::string::npos             ? LostLayers::Drop
                                                                 : LostLayers::Move;
          const auto hash = [&] {
            std::uint64_t h = 1469598103934665603ULL;
            for (const std::uint64_t texel : mDocument.Masks().texels) {
              h = (h ^ texel) * 1099511628211ULL;
            }
            return h;
          };
          const std::string shaderBefore = mScene.TerrainShader();
          (void)mScene.PlanConversion(shader, options); // reads the masks
          const std::uint64_t before = hash();
          std::vector<std::string> report;
          const bool converted = mScene.ConvertLayers(shader, options, report);
          const std::uint64_t after = hash();
          gpg::Logf(
            "editor: convert test: %s -> %s %s, masks %016llx -> %016llx",
            shaderBefore.c_str(),
            shader.c_str(),
            converted ? "converted" : "refused",
            static_cast<unsigned long long>(before),
            static_cast<unsigned long long>(after)
          );
          if (converted && arg.find(",undo") != std::string::npos) {
            const bool undone = mScene.Undo();
            const bool backAgain = hash() == before && mScene.TerrainShader() == shaderBefore;
            const bool redone = mScene.Redo();
            const bool forwardAgain = hash() == after && mScene.TerrainShader() == shader;
            gpg::Logf(
              "editor: convert test: undo %s (masks and shader as before: %s), redo %s (as converted: %s)",
              undone ? "done" : "refused",
              backAgain ? "yes" : "no",
              redone ? "done" : "refused",
              forwardAgain ? "yes" : "no"
            );
          }
        }
        switch (tools.TakeMaskOp()) {
        case EdTools::MaskOp::Clear: {
          std::string message;
          report(mScene.ClearMaskLayer(tools.MaskLayer(), message), message);
          break;
        }
        case EdTools::MaskOp::Fill: {
          std::string message;
          report(mScene.FillMaskLayer(tools.MaskLayer(), message), message);
          break;
        }
        case EdTools::MaskOp::Import:
          if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), false); !file.empty()) {
            std::string message;
            report(mScene.ImportMaskLayer(tools.MaskLayer(), file, message), message);
          }
          break;
        case EdTools::MaskOp::Export:
          if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), true); !file.empty()) {
            std::string message;
            report(mScene.ExportMaskLayer(tools.MaskLayer(), file, message), message);
          }
          break;
        default:
          break;
        }
        if (mBrowseArg >= 0 && ++mBrowseFrames == 60) {
          tools.OpenBrowser(mBrowseArg);
          mBrowseArg = -1;
        }
        if (!mLayerArg.empty()) {
          // `/layer <slot>,<albedo path>[,<size>]` (test runs).
          const std::size_t comma = mLayerArg.find(',');
          value = mScene.LayerSlots()[static_cast<std::size_t>(std::clamp(std::atoi(mLayerArg.c_str()), 0, 9))];
          const std::string rest = comma == std::string::npos ? std::string{} : mLayerArg.substr(comma + 1);
          const std::size_t second = rest.find(',');
          value.albedo = rest.substr(0, second);
          if (second != std::string::npos) {
            value.albedoSize = value.normalsSize = static_cast<float>(std::atof(rest.c_str() + second + 1));
          }
          mScene.ChangeLayerSlot(std::clamp(std::atoi(mLayerArg.c_str()), 0, 9), value);
          mLayerArg.clear();
        }
      } else {
        tools.SetLayerSlots({});
        DriveMaterialEditor();
      }
      if (mMaskLayerArg >= 0) {
        // `/layerweight` (test runs): the paint layer's weight shown.
        tools.SetShowLayerWeight(moho::CFG_GetArgOption("/layerweight", 0, nullptr));
        tools.SetMaskLayer(mMaskLayerArg);
        mMaskLayerArg = -1;
      }
      if (!mBrushTestArg.empty() && mScene.Attached() && ++mBrushTestFrames == 120) {
        int mode = 0;
        float x = 0.0f;
        float z = 0.0f;
        float seconds = 1.0f;
        (void)std::sscanf(mBrushTestArg.c_str(), "%d,%f,%f,%f", &mode, &x, &z, &seconds);
        (void)mScene.TestBrush(static_cast<HeightBrushMode>(std::clamp(mode, 0, 14)), x, z, seconds);
        mBrushTestArg.clear();
      }
      if (!mMaskRuleArg.empty() && mScene.Attached() && ++mMaskRuleFrames == 120) {
        MaskRule rule;
        rule.layer = std::clamp(std::atoi(mMaskRuleArg.c_str()) - 1, 0, 7);
        rule.useHeight = true;
        if (const std::size_t comma = mMaskRuleArg.find(','); comma != std::string::npos) {
          rule.low = static_cast<float>(std::atof(mMaskRuleArg.c_str() + comma + 1));
          if (const std::size_t second = mMaskRuleArg.find(',', comma + 1); second != std::string::npos) {
            rule.high = static_cast<float>(std::atof(mMaskRuleArg.c_str() + second + 1));
          }
        }
        tools.AddRule(rule);
        tools.RequestRules();
        mMaskRuleArg.clear();
      }
      // `/masktest <layer>,<x>,<z>[,<seconds>]` (test runs): a scripted mask stroke, once the map is shown.
      if (!mMaskTestArg.empty() && mScene.Attached() && ++mMaskTestFrames == 130) {
        int layer = 0;
        float x = 0.0f;
        float z = 0.0f;
        float seconds = 1.0f;
        (void)std::sscanf(mMaskTestArg.c_str(), "%d,%f,%f,%f", &layer, &x, &z, &seconds);
        mScene.TestMaskStroke(layer - 1, x, z, seconds);
        mMaskTestArg.clear();
      }
      // `/shaderbrowser <name>` (test runs): the shader browser open on that shader.
      if (!mShaderBrowserDone && mScene.Attached()) {
        mShaderBrowserDone = true;
        if (fa::vector<fa::string> shader; moho::CFG_GetArgOption("/shaderbrowser", 1, &shader) && !shader.empty()) {
          tools.OpenShaderBrowser(shader[0].c_str());
        }
      }
      // `/maskoptions <target>,<scatter>,<min slope degrees>,<build up>` (test runs): the mask brush's options.
      if (!mMaskOptionsDone) {
        mMaskOptionsDone = true;
        if (fa::vector<fa::string> mask; moho::CFG_GetArgOption("/maskoptions", 1, &mask) && !mask.empty()) {
          float target = 1.0f;
          float scatter = 0.0f;
          float slope = 0.0f;
          int buildUp = 0;
          (void)std::sscanf(mask[0].c_str(), "%f,%f,%f,%d", &target, &scatter, &slope, &buildUp);
          tools.SetMaskOptions(target, scatter, slope, buildUp != 0);
        }
      }
      // `/symoptions <part>,<combine>,<seam>,<masks>,<types>` (test runs): Make symmetric's options.
      if (!mSymOptionsDone) {
        mSymOptionsDone = true;
        if (fa::vector<fa::string> sym; moho::CFG_GetArgOption("/symoptions", 1, &sym) && !sym.empty()) {
          int part = 0;
          int combine = 0;
          float seam = 0.0f;
          int masks = 0;
          int types = 0;
          (void)std::sscanf(sym[0].c_str(), "%d,%d,%f,%d,%d", &part, &combine, &seam, &masks, &types);
          tools.SetSymmetrizeOptions(part, combine, seam, masks != 0, types != 0);
        }
      }
      if (mBrushModeArg >= 0) {
        tools.SetBrushMode(mBrushModeArg);
        mBrushModeArg = -1;
        // `/brushshape <shape>,<degrees>` (test runs, with /brush): the brush's shape (a BrushShape) and turn.
        if (fa::vector<fa::string> shape; moho::CFG_GetArgOption("/brushshape", 1, &shape) && !shape.empty()) {
          int kind = 0;
          float angle = 0.0f;
          (void)std::sscanf(shape[0].c_str(), "%d,%f", &kind, &angle);
          tools.SetBrushShape(kind, angle);
        }
        // `/erodetalus <slope>` (test runs, with /brush 9): the Erode brush's talus slope.
        if (fa::vector<fa::string> talus; moho::CFG_GetArgOption("/erodetalus", 1, &talus) && !talus.empty()) {
          tools.SetErodeTalus(static_cast<float>(std::atof(talus[0].c_str())));
        }
      }
      if (!mStampArg.empty()) {
        HeightImage image;
        std::string error;
        if (ReadHeightImage(mStampArg, 0, 0, image, error)) {
          HeightStamp stamp;
          stamp.width = image.width;
          stamp.height = image.height;
          stamp.words = std::move(image.words);
          tools.SetStamp(std::move(stamp), std::filesystem::path(mStampArg).filename().string());
        } else {
          gpg::Warnf("editor: /stamp: %s", error.c_str());
        }
        mStampArg.clear();
      }
      if (mHeightDialog && mScene.Attached() && ++mHeightFileFrames == 120) {
        tools.RequestImport();
      }
      // The brush library's folder, once; the Import button copies picked images into it.
      if (tools.BrushFolder().empty()) {
        if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
          tools.SetBrushFolder(folder / "brushes");
        }
      }
      if (tools.TakeBrushImportRequest()) {
        if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), false); !file.empty()) {
          std::string error;
          const int copied = ImportBrushImages({file}, tools.BrushFolder(), error);
          tools.RescanBrushes();
          gpg::Logf(
            "editor: brush library: %d image%s imported%s%s",
            copied,
            copied == 1 ? "" : "s",
            error.empty() ? "" : ": ",
            error.c_str()
          );
        }
      }
      // `/stampsource <n>` and `/stampstroke <spacing>,<random turn>,<size>,<place>,<mode>` (test runs, with /brush 8).
      if (!mStampSourceDone && !tools.BrushFolder().empty()) {
        mStampSourceDone = true;
        if (fa::vector<fa::string> source; moho::CFG_GetArgOption("/stampsource", 1, &source) && !source.empty()) {
          const bool chose = tools.ChooseStampSource(std::atoi(source[0].c_str()));
          gpg::Logf("editor: stamp source %s: %s", source[0].c_str(), chose ? "chosen" : "not there");
        }
        if (fa::vector<fa::string> stroke; moho::CFG_GetArgOption("/stampstroke", 1, &stroke) && !stroke.empty()) {
          float spacing = 0.0f;
          int random = 0;
          float size = 0.0f;
          float place = 0.0f;
          int mode = 0;
          (void)std::sscanf(stroke[0].c_str(), "%f,%d,%f,%f,%d", &spacing, &random, &size, &place, &mode);
          tools.SetStampStroke(spacing, random != 0, size, place, mode);
        }
      }
      if (tools.TakeStampRequest()) {
        if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), false); !file.empty()) {
          HeightImage image;
          std::string error;
          if (ReadHeightImage(file, 0, 0, image, error)) {
            HeightStamp stamp;
            stamp.width = image.width;
            stamp.height = image.height;
            stamp.words = std::move(image.words);
            gpg::Logf("editor: stamp image %s (%d x %d)", file.string().c_str(), stamp.width, stamp.height);
            tools.SetStamp(std::move(stamp), file.filename().string());
          } else {
            gpg::Warnf("editor: the stamp image didn't load: %s", error.c_str());
          }
        }
      }
      // The Water panel's settings file, or `/waterimport <file>`, `/waterexport <file>` for test runs.
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (tools.TakeWaterImport()) {
          importFile = AskFile(
            HandleOf(mGame.supcomFrame),
            false,
            L"Water settings (*.scmwtr)\0*.scmwtr\0All files\0*.*\0",
            L"scmwtr",
            L"Import water settings"
          );
        }
        if (tools.TakeWaterExport()) {
          exportFile = AskFile(
            HandleOf(mGame.supcomFrame),
            true,
            L"Water settings (*.scmwtr)\0*.scmwtr\0",
            L"scmwtr",
            L"Export water settings"
          );
        }
        if (mScene.Attached() && !mWaterFilesDone) {
          mWaterFilesDone = true;
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/waterimport", 1, &file) && !file.empty()) {
            importFile = file[0].c_str();
          }
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/waterexport", 1, &file) && !file.empty()) {
            exportFile = file[0].c_str();
          }
        }
        if (!importFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::ifstream in(importFile, std::ios::binary);
          const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          const WaterState before = mDocument.WaterNow();
          WaterState water = before;
          std::string error;
          if (!in || !WaterFromScmwtr(text, water, error)) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? error.c_str() : "can't read it");
          } else {
            // The map keeps its own sea: on or off and its levels, as FAForeverMapEditor's import keeps them.
            water.enabled = before.enabled;
            water.elevation = before.elevation;
            water.deep = before.deep;
            water.abyss = before.abyss;
            for (int i = 0; i < 6; ++i) {
              if (water.textures[i] != before.textures[i]) {
                gpg::Logf(
                  "editor: water texture %d: %s (was %s)", i, water.textures[i].c_str(), before.textures[i].c_str()
                );
              }
            }
            mDocument.ApplyWater(water);
            mDocument.WaterEdited(before);
            gpg::Logf(
              "editor: water settings imported from %s: colour %.3f %.3f %.3f, sun reflection %.2f",
              importFile.string().c_str(),
              static_cast<double>(water.shader.mWaterColor[0]),
              static_cast<double>(water.shader.mWaterColor[1]),
              static_cast<double>(water.shader.mWaterColor[2]),
              static_cast<double>(water.shader.mSunReflectionAmount)
            );
          }
        }
        if (!exportFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::ofstream out(exportFile, std::ios::binary | std::ios::trunc);
          const std::string text = WaterToScmwtr(mDocument.WaterNow());
          out.write(text.data(), static_cast<std::streamsize>(text.size()));
          if (out) {
            gpg::Logf("editor: water settings exported to %s", exportFile.string().c_str());
          } else {
            gpg::Warnf("editor: can't write %s", exportFile.string().c_str());
          }
        }
      }
      UpdateLooks();
      TestLooks();
      TestEnvironment();
      TestInterop();
      DriveGenerate();
      TestGenerate();
      DriveLayout();
      TestLayout();
      DrivePlayCopy();
      TestPlayCopy();
      TestMission();
      TestModProject();
      if (mShell->UnitLab().TakeTestAsk()) {
        (void)PlayModProject();
      }
      TestUnitLab();
      TestEffectMod();
      TestAssets();
      TestEditorMods();
      TestUnitViewer();
      TestPause();
      // `/sctest` (test runs): the SC tools window's buttons in turn, a second apart, the heights' checksum each time.
      if (
        mScTestStage < 8 && moho::CFG_GetArgOption("/sctest", 0, nullptr) && !mScene.ModelsPending() &&
        mScene.Attached() && ++mScTestFrames % 60 == 0
      ) {
        using Ask = EdTools::ScAsk;
        gpg::Logf(
          "editor: sc test stage %d: heights %016llx; undo: %s",
          mScTestStage,
          static_cast<unsigned long long>(mScene.HeightsHash()),
          mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
        );
        EdTools& tools = mShell->Tools();
        switch (mScTestStage) {
        case 0:
        case 1:
          tools.AskSc(Ask::PadsApply); // twice: the second replaces the first
          break;
        case 2:
          tools.AskSc(Ask::PadsRemove);
          break;
        case 3:
          tools.AskSc(Ask::SlopeReport);
          break;
        case 4:
          tools.AskSc(Ask::SlopeApply);
          break;
        case 5:
          gpg::Logf("editor: sc test: undo %s", mScene.Undo() ? "took the slope limit back" : "had nothing");
          break;
        case 6:
          mScene.TestRuler(780.0f, 380.0f, 830.0f, 420.0f);
          tools.AskSc(Ask::Ramp);
          break;
        default:
          break;
        }
        ++mScTestStage;
      }
      // `/erosiontest <preset>` (test runs): the window's Preview, Revert, Apply, then Undo, a second apart.
      if (
        fa::vector<fa::string> ero; mErosionTestStage < 5 && !mScene.ModelsPending() && mScene.Attached() &&
        moho::CFG_GetArgOption("/erosiontest", 1, &ero) && !ero.empty() && ++mErosionTestFrames % 60 == 0
      ) {
        using Ask = EdTools::ErosionAsk;
        const Ask asks[3] = {Ask::Preview, Ask::Revert, Ask::Apply};
        gpg::Logf(
          "editor: erosion test stage %d: heights %016llx, masks %016llx; undo: %s",
          mErosionTestStage,
          static_cast<unsigned long long>(mScene.HeightsHash()),
          static_cast<unsigned long long>(mScene.MasksHash()),
          mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
        );
        // `/erosiontest <preset>,masks`: Apply paints wear into layer 5 and deposit into layer 6.
        if (std::string(ero[0].c_str()).find(",masks") != std::string::npos) {
          EdTools::ErosionMaskChoice choice;
          choice.on[0] = true;
          choice.layer[0] = 5;
          choice.on[1] = true;
          choice.layer[1] = 6;
          mShell->Tools().SetErosionMasks(choice);
        }
        if (mErosionTestStage < 3) {
          const std::string preset = std::string(ero[0].c_str()).substr(0, std::string(ero[0].c_str()).find(','));
          mShell->Tools().AskErosion(preset, asks[mErosionTestStage]);
        } else if (mErosionTestStage == 3) {
          gpg::Logf("editor: erosion test: undo %s", mScene.Undo() ? "took the apply back" : "had nothing");
        }
        ++mErosionTestStage;
      }
      if (
        fa::vector<fa::string> at; !mCamAtDone && !mScene.ModelsPending() && mScene.Attached() &&
        moho::CFG_GetArgOption("/camat", 1, &at) && !at.empty()
      ) {
        mCamAtDone = true;
        float x = 0.0f, z = 0.0f, distance = 60.0f;
        (void)std::sscanf(at[0].c_str(), "%f,%f,%f", &x, &z, &distance);
        mScene.TestCameraAt(x, z, distance);
        gpg::Logf(
          "editor: /camat %.1f, %.1f, %.1f",
          static_cast<double>(x),
          static_cast<double>(z),
          static_cast<double>(distance)
        );
      }
      if (!mWaterMaskTestArg.empty() && !mScene.ModelsPending() && ++mWaterMaskTestFrames >= 150) {
        mScene.TestWaterMask(std::exchange(mWaterMaskTestArg, {}));
      }
      // The Lighting panel's "from another map", or `/lightingfrom <map folder>` for test runs: that map's lighting,
      // read from its .scmap.
      {
        std::string scenario = mShell->TakeLightingFromMap();
        if (mScene.Attached() && !mLightingFromDone) {
          mLightingFromDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/lightingfrom", 1, &value) && !value.empty()) {
            std::string wanted = value[0].c_str();
            std::transform(wanted.begin(), wanted.end(), wanted.begin(), [](const unsigned char c) {
              return static_cast<char>(std::tolower(c));
            });
            for (const std::string& map : mPlay.Maps()) {
              std::string folder = MapDisplayName(map);
              std::transform(folder.begin(), folder.end(), folder.begin(), [](const unsigned char c) {
                return static_cast<char>(std::tolower(c));
              });
              if (folder == wanted) {
                scenario = map;
              }
            }
          }
        }
        if (!scenario.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::string text;
          std::string bytes;
          std::smatch path;
          LightingState lighting = mDocument.LightingNow();
          std::string error;
          if (
            !ReadGameFile(scenario, text) ||
            !std::regex_search(text, path, std::regex(R"(\bmap\s*=\s*['"]([^'"]+\.scmap)['"])"))
          ) {
            gpg::Warnf("editor: %s names no map file", scenario.c_str());
          } else if (!ReadGameFile(path[1].str(), bytes) || !LightingFromScmap(bytes, lighting, error)) {
            gpg::Warnf("editor: %s: %s", path[1].str().c_str(), error.empty() ? "can't read it" : error.c_str());
          } else {
            const LightingState before = mDocument.LightingNow();
            mDocument.ApplyLighting(lighting);
            mDocument.LightingEdited(before);
            gpg::Logf(
              "editor: lighting from %s: multiplier %.2f, sun colour %.2f %.2f %.2f, fog %.0f to %.0f",
              path[1].str().c_str(),
              static_cast<double>(lighting.multiplier),
              static_cast<double>(lighting.sunColor[0]),
              static_cast<double>(lighting.sunColor[1]),
              static_cast<double>(lighting.sunColor[2]),
              static_cast<double>(lighting.fogStart),
              static_cast<double>(lighting.fogEnd)
            );
          }
        }
      }
      // The Lighting panel's settings file, or `/lightingimport <file>`, `/lightingexport <file>` for test runs.
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (mShell->TakeLightingImport()) {
          importFile = AskFile(
            HandleOf(mGame.supcomFrame),
            false,
            L"Lighting settings (*.scmlighting)\0*.scmlighting\0All files\0*.*\0",
            L"scmlighting",
            L"Import lighting settings"
          );
        }
        if (mShell->TakeLightingExport()) {
          exportFile = AskFile(
            HandleOf(mGame.supcomFrame),
            true,
            L"Lighting settings (*.scmlighting)\0*.scmlighting\0",
            L"scmlighting",
            L"Export lighting settings"
          );
        }
        if (mScene.Attached() && !mLightingFilesDone) {
          mLightingFilesDone = true;
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/lightingimport", 1, &file) && !file.empty()) {
            importFile = file[0].c_str();
          }
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/lightingexport", 1, &file) && !file.empty()) {
            exportFile = file[0].c_str();
          }
        }
        if (!importFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::ifstream in(importFile, std::ios::binary);
          const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          const LightingState before = mDocument.LightingNow();
          LightingState lighting = before;
          std::string error;
          if (!in || !LightingFromScmlighting(text, lighting, error)) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? error.c_str() : "can't read it");
          } else {
            mDocument.ApplyLighting(lighting);
            mDocument.LightingEdited(before);
            gpg::Logf(
              "editor: lighting imported from %s: multiplier %.2f, sun colour %.2f %.2f %.2f, fog %.0f to %.0f",
              importFile.string().c_str(),
              static_cast<double>(lighting.multiplier),
              static_cast<double>(lighting.sunColor[0]),
              static_cast<double>(lighting.sunColor[1]),
              static_cast<double>(lighting.sunColor[2]),
              static_cast<double>(lighting.fogStart),
              static_cast<double>(lighting.fogEnd)
            );
          }
        }
        if (!exportFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::ofstream out(exportFile, std::ios::binary | std::ios::trunc);
          const std::string text = LightingToScmlighting(mDocument.LightingNow());
          out.write(text.data(), static_cast<std::streamsize>(text.size()));
          (out ? gpg::Logf : gpg::Warnf)("editor: lighting exported to %s", exportFile.string().c_str());
        }
      }
      // The Markers tool's marker file, or `/markersimport <file>`, `/markersexport <file>` for test runs.
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (tools.TakeMarkerFileImport()) {
          importFile = AskFile(
            HandleOf(mGame.supcomFrame),
            false,
            L"Markers (*.fafmapmarkers)\0*.fafmapmarkers\0All files\0*.*\0",
            L"fafmapmarkers",
            L"Import markers"
          );
        }
        if (tools.TakeMarkerFileExport()) {
          exportFile = AskFile(
            HandleOf(mGame.supcomFrame),
            true,
            L"Markers (*.fafmapmarkers)\0*.fafmapmarkers\0",
            L"fafmapmarkers",
            L"Export markers"
          );
        }
        if (mScene.Attached() && !mMarkerFilesDone) {
          mMarkerFilesDone = true;
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/markersexport", 1, &file) && !file.empty()) {
            exportFile = file[0].c_str();
          }
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/markersimport", 1, &file) && !file.empty()) {
            importFile = file[0].c_str();
          }
        }
        // Export first, so a test run can write the map's markers and read them back in one go.
        if (!exportFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          const std::vector<std::string>& names = mScene.SelectedMarkerNames();
          const int size = std::max(mDocument.Facts().fieldWidth - 1, 0);
          const std::string text = MarkersToFafmapmarkers(
            mDocument.SaveData().Markers(), names, size, std::max(mDocument.Facts().fieldHeight - 1, 0)
          );
          std::ofstream out(exportFile, std::ios::binary | std::ios::trunc);
          out.write(text.data(), static_cast<std::streamsize>(text.size()));
          const std::size_t count = names.empty() ? mDocument.SaveData().Markers().size() : names.size();
          (out ? gpg::Logf : gpg::Warnf)(
            "editor: %zu markers (%s) exported to %s",
            count,
            names.empty() ? "all" : "the selected",
            exportFile.string().c_str()
          );
        }
        if (!importFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::ifstream in(importFile, std::ios::binary);
          const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          MarkerImport result;
          std::string error;
          if (!in || !mScene.ImportMarkerFile(text, result, error)) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? error.c_str() : "can't read it");
          } else {
            gpg::Logf(
              "editor: %zu markers imported from %s (%s to %s), %d path links, %d of a type the editor doesn't place "
              "left out",
              result.names.size(),
              importFile.string().c_str(),
              result.names.empty() ? "-" : result.names.front().c_str(),
              result.names.empty() ? "-" : result.names.back().c_str(),
              result.links,
              result.skipped
            );
          }
        }
      }
      // The Units tool's units file, or `/unitsimport <file>`, `/unitsexport <file>` for test runs (the Units tool's
      // army).
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (tools.TakeUnitFileImport()) {
          importFile = AskFile(
            HandleOf(mGame.supcomFrame),
            false,
            L"Units (*.scunits)\0*.scunits\0All files\0*.*\0",
            L"scunits",
            L"Import units"
          );
        }
        if (tools.TakeUnitFileExport()) {
          exportFile =
            AskFile(HandleOf(mGame.supcomFrame), true, L"Units (*.scunits)\0*.scunits\0", L"scunits", L"Export units");
        }
        if (mScene.Attached() && !mUnitFilesDone && !tools.UnitArmy().empty()) {
          mUnitFilesDone = true;
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/unitsexport", 1, &file) && !file.empty()) {
            exportFile = file[0].c_str();
          }
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/unitsimport", 1, &file) && !file.empty()) {
            importFile = file[0].c_str();
          }
        }
        // Export first, so a test run can write units and read them back in one go.
        if (!exportFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          const std::vector<SaveUnit> units = mScene.UnitsToExport(tools.UnitArmy());
          const std::string text = UnitsToScunits(units);
          std::ofstream out(exportFile, std::ios::binary | std::ios::trunc);
          out.write(text.data(), static_cast<std::streamsize>(text.size()));
          (out ? gpg::Logf : gpg::Warnf)(
            "editor: %zu units (%s) exported to %s",
            units.size(),
            mScene.UnitSelectionCount() > 0 ? "the selected" : tools.UnitArmy().c_str(),
            exportFile.string().c_str()
          );
        }
        if (!importFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::ifstream in(importFile, std::ios::binary);
          const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          std::vector<std::string> names;
          bool moved = false;
          std::string error;
          if (!in || !mScene.ImportUnitFile(text, tools.UnitArmy(), names, moved, error)) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? error.c_str() : "can't read it");
          } else {
            gpg::Logf(
              "editor: %zu units imported from %s into %s (%s to %s)%s",
              names.size(),
              importFile.string().c_str(),
              tools.UnitArmy().c_str(),
              names.front().c_str(),
              names.back().c_str(),
              moved ? ", moved onto this map" : ""
            );
          }
        }
      }
      // The Texture tool's layer files, or `/layerimport <slot>,<file>`, `/layerexport <slot>,<file>`, `/layersetimport
      // <file>`,
      // `/layersetexport <file>` for test runs (slot 0 the lower layer, 9 the upper one).
      {
        int slot = 0;
        EdTools::LayerFileAsk ask = tools.TakeLayerFileAsk(slot);
        std::filesystem::path file;
        const wchar_t* const layerFilter = L"Layer settings (*.scmsl)\0*.scmsl\0All files\0*.*\0";
        const wchar_t* const setFilter = L"Layer sets (*.scmst)\0*.scmst\0All files\0*.*\0";
        switch (ask) {
        case EdTools::LayerFileAsk::ImportLayer:
          file = AskFile(HandleOf(mGame.supcomFrame), false, layerFilter, L"scmsl", L"Import layer settings");
          break;
        case EdTools::LayerFileAsk::ExportLayer:
          file = AskFile(HandleOf(mGame.supcomFrame), true, layerFilter, L"scmsl", L"Export layer settings");
          break;
        case EdTools::LayerFileAsk::ImportSet:
          file = AskFile(HandleOf(mGame.supcomFrame), false, setFilter, L"scmst", L"Import a layer set");
          break;
        case EdTools::LayerFileAsk::ExportSet:
          file = AskFile(HandleOf(mGame.supcomFrame), true, setFilter, L"scmst", L"Export the layer set");
          break;
        case EdTools::LayerFileAsk::None:
          break;
        }
        // Test runs: the switches in a fixed order, export before import, one each frame from the map's first one.
        if (ask == EdTools::LayerFileAsk::None && mScene.Attached() && mLayerFileStep < 4) {
          static const char* const kSwitches[4] = {
            "/layersetexport", "/layerexport", "/layersetimport", "/layerimport"
          };
          static const EdTools::LayerFileAsk kAsks[4] = {
            EdTools::LayerFileAsk::ExportSet,
            EdTools::LayerFileAsk::ExportLayer,
            EdTools::LayerFileAsk::ImportSet,
            EdTools::LayerFileAsk::ImportLayer
          };
          const int step = mLayerFileStep++;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption(kSwitches[step], 1, &value) && !value.empty()) {
            std::string text = value[0].c_str();
            if (step % 2 == 1) {
              const std::size_t comma = text.find(',');
              slot = comma == std::string::npos ? 0 : std::atoi(text.c_str());
              text = comma == std::string::npos ? text : text.substr(comma + 1);
            }
            ask = kAsks[step];
            file = text;
          }
        }
        if (!file.empty() && mDocument.GetState() == EdDocument::State::Open && mScene.Attached()) {
          const bool set = ask == EdTools::LayerFileAsk::ImportSet || ask == EdTools::LayerFileAsk::ExportSet;
          slot = std::clamp(slot, 0, 9);
          if (ask == EdTools::LayerFileAsk::ExportLayer || ask == EdTools::LayerFileAsk::ExportSet) {
            const std::vector<LayerSettings> layers = mScene.LayerSettingsNow();
            const std::string text = set ? LayersToScmst(mScene.TerrainShader(), layers)
                                         : LayerToScmsl(layers[static_cast<std::size_t>(slot)]);
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            if (set) {
              (out ? gpg::Logf : gpg::Warnf)(
                "editor: the layer set (%s) exported to %s", mScene.TerrainShader().c_str(), file.string().c_str()
              );
            } else {
              (out ? gpg::Logf : gpg::Warnf)(
                "editor: layer %d (%s) exported to %s",
                slot,
                layers[static_cast<std::size_t>(slot)].albedo.c_str(),
                file.string().c_str()
              );
            }
          } else {
            std::ifstream in(file, std::ios::binary);
            const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            std::string error;
            std::string shader;
            std::vector<std::pair<int, LayerSettings>> changes;
            bool read = static_cast<bool>(in);
            if (read && set) {
              std::vector<LayerSettings> layers;
              read = LayersFromScmst(text, shader, layers, error);
              for (int i = 0; read && i < 10; ++i) {
                changes.emplace_back(i, layers[static_cast<std::size_t>(i)]);
              }
            } else if (read) {
              LayerSettings layer;
              read = LayerFromScmsl(text, layer, error);
              changes.emplace_back(slot, layer);
            }
            if (!read) {
              gpg::Warnf("editor: %s: %s", file.string().c_str(), in ? error.c_str() : "can't read it");
            } else {
              const int changed = mScene.ApplyLayerSettings(shader, changes);
              gpg::Logf(
                "editor: %s imported from %s: %d change%s (one undo step)",
                set ? "a layer set" : "a layer",
                file.string().c_str(),
                changed,
                changed == 1 ? "" : "s"
              );
            }
          }
        }
      }
      // The Props tool's paint list, or `/paintset <file>` (into the list) and `/paintsetexport <file>` for test runs.
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (tools.TakePaintSetImport()) {
          importFile = AskFile(
            HandleOf(mGame.supcomFrame),
            false,
            L"Prop paint sets (*.proppaintset)\0*.proppaintset\0All files\0*.*\0",
            L"proppaintset",
            L"Import a prop paint set"
          );
        }
        if (tools.TakePaintSetExport()) {
          exportFile = AskFile(
            HandleOf(mGame.supcomFrame),
            true,
            L"Prop paint sets (*.proppaintset)\0*.proppaintset\0",
            L"proppaintset",
            L"Export the paint list"
          );
        }
        if (mScene.Attached() && !mPaintSetDone && tools.HasPropBlueprints()) {
          mPaintSetDone = true;
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/paintset", 1, &file) && !file.empty()) {
            importFile = file[0].c_str();
          }
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/paintsetexport", 1, &file) && !file.empty()) {
            exportFile = file[0].c_str();
          }
        }
        if (!importFile.empty()) {
          std::ifstream in(importFile, std::ios::binary);
          const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          std::vector<PropPaintEntry> entries;
          std::string error;
          if (!in || !PaintSetFromProppaintset(text, entries, error)) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? error.c_str() : "can't read it");
          } else {
            int unknown = 0;
            for (PropPaintEntry& entry : entries) {
              if (const std::string known = tools.PropBlueprintNamed(entry.blueprint); !known.empty()) {
                entry.blueprint = known;
              } else if (tools.HasPropBlueprints()) {
                gpg::Warnf(
                  "editor: %s: no prop blueprint %s; Scatter skips it until it is there",
                  importFile.string().c_str(),
                  entry.blueprint.c_str()
                );
                ++unknown;
              }
            }
            gpg::Logf(
              "editor: paint list from %s: %zu props (%d unknown)", importFile.string().c_str(), entries.size(), unknown
            );
            tools.SetPaintList(std::move(entries));
          }
        }
        if (!exportFile.empty()) {
          const std::string text = PaintSetToProppaintset(tools.PaintList());
          std::ofstream out(exportFile, std::ios::binary | std::ios::trunc);
          out.write(text.data(), static_cast<std::streamsize>(text.size()));
          (out ? gpg::Logf : gpg::Warnf)(
            "editor: paint list (%zu props) exported to %s", tools.PaintList().size(), exportFile.string().c_str()
          );
        }
      }
      // The Lighting panel's sky file, or `/skyboximport <file>`, `/skyboxexport <file>` for test runs.
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (mShell->TakeSkyboxImport()) {
          importFile = AskFile(
            HandleOf(mGame.supcomFrame),
            false,
            L"Sky (*.scmskybox)\0*.scmskybox\0All files\0*.*\0",
            L"scmskybox",
            L"Import a sky"
          );
        }
        if (mShell->TakeSkyboxExport()) {
          exportFile = AskFile(
            HandleOf(mGame.supcomFrame), true, L"Sky (*.scmskybox)\0*.scmskybox\0", L"scmskybox", L"Export the sky"
          );
        }
        if (mScene.Attached() && !mSkyboxFilesDone) {
          mSkyboxFilesDone = true;
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/skyboxexport", 1, &file) && !file.empty()) {
            exportFile = file[0].c_str();
          }
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/skyboximport", 1, &file) && !file.empty()) {
            importFile = file[0].c_str();
          }
        }
        // Export first, so a test run can write the sky and read another in one go.
        if (!exportFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          const SkyboxState sky = mDocument.SkyboxNow();
          const std::string text = SkyboxToScmskybox(sky);
          std::ofstream out(exportFile, std::ios::binary | std::ios::trunc);
          out.write(text.data(), static_cast<std::streamsize>(text.size()));
          (out ? gpg::Logf : gpg::Warnf)(
            "editor: the sky (%zu planets, cirrus %s) exported to %s",
            sky.planets.size(),
            sky.cirrusTexture.c_str(),
            exportFile.string().c_str()
          );
        }
        if (!importFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::ifstream in(importFile, std::ios::binary);
          const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          SkyboxState sky;
          std::string error;
          if (!in || !SkyboxFromScmskybox(text, sky, error)) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? error.c_str() : "can't read it");
          } else {
            const SkyboxState before = mDocument.SkyboxNow();
            mDocument.ApplySkybox(sky);
            mDocument.SkyboxEdited(before);
            gpg::Logf(
              "editor: sky imported from %s: dome %.0f, %zu planets, zenith %.2f %.2f %.2f",
              importFile.string().c_str(),
              static_cast<double>(sky.scale),
              sky.planets.size(),
              static_cast<double>(sky.zenithColor[0]),
              static_cast<double>(sky.zenithColor[1]),
              static_cast<double>(sky.zenithColor[2])
            );
          }
        }
      }
      // The Water panel's waves, or `/waves <pattern>,<depth>,<density %>[,<spacing>]`, `/wavesclear`, `/wavesexport
      // <file>`,
      // `/wavesimport <file>`, `/wavepatterns <file>` for test runs (export first, then clear, import, patterns, add).
      {
        tools.SetWaveCount(mDocument.WaveCount());
        std::vector<std::pair<EdTools::WaveAsk, std::filesystem::path>> asks;
        EdTools::WaveSettings settings;
        const EdTools::WaveAsk ask = tools.TakeWaveAsk(settings);
        if (ask != EdTools::WaveAsk::None) {
          asks.emplace_back(ask, std::filesystem::path());
        }
        if (mScene.Attached() && !mWaveSwitchesDone) {
          mWaveSwitchesDone = true;
          const auto file = [](const char* const option) {
            fa::vector<fa::string> value;
            return moho::CFG_GetArgOption(option, 1, &value) && !value.empty() ? std::filesystem::path(value[0].c_str())
                                                                               : std::filesystem::path();
          };
          if (const auto f = file("/wavesexport"); !f.empty()) {
            asks.emplace_back(EdTools::WaveAsk::Export, f);
          }
          if (moho::CFG_GetArgOption("/wavesclear", 0, nullptr)) {
            asks.emplace_back(EdTools::WaveAsk::Clear, std::filesystem::path());
          }
          if (const auto f = file("/wavesimport"); !f.empty()) {
            asks.emplace_back(EdTools::WaveAsk::Import, f);
          }
          if (const auto f = file("/wavepatterns"); !f.empty()) {
            asks.emplace_back(EdTools::WaveAsk::LoadPatterns, f);
          }
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/waves", 1, &value) && !value.empty()) {
            float numbers[4] = {0.0f, 2.0f, 25.0f, 4.0f};
            std::string list = value[0].c_str();
            for (int i = 0; i < 4 && !list.empty(); ++i) {
              numbers[i] = static_cast<float>(std::atof(list.c_str()));
              const std::size_t comma = list.find(',');
              list = comma == std::string::npos ? std::string() : list.substr(comma + 1);
            }
            tools.AskWaves(static_cast<int>(numbers[0]), numbers[1], numbers[2] / 100.0f, numbers[3]);
            (void)tools.TakeWaveAsk(settings);
            asks.emplace_back(EdTools::WaveAsk::AddAlongShore, std::filesystem::path());
          }
        }
        for (auto& [what, path] : asks) {
          if (mDocument.GetState() != EdDocument::State::Open) {
            break;
          }
          const HWND owner = HandleOf(mGame.supcomFrame);
          if (what == EdTools::WaveAsk::Export) {
            if (path.empty()) {
              path =
                AskFile(owner, true, L"Waves (*.scmwaves)\0*.scmwaves\0", L"scmwaves", L"Export the wave generators");
            }
            if (!path.empty()) {
              const std::vector<WaveRecord> waves = mDocument.WavesNow();
              const std::string text = WavesToScmwaves(waves);
              std::ofstream out(path, std::ios::binary | std::ios::trunc);
              out.write(text.data(), static_cast<std::streamsize>(text.size()));
              (out ? gpg::Logf
                   : gpg::Warnf)("editor: %zu wave generators exported to %s", waves.size(), path.string().c_str());
            }
          } else if (what == EdTools::WaveAsk::Import || what == EdTools::WaveAsk::LoadPatterns) {
            const bool patterns = what == EdTools::WaveAsk::LoadPatterns;
            if (path.empty()) {
              path = patterns
                ? AskFile(
                    owner, false, L"Wave patterns (*.lua)\0*.lua\0All files\0*.*\0", L"lua", L"Load wave patterns"
                  )
                : AskFile(
                    owner,
                    false,
                    L"Waves (*.scmwaves)\0*.scmwaves\0All files\0*.*\0",
                    L"scmwaves",
                    L"Import wave generators"
                  );
            }
            if (path.empty()) {
              continue;
            }
            std::ifstream in(path, std::ios::binary);
            const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            std::string error;
            if (patterns) {
              std::vector<WavePattern> read;
              if (!in || !ParseWavePatterns(text, read, error)) {
                gpg::Warnf("editor: %s: %s", path.string().c_str(), in ? error.c_str() : "can't read it");
              } else {
                tools.AddWavePatterns(read);
                gpg::Logf("editor: %zu wave patterns from %s", read.size(), path.string().c_str());
              }
              continue;
            }
            std::vector<WaveRecord> waves;
            if (!in || !WavesFromScmwaves(text, waves, error)) {
              gpg::Warnf("editor: %s: %s", path.string().c_str(), in ? error.c_str() : "can't read it");
              continue;
            }
            std::vector<WaveRecord> before = mDocument.WavesNow();
            mDocument.ApplyWaves(waves);
            mDocument.WavesEdited(std::move(before));
            gpg::Logf(
              "editor: %zu wave generators imported from %s (in place of the map's)",
              waves.size(),
              path.string().c_str()
            );
          } else if (what == EdTools::WaveAsk::Clear) {
            std::vector<WaveRecord> before = mDocument.WavesNow();
            if (!before.empty()) {
              mDocument.ApplyWaves({});
              const std::size_t count = before.size();
              mDocument.WavesEdited(std::move(before));
              gpg::Logf("editor: %zu wave generators cleared", count);
            }
          } else if (what == EdTools::WaveAsk::AddAlongShore) {
            const moho::CHeightField* const field = mDocument.Map()->mTerrainRes->GetHeightField();
            const WaterState water = mDocument.WaterNow();
            if (field == nullptr || !water.enabled) {
              gpg::Warnf("editor: waves need a sea");
              continue;
            }
            const int width = field->width - 1;
            const int height = field->height - 1;
            std::vector<float> heights(
              static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height)
            );
            for (int z = 0; z < field->height; ++z) {
              for (int x = 0; x < field->width; ++x) {
                heights
                  [static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(x)] =
                    mDocument.Map()->mTerrainRes->GetHeightAt(x, z);
              }
            }
            const std::vector<ShorePoint> found =
              FindShorePoints(heights, width, height, water.elevation, settings.depth, settings.centre, settings.range);
            std::uint32_t seed = static_cast<std::uint32_t>(::GetTickCount());
            const std::vector<ShorePoint> picked = PickShorePoints(found, settings.density, settings.spacing, seed);
            std::vector<WaveRecord> before = mDocument.WavesNow();
            std::vector<WaveRecord> after = before;
            for (const ShorePoint& point : picked) {
              after.push_back(MakeShoreWave(settings.pattern, point, water.elevation, seed));
            }
            if (!picked.empty()) {
              mDocument.ApplyWaves(after);
              mDocument.WavesEdited(std::move(before));
            }
            gpg::Logf(
              "editor: %zu %s waves added along the shore (%zu places at depth %.2f, %.0f%% of them, spacing %.1f), %d "
              "now",
              picked.size(),
              settings.pattern.name.c_str(),
              found.size(),
              static_cast<double>(settings.depth),
              static_cast<double>(settings.density * 100.0f),
              static_cast<double>(settings.spacing),
              mDocument.WaveCount()
            );
          }
        }
      }
      // The game's terrain types, read once; `/terraintype <code>` for test runs.
      if (!tools.HasTerrainTypes() && mDocument.GetState() == EdDocument::State::Open) {
        std::string lua;
        if (ReadGameFile("/lua/TerrainTypes.lua", lua)) {
          std::vector<TerrainTypeInfo> types = ParseTerrainTypes(lua);
          gpg::Logf("editor: %zu terrain types from /lua/TerrainTypes.lua", types.size());
          tools.SetTerrainTypes(std::move(types));
        }
      }
      // The Units tool's group tree of its army, twice a second; its asks.
      if (tools.UnitsToolActive() && ++mUnitTreeFrames % 30 == 1) {
        for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
          UnitGroup root;
          std::string error;
          if (entry.name == tools.UnitArmy() && ParseUnitGroup(entry.Get("Units"), root, error)) {
            tools.SetUnitTree(entry.name, std::move(root));
          }
        }
      }
      {
        std::vector<std::string> path;
        std::string name;
        if (
          const EdTools::GroupAsk ask = tools.TakeGroupAsk(path, name);
          ask != EdTools::GroupAsk::None && mDocument.GetState() == EdDocument::State::Open
        ) {
          mScene.ChangeUnitGroups(tools.UnitArmy(), ask, path, name);
          mUnitTreeFrames = 0;
        }
        if (
          EdTools::UnitWreckAsk wreck; tools.TakeUnitWreck(wreck) && mDocument.GetState() == EdDocument::State::Open
        ) {
          mScene.SetUnitsWreck(wreck.army, wreck.names, wreck.wreck);
          mUnitTreeFrames = 0;
        }
        if (
          EdTools::UnitGroupAsk group; tools.TakeUnitGroup(group) && mDocument.GetState() == EdDocument::State::Open
        ) {
          if (group.select) {
            mScene.SelectUnits(std::move(group.units));
          } else if (group.removeGroup) {
            mScene.ChangeUnitGroups(group.army, EdTools::GroupAsk::Remove, group.path, "");
            for (const std::vector<std::string>& path : group.morePaths) {
              mScene.ChangeUnitGroups(group.army, EdTools::GroupAsk::Remove, path, "");
            }
          } else {
            (void)mScene.MoveUnitsToGroup(group.army, group.names, group.path);
            mUnitTreeFrames = 0;
          }
        }
      }
      // `/slope`, `/kmgrid` for test runs: the view aids on.
      if (mScene.Attached() && !mViewAidArgsDone) {
        mViewAidArgsDone = true;
        tools.SetShowSlope(moho::CFG_GetArgOption("/slope", 0, nullptr) || tools.ShowSlope());
        tools.SetShowKmGrid(moho::CFG_GetArgOption("/kmgrid", 0, nullptr) || tools.ShowKmGrid());
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/ruler", 1, &value) && !value.empty()) {
          float ends[4] = {0.0f, 0.0f, 0.0f, 0.0f};
          std::string list = value[0].c_str();
          for (int i = 0; i < 4 && !list.empty(); ++i) {
            ends[i] = static_cast<float>(std::atof(list.c_str()));
            const std::size_t comma = list.find(',');
            list = comma == std::string::npos ? std::string() : list.substr(comma + 1);
          }
          mScene.SetRuler(ends[0], ends[1], ends[2], ends[3]);
        }
      }
      // `/unitgroup <add|rename|remove|move|select>,<a/b path>[,<name>]` (test runs), on the Units tool's army.
      if (mScene.Attached() && !mUnitGroupArgDone && !tools.UnitArmy().empty()) {
        mUnitGroupArgDone = true;
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/unitgroup", 1, &value) && !value.empty()) {
          std::vector<std::string> parts;
          std::string list = value[0].c_str();
          for (std::size_t at = 0; at <= list.size();) {
            const std::size_t comma = std::min(list.find(',', at), list.size());
            parts.push_back(list.substr(at, comma - at));
            at = comma + 1;
          }
          std::vector<std::string> path;
          if (parts.size() > 1) {
            for (std::size_t at = 0; at <= parts[1].size() && !parts[1].empty();) {
              const std::size_t slash = std::min(parts[1].find('/', at), parts[1].size());
              path.push_back(parts[1].substr(at, slash - at));
              at = slash + 1;
            }
          }
          const std::string& verb = parts[0];
          const EdTools::GroupAsk ask = verb == "add" ? EdTools::GroupAsk::Add
            : verb == "rename"                        ? EdTools::GroupAsk::Rename
            : verb == "remove"                        ? EdTools::GroupAsk::Remove
            : verb == "move"                          ? EdTools::GroupAsk::MoveSelected
                                                      : EdTools::GroupAsk::Select;
          tools.AskGroup(ask, path, parts.size() > 2 ? parts[2] : std::string());
        }
      }
      if (mScene.Attached() && !mTerrainTypeArgDone) {
        mTerrainTypeArgDone = true;
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/terraintype", 1, &value) && !value.empty()) {
          tools.SetTerrainTypeTool(std::atoi(value[0].c_str()));
        }
      }
      if (const int browse = tools.TakeInteropBrowse(); browse != 0) {
        // The Import / Export window's Browse buttons: 1 the file to import, 2 the file to export to.
        if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), browse == 2); !file.empty()) {
          tools.SetInteropFile(browse == 2, file.string());
        }
      }
      const bool importAsked = tools.TakeImportRequest();
      const bool exportAsked = tools.TakeExportRequest();
      if (!mScene.Attached()) {
        if (importAsked || exportAsked) {
          gpg::Warnf("editor: open a map first; its heights are imported and exported from the view");
        }
        return;
      }
      std::string message;
      if (importAsked) {
        if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), false); !file.empty()) {
          report(mScene.ImportHeights(file, tools.HeightScale(), message), message);
        }
      }
      if (exportAsked) {
        if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), true); !file.empty()) {
          report(mScene.ExportHeights(file, tools.ExportWidth(), tools.HeightScale(), message), message);
        }
      }
      if ((!mHeightExportFile.empty() || !mHeightImportFile.empty()) && ++mHeightFileFrames == 120) {
        if (!mHeightExportFile.empty()) {
          report(mScene.ExportHeights(mHeightExportFile, tools.ExportWidth(), tools.HeightScale(), message), message);
        }
        if (!mHeightImportFile.empty()) {
          report(mScene.ImportHeights(mHeightImportFile, tools.HeightScale(), message), message);
        }
      }
    }

    void EditorApp::DriveOpens()
    {
      if (!mNewMapSpec.empty() && mDocument.GetState() != EdDocument::State::Loading && mPlay.Maps().size() > 0) {
        NewMapSettings settings;
        std::vector<std::string> parts;
        for (std::size_t at = 0; at <= mNewMapSpec.size();) {
          const std::size_t comma = std::min(mNewMapSpec.find(',', at), mNewMapSpec.size());
          parts.push_back(mNewMapSpec.substr(at, comma - at));
          at = comma + 1;
        }
        settings.folder = parts[0];
        settings.title = parts[0];
        if (parts.size() >= 5) {
          settings.size = std::atoi(parts[1].c_str());
          settings.players = std::atoi(parts[2].c_str());
          settings.height = static_cast<float>(std::atof(parts[3].c_str()));
          settings.seaLevel = static_cast<float>(std::atof(parts[4].c_str()));
          settings.sea = settings.seaLevel > 0.0f;
        }
        if (parts.size() >= 6) {
          settings.sizeZ = std::atoi(parts[5].c_str()); // a depth of its own (the size list's index)
        }
        mNewMapSpec.clear();
        std::string message;
        if (mDocument.CreateNew(settings, message)) {
          gpg::Logf("editor: %s", message.c_str());
        } else {
          gpg::Warnf("editor: %s", message.c_str());
        }
      }
      const bool finished = mDocument.Poll();
      // A new map folder made: mounted at /maps/<folder> as the game's init mounts the vault's, listed, opened.
      std::filesystem::path folder;
      std::string scenario;
      if (finished && mDocument.TakeCreated(folder, scenario)) {
        // The game's file system is always a CVFSImpl (VFS_Create, 0x00467F90).
        if (auto* const vfs = static_cast<moho::CVFSImpl*>(moho::DISK_GetVFS()); vfs != nullptr) {
          // The rules and the sim's Lua built ahead read the mounts on their threads, and the mounts
          // have no lock: a push that moves them under such a reader crashed it (EnumerateFiles).
          moho::RULE_FinishPreparingKept();
          moho::SIM_FinishPreparingLuaState();
          vfs->MountDirectoryLate(folder, ("/maps/" + folder.filename().string()).c_str());
        }
        mPlay.FindMaps();
        (void)mDocument.Open(scenario);
        if (mResize.has_value() && mResize->scenario.empty()) {
          mResize->scenario = scenario;
        }
      }
      if (EdShell::ResizeRequest ask; mShell->TakeResize(ask)) {
        StartResize(ask);
      }
      if (
        mResize.has_value() && !mResize->scenario.empty() && mScene.Attached() &&
        mDocument.GetState() == EdDocument::State::Open && mDocument.Path() == mResize->scenario &&
        ++mResize->frames == 30
      ) {
        FinishResize();
      }
      DriveHeightFiles();
      if (mSymCheckMode >= 0 && mScene.Attached()) {
        ++mSymCheckFrames;
        if (mSymCheckFrames == 120) {
          mShell->Tools().SetSymmetry(mSymCheckMode, mSymCheckTurns);
          mShell->Tools().RequestCheck();
        } else if (mSymCheckFrames == 150 && mSymCheckRepair) {
          mShell->Tools().RequestRepair();
        }
      }
      if (!mSaveAsFolder.empty() && mScene.Attached() && ++mRoundTripFrames == mRoundTripAfter) {
        std::string message;
        const bool saved = mDocument.SaveAsNewFolder(mSaveAsFolder, message);
        if (saved) {
          gpg::Logf("editor: %s", message.c_str());
        } else {
          gpg::Warnf("editor: %s", message.c_str());
        }
        mShell->RequestExit();
      }
      if (mRoundTripShown && mScene.Attached() && ++mRoundTripFrames == mRoundTripAfter) {
        const RoundTripResult trip = RoundTripMap(mDocument, mRoundTripFolder);
        gpg::Logf(
          "editor: round trip of the drawn %s: %s%s",
          MapDisplayName(mDocument.Path()).c_str(),
          trip.ok ? "same data, stable" : trip.differences.c_str(),
          trip.sameAsOriginal ? ", same bytes as the original" : ""
        );
        mShell->RequestExit();
      }
      if (!mOpenAll) {
        return;
      }
      if (finished) {
        if (mDocument.GetState() == EdDocument::State::Open && mDocument.Error().empty()) {
          ++mOpenAllOpened;
          if (!mRoundTripFolder.empty()) {
            const RoundTripResult trip = RoundTripMap(mDocument, mRoundTripFolder);
            mRoundTripOk += trip.ok ? 1 : 0;
            mRoundTripDiskFiles += trip.hasDiskFile ? 1 : 0;
            mRoundTripSameBytes += trip.sameAsOriginal ? 1 : 0;
            gpg::Logf(
              "editor: round trip %s: %s%s%s",
              MapDisplayName(mDocument.Path()).c_str(),
              trip.ok ? "same data" : trip.differences.c_str(),
              trip.hasDiskFile
                ? (trip.sameAsOriginal ? ", same bytes as the original" : ", other bytes than the original")
                : "",
              trip.stable ? "" : ", NOT stable"
            );
          }
        } else {
          mOpenAllFailed.push_back(MapDisplayName(mDocument.Path()) + ": " + mDocument.Error());
        }
      }
      if (mDocument.GetState() == EdDocument::State::Loading) {
        return;
      }
      const std::vector<std::string>& maps = mPlay.Maps();
      if (mOpenAllNext < maps.size()) {
        (void)mDocument.Open(maps[mOpenAllNext++]);
        return;
      }
      mOpenAll = false;
      gpg::Logf("editor: opened %d of %zu maps fully", mOpenAllOpened, maps.size());
      if (!mRoundTripFolder.empty()) {
        gpg::Logf(
          "editor: round trip: %d of %d maps read back with the same data; %d of the %d with a file of their own "
          "saved to the same bytes",
          mRoundTripOk,
          mOpenAllOpened,
          mRoundTripSameBytes,
          mRoundTripDiskFiles
        );
      }
      for (const std::string& failure : mOpenAllFailed) {
        gpg::Warnf("editor:   %s", failure.c_str());
      }
      mDocument.Close();
      mShell->RequestExit();
    }

    void EditorApp::RenderPanels()
    {
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      const gpg::gal::DeviceContext* const context = device->GetDeviceContext();
      if (context->GetHeadCount() <= static_cast<int>(kPanelHead) || ::IsIconic(HandleOf(mGame.supcomFrame)) != FALSE) {
        return;
      }
      // The panels' head, drawn now and presented with the game's head at the game's next paint
      // (CD3DDevice::Paint presents every head).
      const gpg::gal::Head& head = context->GetHead(kPanelHead);
      CopyGameView();
      device->ClearTarget(device->GetHeadOutputContext(kPanelHead));
      device->BeginScene();
      D3DVIEWPORT9 viewport{};
      viewport.Width = head.mWidth;
      viewport.Height = head.mHeight;
      viewport.MaxZ = 1.0f;
      device->SetViewport(&viewport);
      device->Clear(true, false, false, 0xFF1C1F25U, 1.0f, 0);
      mRenderer.Render(ImGui::GetDrawData());
      device->EndScene();
    }

    void EditorApp::CopyGameView()
    {
      // The game's head holds the frame it drew last (CD3DDevice::Paint presents, then draws the next one), not yet
      // presented: copied into a target the panels draw under themselves, also while a dialog is open (it doesn't hide
      // it).
      mViewImage = 0;
      gViewSurface = nullptr;
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      moho::CD3DDevice* const d3d = moho::D3D_GetDevice();
      const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
      if (
        !gComposite || d3d == nullptr || context == nullptr || context->GetHeadCount() < 1 ||
        d3d->GetResources() == nullptr
      ) {
        return;
      }
      const gpg::gal::Head& game = context->GetHead(0);
      if (game.mWidth == 0 || game.mHeight == 0) {
        return;
      }
      bool fresh = false;
      if (!mViewCopy || mViewCopyWidth != game.mWidth || mViewCopyHeight != game.mHeight) {
        fresh = true;
        // The old copy goes: nothing may still point at it (a return below, before the new one is filled, would leave
        // the panels' renderer reading a freed target).
        gViewSurface = nullptr;
        mViewSurface.reset();
        mViewImage = 0;
        mViewCopy.reset();
        moho::ID3DDeviceResources::RenderTargetHandle target;
        (void)d3d->GetResources()->CreateRenderTarget(
          target, static_cast<int>(game.mWidth), static_cast<int>(game.mHeight), 2
        );
        mViewCopy = target;
        mViewCopyWidth = game.mWidth;
        mViewCopyHeight = game.mHeight;
        gpg::Logf("editor: the 3D view composited into the panels (%ux%u)", game.mWidth, game.mHeight);
      }
      const gpg::gal::OutputContext* const output = device->GetHeadOutputContext(0);
      if (!mViewCopy || output == nullptr || !output->surface) {
        return;
      }
      moho::ID3DRenderTarget::SurfaceHandle copy;
      (void)mViewCopy->GetSurface(copy);
      if (!copy) {
        return;
      }
      // A frame with the overhead minimap drawn into its corner: copied around the minimap's rectangle, which keeps
      // the view's last pixels there. The panels draw the minimap rounded over it, so the raw square one would show at
      // the rounded corners every time it is drawn again (a flicker).
      const float* const mini = mScene.MiniMapRect();
      const LONG width = static_cast<LONG>(game.mWidth);
      const LONG height = static_cast<LONG>(game.mHeight);
      const LONG left = std::clamp(static_cast<LONG>(std::floor(mini[0])), 0L, width);
      const LONG top = std::clamp(static_cast<LONG>(std::floor(mini[1])), 0L, height);
      const LONG right = std::clamp(static_cast<LONG>(std::ceil(mini[0] + mini[2])), left, width);
      const LONG bottom = std::clamp(static_cast<LONG>(std::ceil(mini[1] + mini[3])), top, height);
      if (!fresh && mScene.MiniMapInLastFrame() && right > left && bottom > top) {
        const RECT parts[4] = {
          {0, 0, width, top},          // above
          {0, top, left, bottom},      // left of it
          {right, top, width, bottom}, // right of it
          {0, bottom, width, height},  // below
        };
        for (const RECT& part : parts) {
          if (part.right > part.left && part.bottom > part.top) {
            device->StretchRect(output->surface, copy, &part, &part);
          }
        }
      } else {
        device->StretchRect(output->surface, copy, nullptr, nullptr);
      }
      mViewImage = EdImGuiRenderer::TargetImage(copy.get());
      mViewSurface = copy;
      gViewSurface = copy.get();
      CopyMiniMap(*device, *d3d, output->surface);
    }

    void EditorApp::CopyMiniMap(
      gpg::gal::Device& device,
      moho::CD3DDevice& d3d,
      const boost::shared_ptr<gpg::gal::RenderTarget>& output
    )
    {
      EdTools& tools = mShell->Tools();
      const float* const rect = mScene.MiniMapRect();
      const int width = static_cast<int>(rect[2]);
      const int height = static_cast<int>(rect[3]);
      if (width < 8 || height < 8) {
        tools.SetMinimapImage(0);
        mScene.SetMiniMapCached(false);
        return;
      }
      if (mScene.MiniMapInLastFrame()) {
        if (!mMiniCopy || mMiniCopyWidth != width || mMiniCopyHeight != height) {
          mMiniCopy.reset();
          moho::ID3DDeviceResources::RenderTargetHandle target;
          (void)d3d.GetResources()->CreateRenderTarget(target, width, height, 2);
          mMiniCopy = target;
          mMiniCopyWidth = width;
          mMiniCopyHeight = height;
        }
        moho::ID3DRenderTarget::SurfaceHandle surface;
        if (mMiniCopy) {
          (void)mMiniCopy->GetSurface(surface);
        }
        if (surface) {
          const RECT from{
            static_cast<LONG>(rect[0]),
            static_cast<LONG>(rect[1]),
            static_cast<LONG>(rect[0]) + width,
            static_cast<LONG>(rect[1]) + height
          };
          device.StretchRect(output, surface, &from, nullptr);
          mMiniSurface = surface;
          tools.SetMinimapImage(EdImGuiRenderer::TargetImage(surface.get()));
        }
      }
      // Once a copy exists the minimap needn't be drawn every frame.
      mScene.SetMiniMapCached(tools.MinimapImage() != 0);
    }

    bool EditorApp::FitGameView()
    {
      const HWND frame = HandleOf(mGame.supcomFrame);
      const HWND view = HandleOf(moho::ren_Viewport);
      moho::CD3DDevice* const d3d = moho::D3D_GetDevice();
      if (frame == nullptr || view == nullptr || d3d == nullptr || ::IsIconic(frame) != FALSE) {
        return false;
      }
      RECT client{};
      ::GetClientRect(frame, &client);
      const int clientWidth = std::max(1L, client.right);
      const int clientHeight = std::max(1L, client.bottom);

      // The game's picture fills the dock layout's middle (ImGui's pixels are the panels' window's, which covers
      // the frame's client area from its corner).
      const ImVec4 middle = mShell->GameViewRect();
      int x = static_cast<int>(middle.x);
      int y = static_cast<int>(middle.y);
      int width = std::max(64, static_cast<int>(middle.z));
      int height = std::max(64, static_cast<int>(middle.w));
      if (middle.z <= 0.0f || middle.w <= 0.0f) {
        x = 0;
        y = 0;
        width = clientWidth;
        height = clientHeight;
      }

      // The game's view is a window of its own over the panels' window, so anything of the panels' that reaches
      // over it would be hidden: while a modal dialog (New map, Save as, the texture browser) is open the view's
      // window region is empty, and a tooltip, menu or drop-down list over it is cut out of the region, so they
      // show through. Hiding the window instead would stop its paint, and the panels' head is presented with it.
      // The Maps window too: a window the panels draw over the view can't move smoothly through a cut-out, as
      // the view's picture reaches the screen a frame or two apart from the panels' (user report: it lagged).
      const bool modal = mImGuiReady &&
        (ImGui::GetTopMostPopupModal() != nullptr || (!gComposite && mShell != nullptr && mShell->Browser().Open()));
      std::vector<RECT> holes;
      if (mImGuiReady && !modal) {
        for (const ImGuiWindow* const window : ImGui::GetCurrentContext()->Windows) {
          // A window not docked into the layout (the Maps window, the Material Editor, any panel pulled out) floats
          // over the view and takes the mouse there; the dock space's own host window (behind everything) doesn't.
          const bool undocked = (window->Flags & ImGuiWindowFlags_NoBringToFrontOnFocus) == 0 &&
            (window->DockNode == nullptr || ImGui::DockNodeGetRootNode(window->DockNode)->IsFloatingNode());
          const bool floating = undocked ||
            std::strncmp(window->Name, EdMapBrowser::kWindowName, std::strlen(EdMapBrowser::kWindowName)) == 0;
          if (
            !window->WasActive || window->Hidden ||
            ((window->Flags & (ImGuiWindowFlags_Tooltip | ImGuiWindowFlags_Popup | ImGuiWindowFlags_ChildMenu)) == 0 &&
             !floating) ||
            (window->Flags & ImGuiWindowFlags_ChildWindow) != 0
          ) {
            continue;
          }
          RECT hole{
            static_cast<LONG>(window->Pos.x) - x,
            static_cast<LONG>(window->Pos.y) - y,
            static_cast<LONG>(window->Pos.x + window->Size.x + 1.0f) - x,
            static_cast<LONG>(window->Pos.y + window->Size.y + 1.0f) - y
          };
          if (hole.right > 0 && hole.bottom > 0 && hole.left < width && hole.top < height) {
            holes.push_back(hole);
          }
        }
      }
      // The panels' picture reaches the screen with the game's next present, a frame or two after this region
      // does, so a popup or window that moves (a tooltip following the cursor, the Maps window dragged) keeps the
      // holes of the frames before too: the hole never runs ahead of what is drawn in it, which showed as the
      // picture lagging and tooltips flickering (user report).
      gViewWindow = view;
      gViewRect = RECT{x, y, x + width, y + height};
      gOverView.clear();
      for (const RECT& hole : holes) {
        gOverView.push_back(RECT{hole.left + x, hole.top + y, hole.right + x, hole.bottom + y});
      }
      mHoleHistory.push_front(holes);
      while (mHoleHistory.size() > 3) {
        mHoleHistory.pop_back();
      }
      holes.clear();
      for (const std::vector<RECT>& frameHoles : mHoleHistory) {
        holes.insert(holes.end(), frameHoles.begin(), frameHoles.end());
      }
      const auto sameHoles = [&] {
        if (holes.size() != mViewHoles.size()) {
          return false;
        }
        for (std::size_t i = 0; i < holes.size(); ++i) {
          if (::EqualRect(&holes[i], &mViewHoles[i]) == FALSE) {
            return false;
          }
        }
        return true;
      };
      // Composited, the view's window shows nothing of its own: an empty region, as while a dialog is open.
      const bool emptyRegion = modal || gComposite;
      if (emptyRegion != mViewStepsAside || (!emptyRegion && !sameHoles())) {
        mViewStepsAside = emptyRegion;
        mViewHoles = holes;
        HRGN region = nullptr;
        if (emptyRegion) {
          region = ::CreateRectRgn(0, 0, 0, 0);
        } else if (!holes.empty()) {
          region = ::CreateRectRgn(0, 0, width, height);
          for (const RECT& hole : holes) {
            const HRGN cut = ::CreateRectRgnIndirect(&hole);
            (void)::CombineRgn(region, region, cut, RGN_DIFF);
            ::DeleteObject(cut);
          }
        }
        // The window owns the region from here on (SetWindowRgn).
        ::SetWindowRgn(view, region, TRUE);
      }

      RECT panel{};
      ::GetClientRect(gPanelWindow, &panel);
      if (panel.right != clientWidth || panel.bottom != clientHeight) {
        ::MoveWindow(gPanelWindow, 0, 0, clientWidth, clientHeight, FALSE);
      }
      RECT viewRect{};
      ::GetWindowRect(view, &viewRect);
      ::MapWindowPoints(nullptr, frame, reinterpret_cast<POINT*>(&viewRect), 2);
      if (
        viewRect.left != x || viewRect.top != y || viewRect.right - viewRect.left != width ||
        viewRect.bottom - viewRect.top != height
      ) {
        moho::ren_Viewport->SetSize(x, y, width, height);
      }

      // The heads follow: the game's head 0 the viewport, the panels' head the client area. The game's own frame
      // handler sets head 0 to the whole client area when the window is resized; this puts it back.
      const gpg::gal::DeviceContext* const active = gpg::gal::Device::GetInstance()->GetDeviceContext();
      if (active->GetHeadCount() <= static_cast<int>(kPanelHead)) {
        return false;
      }
      const gpg::gal::Head& gameHead = active->GetHead(0);
      const gpg::gal::Head& panelHead = active->GetHead(kPanelHead);
      if (
        gameHead.mWidth != static_cast<std::uint32_t>(width) ||
        gameHead.mHeight != static_cast<std::uint32_t>(height) ||
        panelHead.mWidth != static_cast<std::uint32_t>(clientWidth) ||
        panelHead.mHeight != static_cast<std::uint32_t>(clientHeight)
      ) {
        gpg::gal::DeviceContext context(*active);
        context.GetHead(0).mWidth = static_cast<std::uint32_t>(width);
        context.GetHead(0).mHeight = static_cast<std::uint32_t>(height);
        context.GetHead(kPanelHead).mWidth = static_cast<std::uint32_t>(clientWidth);
        context.GetHead(kPanelHead).mHeight = static_cast<std::uint32_t>(clientHeight);
        // The copies of the view and the minimap are targets of the context about to be re-made: nothing may point
        // at them afterwards (a workspace whose panels resize the view crashed drawing the stale copy).
        gViewSurface = nullptr;
        mViewSurface.reset();
        mViewImage = 0;
        mViewCopy.reset();
        mViewCopyWidth = 0;
        mViewCopyHeight = 0;
        mMiniSurface.reset();
        mMiniCopy.reset();
        mMiniCopyWidth = 0;
        mMiniCopyHeight = 0;
        mShell->Tools().SetMinimapImage(0);
        d3d->Clear();
        (void)d3d->InitContext(&context);
        return true;
      }
      return false;
    }

    void EditorApp::Destroy()
    {
      gEditorApp = nullptr;
      if (mImGuiReady) {
        mRenderer.Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        mImGuiReady = false;
      }
      // The opened map's textures go while the device is up; and before the shell, whose Tools panel the scene points
      // at (closing detaches the scene, which clears the panel's selections; user report: a crash on exit there).
      mDocument.Close();
      mScene.SetTools(nullptr);
      delete mShell;
      mShell = nullptr;
      // Ended normally: the marker goes.
      if (!mRunMarker.empty()) {
        std::error_code ec;
        std::filesystem::remove(mRunMarker, ec);
      }
      if (const HWND viewport = HandleOf(moho::ren_Viewport); viewport != nullptr && gViewportProc != nullptr) {
        (void)::SetWindowLongPtrW(viewport, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(gViewportProc));
      }
      if (const HWND frame = HandleOf(mGame.supcomFrame); frame != nullptr && gFrameProc != nullptr) {
        (void)::SetWindowLongPtrW(frame, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(gFrameProc));
      }
      // Kept rules go while the engine is up, and a session still playing deletes its own.
      moho::RULE_SetKeepBetweenSessions(false);
      mGame.Destroy();
      exitValue = mGame.exitValue;
    }
  } // namespace

  namespace
  {
    /** `gpg::Die` writes the crash report and ends the process, as the game's WinMain sets it up. */
    void EditorDieHandler(
      const char* const message
    )
    {
      gpg::diag::CrashReportContext reportContext{};
      reportContext.reason = (message != nullptr) ? message : "engine Die()";
      gpg::diag::HandleFatalPath(reportContext);
    }

    /**
     * The accessibility hotkeys (sticky, toggle and filter keys) the game turns off while it runs, so holding
     * Shift doesn't open their dialogs, and puts back when it ends (WinMain's
     * ConfigureAccessibilitySystemParameters).
     */
    class AccessibilityKeys
    {
    public:
      AccessibilityKeys()
      {
        (void)::SystemParametersInfoW(SPI_GETSTICKYKEYS, sizeof(STICKYKEYS), &mSticky, 0);
        (void)::SystemParametersInfoW(SPI_GETTOGGLEKEYS, sizeof(TOGGLEKEYS), &mToggle, 0);
        (void)::SystemParametersInfoW(SPI_GETFILTERKEYS, sizeof(FILTERKEYS), &mFilter, 0);
        if ((mSticky.dwFlags & SKF_STICKYKEYSON) == 0) {
          STICKYKEYS next = mSticky;
          next.dwFlags &= ~(SKF_HOTKEYACTIVE | SKF_CONFIRMHOTKEY);
          (void)::SystemParametersInfoW(SPI_SETSTICKYKEYS, sizeof(STICKYKEYS), &next, 0);
        }
        if ((mToggle.dwFlags & TKF_TOGGLEKEYSON) == 0) {
          TOGGLEKEYS next = mToggle;
          next.dwFlags &= ~(TKF_HOTKEYACTIVE | TKF_CONFIRMHOTKEY);
          (void)::SystemParametersInfoW(SPI_SETTOGGLEKEYS, sizeof(TOGGLEKEYS), &next, 0);
        }
        if ((mFilter.dwFlags & FKF_FILTERKEYSON) == 0) {
          FILTERKEYS next = mFilter;
          next.dwFlags &= ~(FKF_HOTKEYACTIVE | FKF_CONFIRMHOTKEY);
          (void)::SystemParametersInfoW(SPI_SETFILTERKEYS, sizeof(FILTERKEYS), &next, 0);
        }
      }

      ~AccessibilityKeys()
      {
        (void)::SystemParametersInfoW(SPI_SETSTICKYKEYS, sizeof(STICKYKEYS), &mSticky, 0);
        (void)::SystemParametersInfoW(SPI_SETTOGGLEKEYS, sizeof(TOGGLEKEYS), &mToggle, 0);
        (void)::SystemParametersInfoW(SPI_SETFILTERKEYS, sizeof(FILTERKEYS), &mFilter, 0);
      }

      AccessibilityKeys(const AccessibilityKeys&) = delete;
      AccessibilityKeys& operator=(const AccessibilityKeys&) = delete;

    private:
      STICKYKEYS mSticky{sizeof(STICKYKEYS), 0};
      TOGGLEKEYS mToggle{sizeof(TOGGLEKEYS), 0};
      FILTERKEYS mFilter{sizeof(FILTERKEYS), 0, 0, 0, 0, 0};
    };
  } // namespace

  int RunEditor()
  {
    // What the game's WinMain does around its app, for the same app inside the editor.
    gpg::SetThreadName(0xFFFFFFFFU, "Main");
    gpg::diag::InstallCrtDiagnosticHooks({});
    (void)gpg::SetDieHandler(&EditorDieHandler);
    const AccessibilityKeys accessibilityKeys;

    int exitCode = 0;
    try {
      EditorApp app;
      moho::WIN_AppExecute(&app);
      exitCode = app.exitValue;
    } catch (const gpg::gal::Error& galError) {
      gpg::Die("GAL Exception: file : %s(%d)\nerror: %s", galError.GetFile(), galError.GetLine(), galError.what());
    } catch (const std::exception& error) {
      gpg::Die("Unhandled exception:\n\n%s", error.what());
    }
    return exitCode;
  }
} // namespace faf::editor

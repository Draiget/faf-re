#include "editor/doc/EdScenarioInfo.h"
#include "editor/EdApp.h"
#include "editor/terrain/gpu/EdGpuOps.h"
#include "editor/ui/EdControls.h"
#include "editor/EdPath.h"
#include "editor/view/EdPropThumbnails.h"
#include "editor/doc/EdAdaptiveTables.h"
#include <utility>
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
#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"
#include "lua/luaplus/include/lauxlib.h"
#include "editor/tools/EdTextureFiles.h"
#include "editor/tools/EdScm.h"
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
#include "editor/ui/EdPerf.h"
#include "editor/tools/EdErosionSuite.h"
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
#include "moho/app/UserWorkerPool.h"
#include "editor/doc/EdLookMoods.h"
#include "editor/tools/EdMeshImport.h"
#include "lua/LuaTableIterator.h"
#include "editor/ui/EdPopouts.h"
#include "editor/ui/EdTipCheck.h"
#include "editor/ui/EdUiQa.h"
#include "editor/ui/EdSelfTests.h"
#include "editor/tools/EdMissionImport.h"
#include "editor/tools/EdUnitWizard.h"
#include "editor/doc/EdStrataThemes.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdFramePacing.h"
#include "editor/doc/EdUserFiles.h"
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
#include <ranges>

// imgui_impl_win32.h leaves this declaration to the application.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace moho
{
  extern bool ren_TerrainSurface; // the height field's surface drawn (WRenViewport.cpp)
} // namespace moho

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
        "/tipcheck",
        "/fieldstest",
        "/popouttest",
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
        "/maskstamptest",
        "/flattentest",
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
        "/console",
        "/pathtest",
        "/keptpathtest",
        "/skeletontest",
        "/gputest",
        "/clicksweep",
        "/perf",
        "/layoutcheck",
        "/selftests",
        "/meshtest",
        "/meshimport2",
        "/layoutchannel",
        "/meshask",
        "/exportpkg",
        "/checksettings",
        "/meshwire",
        "/gfxpreset",
        "/resourcecheck",
        "/viewstage",
        "/layoutsave",
        "/unittestgame",
        "/reseattest",
        "/exportpreview512",
        "/lookthumbtest",
        "/toolsfile",
        "/watermasks",
        "/imagestest",
        "/themesfile",
        "/themelib",
        "/r6test",
        "/r7test",
        "/r8test",
        "/r8inspect",
        "/r9test",
        "/iconrecipe",
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
    // While the QA runs press buttons: Windows' file dialogs are modal and stop the frame loop, so they don't open
    // (they answer as if cancelled).
    bool gNoFileDialogs = false;

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
    /** Pop-out windows made with the device (settings.ini Popouts, `/nopopouts` none). */
    int gPopoutHeads = 4;
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
          if (name.size() > 13 && name.ends_with("_scenario.lua")) {
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
        return message == WM_SETCURSOR ? TRUE : 0; // (the cursor set: no further processing)
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
      if (gPopoutHeads > 0) {
        popouts::AddHeads(context, frame, gPopoutHeads, kPanelHead + 1U);
      }
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
      /** The tools' working state (tools.ini in the settings folder; `/toolsfile <file>` in test runs). */
      std::filesystem::path mToolStateFile;
      std::string mToolStateSaved;
      double mToolStateCheckAt = 0.0;
      bool mToolStateRead = false;
      void KeepToolState()
      {
        EdTools& tools = mShell->Tools();
        const double now = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
        if (!mToolStateRead) {
          mToolStateRead = true;
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/toolsfile", 1, &file) && !file.empty()) {
            mToolStateFile = file[0].c_str();
          } else if (!gTestRun) {
            const std::filesystem::path folder = EditorSettingsFolder();
            mToolStateFile = folder.empty() ? std::filesystem::path{} : folder / "tools.ini";
          }
          if (mToolStateFile.empty()) {
            return;
          }
          if (std::ifstream in(mToolStateFile, std::ios::binary); in) {
            std::stringstream text;
            text << in.rdbuf();
            tools.LoadToolState(text.str());
            gpg::Logf("editor: the tools' state read from %s", mToolStateFile.string().c_str());
          }
          mToolStateSaved = tools.SaveToolState();
          mToolStateCheckAt = now + 2.0;
          return;
        }
        if (mToolStateFile.empty() || now < mToolStateCheckAt) {
          return;
        }
        mToolStateCheckAt = now + 2.0;
        const std::string state = tools.SaveToolState();
        if (state == mToolStateSaved) {
          return;
        }
        mToolStateSaved = state;
        if (std::ofstream out(mToolStateFile, std::ios::binary | std::ios::trunc); out) {
          out << state;
          gpg::Logf("editor: the tools' state kept in %s", mToolStateFile.string().c_str());
        }
      }
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
        scale = std::clamp(scale, kMinUiScale, kMaxUiScale);
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
        const std::vector<std::string> keyProblems = ReadKeymap(mCommands, text.str());
        for (const std::string& problem : keyProblems) {
          gpg::Warnf("editor: %s: %s", mKeysFile.filename().string().c_str(), problem.c_str());
        }
        if (!keyProblems.empty()) {
          if (const std::filesystem::path bad = KeepBadCopy(mKeysFile); !bad.empty()) {
            gpg::Warnf("editor: keys: the file as it was is kept as %s", bad.string().c_str());
          }
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
          // A file from a newer editor is read but never written over; one with lines this editor can't read is
          // kept as settings.ini.bad before it is written again (FAF Studio's userdata rules).
          if (mSettings.FileFormat() > EdSettings::kFormatNow) {
            mSettingsWritable = false;
            mSettingsProblems.push_back(
              "made by a newer editor (format " + std::to_string(mSettings.FileFormat()) + "): it is not written over"
            );
          } else if (!mSettingsProblems.empty()) {
            if (const std::filesystem::path bad = KeepBadCopy(mSettingsFile); !bad.empty()) {
              mSettingsProblems.push_back("the file as it was is kept as " + bad.string());
            }
          }
        }
        gPopoutHeads =
          moho::CFG_GetArgOption("/nopopouts", 0, nullptr) || !mSettings.GetBool(EdSettings::kPopouts) ? 0 : 4;
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
        const auto now = std::chrono::steady_clock::now();
        const HWND front = ::GetForegroundWindow();
        const HWND frame = HandleOf(mGame.supcomFrame);
        // A pop-out window in front is the editor's too (owned by the frame).
        const bool behind = front != frame && (front == nullptr || ::GetAncestor(front, GA_ROOT) != frame) &&
          (front == nullptr || ::GetWindow(front, GW_OWNER) != frame);
        // FAF Studio's pacing (ui/EdFramePacing): the background cap, the idle cap after a few seconds without input
        // (the system's last input: the editor is in front), 60 while models load, none while playing.
        LASTINPUTINFO input{sizeof(LASTINPUTINFO), 0};
        (void)::GetLastInputInfo(&input);
        PacingState pacing;
        pacing.foreground = !behind;
        pacing.playing = mPlay.Active();
        pacing.loading = mShell->Tools().ModelsLoading();
        pacing.secondsSinceInput = static_cast<double>(::GetTickCount() - input.dwTime) / 1000.0;
        pacing.backgroundFps = mSettings.GetInt(EdSettings::kBackgroundFps);
        pacing.idleFps = mSettings.GetInt(EdSettings::kIdleFps);
        // The self tests' frame budget measures the editor's own frames, never the pacing's wait.
        const int cap = uncapped || mSelfTests.Running() ? 0 : PacedFps(pacing);
        if (cap > 0) {
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
            if (ImGui::Button("Reset user settings...")) {
              (void)mCommands.Run("help.resetsettings");
            }
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
            if (
              FillSliderInt(
                "##uiscale",
                &percent,
                static_cast<int>(std::lround(kMinUiScale * 100.0f)),
                static_cast<int>(std::lround(kMaxUiScale * 100.0f)),
                "%d %%",
                ImGuiSliderFlags_AlwaysClamp
              )
            ) {
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
            SettingLabel(
              "Frame rate when idle",
              "In front but untouched for 3 seconds (no play running), the editor draws at most this often; any "
              "input brings the full rate back."
            );
            (void)SettingChoice(
              EdSettings::kIdleFps, {{"10", "10 fps"}, {"30", "30 fps"}, {"60", "60 fps"}, {"0", "No limit"}}
            );
            SettingLabel(
              "Pop-out windows",
              "A panel dragged out of the editor's window gets a window of its own (up to four). Changes when the "
              "editor starts again."
            );
            {
              bool popouts = mSettings.GetBool(EdSettings::kPopouts);
              if (ImGui::Checkbox("Panels can leave the window", &popouts)) {
                (void)mSettings.SetBool(EdSettings::kPopouts, popouts);
                SaveSettings();
              }
            }
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
            DrawGraphicsSettings();
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
        if (const auto written = mDocument.WriteSnapshot(folder); !written) {
          gpg::Warnf("editor: autosave of %s failed: %s", mDocument.FolderName().c_str(), written.error().c_str());
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
        const auto restored = RestoreAutosave(entry, mBackupRoot, std::max(3, mSettings.GetInt(EdSettings::kBackups)));
        if (!restored) {
          gpg::Warnf("editor: recover %s: %s", entry.title.c_str(), restored.error().c_str());
          PostStatusMessage("Recover failed: " + restored.error());
          return;
        }
        gpg::Logf(
          "editor: recovered %s from %s (its files before are in %s)",
          entry.title.c_str(),
          entry.folder.string().c_str(),
          restored->string().c_str()
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
      std::expected<Look, std::string> LoadLook(
        const std::string& id
      )
      {
        if (const auto cached = mLookCache.find(id); cached != mLookCache.end()) {
          return cached->second;
        }
        Look look;
        if (id.starts_with("mood:")) {
          // A shipped mood or biome (doc/EdLookMoods): its light over the map's own look.
          const LookMood* const mood = FindLookMood(id.substr(5));
          if (mood == nullptr) {
            return std::unexpected("no look " + id);
          }
          look = LookOfEnvironment(mDocument.LookEnvironmentNow());
          look.name = mood->name;
          look.lighting = MoodLighting(*mood, look.lighting);
          mLookCache[id] = look;
          return look;
        }
        if (id.starts_with("mine:")) {
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
            return std::unexpected("no look named " + name);
          }
          (void)LightingFromScmlighting(text, look.lighting);
          if (read(std::filesystem::path(base).replace_extension(".scmwtr"), text)) {
            (void)WaterFromScmwtr(text, look.water);
          }
          if (read(std::filesystem::path(base).replace_extension(".scmskybox"), text)) {
            look.hasSky = SkyboxFromScmskybox(text, look.sky).has_value();
          }
        } else {
          std::string text;
          std::string bytes;
          std::smatch path;
          if (
            !ReadGameFile(id, text) ||
            !std::regex_search(text, path, std::regex(R"(\bmap\s*=\s*['"]([^'"]+\.scmap)['"])"))
          ) {
            return std::unexpected(id + " names no map file");
          }
          if (!ReadGameFile(path[1].str(), bytes)) {
            return std::unexpected("can't read " + path[1].str());
          }
          auto read = LookFromScmap(bytes);
          if (!read) {
            return std::unexpected(path[1].str() + ": " + read.error());
          }
          look = std::move(*read);
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
        return look;
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
          if (mLookThumbGround.ready) {
            mShell->ClearLookThumbs();
            mLookThumbGround = {};
          }
          return;
        }
        if (mShell->TakeLookThumbsRedraw()) {
          mShell->ClearLookThumbs();
          mLookThumbGround = {};
        }
        fa::vector<fa::string> thumbDir;
        const bool thumbTest = moho::CFG_GetArgOption("/lookthumbtest", 1, &thumbDir) && !thumbDir.empty();
        if (thumbTest && !mLookThumbTestQueued && mScene.Attached()) {
          mLookThumbTestQueued = true;
          mShell->ShowLighting() = true; // its Looks rows then ask for theirs (logged below as they come)
          for (std::size_t i = 0; i < LookMoods().size() && i < 3; ++i) {
            mLookThumbTest.push_back(std::string("mood:") + LookMoods()[i].id);
          }
        }
        const auto takeThumb = [&](std::string& id) {
          if (mLookThumbTest.empty()) {
            const bool asked = mShell->TakeLookThumbWanted(id);
            if (asked) {
              ++mLookThumbsForRows;
            } else if (mLookThumbsForRows > 0) {
              gpg::Logf("editor: look pictures: %d made for the Looks rows on screen", mLookThumbsForRows);
              mLookThumbsForRows = 0;
            }
            return asked;
          }
          id = mLookThumbTest.front();
          mLookThumbTest.erase(mLookThumbTest.begin());
          return true;
        };
        if (std::string wanted; mScene.Attached() && takeThumb(wanted)) {
          // One look's picture a frame: this map in its layers' colours under the look's own sun.
          constexpr int kLookThumbSide = 64;
          std::uint64_t image = 0;
          std::string error;
          if (const auto look = LoadLook(wanted); !look) {
            error = look.error();
          } else {
            std::vector<std::uint32_t> pixels;
            float width = 0.0f;
            float depth = 0.0f;
            std::size_t dots = 0;
            if (PaintPreview(kLookThumbSide, pixels, width, depth, dots, error, &look->lighting, &mLookThumbGround)) {
              image = EdImGuiRenderer::CreateImage(kLookThumbSide, kLookThumbSide, pixels.data());
              if (thumbTest) {
                double mean[3] = {0.0, 0.0, 0.0};
                for (const std::uint32_t p : pixels) {
                  mean[0] += (p >> 16) & 0xFFu;
                  mean[1] += (p >> 8) & 0xFFu;
                  mean[2] += p & 0xFFu;
                }
                const double n = std::max<double>(1.0, static_cast<double>(pixels.size()));
                std::string name = wanted;
                for (char& c : name) {
                  if (std::isalnum(static_cast<unsigned char>(c)) == 0) {
                    c = '_';
                  }
                }
                std::string written;
                const std::filesystem::path out = std::filesystem::path(thumbDir[0].c_str()) / (name + ".png");
                if (const auto wrote = WriteColourPng(out, kLookThumbSide, kLookThumbSide, pixels); !wrote) {
                  written = wrote.error();
                }
                gpg::Logf(
                  "editor: look picture %s: %d x %d, mean colour %.0f %.0f %.0f, image %s, %s",
                  wanted.c_str(),
                  kLookThumbSide,
                  kLookThumbSide,
                  mean[0] / n,
                  mean[1] / n,
                  mean[2] / n,
                  image != 0U ? "made" : "not made",
                  written.empty() ? out.string().c_str() : written.c_str()
                );
              }
            }
          }
          if (image == 0U) {
            gpg::Logf("editor: look %s has no picture: %s", wanted.c_str(), error.c_str());
          }
          mShell->SetLookThumb(wanted, image);
        }
        EdShell::LookRequest ask;
        if (!mShell->TakeLookRequest(ask)) {
          return;
        }
        using What = EdShell::LookRequest::What;
        const auto tryLook = [&]() {
          const auto loaded = LoadLook(ask.id);
          if (!loaded) {
            mShell->SetLookState(mShell->LookTrying() ? mLookTriedId : std::string(), loaded.error());
            gpg::Warnf("editor: look: %s", loaded.error().c_str());
            return false;
          }
          const Look& look = *loaded;
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
          const std::string name = ask.id.starts_with("mine:") ? ask.id.substr(5) : std::string();
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
            const auto copied = mDocument.WritePlayCopy(scenario);
            if (!copied) {
              gpg::Warnf(
                "editor: play: the unsaved edits couldn't be copied (%s); playing the map as saved",
                copied.error().c_str()
              );
              PostStatusMessage("Playing the map as saved: " + copied.error());
              return selected;
            }
            const std::string& message = *copied;
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
            if (p.text.starts_with("base ")) {
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
        auto opened = panel.Open("EditorModTest");
        if (!opened) {
          opened = panel.Create("EditorModTest");
        }
        if (!opened) {
          gpg::Warnf("editor: mod test: no project: %s", opened.error().c_str());
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
          const auto reopened = OpenModProject(panel.Folder());
          const ModProject back = reopened.value_or(ModProject{});
          gpg::Logf(
            "editor: mod test: reopened %s, uid %s, %zu units changed",
            reopened ? "fine" : reopened.error().c_str(),
            back.uid == p.uid ? "kept" : "changed",
            back.edits.size()
          );
          // The checks, with a derived unit (no icon of its own) and a broken change, then the release.
          (void)AddModDerived(p, "xaa0206", id, "", "", [&](const std::string& unit) {
            moho::RResId res{};
            res.name.assign(unit.c_str());
            return rules->GetUnitBlueprint(res) != nullptr;
          });
          (void)SetModEdit(p, id, "Defense.MaxHealth", 0.0, 1.0);
          for (const ModIssue& issue : panel.Check()) {
            gpg::Logf("editor: mod test: check %c %s", issue.level, issue.text.c_str());
          }
          const auto broken = panel.Release();
          gpg::Logf(
            "editor: mod test: release with a broken change: %s",
            !broken ? ("refused: " + broken.error()).c_str() : "made"
          );
          p.edits[id].erase("Defense.MaxHealth");
          p.derived.clear();
          const auto zip = panel.Release();
          gpg::Logf("editor: mod test: release %s", !zip ? zip.error().c_str() : zip->string().c_str());
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

      // Test in game (FAF Studio's unittest.lua): the unit under test and its dummy targets in the play, by SimLua
      // lines (the editor's plays have cheats on); the sim reports the state once a second (EDUNITTEST live).
      bool mUnitTestSpawned = false;
      bool mUnitTestRestart = false; // Restart: the play stopped, played again once it has
      int mUnitTestFrames = 0;
      int mUnitTestScript = 0; // `/unittestgame`: the step of the test run

      /** One line of sim Lua (no line breaks: a console command). */
      static void SimLine(
        std::string lua
      )
      {
        for (char& c : lua) {
          if (c == '\n' || c == '\r') {
            c = ' ';
          }
        }
        moho::CON_Execute(("SimLua " + lua).c_str());
      }

      /** The unit and the targets for an enemy army near the first start, and the thread that reports them. */
      static void SpawnUnitTest(
        const std::string& unit
      )
      {
        std::string id = unit;
        for (char& c : id) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        SimLine(
          "local b = ArmyBrains[1] local e = ArmyBrains[2] if b then "
          "local x, z = b:GetArmyStartPos() x = x + 12 z = z + 12 "
          "local u = CreateUnitHPR('" +
          id +
          "', b.Name, x, GetTerrainHeight(x, z), z, 0, 0, 0) "
          "EdTest = { unit = u, id = '" +
          id +
          "', x = x, z = z, targets = {}, maxes = {}, army = b } "
          "if e then SetAlliance(b:GetArmyIndex(), e:GetArmyIndex(), 'Enemy') "
          "local list = { { 'uel0106', -10, 25 }, { 'ueb2101', 0, 28 }, { 'uea0101', 10, 25 } } "
          "local sx, sz = x + 20, z + 35 "
          "if GetSurfaceHeight(sx, sz) > GetTerrainHeight(sx, sz) + 1 then table.insert(list, { 'ues0103', 20, 35 }) "
          "end "
          "for _, t in list do local tx, tz = x + t[2], z + t[3] "
          "local tu = CreateUnitHPR(t[1], e.Name, tx, GetTerrainHeight(tx, tz), tz, 0, 0, 0) "
          "table.insert(EdTest.targets, tu) table.insert(EdTest.maxes, tu and tu:GetMaxHealth() or 0) end "
          "else LOG('EDUNITTEST note the map has no second army for the targets') end "
          "if not rawget(_G, 'EdTestThread') then EdTestThread = ForkThread(function() while true do "
          "local T = rawget(_G, 'EdTest') if T then local u = T.unit local s "
          "if u and not u:IsDead() then local p = u:GetPosition() "
          "s = 'alive|' .. math.floor(u:GetHealth()) .. '|' .. math.floor(u:GetMaxHealth()) .. '|' .. math.floor(p[1]) "
          ".. '|' .. math.floor(p[3]) .. '|' .. table.getn(u:GetCommandQueue()) "
          "else s = 'dead|0|0|0|0|0' end "
          "local th = '' for _, t in T.targets do if t and not t:IsDead() then "
          "th = th .. math.floor(t:GetHealth()) .. '/' .. math.floor(t:GetMaxHealth()) .. ' ' else th = th .. 'dead ' "
          "end end "
          "local dealt = 0 for i, t in T.targets do local m = T.maxes[i] or 0 "
          "if t and not t:IsDead() then dealt = dealt + m - t:GetHealth() else dealt = dealt + m end end "
          "local built = 0 for _, e in T.army:GetListOfUnits(categories.ALLUNITS, false) do "
          "if e ~= T.unit and e:GetBlueprint().BlueprintId == T.id and e:GetFractionComplete() >= 1 then "
          "built = built + 1 end end "
          "LOG('EDUNITTEST live ' .. T.id .. '|' .. s .. '|' .. th .. '|' .. math.floor(dealt) .. '|' .. built) end "
          "WaitSeconds(1) end end) end end"
        );
        gpg::Logf("editor: test in game: %s and its targets asked for", id.c_str());
      }

      /** A quick order for the unit under test. */
      static void UnitTestOrder(
        const std::string& order
      )
      {
        const std::string unit = "local T = rawget(_G, 'EdTest') local u = T and T.unit if u and not u:IsDead() then ";
        const std::string first = "local t for _, v in T.targets do if v and not v:IsDead() then t = v break end end ";
        const std::string there = "local x, z = T.x, T.z + 40 local p = { x, GetTerrainHeight(x, z), z } ";
        if (order == "attack") {
          SimLine(unit + first + "if t then IssueClearCommands({ u }) IssueAttack({ u }, t) end end");
        } else if (order == "move") {
          SimLine(unit + there + "IssueClearCommands({ u }) IssueMove({ u }, p) end");
        } else if (order == "patrol") {
          SimLine(unit + there + "IssueClearCommands({ u }) IssuePatrol({ u }, p) end");
        } else if (order == "stop") {
          SimLine(unit + "IssueClearCommands({ u }) end");
        } else if (order == "heal") {
          SimLine(unit + "u:SetHealth(u, u:GetMaxHealth()) end");
        } else if (order == "kill") {
          SimLine(unit + "u:Kill() end");
        } else if (order.starts_with("fire:") || order.starts_with("effect:")) {
          // fire:<projectile blueprint>:<speed> / effect:<EffectTemplates name>:<height>; the name goes into Lua, so
          // only path characters pass.
          const std::size_t a = order.find(':');
          const std::size_t b = order.rfind(':');
          std::string name = b > a ? order.substr(a + 1, b - a - 1) : std::string();
          const double number = b > a ? std::atof(order.c_str() + b + 1) : 0.0;
          const bool ok = !name.empty() && std::all_of(name.begin(), name.end(), [](const char c) {
            return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '/' || c == '.' || c == '-';
          });
          if (!ok) {
            gpg::Warnf("editor: test in game: %s isn't a blueprint or template name", name.c_str());
            return;
          }
          char speed[32];
          (void)std::snprintf(speed, sizeof(speed), "%.2f", number);
          if (order[0] == 'f') {
            SimLine(
              unit + "local p = u:CreateProjectile('" + name + "', 0, 1.5, 0, 0, 0.3, 1) if p then p:SetVelocity(" +
              speed + ") LOG('EDUNITTEST note fired " + name + "') end end"
            );
          } else {
            SimLine(
              unit + "local et = import('/lua/effecttemplates.lua') local list = et['" + name +
              "'] "
              "if list then for _, e in list do local em = CreateEmitterAtEntity(u, u:GetArmy(), e) "
              "if em then em:OffsetEmitter(0, " +
              speed + ", 0) end end LOG('EDUNITTEST note played " + name +
              "') else LOG('EDUNITTEST note no effect template " + name + "') end end"
            );
          }
        } else if (order == "build") {
          // Studio's Build: a factory (mobile units) or an engineer (structures) of the game whose build menu has the
          // unit, the tech 1 one first, made near the unit and ordered to build it (proves the build menu entry).
          SimLine(
            "local T = rawget(_G, 'EdTest') if T then local target = __blueprints[T.id] "
            "local hash = target and target.CategoriesHash or {} local structure = hash.STRUCTURE local best "
            "for bid, b in __blueprints do local c = b.CategoriesHash "
            "if c and b.Economy and b.Economy.BuildableCategory and string.sub(bid, 1, 1) ~= 'z' then "
            "local good if structure then good = c.ENGINEER and c.MOBILE and not c.COMMAND and not c.SUBCOMMAND "
            "else good = c.FACTORY and c.STRUCTURE and not c.SUPPORTFACTORY end "
            "if good then for _, cat in b.Economy.BuildableCategory do "
            "local ok, pc = pcall(ParseEntityCategory, cat) "
            "if ok and pc and EntityCategoryContains(pc, T.id) then "
            "if not best or string.sub(bid, 4, 5) == '01' then best = bid end break end end end end end "
            "if not best then LOG('EDUNITTEST note no factory or engineer of the game builds ' .. T.id) else "
            "local x, z = T.x - 14, T.z - 6 "
            "local bu = CreateUnitHPR(best, T.army.Name, x, GetTerrainHeight(x, z), z, 0, 0, 0) "
            "if bu then IssueClearCommands({ bu }) if structure then "
            "IssueBuildMobile({ bu }, Vector(T.x - 14, GetTerrainHeight(T.x - 14, T.z + 10), T.z + 10), T.id, {}) "
            "else IssueBuildFactory({ bu }, T.id, 1) end T.builder = bu "
            "LOG('EDUNITTEST note ' .. best .. ' builds ' .. T.id) end end end"
          );
        } else if (order == "respawn" || order == "end") {
          SimLine(
            "local T = rawget(_G, 'EdTest') if T then if T.unit and not T.unit:IsDead() then T.unit:Destroy() end "
            "for _, t in T.targets do if t and not t:IsDead() then t:Destroy() end end "
            "if T.builder and not T.builder:IsDead() then T.builder:Destroy() end "
            "if '" +
            order + "' == 'end' then rawset(_G, 'EdTest', false) end end"
          );
        }
        gpg::Logf("editor: test in game: %s", order.c_str());
      }

      /**
       * `/unittestgame` (test runs): a project EditorUnitTestGame, uel0201 selected, Test in game; once the unit and
       * its targets report, Attack, then the state 15 s later (the targets' health), End test and Stop.
       */
      void TestUnitInGame()
      {
        if (
          // The map view is detached during the play: only the first step waits for it.
          // ... and the rules are lent to the play's session while it runs (RULE_PeekKept is null then).
          mUnitTestScript >= 10 || (mUnitTestScript == 0 && (!mScene.Attached() || moho::RULE_PeekKept() == nullptr)) ||
          !moho::CFG_GetArgOption("/unittestgame", 0, nullptr)
        ) {
          return;
        }
        static int frames = 0;
        ++frames;
        EdUnitLabPanel& lab = mShell->UnitLab();
        switch (mUnitTestScript) {
        case 0: {
          if (frames < 120) {
            return;
          }
          EdModPanel& panel = mShell->ModPanel();
          auto opened = panel.Open("EditorUnitTestGame");
          if (!opened) {
            opened = panel.Create("EditorUnitTestGame");
          }
          if (!opened) {
            gpg::Warnf("editor: /unittestgame: no project: %s", opened.error().c_str());
            mUnitTestScript = 10;
            return;
          }
          lab.SelectUnit("uel0201");
          lab.AskTestInGame();
          gpg::Logf("editor: /unittestgame: Test in game asked for uel0201");
          mUnitTestScript = 1;
          frames = 0;
          return;
        }
        case 1:
          if (!lab.testStatus.empty()) {
            gpg::Logf("editor: /unittestgame: first state: %s", lab.testStatus.c_str());
            lab.AskTestOrder("attack");
            mUnitTestScript = 2;
            frames = 0;
          } else if (frames > 60 * 90) {
            gpg::Warnf("editor: /unittestgame: no state from the sim after 90 s");
            mUnitTestScript = 9;
          }
          return;
        case 2:
          if (frames == 60 * 15) {
            gpg::Logf("editor: /unittestgame: 15 s after Attack: %s", lab.testStatus.c_str());
            lab.AskTestOrder("heal");
            mUnitTestScript = 3;
            frames = 0;
          }
          return;
        case 3:
          if (frames == 60 * 2) {
            gpg::Logf("editor: /unittestgame: after Heal: %s", lab.testStatus.c_str());
            lab.AskTestOrder("build"); // a factory of the game builds another uel0201
            mUnitTestScript = 4;
            frames = 0;
          }
          return;
        case 4:
          if (frames == 60 * 25) {
            gpg::Logf(
              "editor: /unittestgame: 25 s after Build: %s; note: %s", lab.testStatus.c_str(), lab.testNote.c_str()
            );
            lab.AskTestOrder("respawn");
            mUnitTestScript = 5;
            frames = 0;
          }
          return;
        case 5:
          if (frames == 60 * 2) {
            lab.AskTestOrder("fire:/projectiles/tdfgauss01/tdfgauss01_proj.bp:25.0");
            mUnitTestScript = 6;
            frames = 0;
          }
          return;
        case 6:
          if (frames == 60 * 2) {
            gpg::Logf("editor: /unittestgame: after Fire: note: %s", lab.testNote.c_str());
            lab.AskTestOrder("effect:ConcussionRingMed01:2.0");
            mUnitTestScript = 7;
            frames = 0;
          }
          return;
        case 7:
          if (frames == 60 * 2) {
            gpg::Logf("editor: /unittestgame: after Play effect: note: %s", lab.testNote.c_str());
            lab.AskTestOrder("restart");
            mUnitTestScript = 8;
            frames = 0;
          }
          return;
        case 8:
          // Restarted: a new state from the new play (not the "Restarting..." placeholder).
          if (frames > 60 * 5 && !lab.testStatus.empty() && lab.testStatus != "Restarting..." && mPlay.Active()) {
            gpg::Logf("editor: /unittestgame: after Restart: %s", lab.testStatus.c_str());
            lab.AskTestOrder("end");
            mUnitTestScript = 9;
            frames = 0;
          } else if (frames > 60 * 120) {
            gpg::Warnf("editor: /unittestgame: no state after Restart in 120 s");
            mUnitTestScript = 9;
            frames = 0;
          }
          return;
        case 9:
          if (frames == 60) {
            mPlay.Stop();
            gpg::Logf("editor: /unittestgame: done");
            mUnitTestScript = 10;
          }
          return;
        default:
          return;
        }
      }

      /** Each frame: the asks of the Unit lab's Test in game, the spawn once the play runs, the state, the orders. */
      void DriveUnitTest()
      {
        EdUnitLabPanel& lab = mShell->UnitLab();
        if (lab.TakeTestInGameAsk() && !lab.Unit().empty()) {
          // Every projectile of the game, for Fire (read now: the rules are lent to the play's session while it runs).
          if (
            moho::RRuleGameRules* const rules = moho::RULE_PeekKept(); rules != nullptr && lab.testProjectiles.empty()
          ) {
            for (const auto& [id, blueprint] : rules->GetProjectileBlueprints()) {
              (void)blueprint;
              lab.testProjectiles.emplace_back(id.c_str());
            }
            std::sort(lab.testProjectiles.begin(), lab.testProjectiles.end());
          }
          if (PlayModProject()) {
            lab.testUnit = lab.Unit();
            lab.testStatus.clear();
            mUnitTestSpawned = false;
            mUnitTestFrames = 0;
          } else {
            PostStatusMessage("Test in game: the play couldn't start (a project, an open map, no play running)");
          }
        }
        if (lab.testUnit.empty()) {
          return;
        }
        ++mUnitTestFrames;
        moho::CWldSession* const session = moho::WLD_GetActiveSession();
        // Restart (Studio's): the play stopped; the project is written and played again.
        if (mUnitTestRestart) {
          if (!mPlay.Active() && mUnitTestFrames > 30) {
            mUnitTestRestart = false;
            mUnitTestSpawned = false;
            mUnitTestFrames = 0;
            lab.testStatus = "Restarting...";
            if (!PlayModProject()) {
              lab.testUnit.clear();
              PostStatusMessage("Test in game: the play couldn't start again");
            } else {
              gpg::Logf("editor: test in game: restarted (the project written and played again)");
            }
          }
          return;
        }
        if (!mPlay.Active() && mUnitTestFrames > 600) {
          lab.testUnit.clear(); // the play ended
          return;
        }
        if (!mUnitTestSpawned && session != nullptr && session->mGameTick > 20) {
          mUnitTestSpawned = true;
          SpawnUnitTest(lab.testUnit);
        }
        if (std::string line; mLog.TakeUnitTestLive(line)) {
          // id|alive|health|max|x|z|orders|targets...
          std::vector<std::string> f;
          std::size_t at = 0;
          while (at <= line.size()) {
            const std::size_t bar = std::min(line.find('|', at), line.size());
            f.push_back(line.substr(at, bar - at));
            at = bar + 1;
          }
          if (f.size() >= 8) {
            lab.testStatus = f[0] +
              (f[1] == "alive"
                 ? ": " + f[2] + " / " + f[3] + " health at " + f[4] + ", " + f[5] + ", " + f[6] + " orders"
                 : ": dead") +
              "; targets: " + (f[7].empty() ? "none" : f[7]) +
              (f.size() >= 10 ? "; damage dealt " + f[8] + ", built " + f[9] : std::string());
          }
        }
        if (std::string note; mLog.TakeUnitTestNote(note)) {
          lab.testNote = note;
        }
        if (const std::string order = lab.TakeTestOrder(); order == "restart" && mUnitTestSpawned) {
          UnitTestOrder("end");
          mPlay.Stop();
          mUnitTestRestart = true;
          mUnitTestFrames = 0;
        } else if (!order.empty() && mUnitTestSpawned) {
          UnitTestOrder(order);
          if (order == "respawn") {
            SpawnUnitTest(lab.testUnit);
          } else if (order == "end") {
            lab.testUnit.clear();
          }
        }
      }

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
          auto opened = panel.Open("EditorUnitLabTest");
          if (!opened) {
            opened = panel.Create("EditorUnitLabTest");
          }
          if (!opened) {
            gpg::Warnf("editor: unit lab test: no project: %s", opened.error().c_str());
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
              damage == nullptr && f.key.starts_with("Weapon:") && f.key.size() > 7 && f.key.ends_with(".Damage")
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
          const std::size_t afterUndo = p.edits.contains(unit) ? p.edits[unit].size() : 0;
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
          if (const auto derived = lab.Derive("xel0201", "Lab Tank", "A heavier Medium Tank"); derived) {
            (void)lab.SetField(*mass, mass->base * 2.0 + 44.0, false);
            // With a script of its own (the play logs the module the sim has for it).
            if (ModProject* const scripted = panel.Project(); scripted != nullptr) {
              if (const auto made = scripted->derived.find("xel0201"); made != scripted->derived.end()) {
                made->second.script = true;
              }
            }
            // And a model of its own: a 4-unit cube from an OBJ.
            {
              std::error_code ec;
              const std::filesystem::path obj = std::filesystem::temp_directory_path(ec) / "FafEditor" / "labcube.obj";
              std::filesystem::create_directories(obj.parent_path(), ec);
              std::ofstream cube(obj, std::ios::binary | std::ios::trunc);
              cube << "v -2 0 -2\nv 2 0 -2\nv 2 4 -2\nv -2 4 -2\nv -2 0 2\nv 2 0 2\nv 2 4 2\nv -2 4 2\n"
                      "vt 0 0\nvt 1 0\nvt 1 1\nvt 0 1\n"
                      "f 1/1 4/4 3/3 2/2\nf 5/1 6/2 7/3 8/4\nf 1/1 2/2 6/3 5/4\nf 4/1 8/2 7/3 3/4\nf 1/1 5/2 8/3 4/4\n"
                      "f 2/1 3/2 7/3 6/4\n";
              cube.close();
              const auto model = ImportUnitModel("xel0201", obj);
              gpg::Logf("editor: unit lab test: model from an OBJ: %s", model ? model->c_str() : model.error().c_str());
            }
            gpg::Logf(
              "editor: unit lab test: derived xel0201 from %s, mass %g; %zu history steps",
              unit.c_str(),
              mass->base * 2.0 + 44.0,
              panel.History().Size()
            );
          } else {
            gpg::Warnf("editor: unit lab test: no derived unit: %s", derived.error().c_str());
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
            "d.Economy.BuildCostMass, ', name ', d.General.UnitName, ', weapon 1 damage ', d.Weapon[1].Damage, "
            "', script ', tostring(d.ScriptModule), ', mesh ', tostring(d.Display.Mesh.LODs[1].MeshName)) "
            "else LOG('editor: unit lab test: the sim has no xel0201') end"
          );
          moho::CON_Execute(command);
          if (mLabTestStage == 4) {
            // One made, so the sim imports its own script (a failed import logs "Error importing").
            moho::CON_Execute(
              "SimLua local u = CreateUnitHPR('xel0201', 'ARMY_1', 300, 25, 300, 0, 0, 0) "
              "LOG('editor: unit lab test: made xel0201: ', tostring(u ~= nil), ', its class from its script: ', "
              "tostring(u ~= nil and u.OnStopBeingBuilt ~= nil))"
            );
          }
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
          auto opened = panel.Open("EditorEffectTest");
          if (!opened) {
            opened = panel.Create("EditorEffectTest");
          }
          if (!opened) {
            gpg::Warnf("editor: effect mod test: no project: %s", opened.error().c_str());
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
            if (!ReadGameFile(other, text)) {
              continue;
            }
            auto parsed = ParseEmitter(text);
            if (!parsed) {
              continue;
            }
            EmitterBlueprint& cut = *parsed;
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
        EdModHost& host = mShell->ModHost();
        const std::string uid = "11111111-2222-4333-a444-555555555555";
        const auto hello = EditorModCommandId("EditorModApiTest", "hello");
        const auto broken = EditorModCommandId("EditorModApiTest", "broken");
        if (mEditorModTestFrames > 150) {
          // The second stage, 60 frames on: what the panels did, the menu entries, then the failing command
          // (`/editormodtest panels` stops before it, the panels left drawing for a capture).
          fa::vector<fa::string> what;
          const bool panelsOnly =
            moho::CFG_GetArgOption("/editormodtest", 1, &what) && !what.empty() && what[0] == "panels";
          if (mEditorModTestFrames < 210) {
            return;
          }
          mEditorModTestDone = true;
          mEditorModTestDone = true;
          for (const EdModHost::ModPanel& panel : host.Panels()) {
            gpg::Logf(
              "editor: editor mod test: panel %s (%s): %s, %s",
              panel.id.c_str(),
              panel.title.c_str(),
              panel.shown ? "shown" : "hidden",
              panel.error.empty() ? "drawing" : ("stopped: " + panel.error).c_str()
            );
          }
          for (const EdModHost::ModMenu& entry : host.MenuEntries()) {
            gpg::Logf(
              "editor: editor mod test: menu entry %s (%s), command %s",
              entry.label.c_str(),
              entry.command.c_str(),
              mCommands.Find(entry.command) != nullptr ? "found" : "missing"
            );
          }
          if (panelsOnly) {
            // The Camera Info marker the mod added, selected: its view frame shows in the capture.
            for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
              if (MarkerTypeOf(marker) == "Camera Info") {
                mScene.SelectMarkers({marker.name}, false);
                gpg::Logf("editor: editor mod test: selected %s", marker.name.c_str());
                break;
              }
            }
            return;
          }
          gpg::Logf(
            "editor: editor mod test: run broken: %s", mCommands.Run(broken) ? "ran" : mCommands.WhyNot(broken).c_str()
          );
          gpg::Logf(
            "editor: editor mod test: hello now: %s",
            mCommands.WhyNot(hello).empty() ? "can run" : mCommands.WhyNot(hello).c_str()
          );
          const bool undone = mCommands.Run("edit.undo");
          gpg::Logf(
            "editor: editor mod test: undo the mod's marker: %s, markers %zu",
            undone ? "ran" : mCommands.WhyNot("edit.undo").c_str(),
            mDocument.SaveData().Markers().size()
          );
          (void)host.SetEnabled(uid, false);
          return;
        }
        mShell->SwitchWorkspace(7);
        mShell->HideHome();
        mShell->ShowEditorMods();
        for (const auto& mod : host.Mods()) {
          gpg::Logf(
            "editor: editor mod test: found %s (%s), api %d, %s",
            mod->info.name.c_str(),
            mod->info.uid.c_str(),
            mod->info.api,
            mod->running ? "running" : ("not running: " + mod->error).c_str()
          );
        }
        (void)host.SetEnabled(uid, true);
        gpg::Logf(
          "editor: editor mod test: %s in the registry: %s",
          hello.c_str(),
          mCommands.Find(hello) != nullptr ? "yes" : "no"
        );
        // The map API of round 3 (paint, props, decals, units, the map's store), before the steps below so their undo
        // checks see what they did last.
        if (
          const std::string probe3 = EditorModCommandId("EditorModApiTest", "probe3"); mCommands.Find(probe3) != nullptr
        ) {
          gpg::Logf(
            "editor: editor mod test: run probe3: %s", mCommands.Run(probe3) ? "ran" : mCommands.WhyNot(probe3).c_str()
          );
        }
        gpg::Logf("editor: editor mod test: markers before %zu", mDocument.SaveData().Markers().size());
        gpg::Logf(
          "editor: editor mod test: run hello: %s", mCommands.Run(hello) ? "ran" : mCommands.WhyNot(hello).c_str()
        );
        // The mod's tool: turned on by its command, then a click on the view at the map's middle (the view's own path
        // after the Win32 message), then off again with its command.
        const std::string bump = EditorModCommandId("EditorModApiTest", "tool.bump");
        gpg::Logf("editor: editor mod test: tool on: %s", mCommands.Run(bump) ? "ran" : mCommands.WhyNot(bump).c_str());
        const float middle = static_cast<float>(mDocument.Facts().fieldWidth - 1) * 0.5f;
        const auto heightThere = [this, middle] {
          const LayoutGround ground = LayoutGroundNow();
          return ground.height ? ground.height(middle, middle) : -1.0f;
        };
        const float before = heightThere();
        const bool taken = mScene.viewClickHook && mScene.viewClickHook(middle, middle, true, false);
        const float bumped = heightThere();
        const bool undone = mCommands.Run("edit.undo");
        gpg::Logf(
          "editor: editor mod test: tool click %s; height there %.2f -> %.2f, undo %s -> %.2f",
          taken ? "taken" : "not taken",
          before,
          bumped,
          undone ? "ran" : "refused",
          heightThere()
        );
        (void)mCommands.Run(bump);
        gpg::Logf("editor: editor mod test: tool off: %s", mShell->ModHost().ActiveTool() == nullptr ? "yes" : "no");
        // Both panels shown through their commands; they draw over the next 60 frames.
        for (const char* const id : {"panel.probe", "panel.bad"}) {
          const std::string full = EditorModCommandId("EditorModApiTest", id);
          gpg::Logf(
            "editor: editor mod test: show %s: %s",
            full.c_str(),
            mCommands.Run(full) ? "ran" : mCommands.WhyNot(full).c_str()
          );
        }
      }
      /**
       * `/unitviewtest` (test runs): a project EditorViewTest with xel0301 derived from uel0201; the unit viewer shows
       * it (the pixels the renderer drew counted), Make icon writes its icon, the derived unit then names it in the
       * hook.
       */
      float mPreviewTimeSeen = 0.0f;
      float mPreviewLightBefore = 0.0f;
      void TestUnitViewer()
      {
        if (
          mViewTestStage >= 14 || !mScene.Attached() || moho::RULE_PeekKept() == nullptr ||
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
          auto opened = panel.Open("EditorViewTest");
          if (!opened) {
            opened = panel.Create("EditorViewTest");
          }
          if (!opened) {
            gpg::Warnf("editor: unit view test: no project: %s", opened.error().c_str());
            mViewTestStage = 14;
            return;
          }
          panel.Project()->derived.clear();
          panel.Project()->edits.clear();
          mShell->UnitLab().SelectUnit("uel0201");
          const auto derived = mShell->UnitLab().Derive("xel0301", "Viewer Tank", "");
          viewer.SetAngles(35.0f, 15.0f);
          viewer.Focus();
          gpg::Logf("editor: unit view test: derived xel0301: %s", derived ? "yes" : derived.error().c_str());
          // `/iconrecipe heading,pitch,fov,fill,edge`: the icon's recipe for this run.
          if (fa::vector<fa::string> recipe; moho::CFG_GetArgOption("/iconrecipe", 1, &recipe) && !recipe.empty()) {
            float v[5] = {35.0f, 15.0f, 0.0f, 0.9f, 0.0f};
            (void)std::sscanf(recipe[0].c_str(), "%f,%f,%f,%f,%f", &v[0], &v[1], &v[2], &v[3], &v[4]);
            mShell->UnitViewer().SetIconRecipe(v[0], v[1], v[2], v[3], v[4]);
            gpg::Logf(
              "editor: unit view test: icon recipe heading %.0f pitch %.0f fov %.0f fill %.2f edge %.1f",
              v[0],
              v[1],
              v[2],
              v[3],
              v[4]
            );
          }
          break;
        }
        case 1:
          viewer.Focus(); // again, after the workspace's layout is in place
          break;
        case 2: {
          gpg::Logf("editor: unit view test: the viewer drew %d of %d pixels", viewer.DrawnPixels(), 384 * 384);
          const auto asked = viewer.AskIcon();
          gpg::Logf("editor: unit view test: make icon: %s", asked ? "asked" : asked.error().c_str());
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
            panel.Project()->derived.contains("xel0301") && panel.Project()->derived.at("xel0301").icon ? "set"
                                                                                                        : "not set",
            text.str().contains("'Viewer Tank', '', true,") ? "names the icon" : "doesn't name it",
            std::any_of(
              panel.Check().begin(),
              panel.Check().end(),
              [](const ModIssue& i) {
            return i.text.contains("xel0301 shows");
          }
            )
              ? "still there"
              : "gone"
          );
          (void)report;
          // Then the first weapon's projectile in the view: dalk003's (AASerpentine, one of the few with a model).
          mShell->UnitLab().SelectUnit("dalk003");
          if (moho::RRuleGameRules* const rules = moho::RULE_PeekKept(); rules != nullptr) {
            moho::RResId id{};
            id.name.assign("dalk003");
            if (const moho::RUnitBlueprint* const aa = rules->GetUnitBlueprint(id); aa != nullptr) {
              const auto& weapons = aa->Weapons.WeaponBlueprints;
              for (std::size_t i = 0; i < weapons.size(); ++i) {
                if (!weapons[i].ProjectileId.name.empty()) {
                  viewer.ShowWeapon(static_cast<int>(i));
                  gpg::Logf(
                    "editor: unit view test: dalk003's weapon %zu fires %s", i, weapons[i].ProjectileId.name.c_str()
                  );
                  break;
                }
              }
            }
          }
          break;
        }
        case 6:
          gpg::Logf(
            "editor: unit view test: dalk003's projectile drew %d of %d pixels", viewer.DrawnPixels(), 384 * 384
          );
          viewer.ShowWeapon(-1);
          gpg::Logf(
            "editor: unit view test: icon compared: %s",
            viewer.Comparison().empty() ? "(nothing)" : viewer.Comparison().c_str()
          );
          gpg::Logf("editor: unit view test: icon pictures %d of 3", viewer.IconPictureCount());
          break;
        case 7:
          // The new-unit wizard: a UEF tank from its template into the project, then its checks.
          gpg::Logf("editor: unit view test: wizard: %s", mShell->UnitWizard().Test("tank", "UEF").c_str());
          break;
        case 8: {
          // The unit in the view, animated (Unit viewer > In the view): uel0106 at the map's middle.
          UnitPreviewState& preview = viewer.Preview();
          preview.active = true;
          preview.unit = "uel0106"; // the Mech Marine: it names a walk animation
          preview.animation.clear();
          break;
        }
        case 9: {
          UnitPreviewState& preview = viewer.Preview();
          gpg::Logf(
            "editor: unit view test: preview of %s: %zu animations named; %s",
            preview.unit.c_str(),
            preview.animations.size(),
            preview.status.c_str()
          );
          if (!preview.animations.empty()) {
            preview.animation = preview.animations.front();
            preview.playing = true;
            preview.loop = true;
          }
          break;
        }
        case 10:
          mPreviewTimeSeen = viewer.Preview().time;
          break;
        case 11: {
          const UnitPreviewState& preview = viewer.Preview();
          gpg::Logf(
            "editor: unit view test: animation %s: %s; duration %.2f s, the clock went %.2f -> %.2f",
            preview.animation.empty() ? "(none)" : preview.animation.c_str(),
            preview.status.c_str(),
            static_cast<double>(preview.duration),
            static_cast<double>(mPreviewTimeSeen),
            static_cast<double>(preview.time)
          );
          // Studio's viewer extras: LOD 1 by the camera, the empty stage, the Evening light (one undo step).
          UnitPreviewState& p = viewer.Preview();
          p.lod = p.lodCutoffs.size() > 1 ? 1 : 0;
          p.stage = true;
          p.light = "Evening";
          // A shot of its first weapon (the log says where it landed).
          p.fireWeapon = 0;
          p.fire = true;
          // Studio's camera preset, a picked bone, a named colour.
          p.frame = "iso";
          p.bone = p.boneNames.empty() ? -1 : 0;
          p.colour = "Red";
          mPreviewLightBefore = mDocument.LightingNow().sunColor[1];
          break;
        }
        case 12: {
          UnitPreviewState& p = viewer.Preview();
          gpg::Logf(
            "editor: unit view test: %zu LODs; the sun's green %.2f -> %.2f (Evening's is 0.70)",
            p.lodCutoffs.size(),
            static_cast<double>(mPreviewLightBefore),
            static_cast<double>(mDocument.LightingNow().sunColor[1])
          );
          gpg::Logf(
            "editor: unit view test: %zu bones, bone %d picked (%s), colour %s; fire: %s",
            p.boneNames.size(),
            p.bone,
            p.bone >= 0 && static_cast<std::size_t>(p.bone) < p.boneNames.size()
              ? p.boneNames[static_cast<std::size_t>(p.bone)].c_str()
              : "none",
            p.colour.c_str(),
            p.fireStatus.c_str()
          );
          p.light = "Map";
          p.stage = false;
          p.lod = -1;
          // A weapon whose projectile has a model of its own: dalk003's AA missile (aaserpentine).
          mShell->UnitLab().SelectUnit("dalk003"); // the viewer shows the lab's unit
          p.unit = "dalk003";
          p.fireWeapon = 1;
          p.fire = true;
          p.frame = "range"; // its largest weapon range in view: the distance is 2.4 x that range
          break;
        }
        case 13:
          gpg::Logf(
            "editor: unit view test: light back to the map's: the sun's green %.2f; dalk003 fire: %s",
            static_cast<double>(mDocument.LightingNow().sunColor[1]),
            viewer.Preview().fireStatus.c_str()
          );
          viewer.Preview().active = false;
          break;
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
      int mMeshTestFrames = 0; // `/meshtest`: frames since the import was asked (0: none)
      int mReseatTestFrames = 0; // `/reseattest`: frames since the ground was raised (0: none)
      void DriveReseatTest()
      {
        if (mReseatTestFrames == 0 || ++mReseatTestFrames != 30) {
          return;
        }
        mReseatTestFrames = 0;
        const float c = static_cast<float>(std::max(mDocument.Facts().fieldWidth - 1, 2)) * 0.5f;
        for (const EdMapScene::ModObject& p : mScene.ModProps()) {
          if (std::fabs(p.x - (c + 20.0f)) < 1.0f && std::fabs(p.z - c) < 1.0f) {
            gpg::Logf(
              "editor: /reseattest: the prop stands at %.2f, the ground there %.2f",
              static_cast<double>(p.y),
              static_cast<double>(mScene.GroundHeightAt(p.x, p.z))
            );
          }
        }
        for (const EdMapScene::ModObject& u : mScene.ModUnits()) {
          if (std::fabs(u.x - (c - 20.0f)) < 1.5f && std::fabs(u.z - c) < 1.5f) {
            gpg::Logf(
              "editor: /reseattest: unit %s stands at %.2f, the ground there %.2f",
              u.name.c_str(),
              static_cast<double>(u.y),
              static_cast<double>(mScene.GroundHeightAt(u.x, u.z))
            );
          }
        }
      }
      // Named workspace layouts (FAF Studio's shell save / load layout): `layouts/<name>.ini` in the settings folder.
      std::filesystem::path mLayoutToLoad;
      bool mShowLayouts = false;
      char mLayoutName[64] = "";
      std::string mLayoutSaveFile; // `/layoutsave <file>`
      int mLayoutSaveFrames = 0;
      std::vector<std::string> mLayoutSavedPanels;
      [[nodiscard]] static std::filesystem::path LayoutsFolder()
      {
        const std::filesystem::path settings = EditorSettingsFolder();
        return settings.empty() ? std::filesystem::path{} : settings / "layouts";
      }
      bool SaveLayoutTo(
        const std::filesystem::path& file
      )
      {
        std::size_t size = 0;
        // What is shown now, also in a test run (whose layout.ini writes back what it read, not what it showed).
        const bool testRun = std::exchange(gTestRun, false);
        const char* const text = ImGui::SaveIniSettingsToMemory(&size);
        gTestRun = testRun;
        std::error_code ec;
        std::filesystem::create_directories(file.parent_path(), ec);
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write(text, static_cast<std::streamsize>(size));
        gpg::Logf("editor: layout saved to %s (%zu bytes)", file.string().c_str(), size);
        return static_cast<bool>(out);
      }
      /** Window > Layouts...: save the panels as they are under a name, or load a saved one. */
      void DrawLayouts()
      {
        if (!mShowLayouts) {
          return;
        }
        ImGui::SetNextWindowSize(ImVec2(Em(340.0f), Em(300.0f)), ImGuiCond_FirstUseEver);
        if (!ImGui::Begin("Layouts###NamedLayouts", &mShowLayouts)) {
          ImGui::End();
          return;
        }
        const std::filesystem::path folder = LayoutsFolder();
        if (folder.empty()) {
          ImGui::TextDisabled("No settings folder: layouts can't be kept.");
          ImGui::End();
          return;
        }
        ImGui::SetNextItemWidth(Em(200.0f));
        ImGui::InputTextWithHint("##layoutname", "name", mLayoutName, sizeof(mLayoutName));
        ImGui::SameLine();
        std::string name = mLayoutName;
        name.erase(
          std::remove_if(
            name.begin(),
            name.end(),
            [](const char c) {
          return c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' ||
            c == '|';
        }
          ),
          name.end()
        );
        ImGui::BeginDisabled(name.empty());
        if (ImGui::Button("Save the panels as this")) {
          PostStatusMessage(
            SaveLayoutTo(folder / (name + ".ini")) ? "Layout " + name + " saved"
                                                   : "Layout " + name + " couldn't be saved"
          );
        }
        ImGui::EndDisabled();
        ImGui::Separator();
        std::error_code ec;
        bool any = false;
        for (const auto& entry : std::filesystem::directory_iterator(folder, ec)) {
          if (entry.path().extension() != ".ini") {
            continue;
          }
          any = true;
          ImGui::PushID(entry.path().string().c_str());
          if (ImGui::Button("Load")) {
            mLayoutToLoad = entry.path();
          }
          ImGui::SameLine();
          ImGui::TextUnformatted(entry.path().stem().string().c_str());
          ImGui::PopID();
        }
        if (!any) {
          ImGui::TextDisabled("No layouts saved yet.");
        }
        ImGui::End();
      }

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
          mShell->Tools().PickSymmetry(std::to_underlying(SymmetryOfOp(symmetryName)));
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
        if (panel.TakeCentreSymmetryAsk()) {
          float ax0 = 0.0f, az0 = 0.0f, ax1 = 0.0f, az1 = 0.0f;
          mDocument.LayoutArea(ax0, az0, ax1, az1);
          const MapFacts& f = mDocument.Facts();
          const float ox = (ax0 + ax1) * 0.5f - static_cast<float>(f.fieldWidth - 1) * 0.5f;
          const float oz = (az0 + az1) * 0.5f - static_cast<float>(f.fieldHeight - 1) * 0.5f;
          mShell->Tools().SetSymmetryCentre(ox, oz);
          panel.SetStatus(
            "The symmetry's centre is the middle of the drawing (" + std::to_string(static_cast<int>(ox)) + ", " +
            std::to_string(static_cast<int>(oz)) + " from the map's middle)."
          );
          gpg::Logf(
            "editor: layout: symmetry centre offset %.1f, %.1f", static_cast<double>(ox), static_cast<double>(oz)
          );
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
        LayoutBuildOptions buildOptions;
        buildOptions.weather = layout.weather;
        if (const auto built = BuildLayout(layout, like, buildOptions, heights, nullptr); !built) {
          panel.SetStatus("Generate terrain: " + built.error());
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
          if (SymmetrizeHeights(words.data(), heights.w, heights.h, options)) {
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
        if (panel.PaintGroundToo()) {
          mShell->Tools().AskRecipeApply();
          status += " The ground is painted by the Stratum recipe next.";
        }
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
        if (std::string(arg[0].c_str()).starts_with("picture:")) {
          EdLayoutPanel& panel = mShell->LayoutPanel();
          switch (mLayoutTestStage) {
          case 0:
            mShell->SwitchWorkspace(3);
            mShell->HideHome();
            mShell->ShowLayout();
            mDocument.Layout().selected = 0;
            // `/layoutchannel <n>`: what the picture import reads (0 brightness, 1 red, 2 green, 3 blue, 4 alpha).
            if (
              fa::vector<fa::string> channel; moho::CFG_GetArgOption("/layoutchannel", 1, &channel) && !channel.empty()
            ) {
              panel.SetPictureChannel(std::atoi(channel[0].c_str()));
            }
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
          if (auto tile = MakeAtlasTile(albedo, normal, kinds[static_cast<std::size_t>(layer)], writes.atlasSettings)) {
            made[static_cast<std::size_t>(layer)] = std::move(*tile);
            tiles[static_cast<std::size_t>(layer)] = &made[static_cast<std::size_t>(layer)];
            ++textured;
          } else {
            gpg::Warnf("editor: atlas: layer %d: %s", layer, tile.error().c_str());
          }
        }
        std::vector<float> rgba;
        PackAtlas(tiles, kinds, writes.atlasSettings, writes.atlasSize, rgba);
        TexImage image;
        image.Reset(writes.atlasSize, 4, 0.0f);
        image.data = std::move(rgba);
        const auto encoded = EncodeDds(image, DdsKind::Bgra);
        if (!encoded) {
          return "The atlas wasn't encoded: " + encoded.error() + ".";
        }
        const std::vector<std::uint8_t>& dds = *encoded;
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
          const std::string file = "layer" + std::to_string(slot) + (baseOnly ? "_opacity.dds" : "_alpha.dds");
          const auto encoded = EncodeDds(out, DdsKind::Bgra);
          if (!encoded) {
            skipped += (skipped.empty() ? "" : ", ") + std::to_string(slot) + " (" + encoded.error() + ")";
            return;
          }
          const std::vector<std::uint8_t>& dds = *encoded;
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

      /**
       * Convert layers' textures (FAF Studio's texconv.lua): after the masks moved to `shader`, the textures it reads
       * made as new files beside the map: the layers' albedo copies with the alpha it wants (specularity, 1 -
       * specularity, the base opacity), and for the 1xx / 2xx shaders the roughness / height atlas in the Upper layer.
       * Lines go to `report`.
       */
      void ConvertTextures(
        const std::string& shader,
        std::vector<std::string>& report
      )
      {
        std::string lower = shader;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
        const bool atlas = lower.size() >= 10 && lower.starts_with("terrain") && (lower[7] == '1' || lower[7] == '2') &&
          std::isdigit(static_cast<unsigned char>(lower[8])) != 0;
        const ShaderAlphaUse use = ShaderAlphaOf(shader);
        TerrainBuildWrites writes;
        if (use.layers == LayerAlphaUse::Specularity || use.layers == LayerAlphaUse::Matte || use.baseOpacity) {
          writes.texAlpha = true;
          writes.texAlphaMode = TextureAlphaMode::Generate;
          writes.baseOpacity = 1.0f;
          report.push_back("Textures: " + MakeTextureAlpha(writes));
        }
        if (atlas) {
          writes.atlas = true;
          writes.atlasSize = 1024;
          report.push_back("Textures: " + MakeAtlasTexture(writes));
        }
        if (!writes.texAlpha && !atlas) {
          report.push_back(
            "Textures: " + shader + " reads nothing from the textures' alpha or an atlas; none were made."
          );
        }
        gpg::Logf("editor: convert layers: textures for %s written", shader.c_str());
      }

      void DriveGenerate()
      {
        EdGenerate& generate = mShell->Generate();
        if (!mGenerateWired) {
          mGenerateWired = true;
          generate.SetGroundSource([this](TerrainGround& ground) {
            return mScene.Attached() && !mScene.ModelsPending() && mScene.GraphGround(ground);
          });
        }
        // A graph node shown on the map as a mask (the inspector's "Show on the map as a mask").
        if (!mShell->GenerateShown() && generate.MaskNode() != 0) {
          generate.ShowAsMask(0);
        }
        if (field::Grid mask; generate.TakeMaskAsk(mask)) {
          mScene.SetOverlayMask(std::move(mask));
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
            // The graph's own symmetry (when not "follow the map") for its scatters too: the props and decals are
            // placed in its first part with their copies (FAF Studio's Scatter.Plan{ symmetry }).
            EdTools& symTools = mShell->Tools();
            const int keptSymmetry = symTools.SymmetryIndex();
            const int keptTurns = symTools.NWayTurns();
            {
              static const std::map<std::string, std::pair<Symmetry, int>> kGraphSymmetry = {
                {"off", {Symmetry::None, 3}},
                {"mirror_x", {Symmetry::LeftRight, 3}},
                {"mirror_z", {Symmetry::TopBottom, 3}},
                {"mirror_xz", {Symmetry::BothAxes, 3}},
                {"rot2", {Symmetry::HalfTurn, 3}},
                {"rot4", {Symmetry::QuarterTurns, 3}},
                {"diag", {Symmetry::DiagonalBack, 3}},
                {"adiag", {Symmetry::DiagonalForward, 3}},
                {"diag_both", {Symmetry::BothDiagonals, 3}},
                {"rotn3", {Symmetry::NWay, 3}},
                {"rotn5", {Symmetry::NWay, 5}},
                {"rotn6", {Symmetry::NWay, 6}},
              };
              if (const auto found = kGraphSymmetry.find(generate.Symmetry()); found != kGraphSymmetry.end()) {
                symTools.SetSymmetryOnly(std::to_underlying(found->second.first), found->second.second);
              }
            }
            std::string status = mScene.ApplyGraphBuild(ask.result, ask.plain, ask.writes);
            symTools.SetSymmetryOnly(keptSymmetry, keptTurns);
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
            (std::string(arg[0].c_str()).starts_with("file:")
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
          auto read = ReadHeightImage(file, 0, 0);
          if (!read) {
            gpg::Warnf("editor: interop test: can't read %s: %s", file.string().c_str(), read.error().c_str());
            return;
          }
          HeightImage& image = *read;
          for (int z = 200; z < 300 && z < image.height; ++z) {
            for (int x = 200; x < 300 && x < image.width; ++x) {
              std::uint16_t& w = image.words[static_cast<std::size_t>(z) * image.width + x];
              w = static_cast<std::uint16_t>(std::min(65535, w + 1280));
            }
          }
          if (const auto wrote = WriteHeightImage(file, image); !wrote) {
            gpg::Warnf("editor: interop test: can't write %s: %s", file.string().c_str(), wrote.error().c_str());
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
        if (parts[0].starts_with("save:")) {
          EdShell::LookRequest save;
          save.what = EdShell::LookRequest::What::Save;
          save.name = parts[0].substr(5);
          mShell->RequestLook(save);
          UpdateLooks();
          return;
        }
        std::string scenario = parts[0].starts_with("mine:") ? parts[0] : std::string();
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

      /** The graphics settings (Settings > Performance): each a choice of the engine's switch or its default. */
      void DrawGraphicsSettings()
      {
        SettingLabel(
          "Graphics",
          "How the view draws (the game's own switches). Auto keeps the engine's default; a change applies at once and "
          "is kept in settings.ini."
        );
        struct Row
        {
          const char* key;
          const char* label;
          const char* about;
        };
        static constexpr Row kRows[] = {
          {EdSettings::kGfxShadows, "Shadows", "Units, props and terrain cast shadows"},
          {EdSettings::kGfxShadowSize, "Shadow detail", "The shadow map's size: sharper shadows cost more"},
          {EdSettings::kGfxBloom, "Bloom", "Glow around bright parts"},
          {EdSettings::kGfxFxaa, "Antialiasing (FXAA)", "Smooths jagged edges"},
          {EdSettings::kGfxAo, "Ambient occlusion", "Soft shade where things meet the ground"},
          {EdSettings::kGfxTextureDetail, "Texture detail", "Lower skips the largest texture levels (less memory)"},
          {EdSettings::kGfxAnisotropy,
           "Texture filtering",
           "Anisotropic filtering: ground seen at a slant stays sharp"},
          {EdSettings::kGfxFidelity, "Fidelity", "Overall detail of the terrain shading, water and effects"},
          {EdSettings::kGfxShadowDistance, "Shadow distance", "How far from the camera shadows are drawn"},
          {EdSettings::kGfxModelDetail,
           "Model detail",
           "How long models keep their detailed meshes as the camera moves away"},
          {EdSettings::kGfxVsync,
           "Vertical sync",
           "Wait for the monitor before showing a frame: no tearing, fewer frames"},
          {EdSettings::kGfxShadowQuality,
           "Shadow quality",
           "Whether and how well objects cast shadows (Studio's four levels)"},
        };
        // Studio's quality presets: the settings above set together.
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Quality preset");
        ImGui::SameLine(Em(180.0f));
        const std::string preset = mSettings.GraphicsPreset();
        for (const char* name : {"low", "medium", "high", "ultra"}) {
          const char* label = name[0] == 'l' ? "Low" : name[0] == 'm' ? "Medium" : name[0] == 'h' ? "High" : "Ultra";
          if (ModeTile(label, preset == name, ImVec2(Em(64.0f), 0.0f)) && preset != name) {
            (void)mSettings.ApplyGraphicsPreset(name);
            SaveSettings();
            ApplyGraphicsSettings();
            gpg::Logf("editor: graphics preset %s", name);
          }
          ImGui::SameLine();
        }
        ImGui::TextDisabled("%s", preset == "custom" ? "(custom)" : "");
        EdSetItemTooltip("FAF Studio's presets: fidelity, shadows, shadow size and distance, texture and model detail");
        for (const Row& row : kRows) {
          const std::vector<std::string> choices = EdSettings::Allowed(row.key);
          const std::string now = mSettings.Get(row.key);
          ImGui::AlignTextToFramePadding();
          ImGui::TextUnformatted(row.label);
          ImGui::SameLine(Em(180.0f));
          ImGui::SetNextItemWidth(Em(140.0f));
          if (EdBeginCombo((std::string("##gfx") + row.key).c_str(), now.c_str())) {
            for (const std::string& choice : choices) {
              if (ImGui::Selectable(choice.c_str(), choice == now) && choice != now) {
                (void)mSettings.Set(row.key, choice);
                SaveSettings();
                ApplyGraphicsSettings();
              }
            }
            ImGui::EndCombo();
          }
          EdSetItemTooltip("%s", row.about);
        }
        DrawGpuSettings();
      }

      /**
       * Settings > GPU compute (FAF Studio's ed_gpu_compute, gpu_ab.lua): the terrain tools' field ops (blur, filters,
       * generators, droplet / hydraulic / thermal erosion) on a compute-only Direct3D 11 device of their own, the CPU
       * op on any problem; the smallest field it takes, the self test, and which ops ran where.
       */
      void DrawGpuSettings()
      {
        SettingLabel(
          "GPU compute",
          "The terrain tools' heavy work (erosion, generators, filters) on the graphics card, on a compute device of "
          "its "
          "own beside the renderer; any problem and the CPU does it, with the same result."
        );
        bool on = mSettings.GetBool(EdSettings::kGpuCompute);
        if (ImGui::Checkbox("Use the GPU for the terrain tools", &on)) {
          (void)mSettings.SetBool(EdSettings::kGpuCompute, on);
          SaveSettings();
          ApplyGpuSettings();
        }
        const std::string cells = mSettings.Get(EdSettings::kGpuMinCells);
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Smallest field");
        ImGui::SameLine(Em(180.0f));
        ImGui::SetNextItemWidth(Em(140.0f));
        if (EdBeginCombo("##gpucells", cells.c_str())) {
          for (const std::string& choice : EdSettings::Allowed(EdSettings::kGpuMinCells)) {
            if (ImGui::Selectable(choice.c_str(), choice == cells) && choice != cells) {
              (void)mSettings.Set(EdSettings::kGpuMinCells, choice);
              SaveSettings();
              ApplyGpuSettings();
            }
          }
          ImGui::EndCombo();
        }
        EdSetItemTooltip(
          "Fields with fewer samples stay on the CPU: sending them to the card costs more than it saves"
        );
        if (ImGui::Button("Run the GPU self test")) {
          mGpuTestText = GpuSelfTestText();
        }
        ImGui::SameLine();
        if (ImGui::Button("Op statistics")) {
          mGpuTestText = GpuStatsText(false);
        }
        if (!mGpuTestText.empty()) {
          ImGui::TextWrapped("%s", mGpuTestText.c_str());
        }
      }
      std::string mGpuTestText;
      std::string mMeshLoadedFor; // the map whose mesh terrain was read
      int mFramesUp = 0;
      std::string mModMapSeen;
      std::vector<std::string> mModEdits; // undo steps since the last frame, for the mods' "edit" event

      void ApplyGpuSettings()
      {
        gpu::Policy& policy = gpu::GetPolicy();
        policy.enabled = mSettings.GetBool(EdSettings::kGpuCompute);
        policy.minCells =
          static_cast<float>(std::max(1024, std::atoi(mSettings.Get(EdSettings::kGpuMinCells).c_str())));
        policy.selfTestFirst = true;
        static bool installed = false;
        if (!installed) {
          installed = true;
          gpu::Install();
        }
        gpg::Logf(
          "editor: GPU compute %s (fields from %.0f samples, %zu GPU ops)",
          policy.enabled ? "on" : "off",
          static_cast<double>(policy.minCells),
          gpu::GpuOpNames().size()
        );
      }

      static std::string GpuSelfTestText()
      {
        const gpu::SelfTestReport report = gpu::RunSelfTest();
        std::string text;
        if (!report.error.empty()) {
          text = "No GPU compute: " + report.error;
        } else {
          char head[160];
          (void)std::snprintf(
            head,
            sizeof(head),
            "Self test %s in %.0f ms%s:",
            report.ok ? "passed" : "FAILED",
            report.ms,
            report.texturesOk ? "" : " (textures not usable: buffer kernels only)"
          );
          text = head;
          for (const gpu::SelfTestPart& part : report.parts) {
            text += "\n  " + part.name + ": " + (part.ok ? "ok" : "failed") +
              (part.detail.empty() ? "" : " (" + part.detail + ")");
          }
        }
        gpg::Logf("editor: GPU self test: %s", text.c_str());
        return text;
      }

      static std::string GpuStatsText(
        const bool reset
      )
      {
        const std::map<std::string, field::OpStat> stats = field::OpStats(reset);
        std::string text;
        std::uint64_t gpuCalls = 0;
        std::uint64_t cpuCalls = 0;
        for (const auto& [name, s] : stats) {
          gpuCalls += s.gpuCalls;
          cpuCalls += s.cpuCalls;
          char line[200];
          (void)std::snprintf(
            line,
            sizeof(line),
            "\n  %s: GPU %llu (%.0f ms), CPU %llu (%.0f ms)%s",
            name.c_str(),
            static_cast<unsigned long long>(s.gpuCalls),
            s.gpuMs,
            static_cast<unsigned long long>(s.cpuCalls),
            s.cpuMs,
            s.fallbacks > 0 ? (", " + std::to_string(s.fallbacks) + " fell back").c_str() : ""
          );
          text += line;
        }
        const std::string error = gpu::LastOpError();
        return "Ops this session: " + std::to_string(gpuCalls) + " on the GPU, " + std::to_string(cpuCalls) +
          " on the CPU." + text + (error.empty() ? "" : "\nLast GPU problem: " + error);
      }

      /** The graphics settings that aren't "auto" put into the engine's switches (start, and each change). */
      void ApplyGraphicsSettings()
      {
        for (const std::string& command : mSettings.GraphicsCommands()) {
          moho::CON_Execute(command.c_str());
          gpg::Logf("editor: graphics: %s", command.c_str());
        }
      }

      /**
       * Help > Save diagnostics for a bug report (FAF Studio's): one text file in the settings folder's `diagnostics`
       * with the build, the renderer, the monitors, the open map, the editor mods, the settings file, the last 400
       * lines of the log and the newest crash report beside the exe; its path goes to the clipboard.
       */
      void SaveDiagnostics()
      {
        std::ostringstream out;
        const std::time_t now = std::time(nullptr);
        char stamp[32] = {};
        std::tm local{};
        (void)localtime_s(&local, &now);
        (void)std::strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &local);
        out << "== FAF map editor diagnostics, " << stamp << "\n";
        out << "build: " << __DATE__ << " " << __TIME__ << "\n";
        const std::filesystem::path settingsFolder =
          mSettingsFile.empty() ? EditorSettingsFolder() : mSettingsFile.parent_path();
        out << "settings folder: " << settingsFolder.string() << "\n";
        gpg::gal::DeviceRuntimeInfo device;
        if (gpg::gal::Device::IsReady() && gpg::gal::Device::GetInstance()->GetRuntimeInfo(device)) {
          out << "renderer: " << device.api.c_str() << " on " << device.adapter.c_str() << "\n";
        }
        out << "UI scale: " << static_cast<int>(std::lround(Em(100.0f))) << "%\n";
        out << "monitors: " << ::GetSystemMetrics(SM_CMONITORS) << ", primary " << ::GetSystemMetrics(SM_CXSCREEN)
            << "x" << ::GetSystemMetrics(SM_CYSCREEN) << "\n";
        if (mDocument.GetState() == EdDocument::State::Open) {
          const MapFacts& facts = mDocument.Facts();
          out << "map: " << facts.name << " (" << mDocument.Path() << "), " << facts.fieldWidth - 1 << " x "
              << facts.fieldHeight - 1 << ", " << mDocument.SaveData().Markers().size() << " markers, " << facts.props
              << " props, unsaved changes: " << (mDocument.Modified() ? "yes" : "no") << "\n";
        } else {
          out << "map: none open\n";
        }
        std::string mods;
        for (const auto& mod : mShell->ModHost().Mods()) {
          if (mod->running || mod->error.starts_with("failed")) {
            mods += (mods.empty() ? "" : ", ") + mod->info.name + (mod->running ? "" : " (" + mod->error + ")");
          }
        }
        out << "editor mods: " << (mods.empty() ? "none on" : mods) << "\n";
        const auto readFile = [](const std::filesystem::path& path, const std::size_t limit) {
          std::ifstream in(path, std::ios::binary);
          std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          if (text.size() > limit) {
            text = "(the last " + std::to_string(limit) + " bytes)\n" + text.substr(text.size() - limit);
          }
          return text;
        };
        out << "\n== settings.ini\n"
            << readFile(mSettingsFile.empty() ? settingsFolder / "settings.ini" : mSettingsFile, 32768) << "\n";
        out << "\n== the log (the last 400 lines)\n";
        for (const std::string& line : mLog.Tail(400)) {
          out << line << "\n";
        }
        // The newest crash report the engine wrote beside the exe (faf_crash_<date>_<time>.txt).
        std::filesystem::path newest;
        std::filesystem::file_time_type newestTime{};
        std::error_code ignored;
        wchar_t exe[MAX_PATH] = {};
        (void)::GetModuleFileNameW(nullptr, exe, MAX_PATH);
        for (const auto& item :
             std::filesystem::directory_iterator(std::filesystem::path(exe).parent_path(), ignored)) {
          const std::string name = item.path().filename().string();
          if (name.starts_with("faf_crash_") && item.path().extension() == ".txt") {
            const auto written = item.last_write_time(ignored);
            if (newest.empty() || written > newestTime) {
              newest = item.path();
              newestTime = written;
            }
          }
        }
        out << "\n== the newest crash report: " << (newest.empty() ? "none" : newest.string()) << "\n";
        if (!newest.empty()) {
          out << readFile(newest, 65536) << "\n";
        }
        const std::filesystem::path folder = settingsFolder / "diagnostics";
        std::filesystem::create_directories(folder, ignored);
        const std::filesystem::path file = folder / (std::string("diagnostics_") + stamp + ".txt");
        const std::string text = out.str();
        std::ofstream(file, std::ios::binary) << text;
        ImGui::SetClipboardText(file.string().c_str());
        gpg::Logf("editor: diagnostics saved as %s (%zu bytes)", file.string().c_str(), text.size());
        PostStatusMessage("Diagnostics saved as " + file.string() + " (the path is on the clipboard)");
      }

      /** Terrain > Flatten map: the whole map to one height (FAF Studio's), with the map's range beside it. */
      void DrawFlatten()
      {
        constexpr const char* kTitle = "Flatten map";
        if (std::exchange(mFlattenAsk, false) && mDocument.GetState() == EdDocument::State::Open) {
          if (!mScene.HeightRange(mFlattenLow, mFlattenHigh, mFlattenMean)) {
            return;
          }
          mFlattenHeight = mFlattenMean;
          ImGui::OpenPopup(kTitle);
        }
        ImGui::SetNextWindowSize(ImVec2(Em(420.0f), 0.0f), ImGuiCond_Appearing);
        if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_NoSavedSettings)) {
          return;
        }
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextDisabled(
          "Every height sample of the map to one height (one undo step). The map now: %.1f to %.1f, mean %.1f.",
          mFlattenLow,
          mFlattenHigh,
          mFlattenMean
        );
        ImGui::PopTextWrapPos();
        ImGui::SetNextItemWidth(-1.0f);
        (void)FillSliderFloat("##flatten", &mFlattenHeight, 0.0f, 511.0f, "Height %.1f");
        const WaterState water = mDocument.WaterNow();
        if (water.enabled) {
          if (ImGui::Button("Water level + 2")) {
            mFlattenHeight = water.elevation + 2.0f;
          }
          ImGui::SameLine();
        }
        if (ImGui::Button("Mean")) {
          mFlattenHeight = mFlattenMean;
        }
        ImGui::Separator();
        if (ImGui::Button("Flatten")) {
          const auto flattened = mScene.FlattenWhole(mFlattenHeight);
          PostStatusMessage(flattened ? *flattened : flattened.error());
          ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
          ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
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
      /** `/lookthumbtest <folder>`: the looks whose pictures are made and written there, then logged. */
      std::vector<std::string> mLookThumbTest;
      bool mLookThumbTestQueued = false;
      int mLookThumbsForRows = 0; // pictures the Looks rows asked for since the queue last ran dry (logged then)
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
      bool mFlattenAsk = false;
      bool mMirrorHalfAsk = false;
      EdMapScene::MirrorHalfOptions mMirrorHalf;
      /** Edit > Mirror half the map (FAF Studio's dialogs_mirror.lua): the part copied and what follows it. */
      void DrawMirrorHalf()
      {
        constexpr const char* kTitle = "Mirror half the map";
        if (std::exchange(mMirrorHalfAsk, false) && mDocument.GetState() == EdDocument::State::Open) {
          ImGui::OpenPopup(kTitle);
        }
        ImGui::SetNextWindowSize(ImVec2(Em(440.0f), 0.0f), ImGuiCond_Appearing);
        if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_NoSavedSettings)) {
          return;
        }
        const int parts = mScene.SymmetryParts();
        if (parts <= 1) {
          ImGui::TextWrapped("Pick a symmetry on the toolbar first: its parts are what is copied.");
        } else {
          mMirrorHalf.source = std::clamp(mMirrorHalf.source, 0, parts - 1);
          ImGui::SetNextItemWidth(Em(200.0f));
          FillSliderInt("##mirrorsource", &mMirrorHalf.source, 0, parts - 1, "Copy from part %d");
          EdSetItemTooltip("The symmetry's parts in order by z then x: part 0 holds the top left");
          ImGui::TextDisabled("What follows");
          ImGui::Checkbox("Markers", &mMirrorHalf.markers);
          ImGui::SameLine();
          ImGui::Checkbox("Props", &mMirrorHalf.props);
          ImGui::SameLine();
          ImGui::Checkbox("Decals", &mMirrorHalf.decals);
          ImGui::SameLine();
          ImGui::Checkbox("Units", &mMirrorHalf.units);
          ImGui::SameLine();
          ImGui::Checkbox("Areas", &mMirrorHalf.areas);
          ImGui::Checkbox("Units go to the mirrored army", &mMirrorHalf.mapArmies);
          EdSetItemTooltip("The army whose start position is the copy of the unit's army's start; else their own");
          ImGui::Checkbox("Replace what is on the other parts", &mMirrorHalf.replace);
          EdSetItemTooltip("Off: the copies are added to what is there");
          ImGui::TextDisabled(
            "Start positions and AREA_1 never change; props and decals keep their pictures, only their "
            "headings turn."
          );
          if (PrimaryButton("Mirror")) {
            const int made = mScene.MirrorHalf(mMirrorHalf);
            PostStatusMessage("Mirror half: " + std::to_string(made) + " copies");
            ImGui::CloseCurrentPopup();
          }
          ImGui::SameLine();
        }
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
          ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
      }
      float mFlattenHeight = 0.0f;
      float mFlattenLow = 0.0f;
      float mFlattenHigh = 0.0f;
      float mFlattenMean = 0.0f;
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
      std::string mMaskStampArg; // `/maskstamptest <layer>,<x0>,<z0>,<x1>,<z1>,<spacing>`
      bool mFlattenTestDone = false;
      int mFlattenTestFrames = 0;
      int mMaskStampFrames = 0;
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
        const std::shared_ptr<gpg::gal::RenderTarget>& output
      );
      moho::ID3DDeviceResources::RenderTargetHandle mMiniCopy;
      moho::ID3DRenderTarget::SurfaceHandle mMiniSurface;
      // The copy a resize replaced: this frame's panels were built with its image, so it lives one frame more.
      moho::ID3DDeviceResources::RenderTargetHandle mMiniRetired;
      moho::ID3DRenderTarget::SurfaceHandle mMiniSurfaceRetired;
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
      /** `/tipcheck`: the tooltip coverage check, then the editor closes. */
      EdTipCheck mTipCheck;
      bool mTipCheckAsked = false;
      // The QA runs (EdUiQa) and the self tests (EdSelfTests), from Help or `/clicksweep`, `/layoutcheck`,
      // `/selftests`.
      EdUiQa mUiQa;
      EdSelfTests mSelfTests;
      bool mClickSweepAsked = false;
      bool mLayoutCheckAsked = false;
      bool mSelfTestsAsked = false;
      bool mQaExitAfter = false;
      bool mShowSelfTests = false;
      bool mStressOn = false;
      std::vector<std::string> mQaReport;
      void WireUiQa()
      {
        mUiQa.getScale = [this] {
          return mShell->UiScale();
        };
        mUiQa.setScale = [this](const float scale) {
          mShell->UiScale() = scale;
        };
        mUiQa.panels = [this] {
          return mShell->PanelWindows();
        };
        mUiQa.showPanel = [this](const std::string& window, const bool on) {
          return mShell->ShowPanelWindow(window, on);
        };
      }
      /** The self tests (Help > Self tests): each goes through the editor's own operations and undo on the open map. */
      void RegisterSelfTests()
      {
        // The budget's stress (Studio's perfstress.lua): 4000 markers over the map as one undo step, taken back after.
        mSelfTests.stressOn = [this] {
          const MarkerType* const type = FindMarkerType("Blank Marker");
          if (type == nullptr || mDocument.Map() == nullptr) {
            return;
          }
          EdDocument::SaveSnapshot snapshot = mDocument.SaveDataNow();
          std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
          const float w = static_cast<float>(std::max(2, mDocument.Facts().fieldWidth) - 1);
          for (int i = 0; i < 4000; ++i) {
            const float x = std::fmod(static_cast<float>(i) * 37.13f, w);
            const float z = std::fmod(static_cast<float>(i) * 91.71f, w);
            markers.push_back(NewMarker(*type, NextMarkerName(markers, *type), x, mScene.GroundHeightAt(x, z), z));
          }
          mDocument.SaveDataEdited(std::move(snapshot));
          mStressOn = true;
          gpg::Logf("editor: self tests: the budget runs with 4000 more markers");
        };
        mSelfTests.stressOff = [this] {
          if (std::exchange(mStressOn, false)) {
            (void)mScene.Undo();
          }
        };
        const auto heightsBack = [this](const std::uint64_t before, const char* what) -> std::string {
          return mScene.HeightsHash() == before ? std::string()
                                                : std::string(what) + ": undo didn't bring the heights back";
        };
        mSelfTests.Add("height stroke and its undo", [this, heightsBack] {
          const std::uint64_t before = mScene.HeightsHash();
          float low = 0.0f, high = 0.0f, mean = 0.0f;
          (void)mScene.HeightRange(low, high, mean);
          const float mid = static_cast<float>(mDocument.Facts().fieldWidth) * 0.5f;
          if (!mScene.TestRaise(mid, mid, 0.5f)) {
            return std::string("the stroke changed nothing");
          }
          (void)mScene.Undo();
          return heightsBack(before, "stroke");
        });
        mSelfTests.Add("flatten the map and its undo", [this, heightsBack] {
          const std::uint64_t before = mScene.HeightsHash();
          float low = 0.0f, high = 0.0f, mean = 0.0f;
          (void)mScene.HeightRange(low, high, mean);
          if (const auto flattened = mScene.FlattenWhole(mean + 3.0f); !flattened) {
            return "flatten refused: " + flattened.error();
          }
          (void)mScene.Undo();
          return heightsBack(before, "flatten");
        });
        mSelfTests.Add("kept path: apply, apply again, take off, undo", [this, heightsBack] {
          const std::uint64_t before = mScene.HeightsHash();
          EdDocument::PathsState pathsBefore = mDocument.PathsNow();
          KeptPath path = NewKeptPath(KeptPathMode::Carve, false, mDocument.EditPaths().set.TakeId());
          const float w = static_cast<float>(mDocument.Facts().fieldWidth);
          const auto ground = [this](const float x, const float z) {
            return mScene.GroundHeightAt(x, z);
          };
          AddKeptPathPoint(path, w * 0.3f, w * 0.3f, ground);
          AddKeptPathPoint(path, w * 0.6f, w * 0.5f, ground);
          const std::string id = path.id;
          mDocument.EditPaths().set.paths.push_back(std::move(path));
          mDocument.PathsEdited(std::move(pathsBefore));
          (void)mScene.ApplyKeptPaths({id});
          const std::uint64_t applied = mScene.HeightsHash();
          (void)mScene.ApplyKeptPaths({id});
          std::string result;
          if (applied == before) {
            result = "the path changed nothing";
          } else if (mScene.HeightsHash() != applied) {
            result = "applying again didn't give the same heights";
          }
          (void)mScene.UnapplyKeptPath(id);
          if (result.empty() && mScene.HeightsHash() != before) {
            result = "taking it off didn't bring the heights back";
          }
          for (int i = 0; i < 4; ++i) {
            (void)mScene.Undo();
          }
          return result.empty() ? heightsBack(before, "path") : result;
        });
        mSelfTests.Add("map skeleton: generate, apply all, undo", [this, heightsBack] {
          const std::uint64_t before = mScene.HeightsHash();
          SkeletonSettings settings;
          // Ridges: raised ground on any map (open lanes on flat ground rightly change nothing).
          settings.style = SkeletonStyle::Ridge;
          const std::string generated = mScene.GenerateSkeleton(settings);
          if (generated.contains("needs at least two")) {
            return "skip: " + generated;
          }
          (void)mScene.ApplySkeleton(settings);
          const bool changed = mScene.HeightsHash() != before;
          (void)mScene.Undo();
          const std::string back = heightsBack(before, "skeleton");
          (void)mScene.Undo();
          return !changed ? std::string("the skeleton changed nothing") : back;
        });
        mSelfTests.Add("detail pass and its undo", [this] {
          const std::size_t before = mDocument.PropsNow().entries.size();
          DetailRun run;
          run.environment = mScene.DetailEnvironmentGuess();
          run.density = 0.2f;
          const std::string text = mScene.RunDetailPass(run);
          const std::size_t after = mDocument.PropsNow().entries.size();
          if (after == before) {
            return "skip: " + text;
          }
          (void)mScene.Undo();
          return mDocument.PropsNow().entries.size() == before ? std::string() : std::string("undo left props behind");
        });
        mSelfTests.Add("GPU and CPU blur agree", [] {
          auto grid = std::make_shared<field::Grid>(512, 512, 1.0f, 0.0f, 0.0f);
          for (int z = 0; z < 512; ++z) {
            for (int x = 0; x < 512; ++x) {
              grid->At(x, z) = static_cast<float>((x * 13 + z * 7) % 31);
            }
          }
          field::OpArgs args;
          args.in["a"] = grid;
          args.p.num["radius"] = 4.0;
          field::Grid a;
          field::Grid b;
          if (const auto ran = field::RunOp("blur", args, a); !ran) {
            return "the blur failed: " + ran.error();
          }
          if (const auto ran = field::RunOpCpu("blur", args, b); !ran) {
            return "the blur failed: " + ran.error();
          }
          for (std::size_t k = 0; k < a.v.size(); ++k) {
            if (std::abs(a.v[k] - b.v[k]) > 1e-3f) {
              return std::string("the GPU blur differs from the CPU's");
            }
          }
          return std::string();
        });
        mSelfTests.Add("the map's script reads as a mission outline", [this] {
          const MissionOutline o = ParseMissionScript(mDocument.Script());
          return o.lineCount > 0 ? std::string() : std::string("skip: the map has no script text");
        });
        mSelfTests.Add("the unit wizard's template data loads", [] {
          UnitWizardData data;
          const auto loaded = LoadUnitWizardData(EmbeddedEditorData("unitwizdata.lua"), data);
          return loaded ? std::string() : loaded.error();
        });
        mSelfTests.Add("turn a selected marker, then undo", [this] {
          const auto& markers = mDocument.SaveData().Markers();
          if (markers.empty()) {
            return std::string("skip: the map has no markers");
          }
          const std::string name = markers.front().name;
          const auto heading = [this, &name]() {
            for (const SaveEntry& m : mDocument.SaveData().Markers()) {
              if (m.name == name) {
                std::vector<double> o = ValueNumbers(m.Get("orientation"));
                return o.size() >= 2 ? o[1] : 0.0;
              }
            }
            return 0.0;
          };
          const double before = heading();
          mScene.SelectMarkers({name}, false);
          const bool turned = mScene.TurnEverySelected(0.7853982f);
          const double after = heading();
          (void)mScene.Undo();
          const double back = heading();
          mScene.SelectMarkers({}, false);
          if (!turned || std::fabs(after - before - 0.7853982) > 1.0e-3) {
            return "the marker didn't turn by 45 degrees (" + std::to_string(before) + " -> " + std::to_string(after) +
              ")";
          }
          return std::fabs(back - before) < 1.0e-6 ? std::string() : std::string("undo didn't turn it back");
        });
        mSelfTests.Add("undo and redo of a marker", [this] {
          const std::size_t before = mDocument.SaveData().Markers().size();
          const MarkerType* const type = FindMarkerType("Blank Marker");
          if (type == nullptr) {
            return std::string("skip: no Blank Marker type");
          }
          EdDocument::SaveSnapshot snapshot = mDocument.SaveDataNow();
          std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
          markers.push_back(
            NewMarker(*type, NextMarkerName(markers, *type), 10.0f, mScene.GroundHeightAt(10.0f, 10.0f), 10.0f)
          );
          mDocument.SaveDataEdited(std::move(snapshot));
          const bool added = mDocument.SaveData().Markers().size() == before + 1;
          (void)mScene.Undo();
          return added && mDocument.SaveData().Markers().size() == before
            ? std::string()
            : std::string("the marker didn't come and go");
        });
      }
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
        // `/pathtest <mode>,x0,z0,x1,z1[,...]` (test runs): a terrain path applied (EdMapScene::TestPath).
        if (fa::vector<fa::string> path; moho::CFG_GetArgOption("/pathtest", 1, &path) && !path.empty()) {
          gpg::Logf("editor: /pathtest: %s", mScene.TestPath(path[0].c_str()).c_str());
        }
        // `/keptpathtest <mode>,x0,z0,x1,z1[,...]` (test runs): a kept path applied, re-applied, unapplied, undone.
        if (fa::vector<fa::string> path; moho::CFG_GetArgOption("/keptpathtest", 1, &path) && !path.empty()) {
          mScene.TestKeptPath(path[0].c_str());
        }
        // `/meshtest <obj file>` (test runs): the OBJ imported as the open map's mesh terrain (the scenario made a mesh
        // map), then the mesh checks and the placement heights logged (DriveImagesAndMesh).
        if (fa::vector<fa::string> obj; moho::CFG_GetArgOption("/meshtest", 1, &obj) && !obj.empty()) {
          mShell->AskMeshImport(obj[0].c_str(), true);
          mMeshTestFrames = 1;
        }
        // `/reseattest` (test runs): a prop and a unit placed, the ground under both raised by 10, and 30 frames later
        // their heights against the ground's (DriveReseatTest).
        if (moho::CFG_GetArgOption("/reseattest", 0, nullptr)) {
          const float w = static_cast<float>(std::max(mDocument.Facts().fieldWidth - 1, 2));
          const float c = w * 0.5f;
          std::string unitName;
          const std::string prop = mScene.ModAddProp("/env/evergreen/props/rocks/rock01_prop.bp", c + 20.0f, c, 1.0f);
          const std::string unit = mScene.ModAddUnit("uel0201", "ARMY_1", c - 20.0f, c, unitName);
          gpg::Logf(
            "editor: /reseattest: prop %s, unit %s",
            prop.empty() ? "placed" : prop.c_str(),
            unit.empty() ? unitName.c_str() : unit.c_str()
          );
          gpg::Logf(
            "editor: /reseattest: the ground before: %.2f under the prop, %.2f under the unit; raising both by 10",
            static_cast<double>(mScene.GroundHeightAt(c + 20.0f, c)),
            static_cast<double>(mScene.GroundHeightAt(c - 20.0f, c))
          );
          for (const float x : {c + 20.0f, c - 20.0f}) {
            const int x0 = static_cast<int>(x) - 6;
            const int z0 = static_cast<int>(c) - 6;
            std::vector<float> heights(13 * 13);
            for (int dz = 0; dz < 13; ++dz) {
              for (int dx = 0; dx < 13; ++dx) {
                heights[static_cast<std::size_t>(dz) * 13 + dx] =
                  mScene.GroundHeightAt(static_cast<float>(x0 + dx), static_cast<float>(z0 + dz)) + 10.0f;
              }
            }
            (void)mScene.WriteHeightRect(x0, z0, 13, 13, heights);
          }
          mReseatTestFrames = 1;
        }
        // `/resourcecheck` (test runs): the resources by the build rules, logged one line a marker.
        if (moho::CFG_GetArgOption("/resourcecheck", 0, nullptr)) {
          int blocked = 0;
          const std::vector<EdMapScene::ResourceFit> fits = mScene.ResourceFits("ueb1103", "ueb1102");
          for (const EdMapScene::ResourceFit& fit : fits) {
            blocked += fit.problem.empty() ? 0 : 1;
            gpg::Logf(
              "editor: /resourcecheck: %s at %.1f, %.1f: %s; %d props in the footprint",
              fit.marker.c_str(),
              static_cast<double>(fit.x),
              static_cast<double>(fit.z),
              fit.problem.empty() ? "can be built" : fit.problem.c_str(),
              fit.props
            );
          }
          gpg::Logf("editor: /resourcecheck: %zu resources, %d can't be built", fits.size(), blocked);
        }
        // `/skeletontest <style>,<topology>` (test runs): the map skeleton generated, applied and undone.
        if (fa::vector<fa::string> spec; moho::CFG_GetArgOption("/skeletontest", 1, &spec) && !spec.empty()) {
          mScene.TestSkeleton(spec[0].c_str());
        }
        // `/console <line>` (test runs): a console line, as if typed in the Log panel and Entered.
        if (fa::vector<fa::string> line; moho::CFG_GetArgOption("/console", 1, &line) && !line.empty()) {
          mLog.QueueCommand(line[0].c_str());
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
          const auto exported = mDocument.ExportPreview(file[0].c_str());
          const bool ok = exported.has_value();
          const std::string& message = ok ? *exported : exported.error();
          (ok ? gpg::Logf : gpg::Warnf)("editor: %s", message.c_str());
        }
        // `/exportpreview512 <file>` (test runs): the preview painted at 512 px (layers' colours, the map's sun).
        if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/exportpreview512", 1, &file) && !file.empty()) {
          const auto exported = ExportPaintedPreview(file[0].c_str(), 512);
          const bool ok = exported.has_value();
          const std::string& message = ok ? *exported : exported.error();
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
      /** The Images panel's exports and imports, and the Mesh terrain panel's import. */
      void DriveImagesAndMesh();
      std::string mModsMapSeen;
      const void* mRulesSeen = nullptr;
      /** Save's question for a map outside the vault: write over it there, Save as, or nothing. */
      void DrawOverwriteAsk();
      bool mAskOverwrite = false;
      /** File > Update the lobby picture on save (FAF Studio renders it on every save; the editor keeps it by default).
       */
      bool mUpdatePreviewOnSave = false;
      /** A new map's first save draws its lobby picture from the map (New made a plain one). */
      bool mPreviewOnFirstSave = false;
      /** File > New sample map: once the new map is open, the Generate workspace's island graph builds its ground. */
      bool mSampleMapPending = false;
      bool mSampleBuildDue = false;
      std::string mFieldsTest;
      int mFieldsTestFrames = 0;
      /**
       * The Log panel's console line: `sim <code>` runs in the sim (the engine's SimLua, with a session), `con
       * <command>` is the engine's console, anything else runs in the interface's Lua; `=expr` prints its value.
       */
      void RunConsoleLine(const std::string& line);
      bool mMarkerTemplatesRead = false;
      std::string mGraphMap;       // the map the Generate graph was built on (or came with): saved beside it
      std::string mGraphOpenedFor; // the map whose own graph was looked for
      /**
       * Map > Resize, in two steps: StartResize takes what the map has (heights and masks as images, resized; props,
       * decals, markers, areas and units moved; the look, the layers and the scenario's fields) and makes the new
       * folder; once the new map is open, FinishResize puts it all on it, saves it and opens it again.
       */
      void StartResize(const EdShell::ResizeRequest& request);
      /** The view menu's place-here, focus, snap, set-army and move-to-group entries, at its point. */
      void RunViewMenuAction(
        const EdShell::ViewMenuPoint& at,
        const EdShell::ViewMenuAction& action
      )
      {
        using Kind = EdShell::ViewMenuAction::Kind;
        EdTools& tools = mShell->Tools();
        switch (action.kind) {
        case Kind::PlaceMarker:
          tools.SetMarkerTool(action.arg);
          mScene.PlaceMarkers(at.x, at.z);
          break;
        case Kind::AddArea:
          tools.SetMarkerTool(tools.PlaceMarkerType().type);
          tools.AskAddAreaAt(at.x, at.z);
          break;
        case Kind::PlaceUnit:
          mScene.PlaceUnitHere(at.x, at.z);
          break;
        case Kind::PlaceProp:
          mScene.PlacePropHere(at.x, at.z);
          break;
        case Kind::FocusHere:
          mScene.FramePoint(at.x, at.z);
          break;
        case Kind::SnapToGrid:
          (void)mScene.SnapMarkerToGrid(action.arg);
          break;
        case Kind::SetArmy:
          gpg::Logf("editor: view menu: %d units to %s", mScene.GiveSelectionTo(action.arg), action.arg.c_str());
          break;
        case Kind::MoveToGroup:
          (void)mScene.MoveUnitsToGroup(action.arg, {at.unitName}, action.path);
          break;
        default:
          break;
        }
        gpg::Logf(
          "editor: view menu action %d at %.1f, %.1f%s%s",
          std::to_underlying(action.kind),
          static_cast<double>(at.x),
          static_cast<double>(at.z),
          action.arg.empty() ? "" : ": ",
          action.arg.c_str()
        );
      }
      /** Map > Regenerate preview: the lobby picture drawn anew from the heights, the sea and the markers. */
      [[nodiscard]] std::expected<std::string, std::string> RegeneratePreview();
      /** The lobby preview painted at `side` (FAF Studio's preview.lua look): layers' colours, the map's sun, dots. */
      /** What every picture of this map shares (heights and layer colours), kept while the look pictures are made. */
      struct PreviewGround
      {
        HeightImage heights;
        std::array<std::array<float, 3>, 9> colours{};
        bool ready = false;
      };
      PreviewGround mLookThumbGround;
      /** `lighting` (null: the map's) lights it; `ground` (null: read now) keeps the heights and colours between calls.
       */
      bool PaintPreview(
        int side,
        std::vector<std::uint32_t>& pixels,
        float& width,
        float& depth,
        std::size_t& dotCount,
        std::string& message,
        const LightingState* lighting = nullptr,
        PreviewGround* ground = nullptr
      );
      std::array<std::array<float, 3>, 9> LayerColours();
      /** File > Export the lobby preview at 512 px: painted afresh at that size, as a PNG. */
      [[nodiscard]] std::expected<std::string, std::string>
      ExportPaintedPreview(const std::filesystem::path& file, int side);
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
      /** The rules' context: the heights (and the paint when a rule reads it). Or the error. */
      [[nodiscard]] std::expected<void, std::string>
      MaskGenContextOf(const std::vector<MaskGenRule>& rules, MaskGenContext& context);
      /** The Images panel's previews: one a frame for the rows on screen, all dropped when the map was edited. */
      std::uint64_t mImageThumbEdits = ~0ULL;
      void ImagesPanelThumbs()
      {
        if (!mScene.Attached()) {
          if (mImageThumbEdits != ~0ULL) {
            mShell->ClearImageThumbs();
            mImageThumbEdits = ~0ULL;
          }
          return;
        }
        if (mDocument.EditCount() != mImageThumbEdits) {
          mShell->ClearImageThumbs();
          mImageThumbEdits = mDocument.EditCount();
          return;
        }
        std::string what;
        if (!mShell->TakeImageThumbWanted(what)) {
          return;
        }
        constexpr int kSide = 64;
        std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kSide) * kSide, 0xFF202020u);
        const auto grey = [](const float v) {
          const auto g = static_cast<std::uint32_t>(std::clamp(v, 0.0f, 1.0f) * 255.0f + 0.5f);
          return 0xFF000000u | (g << 16) | (g << 8) | g;
        };
        bool made = false;
        if (what == "heights") {
          if (
            const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
            terrain != nullptr && terrain->width > 1
          ) {
            const auto [low, high] = std::minmax_element(terrain->heights.begin(), terrain->heights.end());
            const float span = std::max(*high - *low, 0.001f);
            for (int y = 0; y < kSide; ++y) {
              for (int x = 0; x < kSide; ++x) {
                const int sx = x * (terrain->width - 1) / (kSide - 1);
                const int sz = y * (terrain->height - 1) / (kSide - 1);
                pixels[static_cast<std::size_t>(y) * kSide + x] =
                  grey((terrain->heights[static_cast<std::size_t>(sz) * terrain->width + sx] - *low) / span);
              }
            }
            made = true;
          }
        } else if (what.starts_with("mask")) {
          const int byte = std::clamp(std::atoi(what.c_str() + 4), 1, 8) - 1;
          const EdDocument::MaskGrid& masks = mScene.ReadMasks();
          if (!masks.texels.empty()) {
            const bool range = (RemappedStrata(mScene.TerrainShader()) & (1U << byte)) != 0;
            for (int y = 0; y < kSide; ++y) {
              for (int x = 0; x < kSide; ++x) {
                const std::uint64_t texel =
                  masks.texels
                    [static_cast<std::size_t>(y * (masks.height - 1) / (kSide - 1)) * masks.width +
                     x * (masks.width - 1) / (kSide - 1)];
                pixels[static_cast<std::size_t>(y) * kSide + x] =
                  grey(MaskWeight(MaskByte(texel, byte), range) / 255.0f);
              }
            }
            made = true;
          }
        } else if (what.starts_with("water")) {
          int width = 0;
          int height = 0;
          if (
            const std::uint8_t* const cells = mDocument.WaterMaskCells(
              static_cast<WaterMask>(std::clamp(std::atoi(what.c_str() + 5), 0, 2)), width, height
            );
            cells != nullptr && width > 1 && height > 1
          ) {
            for (int y = 0; y < kSide; ++y) {
              for (int x = 0; x < kSide; ++x) {
                pixels[static_cast<std::size_t>(y) * kSide + x] =
                  grey(cells[(y * (height - 1) / (kSide - 1)) * width + x * (width - 1) / (kSide - 1)] / 255.0f);
              }
            }
            made = true;
          }
        } else if (what == "types") {
          int width = 0;
          int height = 0;
          if (
            const std::uint8_t* const cells = mDocument.TerrainTypeCells(width, height);
            cells != nullptr && width > 1 && height > 1
          ) {
            for (int y = 0; y < kSide; ++y) {
              for (int x = 0; x < kSide; ++x) {
                const std::uint32_t id =
                  cells[(y * (height - 1) / (kSide - 1)) * width + x * (width - 1) / (kSide - 1)];
                // Each id its own colour (a hash), so neighbouring types stand apart.
                const std::uint32_t h = id * 2654435761u;
                pixels[static_cast<std::size_t>(y) * kSide + x] = 0xFF000000u | (h & 0x00C0C0C0u) | 0x00303030u;
              }
            }
            made = true;
          }
        }
        const std::uint64_t image = made ? EdImGuiRenderer::CreateImage(kSide, kSide, pixels.data()) : 0U;
        mShell->SetImageThumb(what, image);
        if (moho::CFG_GetArgOption("/imagestest", 0, nullptr)) {
          gpg::Logf("editor: images: preview of %s %s", what.c_str(), image != 0U ? "made" : "not made");
        }
      }
      /** Layers > Theme library: the shipped themes (read once) and the user's (themes.lua in the settings folder). */
      std::vector<StrataTheme> mStrataThemes;
      bool mStrataThemesRead = false;
      std::filesystem::path StrataThemesFile() const
      {
        if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/themesfile", 1, &file) && !file.empty()) {
          return std::filesystem::path(file[0].c_str());
        }
        if (gTestRun) {
          return {};
        }
        const std::filesystem::path folder = EditorSettingsFolder();
        return folder.empty() ? std::filesystem::path{} : folder / "themes.lua";
      }
      void StrataThemesUpdate(
        const std::vector<EdTools::LayerSlot>& slots
      )
      {
        EdTools& tools = mShell->Tools();
        const auto publish = [&] {
          std::vector<std::string> labels;
          std::vector<bool> user;
          for (const StrataTheme& theme : mStrataThemes) {
            labels.push_back((theme.user ? std::string("My themes") : theme.group) + ": " + theme.name);
            user.push_back(theme.user);
          }
          tools.SetStrataThemeList(std::move(labels), std::move(user));
        };
        const auto saveUser = [&] {
          std::vector<StrataTheme> mine;
          for (const StrataTheme& theme : mStrataThemes) {
            if (theme.user) {
              mine.push_back(theme);
            }
          }
          if (const std::filesystem::path file = StrataThemesFile(); !file.empty()) {
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            out << WriteStrataThemes(mine);
          }
        };
        if (!mStrataThemesRead) {
          mStrataThemesRead = true;
          if (const std::filesystem::path file = StrataThemesFile(); !file.empty()) {
            if (std::ifstream in(file, std::ios::binary); in) {
              std::stringstream text;
              text << in.rdbuf();
              std::vector<StrataTheme> mine;
              if (const auto read = ParseStrataThemes(text.str(), "UserThemes", mine)) {
                for (StrataTheme& theme : mine) {
                  theme.user = true;
                  mStrataThemes.push_back(std::move(theme));
                }
              } else {
                gpg::Warnf("editor: %s: %s", file.string().c_str(), read.error().c_str());
              }
            }
          }
          std::vector<StrataTheme> shipped;
          if (const auto read = ParseStrataThemes(EmbeddedEditorData("envlib_themes.lua"), "Themes", shipped); !read) {
            gpg::Warnf("editor: the theme library: %s", read.error().c_str());
          }
          mStrataThemes.insert(mStrataThemes.end(), shipped.begin(), shipped.end());
          gpg::Logf("editor: theme library: %zu themes (%zu shipped)", mStrataThemes.size(), shipped.size());
          publish();
        }
        EdTools::StrataThemeAsk ask;
        if (!tools.TakeStrataThemeAsk(ask) || !mScene.Attached()) {
          return;
        }
        using Op = EdTools::StrataThemeAsk::Op;
        const auto addUser = [&](StrataTheme theme) {
          theme.user = true;
          theme.group = "My themes";
          mStrataThemes.erase(
            std::remove_if(
              mStrataThemes.begin(),
              mStrataThemes.end(),
              [&](const StrataTheme& t) {
            return t.user && t.id == theme.id;
          }
            ),
            mStrataThemes.end()
          );
          mStrataThemes.insert(mStrataThemes.begin(), std::move(theme));
          saveUser();
          publish();
        };
        std::string status;
        switch (ask.op) {
        case Op::Try:
        case Op::Apply: {
          if (ask.index < 0 || ask.index >= static_cast<int>(mStrataThemes.size())) {
            break;
          }
          const StrataTheme& theme = mStrataThemes[static_cast<std::size_t>(ask.index)];
          std::vector<std::pair<int, LayerSettings>> layers;
          std::vector<std::pair<int, LayerSettings>> before;
          for (const auto& [slot, layer] : theme.layers) {
            layers.push_back({slot, LayerSettings{layer.albedo, layer.normal, layer.size, layer.nsize}});
            if (static_cast<std::size_t>(slot) < slots.size()) {
              const EdTools::LayerSlot& now = slots[static_cast<std::size_t>(slot)];
              before.push_back({slot, LayerSettings{now.albedo, now.normals, now.albedoSize, now.normalsSize}});
            }
          }
          const int changed = mScene.ApplyLayerSettings({}, layers);
          int cleared = 0;
          if (ask.op == Op::Try) {
            mThemeBefore = std::move(before);
            mThemeTrying = changed > 0;
          } else if (ask.clearUnused) {
            for (int slot = 1; slot <= 8; ++slot) {
              if (
                !theme.layers.contains(slot) && static_cast<std::size_t>(slot) < slots.size() &&
                !slots[static_cast<std::size_t>(slot)].albedo.empty() && tools.RunLayerMenuItem(slot, "remove")
              ) {
                ++cleared;
              }
            }
          }
          status = "Theme " + theme.name + ": " + std::to_string(changed) + " layers" +
            (cleared > 0 ? ", " + std::to_string(cleared) + " unused layers cleared" : std::string());
          break;
        }
        case Op::Save: {
          StrataTheme theme;
          theme.name = ask.arg;
          theme.id = StrataThemeId(ask.arg);
          theme.desc = "Saved from " + mDocument.Facts().name;
          for (std::size_t slot = 0; slot < slots.size() && slot < 10; ++slot) {
            if (!slots[slot].albedo.empty()) {
              theme.layers[static_cast<int>(slot)] = StrataThemeLayer{
                slots[slot].albedo, slots[slot].normals, slots[slot].albedoSize, slots[slot].normalsSize
              };
            }
          }
          status = "Saved the theme " + theme.name + " (" + std::to_string(theme.layers.size()) + " layers)";
          addUser(std::move(theme));
          break;
        }
        case Op::Import: {
          // The map by its folder, as the Looks list names maps: its .scmap's strata.
          std::string wanted = ask.arg;
          std::transform(wanted.begin(), wanted.end(), wanted.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
          });
          std::string scenario;
          for (const std::string& map : mPlay.Maps()) {
            std::string folder = MapDisplayName(map);
            std::transform(folder.begin(), folder.end(), folder.begin(), [](const unsigned char c) {
              return static_cast<char>(std::tolower(c));
            });
            if (folder == wanted) {
              scenario = map;
              break;
            }
          }
          std::string text;
          std::string bytes;
          std::smatch path;
          std::expected<Look, std::string> look = std::unexpected(std::string());
          if (scenario.empty()) {
            status = "No map " + ask.arg + " among the game's maps";
          } else if (
            !ReadGameFile(scenario, text) ||
            !std::regex_search(text, path, std::regex(R"(\bmap\s*=\s*['"]([^'"]+\.scmap)['"])")) ||
            !ReadGameFile(path[1].str(), bytes) || !(look = LookFromScmap(bytes))
          ) {
            status =
              "Can't read " + ask.arg + "'s map file" + (look.error().empty() ? std::string() : ": " + look.error());
          } else if (look->strataAlbedo.empty()) {
            status = ask.arg + "'s map file is older than format 54: its layers aren't read";
          } else {
            StrataTheme theme;
            theme.name = MapDisplayName(scenario);
            theme.id = StrataThemeId(theme.name);
            theme.desc = "Imported from " + theme.name;
            for (std::size_t slot = 0; slot < look->strataAlbedo.size(); ++slot) {
              if (look->strataAlbedo[slot].first.empty()) {
                continue;
              }
              StrataThemeLayer layer;
              layer.albedo = look->strataAlbedo[slot].first;
              layer.size = look->strataAlbedo[slot].second;
              if (slot < look->strataNormal.size()) {
                layer.normal = look->strataNormal[slot].first;
                layer.nsize = look->strataNormal[slot].second;
              }
              theme.layers[static_cast<int>(slot)] = layer;
            }
            status = "Imported " + theme.name + "'s layers as a theme (" + std::to_string(theme.layers.size()) + ")";
            addUser(std::move(theme));
          }
          break;
        }
        case Op::Delete:
          if (
            ask.index >= 0 && ask.index < static_cast<int>(mStrataThemes.size()) &&
            mStrataThemes[static_cast<std::size_t>(ask.index)].user
          ) {
            status = "Deleted the theme " + mStrataThemes[static_cast<std::size_t>(ask.index)].name;
            mStrataThemes.erase(mStrataThemes.begin() + ask.index);
            saveUser();
            publish();
          }
          break;
        default:
          break;
        }
        if (!status.empty()) {
          tools.SetStrataThemeStatus(status);
          PostStatusMessage(status);
          gpg::Logf("editor: theme library: %s", status.c_str());
        }
      }
      /**
       * `/r6test <folder>` (test runs): the fourth comparison's features driven one a step, each logged: the chain of
       * the selected marker, marker models, a camera marker set from the view and looked through, the view menu's
       * point and a marker placed there, a unit line, a marker's height check and its fix, a resource snapped to the
       * grid, the army's groups, an imported mask, the theme library (apply, save, import), the Images panel.
       */
      int mR6Stage = 0;
      int mR6Frames = 0;
      std::string mR6Marker;
      void DriveRoundSixTest()
      {
        fa::vector<fa::string> arg;
        if (
          mR6Stage >= 14 || !mScene.Attached() || !mScene.UnitsReady() || !moho::CFG_GetArgOption("/r6test", 1, &arg) ||
          arg.empty() || ++mR6Frames % 90 != 0
        ) {
          return;
        }
        const std::filesystem::path folder(arg[0].c_str());
        EdTools& tools = mShell->Tools();
        const float c = static_cast<float>(std::max(mDocument.Facts().fieldWidth - 1, 2)) * 0.5f;
        std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
        const auto count = [&](const char* type) {
          return std::count_if(markers.begin(), markers.end(), [type](const SaveEntry& m) {
            return MarkerTypeOf(m) == type;
          });
        };
        switch (mR6Stage++) {
        case 0: {
          // The tools' state: brush mode 0 set to 33 / 0.4 / 0.7 and a 45 degree step (/toolsfile keeps it).
          tools.LoadToolState("brushMode=0\nbrush.0=33,0.4,0.7\nturnStep=45\n");
          // The first chain's first marker selected under the Markers tool.
          tools.SetMarkerTool("Blank Marker");
          const std::vector<MarkerChain>& chains = mDocument.SaveData().Chains();
          for (const MarkerChain& chain : chains) {
            if (!chain.markers.empty()) {
              mScene.SelectMarkers({chain.markers.front()}, false);
              mR6Marker = chain.name;
              break;
            }
          }
          gpg::Logf("editor: /r6test: %zu chains; selected the first marker of %s", chains.size(), mR6Marker.c_str());
          break;
        }
        case 1:
          gpg::Logf(
            "editor: /r6test: the current chain is %s (wanted %s); %zu marker models drawn for %zu markers",
            tools.ChainName().c_str(),
            mR6Marker.c_str(),
            mScene.MarkerModelCount(),
            markers.size()
          );
          break;
        case 2: {
          // A camera marker: placed at the middle, set from the view, the camera moved away, then looked through.
          tools.SetMarkerTool("Camera Info");
          mScene.PlaceMarkers(c, c);
          const std::string camera = mScene.SelectedCameraMarker();
          mScene.FramePoint(c, c, 220.0f);
          const EdMapScene::CameraPose set = mScene.GetCameraPose();
          (void)mScene.SetCameraMarkerFromView(camera);
          mScene.FramePoint(c * 0.5f, c * 0.5f, 90.0f);
          (void)mScene.LookThroughCamera(camera);
          const EdMapScene::CameraPose back = mScene.GetCameraPose();
          gpg::Logf(
            "editor: /r6test: camera %s: set at %.1f, %.1f distance %.1f; looked through: %.1f, %.1f distance %.1f",
            camera.c_str(),
            static_cast<double>(set.targetX),
            static_cast<double>(set.targetZ),
            static_cast<double>(set.distance),
            static_cast<double>(back.targetX),
            static_cast<double>(back.targetZ),
            static_cast<double>(back.distance)
          );
          break;
        }
        case 3: {
          // The view menu at the middle of the view, and a start position placed at its point.
          mScene.AskContextMenu();
          const long before = static_cast<long>(count("Blank Marker"));
          const EdMapScene::ContextPoint& here = mScene.ContextPointNow();
          EdShell::ViewMenuPoint point;
          point.valid = here.valid;
          point.x = here.x;
          point.z = here.z;
          EdShell::ViewMenuAction action;
          action.kind = EdShell::ViewMenuAction::Kind::PlaceMarker;
          action.arg = "Blank Marker";
          RunViewMenuAction(point, action);
          gpg::Logf(
            "editor: /r6test: view menu point %s %.1f, %.1f (%s); start positions %ld -> %ld",
            here.valid ? "at" : "missing",
            static_cast<double>(here.x),
            static_cast<double>(here.z),
            here.what.empty() ? "nothing under it" : here.what.c_str(),
            before,
            static_cast<long>(count("Blank Marker"))
          );
          (void)mScene.Undo();
          break;
        }
        case 4:
          // A line of tanks 60 long (one undo step), then undone.
          tools.SetUnitTool("uel0201", "ARMY_1", false);
          mScene.PlaceUnitLineHere(c - 30.0f, c + 40.0f, c + 30.0f, c + 40.0f);
          gpg::Logf(
            "editor: /r6test: the unit line's undo step: %s",
            mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
          );
          (void)mScene.Undo();
          break;
        case 5: {
          // A path node lifted 10 above the ground: the check's note and its fix.
          for (SaveEntry& marker : markers) {
            float x = 0.0f, y = 0.0f, z = 0.0f;
            const std::string type = MarkerTypeOf(marker);
            if (type == "Mass" || type == "Hydrocarbon" || type == "Blank Marker" || !MarkerPosition(marker, x, y, z)) {
              continue;
            }
            mScene.EditMarker(marker.name, "position", Vector3Value(x, mScene.GroundHeightAt(x, z) + 10.0f, z));
            mR6Marker = marker.name;
            break;
          }
          const auto issues = [&] {
            MarkerCheckInput input;
            input.markers = &markers;
            input.groundAt = [](const void* scene, const float x, const float z) {
              return static_cast<const EdMapScene*>(scene)->GroundHeightAt(x, z);
            };
            input.groundContext = &mScene;
            input.width = mDocument.Facts().fieldWidth;
            input.height = mDocument.Facts().fieldHeight;
            int n = 0;
            for (const CheckIssue& issue : CheckMarkers(input)) {
              if (issue.fix == CheckIssue::Fix::ToGround && issue.marker == mR6Marker) {
                gpg::Logf("editor: /r6test: check: %s %s", issue.marker.c_str(), issue.text.c_str());
                ++n;
              }
            }
            return n;
          };
          const int found = issues();
          // The fix as the Check panel runs it: the marker's height set to the ground's.
          for (const SaveEntry& marker : markers) {
            float x = 0.0f, y = 0.0f, z = 0.0f;
            if (marker.name == mR6Marker && MarkerPosition(marker, x, y, z)) {
              mScene.EditMarker(
                marker.name,
                "position",
                Vector3Value(
                  x,
                  mDocument.Map()->mTerrainRes->GetHeightAt(
                    static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
                  ),
                  z
                )
              );
              break;
            }
          }
          gpg::Logf(
            "editor: /r6test: %s off the ground: %d notes before the fix, %d after", mR6Marker.c_str(), found, issues()
          );
          break;
        }
        case 6: {
          // A mass point moved off its grid cell's middle, then snapped back.
          for (const SaveEntry& marker : markers) {
            float x = 0.0f, y = 0.0f, z = 0.0f;
            if (MarkerTypeOf(marker) == "Mass" && MarkerPosition(marker, x, y, z)) {
              mScene.EditMarker(marker.name, "position", Vector3Value(x + 0.3, y, z - 0.2));
              (void)mScene.SnapMarkerToGrid(marker.name);
              break;
            }
          }
          gpg::Logf("editor: /r6test: ARMY_1 has %zu group paths", mScene.GroupPathsOf("ARMY_1").size());
          break;
        }
        case 7: {
          // An imported mask: the heights and layer 1's mask written beside each other; slot 1 read by a rule.
          std::error_code ec;
          std::filesystem::create_directories(folder, ec);
          (void)mScene.ExportHeights(folder / "r6_heights.png", 0, 1.0f);
          (void)mScene.ExportMaskLayer(0, folder / "r6_wear.png");
          tools.SetInteropFile(false, (folder / "r6_heights.png").string());
          MaskGenRule rule = NewMaskRule("named");
          rule.v["slot"] = 1;
          MaskGenContext context;
          field::Grid mask;
          std::string error;
          const auto made = MaskGenContextOf({rule}, context).and_then([&] {
            return EvaluateMaskRules(context, {rule}, mask);
          });
          if (!made) {
            error = made.error();
          }
          const bool ok = made.has_value();
          double sum = 0.0;
          for (const float v : mask.v) {
            sum += v;
          }
          gpg::Logf(
            "editor: /r6test: imported mask slot 1: %s, mean %.3f over %zu samples%s%s",
            ok ? "read" : "failed",
            mask.v.empty() ? 0.0 : sum / static_cast<double>(mask.v.size()),
            mask.v.size(),
            error.empty() ? "" : ": ",
            error.c_str()
          );
          break;
        }
        case 8:
          tools.AskStrataTheme({EdTools::StrataThemeAsk::Op::Apply, 0, {}, true});
          break;
        case 9:
          tools.AskStrataTheme({EdTools::StrataThemeAsk::Op::Save, 0, "r6 saved", false});
          break;
        case 10:
          tools.AskStrataTheme({EdTools::StrataThemeAsk::Op::Import, 0, "scmp_012", false});
          break;
        case 11:
          if (bool* const shown = mShell->PanelShown("Images"); shown != nullptr) {
            *shown = true;
          }
          break;
        case 13:
          gpg::Logf("editor: /r6test: done");
          break;
        default:
          break;
        }
      }
      void RunQuickGen(
        EdFieldsPanel& fields,
        const EdFieldsPanel::QuickGenSettings& q,
        const bool applyIt
      )
      {
        const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
        if (terrain == nullptr || terrain->width < 2) {
          fields.SetQuickGenResult({}, "No terrain.");
          return;
        }
        const int w = terrain->width;
        const int h = terrain->height;
        auto heights = std::make_shared<field::Grid>(w, h, 1.0f, 0.0f, 0.0f);
        heights->v = terrain->heights;
        const auto run = [](const char* op, field::OpArgs args, std::string& error) -> std::shared_ptr<field::Grid> {
          auto out = std::make_shared<field::Grid>();
          if (const auto ran = field::RunOpCpu(op, args, *out); !ran) {
            error = ran.error();
            return nullptr;
          }
          return out;
        };
        std::string error;
        // FAF Studio's presets (fieldgen.lua): each an op chain of the field library, then, with gullies, a brief
        // droplet erosion, then the relief's size.
        using Num = std::map<std::string, double>;
        using Str = std::map<std::string, std::string>;
        const auto op = [&](
                          const char* name,
                          const std::map<std::string, std::shared_ptr<field::Grid>>& in,
                          const Num& num,
                          const Str& str = {}
                        ) -> std::shared_ptr<field::Grid> {
          if (!error.empty()) {
            return nullptr;
          }
          field::OpArgs args;
          for (const auto& [key, grid] : in) {
            if (grid == nullptr) {
              error = std::string(name) + ": an input failed";
              return nullptr;
            }
            args.in[key] = grid;
          }
          for (const auto& [key, value] : num) {
            args.p.num[key] = value;
          }
          for (const auto& [key, value] : str) {
            args.p.str[key] = value;
          }
          return run(name, args, error);
        };
        const double scale = q.scale;
        const double warp = q.warp;
        const double finest = std::max(3.0, scale * (0.22 - 0.19 * q.detail));
        const auto fractal = [&](const int k, Num num, Str str = {}) {
          num.emplace("seed", q.seed + k);
          num.emplace("octaves", 8);
          num.emplace("finest", finest);
          return op("fractal", {{"like", heights}}, num, str);
        };
        const auto centred = [&](const std::shared_ptr<field::Grid>& f) {
          return op("affine", {{"a", f}}, {{"mul", 1.0}, {"add", -0.5}});
        };
        const auto blend = [&](
                             const std::shared_ptr<field::Grid>& a,
                             const std::shared_ptr<field::Grid>& b,
                             const char* mode,
                             const double opacity
                           ) {
          return op("blend", {{"a", a}, {"b", b}}, {{"opacity", opacity}}, {{"mode", mode}});
        };
        std::shared_ptr<field::Grid> raw;
        switch (std::clamp(q.preset, 0, 5)) {
        case 0: { // hills
          const auto a = fractal(
            0,
            {{"scale", scale}, {"persistence", 0.42}, {"warp", warp * 0.2 * scale}, {"erosion", 1.5}},
            {{"kind", "billow"}, {"style", "erosive"}}
          );
          const auto b = fractal(
            1,
            {{"scale", scale * 1.8},
             {"persistence", 0.5},
             {"warp", warp * 0.15 * scale},
             {"slope_detail", 0.3},
             {"erosion", 1.5}},
            {{"kind", "fbm"}, {"style", "erosive"}}
          );
          raw = blend(a, b, "normal", 0.5);
          break;
        }
        case 1: { // mountains: ridged crests over a broad massif
          const auto r = fractal(
            0,
            {{"scale", scale},
             {"persistence", 0.5},
             {"sharpness", 2.2},
             {"warp", warp * 0.2 * scale},
             {"slope_detail", 0.5},
             {"erosion", 1.0}},
            {{"kind", "ridged"}, {"style", "erosive"}}
          );
          const auto peaks = op("gamma", {{"a", r}}, {{"gamma", 1.3}});
          const auto massif = fractal(
            1,
            {{"scale", scale * 1.35}, {"persistence", 0.5}, {"warp", warp * 0.2 * scale}, {"erosion", 1.5}},
            {{"kind", "fbm"}, {"style", "erosive"}}
          );
          raw = blend(peaks, massif, "normal", 0.4);
          break;
        }
        case 2: { // badlands: stepped mesas, rough cliffs
          const auto base = op(
            "fractal",
            {{"like", heights}},
            {{"seed", q.seed},
             {"scale", scale},
             {"octaves", 3},
             {"finest", std::max(finest, scale * 0.18)},
             {"warp", warp * 0.1 * scale}}
          );
          const auto shaped = op("smoothstep", {{"a", base}}, {{"edge0", 0.3}, {"edge1", 0.7}});
          const auto steps =
            op("terrace", {{"a", shaped}}, {{"steps", 5}, {"sharpness", 0.9}, {"lo", 0.0}, {"hi", 1.0}});
          const auto slope = op("slope", {{"a", steps}}, {}, {{"mode", "gradient"}});
          const auto cliff = op(
            "blur",
            {{"a",
              op(
                "clamp",
                {{"a", op("affine", {{"a", slope}}, {{"mul", 10.0}, {"add", 0.0}})}},
                {{"lo", 0.0}, {"hi", 1.0}}
              )}},
            {{"radius", 2.0}}
          );
          const auto rough = fractal(1, {{"scale", scale * 0.18}, {"persistence", 0.55}}, {{"kind", "ridged"}});
          const auto detail = op("mul", {{"a", centred(rough)}, {"b", cliff}}, {});
          const auto sum = blend(steps, detail, "add", 0.35);
          const auto grit = fractal(2, {{"scale", scale * 0.15}, {"octaves", 3}}, {{"kind", "fbm"}});
          raw = blend(sum, centred(grit), "add", 0.03);
          break;
        }
        case 3: { // dunes: crests, some stretches flat
          const auto d = op(
            "dunes",
            {{"like", heights}},
            {{"seed", q.seed},
             {"wavelength", scale},
             {"angle", static_cast<double>((q.seed * 47) % 180)},
             {"asym", 0.9},
             {"warp", warp * 0.5 * scale},
             {"warp_size", scale * 2.0},
             {"variation", 0.6},
             {"ripples", 0.0}}
          );
          const auto patches = fractal(1, {{"scale", scale * 2.5}, {"octaves", 2}, {"finest", scale}});
          const auto patchy = op("smoothstep", {{"a", patches}}, {{"edge0", 0.35}, {"edge1", 0.65}});
          const auto big = blend(d, patchy, "mul", 0.8);
          raw = blend(big, fractal(2, {{"scale", scale * 0.75}, {"persistence", 0.45}}), "normal", 0.25);
          break;
        }
        case 4: // plains detail
          raw = fractal(
            0,
            {{"scale", scale},
             {"persistence", 0.45},
             {"warp", warp * 0.15 * scale},
             {"slope_detail", 0.7},
             {"erosion", 1.0}},
            {{"kind", "fbm"}, {"style", "erosive"}}
          );
          break;
        default: { // rocks: boulder domes
          const auto cells = op(
            "cells",
            {{"like", heights}},
            {{"seed", q.seed}, {"scale", scale}, {"warp", warp * 0.2 * scale}, {"warp_scale", scale * 0.8}},
            {{"mode", "f1"}}
          );
          const auto domes = op("invert", {{"a", cells}}, {{"lo", 0.0}, {"hi", 1.0}});
          raw = blend(domes, fractal(1, {{"scale", scale * 0.8}, {"persistence", 0.5}}), "normal", 0.3);
          break;
        }
        }
        // Gullies: a brief droplet erosion of the relief at twice its size (Studio's Weather).
        if (raw != nullptr && q.gullies > 0.001f) {
          const auto range = op(
            "amplitude",
            {{"a", raw}},
            {{"amplitude", std::max(1.0, static_cast<double>(q.amplitude)) * 2.0}},
            {{"mode", "range"}, {"centre", "min"}}
          );
          const ErosionSolver* const droplet = FindErosionSolver("droplet");
          if (range != nullptr && droplet != nullptr) {
            ErosionValues v = ErosionDefaults(*droplet);
            const std::map<std::string, double> mine = {
              {"density", 0.3 + 3.2 * q.gullies},
              {"lifetime", 70},
              {"inertia", 0.25},
              {"capacity", 6},
              {"erode", 0.45},
              {"deposit", 0.12},
              {"gravity", 5},
              {"thermal", 0.4},
              {"thermal_steps", 3},
              {"talus", 0.9},
              {"vary", 0.4},
              {"protect", 0.5},
              {"drop_vary", 0.6},
              {"radius", 2},
              {"creep", 1.5},
              {"max_change", std::max(1.0, q.amplitude * 0.5)}
            };
            for (const auto& [key, value] : mine) {
              v[key] = value;
            }
            field::OpArgs args;
            args.in["a"] = range;
            for (const auto& [key, value] : ErosionOpValues(*droplet, v, 1.0)) {
              args.p.num[key] = value;
            }
            args.p.num["seed"] = q.seed + 100;
            args.p.num["masks"] = 0;
            if (const auto eroded = run(droplet->op, args, error); eroded != nullptr) {
              raw = eroded;
            }
          }
        }
        const std::shared_ptr<field::Grid> relief =
          raw != nullptr ? op("amplitude", {{"a", raw}}, {{"amplitude", q.amplitude}}, {{"mode", "peak"}}) : nullptr;
        if (relief == nullptr) {
          fields.SetQuickGenResult({}, "Generate: " + error);
          return;
        }
        // The mask: the region (whole map, playable area or an area) with a soft border, the flat spots kept.
        auto mask = std::make_shared<field::Grid>(w, h, 1.0f, 0.0f, 0.0f);
        float x0 = 0.0f, z0 = 0.0f, x1 = static_cast<float>(w - 1), z1 = static_cast<float>(h - 1);
        bool region = false;
        if (q.mask == 1) {
          if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea()) {
            x0 = static_cast<float>(area->x0);
            z0 = static_cast<float>(area->z0);
            x1 = static_cast<float>(area->x1);
            z1 = static_cast<float>(area->z1);
            region = true;
          }
        } else if (q.mask == 2) {
          for (const SaveEntry& a : mDocument.SaveData().Areas()) {
            const std::vector<double> r = ValueNumbers(a.Get("rectangle"));
            if (a.name == q.area && r.size() >= 4) {
              x0 = static_cast<float>(std::min(r[0], r[2]));
              z0 = static_cast<float>(std::min(r[1], r[3]));
              x1 = static_cast<float>(std::max(r[0], r[2]));
              z1 = static_cast<float>(std::max(r[1], r[3]));
              region = true;
            }
          }
          if (!region) {
            fields.SetQuickGenResult({}, "Choose an area of the map.");
            return;
          }
        }
        std::vector<std::array<float, 3>> spots; // x, z, radius
        if (q.keepFlat) {
          for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
            float mx = 0.0f, my = 0.0f, mz = 0.0f;
            const std::string type = MarkerTypeOf(marker);
            if (MarkerPosition(marker, mx, my, mz)) {
              if (type == "Blank Marker") {
                spots.push_back({mx, mz, q.flatRadius});
              } else if (type == "Mass" || type == "Hydrocarbon") {
                spots.push_back({mx, mz, q.flatRadius * 0.4f});
              }
            }
          }
        }
        const auto smooth = [](const float t) {
          const float c = std::clamp(t, 0.0f, 1.0f);
          return c * c * (3.0f - 2.0f * c);
        };
        for (int z = 0; z < h; ++z) {
          for (int x = 0; x < w; ++x) {
            float m = 1.0f;
            if (region) {
              const float inside = std::min(
                {static_cast<float>(x) - x0,
                 x1 - static_cast<float>(x),
                 static_cast<float>(z) - z0,
                 z1 - static_cast<float>(z)}
              );
              m = inside < 0.0f ? 0.0f : (q.feather > 0.0f ? smooth(inside / q.feather) : 1.0f);
            }
            for (const auto& s : spots) {
              const float d = std::hypot(static_cast<float>(x) - s[0], static_cast<float>(z) - s[1]);
              m *= smooth((d - s[2]) / std::max(4.0f, s[2] * 0.75f));
            }
            mask->v[static_cast<std::size_t>(z) * w + x] = m;
          }
        }
        static constexpr const char* kModes[] = {"add", "multiply", "max", "min", "replace"};
        field::OpArgs mix;
        mix.in["a"] = heights;
        mix.in["b"] = relief;
        mix.in["mask"] = mask;
        mix.p.str["mode"] = kModes[std::clamp(q.blend, 0, 4)];
        mix.p.num["strength"] = q.strength;
        std::shared_ptr<field::Grid> result = run("terrain_mix", mix, error);
        const WaterState water = mDocument.WaterNow();
        if (result != nullptr && q.keepWater && water.enabled) {
          field::OpArgs keep;
          keep.in["a"] = result;
          keep.in["b"] = heights;
          keep.p.num["level"] = water.elevation;
          keep.p.num["margin"] = 0.25;
          result = run("keep_side", keep, error);
        }
        if (result == nullptr) {
          fields.SetQuickGenResult({}, "Generate: " + error);
          return;
        }
        // What changed: the largest move, the mean, the share that moved more than 0.05.
        field::Grid change(w, h, 1.0f, 0.0f, 0.0f);
        float largest = 0.0f;
        double sum = 0.0;
        std::size_t moved = 0;
        for (std::size_t i = 0; i < change.v.size(); ++i) {
          const float d = result->v[i] - heights->v[i];
          change.v[i] = d;
          largest = std::max(largest, std::fabs(d));
          sum += std::fabs(d);
          moved += std::fabs(d) > 0.05f ? 1 : 0;
        }
        char text[200];
        (void)std::snprintf(
          text,
          sizeof(text),
          "%s (%s): the ground moves up to %.1f units, %.2f on average; %.0f %% of the map changes",
          EdFieldsPanel::QuickGenPresets()[static_cast<std::size_t>(std::clamp(q.preset, 0, 5))].label,
          kModes[std::clamp(q.blend, 0, 4)],
          static_cast<double>(largest),
          sum / static_cast<double>(std::max<std::size_t>(change.v.size(), 1)),
          100.0 * static_cast<double>(moved) / static_cast<double>(std::max<std::size_t>(change.v.size(), 1))
        );
        std::string status = text;
        if (applyIt) {
          status += ". " + mScene.ApplyGraphBuild(*result, true, TerrainBuildWrites{});
        }
        gpg::Logf("editor: fields: generate: %s", status.c_str());
        fields.SetQuickGenResult(std::move(change), status);
      }
      /**
       * `/r7test` (test runs): the fifth comparison's features a step at a time, each logged: mirror half from part 1
       * with units, areas and the armies mapped (added, then undone); the recipes' Measure, Show, Assign and
       * Layered; Generate into the map (then undone); a base defined from an area; the layout's Centre symmetry.
       */
      int mR7Stage = 0;
      int mR7Frames = 0;
      void DriveRoundSevenTest()
      {
        if (
          mR7Stage >= 12 || !mScene.Attached() || !mScene.UnitsReady() ||
          !moho::CFG_GetArgOption("/r7test", 0, nullptr) || ++mR7Frames % 90 != 0
        ) {
          return;
        }
        EdTools& tools = mShell->Tools();
        const auto unitCount = [this]() {
          std::size_t n = 0;
          for (const SaveEntry& army : mDocument.SaveData().Armies()) {
            UnitGroup root;
            if (ParseUnitGroup(army.Get("Units"), root)) {
              std::vector<const SaveUnit*> units;
              CollectUnits(root, units);
              n += units.size();
            }
          }
          return n;
        };
        switch (mR7Stage++) {
        case 0: {
          tools.SetSymmetry(std::to_underlying(Symmetry::LeftRight), 3);
          EdMapScene::MirrorHalfOptions o;
          o.source = 1;
          o.units = true;
          o.areas = true;
          o.replace = false;
          o.mapArmies = true;
          const std::size_t unitsBefore = unitCount();
          const std::size_t areasBefore = mDocument.SaveData().Areas().size();
          const int made = mScene.MirrorHalf(o);
          gpg::Logf(
            "editor: /r7test: mirror half from part 1 of %d (add, units mapped): %d copies; units %zu -> %zu; areas "
            "%zu "
            "-> %zu",
            mScene.SymmetryParts(),
            made,
            unitsBefore,
            unitCount(),
            areasBefore,
            mDocument.SaveData().Areas().size()
          );
          break;
        }
        case 1:
          for (int i = 0; i < 6; ++i) {
            (void)mScene.Undo();
          }
          tools.SetSymmetry(0, 3);
          tools.AskRecipe(EdTools::RecipeAsk::Measure);
          break;
        case 2:
          tools.AskRecipe(EdTools::RecipeAsk::Show, 2);
          break;
        case 3:
          tools.AskRecipe(EdTools::RecipeAsk::Assign);
          break;
        case 4:
          tools.AskRecipe(EdTools::RecipeAsk::Layered);
          break;
        case 5:
          (void)mScene.Undo();
          mShell->Fields().AskQuickGen(1, 0);
          break;
        case 6:
          (void)mScene.Undo();
          gpg::Logf("editor: /r7test: generate undone");
          break;
        case 7: {
          // A base from an area put round the first unit of the first army that has units.
          std::string army;
          float ux = 0.0f, uz = 0.0f;
          for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
            UnitGroup root;
            std::vector<const SaveUnit*> units;
            if (ParseUnitGroup(entry.Get("Units"), root)) {
              CollectUnits(root, units);
            }
            if (!units.empty()) {
              army = entry.name;
              ux = units.front()->position[0];
              uz = units.front()->position[2];
              break;
            }
          }
          EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
          SaveEntry area;
          area.name = "AREA_R7";
          area.Set("rectangle", RectangleValue(ux - 40.0, uz - 40.0, ux + 40.0, uz + 40.0));
          mDocument.SaveData().Areas().push_back(area);
          mDocument.SaveDataEdited(std::move(before));
          const auto defined = mShell->MissionPanel().DefineBaseFromArea("R7Base", army, "AREA_R7");
          gpg::Logf(
            "editor: /r7test: define base from AREA_R7 round %.0f, %.0f for %s: %s",
            static_cast<double>(ux),
            static_cast<double>(uz),
            army.c_str(),
            defined ? "asked" : defined.error().c_str()
          );
          break;
        }
        case 8: {
          const auto& markers = mDocument.SaveData().Markers();
          const bool marker = std::any_of(markers.begin(), markers.end(), [](const SaveEntry& m) {
            return m.name == "R7Base_Marker";
          });
          const Mission& mission = mDocument.MissionNow();
          const bool base = std::any_of(mission.bases.begin(), mission.bases.end(), [](const MissionBase& b) {
            return b.name == "R7Base";
          });
          gpg::Logf(
            "editor: /r7test: base in the mission: %s, its marker on the map: %s",
            base ? "yes" : "no",
            marker ? "yes" : "no"
          );
          mShell->LayoutPanel().AskCentreSymmetry();
          break;
        }
        case 11:
          gpg::Logf("editor: /r7test: done");
          break;
        default:
          break;
        }
      }
      /**
       * `/r8test` (test runs): the sixth comparison's features a step at a time, each logged: the terrain graph's
       * frame, undo, copy and paste, a node as a mask on the map, its scatter with the graph's symmetry; Fill the map's
       * Count; the mask generator into a terrain type; masks imported by name; a raw heightmap with its options; the
       * export package; a map-wide texture at a set size; the mesh terrain's manifest saved (with `/meshtest`).
       */
      int mR8Stage = 0;
      int mR8Frames = 0;
      int mR8Nodes = 0;
      int mR8First = 0;
      std::size_t mR8Props = 0;
      void DriveRoundEightTest()
      {
        // `/r8inspect <node type>` (test runs): the graph workspace with a curve and a scatter node added, the first
        // node of the type selected, so a picture of the window shows its inspector (curve, presets, blueprint list).
        if (
          fa::vector<fa::string> inspect; mR8Stage == 0 && mScene.Attached() && !mScene.ModelsPending() &&
          moho::CFG_GetArgOption("/r8inspect", 1, &inspect) && !inspect.empty() && ++mR8Frames == 60
        ) {
          mR8Stage = 100;
          mShell->SwitchWorkspace(4);
          mShell->ShowGenerate();
          EdGenerate& generate = mShell->Generate();
          (void)generate.OpenShipped("hills");
          NodeGraph& graph = generate.Graph();
          const int curve = graph.AddNode("remap", -300.0f, 0.0f);
          if (GraphNode* node = graph.Find(curve)) {
            ParamValue v = node->params[0];
            v.text = "0 0 0.3 0.1 0.6 0.7 1 1";
            graph.SetParam(curve, 0, v);
          }
          const int scatter = graph.AddNode("out_scatter", -300.0f, 300.0f);
          if (GraphNode* node = graph.Find(scatter)) {
            for (std::size_t p = 0; p < node->type->params.size(); ++p) {
              if (node->type->params[p].name == "entries") {
                ParamValue v = node->params[p];
                v.text = "/env/evergreen/props/rocks/rock01_prop.bp:300;/env/evergreen/props/trees/pine06_prop.bp:100";
                graph.SetParam(scatter, p, v);
              }
            }
          }
          generate.SelectFirst(inspect[0].c_str());
          gpg::Logf("editor: /r8inspect: %s selected (%zu nodes)", inspect[0].c_str(), graph.Nodes().size());
          return;
        }
        if (
          mR8Stage >= 20 || !mScene.Attached() || mScene.ModelsPending() ||
          !moho::CFG_GetArgOption("/r8test", 0, nullptr) || ++mR8Frames % 90 != 0
        ) {
          return;
        }
        EdTools& tools = mShell->Tools();
        EdGenerate& generate = mShell->Generate();
        const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_r8test";
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        const int width = mDocument.Facts().fieldWidth;
        const int height = mDocument.Facts().fieldHeight;
        if (mR8Stage == 0) {
          mShell->ShowGenerate();
          (void)generate.OpenShipped("hills"); // (a new graph: fetched after)
        }
        NodeGraph& graph = generate.Graph();
        switch (mR8Stage++) {
        case 0: {
          const bool opened = !graph.Nodes().empty();
          mR8First = 0;
          for (const GraphNode& node : graph.Nodes()) {
            if (mR8First == 0 && !node.type->outputs.empty() && !node.type->inputs.empty()) {
              mR8First = node.id;
            }
          }
          gpg::Logf(
            "editor: /r8test: graph hills %s, %zu nodes, first %d",
            opened ? "opened" : "missing",
            graph.Nodes().size(),
            mR8First
          );
          break;
        }
        case 1: {
          // A frame round the first node takes it along; then the node removed (a step to undo).
          const GraphNode* first = graph.Find(mR8First);
          if (first == nullptr) {
            gpg::Logf("editor: /r8test: no node to frame");
            break;
          }
          const int frame = graph.AddNode("frame", first->x - 40.0f, first->y - 60.0f);
          GraphNode* f = graph.Find(frame);
          ParamValue w = f->params[1];
          w.value[0] = 800.0f;
          graph.SetParam(frame, 1, w);
          ParamValue h = f->params[2];
          h.value[0] = 900.0f;
          graph.SetParam(frame, 2, h);
          const std::set<int> moving = generate.Canvas().MoveSetFor(graph, {frame});
          graph.SetName(mR8First, "R8 first");
          mR8Nodes = static_cast<int>(graph.Nodes().size());
          gpg::Logf(
            "editor: /r8test: frame %d drags %zu nodes (the first in it: %s)",
            frame,
            moving.size(),
            moving.contains(mR8First) ? "yes" : "no"
          );
          break;
        }
        case 2:
          (void)graph.RemoveNode(mR8First);
          gpg::Logf("editor: /r8test: removed node %d: %zu nodes", mR8First, graph.Nodes().size());
          break;
        case 3: {
          generate.Undo();
          const GraphNode* back = graph.Find(mR8First);
          gpg::Logf(
            "editor: /r8test: undo: %zu nodes (were %d), node %d back: %s, its name %s; %zu steps left",
            graph.Nodes().size(),
            mR8Nodes,
            mR8First,
            back != nullptr ? "yes" : "no",
            back != nullptr ? back->name.c_str() : "-",
            generate.UndoSteps()
          );
          generate.Redo();
          const std::size_t afterRedo = graph.Nodes().size();
          generate.Undo();
          const auto pasted = graph.Paste(graph.SaveSome({mR8First}), 0.0f, 3000.0f);
          gpg::Logf(
            "editor: /r8test: redo %zu nodes, undo again %zu; pasted %zu (%s)",
            afterRedo,
            graph.Nodes().size(),
            pasted ? pasted->size() : std::size_t{0},
            pasted ? "" : pasted.error().c_str()
          );
          break;
        }
        case 4:
          generate.ShowAsMask(mR8First);
          generate.EvaluateNow();
          break;
        case 5: {
          const field::Grid& mask = mScene.OverlayMask();
          gpg::Logf(
            "editor: /r8test: node %d as a mask on the map: %d x %d samples", generate.MaskNode(), mask.w, mask.h
          );
          generate.ShowAsMask(0);
          break;
        }
        case 6: {
          // The graph's scatter with its own symmetry: the props placed with their mirrored copies.
          generate.ShowAsMask(0);
          const int noise = graph.AddNode("perlin", 0.0f, 4000.0f);
          const int scatter = graph.AddNode("out_scatter", 300.0f, 4000.0f);
          (void)graph.Link(noise, 0, scatter, 0);
          GraphNode* s = graph.Find(scatter);
          for (std::size_t p = 0; p < s->type->params.size(); ++p) {
            ParamValue v = s->params[p];
            if (s->type->params[p].name == "entries") {
              v.text = "/env/evergreen/props/rocks/rock01_prop.bp:100";
            } else if (s->type->params[p].name == "count") {
              v.value[0] = 30.0f;
            } else {
              continue;
            }
            graph.SetParam(scatter, p, v);
          }
          generate.SetSymmetry("mirror_x");
          mR8Props = mScene.PropCountNow();
          generate.AskBuild();
          gpg::Logf("editor: /r8test: scatter build asked (mirror_x), props %zu", mR8Props);
          break;
        }
        case 8: {
          gpg::Logf("editor: /r8test: after the build: props %zu -> %zu", mR8Props, mScene.PropCountNow());
          for (int i = 0; i < 4 && mScene.PropCountNow() != mR8Props; ++i) {
            (void)mScene.Undo();
          }
          gpg::Logf("editor: /r8test: undone: props %zu", mScene.PropCountNow());
          // Two mask files guessed by name: layer2 (grey 50 %) and one with no use in its name.
          const std::filesystem::path layer = folder / "layer2.png";
          const std::filesystem::path notes = folder / "notes.png";
          std::string error;
          const int w = std::max(width, 2);
          const int h = std::max(height, 2);
          const auto both =
            WriteColourPng(layer, w, h, std::vector<std::uint32_t>(static_cast<std::size_t>(w) * h, 0xFF808080u))
              .and_then([&] {
            return WriteColourPng(notes, 4, 4, std::vector<std::uint32_t>(16, 0xFFFFFFFFu));
          });
          if (!both) {
            error = both.error();
          }
          const bool wrote = both.has_value();
          EdTools::MaskImport& mi = tools.MaskImportSettings();
          mi.files.clear();
          mi.files.push_back(MaskImportFile{layer.string()});
          mi.files.push_back(MaskImportFile{notes.string()});
          tools.AskMaskImport(1);
          gpg::Logf("editor: /r8test: mask files %s (%s)", wrote ? "written" : "not written", error.c_str());
          break;
        }
        case 9: {
          const EdTools::MaskImport& mi = tools.MaskImportSettings();
          std::string guessed;
          for (const MaskImportFile& f : mi.files) {
            guessed += std::filesystem::path(f.path).filename().string() + "=" +
              (f.target == MaskImportFile::Target::Layer    ? "layer " + std::to_string(f.layer)
                 : f.target == MaskImportFile::Target::Skip ? std::string("skip")
                                                            : std::string("other")) +
              " ";
          }
          gpg::Logf("editor: /r8test: masks guessed: %s", guessed.c_str());
          tools.AskMaskImport(2);
          break;
        }
        case 10: {
          (void)mScene.Undo();
          // A raw heightmap: 16-bit big-endian, a ramp along x, read inverted into 10..60 (kept for the next steps).
          const std::filesystem::path raw = folder / "ramp.r16";
          {
            std::ofstream out(raw, std::ios::binary | std::ios::trunc);
            for (int z = 0; z < height; ++z) {
              for (int x = 0; x < width; ++x) {
                const std::uint16_t word = static_cast<std::uint16_t>(65535.0 * x / std::max(1, width - 1));
                const char bytes[2] = {static_cast<char>(word >> 8), static_cast<char>(word & 0xFF)};
                out.write(bytes, 2);
              }
            }
          }
          tools.SetInteropFile(false, raw.string());
          ImportSettings& s = tools.InteropSettings();
          const ImportSettings kept = s;
          s = ImportSettings{};
          s.low = 10.0f;
          s.high = 60.0f;
          s.invert = true;
          s.read.bigEndian = true;
          const std::string status = mScene.InteropImportNow(false);
          const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
          float left = -1.0f;
          float right = -1.0f;
          if (terrain != nullptr && !terrain->heights.empty()) {
            const std::size_t row = static_cast<std::size_t>(height / 2) * static_cast<std::size_t>(width);
            left = terrain->heights[row];
            right = terrain->heights[row + static_cast<std::size_t>(width - 1)];
          }
          gpg::Logf(
            "editor: /r8test: raw import (big-endian, inverted, 10..60): %s; left %.1f right %.1f",
            status.c_str(),
            static_cast<double>(left),
            static_cast<double>(right)
          );
          s = kept;
          break;
        }
        case 11: {
          // On the ramp: Fill the map's Count with the new limits, and the mask generator into terrain type 2.
          tools.SetPropTool("/env/evergreen/props/rocks/rock01_prop.bp", 0);
          EdTools::FillOptions fill;
          fill.countOnly = true;
          fill.heightWindow = true;
          fill.heightLow = 0.0f;
          fill.heightHigh = 40.0f;
          fill.minSlope = 2.0f;
          fill.keepAway = 8.0f;
          fill.margin = 20.0f;
          fill.seed = 7;
          tools.RequestFill(fill);
          EdTools::MaskGenTarget& target = tools.GenTarget();
          target.toTypes = true;
          target.typeCode = 2;
          target.threshold = 0.5f;
          tools.AskGenPreset("buildable");
          tools.AskGenApply();
          break;
        }
        case 12: {
          gpg::Logf("editor: /r8test: fill count: %s; props %zu", tools.FillMessage().c_str(), mScene.PropCountNow());
          tools.GenTarget().toTypes = false;
          (void)mScene.Undo(); // the terrain types
          (void)mScene.Undo(); // the raw import
          EdTools::ExportPackage& p = tools.PackageSettings();
          (void)std::snprintf(p.folder, sizeof(p.folder), "%s", (folder / "package").string().c_str());
          p.flow = true;
          p.wear = true;
          p.types = true;
          tools.AskPackage();
          break;
        }
        case 13: {
          std::string files;
          for (const auto& entry : std::filesystem::directory_iterator(folder / "package", ec)) {
            files += entry.path().filename().string() + " ";
          }
          gpg::Logf("editor: /r8test: package folder: %s", files.c_str());
          // A shader that reads map-wide textures, for Make.
          mScene.ChangeTerrainShader("Terrain301");
          break;
        }
        case 14: {
          tools.SetMapTextureSize(128);
          const bool made = MakeMapTexture(static_cast<MapTextureKind>(0));
          gpg::Logf(
            "editor: /r8test: map-wide normal map at 128 (shader %s): %s, preview %s",
            mScene.TerrainShader().c_str(),
            made ? "made" : "not made",
            tools.MapTexturePreview(0) != 0 ? "yes" : "no"
          );
          if (made) {
            (void)mScene.Undo();
          }
          (void)mScene.Undo(); // the shader
          tools.SetMapTextureSize(0);
          break;
        }
        case 15:
          if (mScene.MeshMapRef().Loaded()) {
            mShell->AskMeshMore(3);
          } else {
            gpg::Logf("editor: /r8test: no mesh terrain (run with /meshtest for the manifest)");
          }
          break;
        case 16:
          if (mScene.MeshMapRef().Loaded()) {
            gpg::Logf("editor: /r8test: manifest read back:\n%s", mScene.MeshMapRef().ManifestText().c_str());
            mShell->AskMeshMore(4);
          } else {
            gpg::Logf("editor: /r8test: the mesh terrain isn't loaded after the save");
          }
          break;
        case 17:
          if (mScene.MeshMapRef().Loaded()) {
            const bool heightfield = mDocument.Scenario().contains("heightfield");
            gpg::Logf(
              "editor: /r8test: after unset, the scenario names the height field: %s", heightfield ? "yes" : "no"
            );
          }
          break;
        case 19:
          gpg::Logf("editor: /r8test: done");
          break;
        default:
          break;
        }
      }
      /**
       * `/r9test` (test runs): the seventh comparison's features in the view, each logged: the area tools, the names
       * written in the view far and close, the resource footprints' states (one Mass marker nudged off the grid, then
       * back), the asset browser's view kept in its file, the shipped brush images.
       */
      int mR9Stage = 0;
      int mR9Frames = 0;
      void DriveRoundNineTest()
      {
        if (
          mR9Stage >= 8 || !mScene.Attached() || mScene.ModelsPending() ||
          !moho::CFG_GetArgOption("/r9test", 0, nullptr) || ++mR9Frames % 90 != 0
        ) {
          return;
        }
        EdTools& tools = mShell->Tools();
        const auto states = [this]() {
          int n[4] = {0, 0, 0, 0};
          for (const EdMapScene::ResourceMark& mark : mScene.ResourceMarks()) {
            ++n[std::clamp(mark.state, 0, 3)];
          }
          char text[120];
          (void)std::snprintf(
            text, sizeof(text), "%d fine, %d blocked, %d stacked, %d off the grid", n[0], n[1], n[2], n[3]
          );
          return std::string(text);
        };
        switch (mR9Stage++) {
        case 0:
          tools.SetTool(6); // the Markers tool (the areas' outlines and handles)
          mScene.FrameMap();
          break;
        case 1:
          gpg::Logf("editor: /r9test: names far: %zu", mScene.ViewLabels().size());
          gpg::Logf("editor: /r9test: resources: %s", states().c_str());
          break;
        case 2: {
          gpg::Logf("editor: /r9test: areas: %s", mScene.TestAreaTools().c_str());
          // Close to the first Mass marker: every name there; that marker nudged off the build grid.
          for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
            if (MarkerTypeOf(marker) == "Mass") {
              mScene.FrameMarker(marker.name, 60.0f);
              mR9Marker = marker.name;
              EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
              for (SaveEntry& m : mDocument.SaveData().Markers()) {
                if (m.name == marker.name) {
                  const std::vector<double> p = ValueNumbers(m.Get("position"));
                  if (p.size() >= 3) {
                    m.Set("position", Vector3Value(p[0] + 0.3, p[1], p[2]));
                  }
                }
              }
              mDocument.SaveDataEdited(std::move(before));
              break;
            }
          }
          break;
        }
        case 3:
          gpg::Logf("editor: /r9test: names close to %s: %zu", mR9Marker.c_str(), mScene.ViewLabels().size());
          gpg::Logf("editor: /r9test: resources with %s nudged 0.3: %s", mR9Marker.c_str(), states().c_str());
          (void)mScene.Undo();
          break;
        case 4: {
          gpg::Logf("editor: /r9test: resources after undo: %s", states().c_str());
          EdAssetBrowser& assets = mShell->Assets();
          assets.SetViewForTest(58.0f, true);
          std::ifstream in(assets.MarksFile(), std::ios::binary);
          std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          const bool tile = text.contains("v:tile=58");
          const bool list = text.contains("v:list=1");
          gpg::Logf(
            "editor: /r9test: asset view kept: tile 58 %s, list %s (%s)",
            tile ? "yes" : "no",
            list ? "yes" : "no",
            assets.MarksFile().string().c_str()
          );
          assets.SetViewForTest(76.0f, false);
          break;
        }
        case 5: {
          std::string names;
          for (const BrushImage& image : ListBrushImages(tools.BrushFolder())) {
            names += image.name + " ";
          }
          gpg::Logf("editor: /r9test: brush library %s: %s", tools.BrushFolder().string().c_str(), names.c_str());
          break;
        }
        case 7:
          gpg::Logf("editor: /r9test: done");
          break;
        default:
          break;
        }
      }
      std::string mR9Marker;
      /**
       * `/r10test` (test runs): the eighth comparison's features, each logged: the view's cursor for the tools and an
       * area's parts; Generate into the map with each preset (then undone); the map's own textures listed; the picked
       * areas with the markers (duplicated together, arranged, following a drag); with `/meshtest`, the mesh drawn as
       * models, the height field hidden in Mesh only and the pointer on the mesh.
       */
      /**
       * `/r11test` (test runs): the brush cursors for each brush kind and the marker pin; the texture browser's stars,
       * recent and list view as read from the tools file (`/toolsfile`), then a star, a recent texture and the list
       * view set (the file keeps them for the next run).
       */
      int mR11Stage = 0;
      int mR11Frames = 0;
      void DriveRoundElevenTest()
      {
        if (
          mR11Stage >= 4 || !mScene.Attached() || mScene.ModelsPending() ||
          !moho::CFG_GetArgOption("/r11test", 0, nullptr) || ++mR11Frames % 90 != 0
        ) {
          return;
        }
        EdTools& tools = mShell->Tools();
        const float cx = static_cast<float>(mDocument.Facts().fieldWidth - 1) * 0.5f;
        const float cz = static_cast<float>(mDocument.Facts().fieldHeight - 1) * 0.5f;
        switch (mR11Stage++) {
        case 0: {
          std::string stars;
          for (const std::string& path : tools.StarredTextures()) {
            stars += path + " ";
          }
          gpg::Logf(
            "editor: /r11test: read: %zu starred (%s), %zu recent, list view %s",
            tools.StarredTextures().size(),
            stars.c_str(),
            tools.RecentTextures().size(),
            tools.BrowseList() ? "on" : "off"
          );
          mScene.FrameMap();
          break;
        }
        case 1: {
          const POINT middle = mScene.ScreenOf(cx, cz);
          std::string cursors;
          static constexpr std::pair<HeightBrushMode, const char*> kModes[] = {
            {HeightBrushMode::Raise, "raise"},
            {HeightBrushMode::Lower, "lower"},
            {HeightBrushMode::Flatten, "flatten"},
            {HeightBrushMode::Smooth, "smooth"},
            {HeightBrushMode::Noise, "noise"},
            {HeightBrushMode::SetHeight, "set height"},
            {HeightBrushMode::WaterErode, "water erode"},
            {HeightBrushMode::Stamp, "stamp"},
          };
          for (const auto& [mode, name] : kModes) {
            tools.SetBrushMode(std::to_underlying(mode));
            cursors += std::string(name) + " " + std::to_string(mScene.ViewCursorAt(middle)) + ", ";
          }
          tools.SetTool(6);
          cursors += "markers tool " + std::to_string(mScene.ViewCursorAt(middle));
          gpg::Logf("editor: /r11test: cursors: %s", cursors.c_str());
          break;
        }
        case 2:
          tools.StarredTextures() = {"/env/evergreen/layers/SandLight_albedo.dds"};
          tools.RecentTextures() = {"/env/evergreen/layers/RockMed_albedo.dds"};
          tools.SetBrowseList(true);
          gpg::Logf("editor: /r11test: starred SandLight, recent RockMed, list view on");
          break;
        case 3:
          gpg::Logf("editor: /r11test: done");
          break;
        default:
          break;
        }
      }
      int mR10Stage = 0;
      int mR10Frames = 0;
      void DriveRoundTenTest()
      {
        if (
          mR10Stage >= 20 || !mScene.Attached() || mScene.ModelsPending() ||
          !moho::CFG_GetArgOption("/r10test", 0, nullptr) || ++mR10Frames % 90 != 0
        ) {
          return;
        }
        EdTools& tools = mShell->Tools();
        const int width = mDocument.Facts().fieldWidth;
        const int height = mDocument.Facts().fieldHeight;
        const float cx = static_cast<float>(width - 1) * 0.5f;
        const float cz = static_cast<float>(height - 1) * 0.5f;
        const auto count = [this](const char* what) {
          return what[0] == 'a' ? mDocument.SaveData().Areas().size() : mDocument.SaveData().Markers().size();
        };
        switch (mR10Stage++) {
        case 0: {
          mScene.FrameMap();
          tools.SetTool(1); // the Terrain tool
          break;
        }
        case 1: {
          const POINT middle = mScene.ScreenOf(cx, cz);
          gpg::Logf("editor: /r10test: cursor, Terrain tool raising: %d", mScene.ViewCursorAt(middle));
          tools.SetTool(6); // the Markers tool
          // An area round the middle, picked: its corner and its outline.
          EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
          SaveEntry area{"AREA_R10", {}};
          area.Set("rectangle", RectangleValue(cx - 60.0, cz - 40.0, cx + 60.0, cz + 40.0));
          mDocument.SaveData().Areas().push_back(area);
          mDocument.SaveDataEdited(std::move(before));
          tools.AreaSelection() = {"AREA_R10"};
          break;
        }
        case 2: {
          gpg::Logf(
            "editor: /r10test: cursor, Markers tool: corner %d, right edge %d, outline %d, open ground %d",
            mScene.ViewCursorAt(mScene.ScreenOf(cx + 60.0f, cz + 40.0f)),
            mScene.ViewCursorAt(mScene.ScreenOf(cx + 60.0f, cz)),
            mScene.ViewCursorAt(mScene.ScreenOf(cx + 30.0f, cz - 40.0f)),
            mScene.ViewCursorAt(mScene.ScreenOf(cx + 20.0f, cz + 5.0f))
          );
          // The area with the first marker: duplicated together, then arranged.
          const std::size_t areas = count("areas");
          const std::size_t markers = count("markers");
          std::string first;
          for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
            if (!marker.name.empty()) {
              first = marker.name;
              break;
            }
          }
          mScene.SelectMarkers({first}, false);
          tools.AreaSelection() = {"AREA_R10"};
          mScene.CtrlKey('D');
          gpg::Logf(
            "editor: /r10test: marker %s and AREA_R10 duplicated together: areas %zu -> %zu, markers %zu -> %zu",
            first.c_str(),
            areas,
            count("areas"),
            markers,
            count("markers")
          );
          break;
        }
        case 3: {
          // Follow: the picked areas go along with a marker drag (here its start and a move of 12, 0).
          tools.AreaSelection() = {"AREA_R10"};
          mScene.BeginAreaFollow();
          mScene.FollowAreas(12.0f, 0.0f);
          std::string rect;
          for (const SaveEntry& area : mDocument.SaveData().Areas()) {
            if (area.name == "AREA_R10") {
              const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
              char text[80];
              (void)std::snprintf(text, sizeof(text), "%.0f,%.0f,%.0f,%.0f", e[0], e[1], e[2], e[3]);
              rect = text;
            }
          }
          gpg::Logf(
            "editor: /r10test: AREA_R10 after a marker drag of 12, 0: %s (was %.0f,%.0f,%.0f,%.0f)",
            rect.c_str(),
            cx - 60.0,
            cz - 40.0,
            cx + 60.0,
            cz + 40.0
          );
          for (int i = 0; i < 4; ++i) {
            (void)mScene.Undo();
          }
          break;
        }
        case 4: {
          // The map's own textures in the browser's first section.
          const std::vector<LayerTexture>& own = tools.Library().MapTextures("/maps/" + mDocument.FolderName());
          gpg::Logf(
            "editor: /r10test: this map's textures (/maps/%s): %zu, first %s",
            mDocument.FolderName().c_str(),
            own.size(),
            own.empty() ? "-" : own.front().path.c_str()
          );
          tools.OpenBrowser(1);
          break;
        }
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10: {
          // Generate into the map: each preset, applied (its status logs the change), then undone.
          if (mR10Stage > 6) {
            (void)mScene.Undo();
          }
          mShell->Fields().AskQuickGen(mR10Stage - 6, 0);
          break;
        }
        case 11:
          (void)mScene.Undo();
          gpg::Logf("editor: /r10test: generate undone");
          break;
        case 12: {
          // With /meshtest: the mesh as models; Mesh only hides the height field; the pointer on the mesh.
          if (!mScene.MeshMapRef().Loaded()) {
            gpg::Logf("editor: /r10test: no mesh terrain (run with /meshtest)");
            break;
          }
          mShell->mMeshMode = 1;
          break;
        }
        case 13: {
          if (!mScene.MeshMapRef().Loaded()) {
            break;
          }
          float gx = 0.0f, gz = 0.0f;
          const POINT middle = mScene.ScreenOf(256.0f, 256.0f);
          const bool hit = mScene.GroundAtForTest(static_cast<float>(middle.x), static_cast<float>(middle.y), gx, gz);
          gpg::Logf(
            "editor: /r10test: mesh only: %zu patch models, height field drawn %s; the pointer at the hill's "
            "middle (256, 256 on the height field) meets the mesh at %.1f, %.1f (%s); placement height there %.2f",
            mScene.MeshPatchModels(),
            moho::ren_TerrainSurface ? "yes" : "no",
            static_cast<double>(gx),
            static_cast<double>(gz),
            hit ? "hit" : "missed",
            static_cast<double>(mScene.PlacementHeight(gx, gz))
          );
          mShell->mMeshMode = 0;
          break;
        }
        case 14:
          if (mScene.MeshMapRef().Loaded()) {
            gpg::Logf("editor: /r10test: terrain only: height field drawn %s", moho::ren_TerrainSurface ? "yes" : "no");
            mShell->mMeshMode = 1;
          }
          break;
        case 19:
          gpg::Logf("editor: /r10test: done");
          break;
        default:
          break;
        }
      }
      /** Import / Export > Masks: the files' uses guessed by name, then read and written together. */
      void MaskImportUpdate()
      {
        EdTools& tools = mShell->Tools();
        const int ask = tools.TakeMaskImportAsk();
        if (ask == 0 || !mScene.Attached()) {
          return;
        }
        EdTools::MaskImport& mi = tools.MaskImportSettings();
        if (ask == 1) {
          // Each layer's kind of ground from its texture, for names like "rock" or "snow".
          std::array<std::string, 9> kinds;
          const std::vector<EdTools::LayerSlot> slots = mScene.LayerSlots();
          for (int layer = 1; layer <= 8 && layer < static_cast<int>(slots.size()); ++layer) {
            const std::string& albedo = slots[static_cast<std::size_t>(layer)].albedo;
            if (!albedo.empty()) {
              float rgb[3] = {};
              kinds[static_cast<std::size_t>(layer)] =
                GroundKindName(GroundKindOf(albedo, tools.Library().AverageColour(albedo, rgb) ? rgb : nullptr).kind);
            }
          }
          for (MaskImportFile& f : mi.files) {
            const MaskImportFile guessed = GuessMaskImport(f.path, kinds);
            f.target = guessed.target;
            f.layer = guessed.layer;
          }
          return;
        }
        const MapFacts& facts = mDocument.Facts();
        const int w = facts.fieldWidth;
        const int h = facts.fieldHeight;
        std::vector<std::pair<int, field::Grid>> layers;
        std::string report;
        const auto toGrid = [&](const HeightImage& image, const MaskImportFile& f) {
          HeightImage fitted = ResampleHeights(image, w, h);
          std::uint16_t lo = 0, hi = 65535;
          if (f.stretch) {
            HeightImageRange(fitted, lo, hi);
          }
          field::Grid g(w, h, 1.0f, 0.0f, 0.0f);
          const float span = std::max(1.0f, static_cast<float>(hi - lo));
          for (std::size_t i = 0; i < g.v.size(); ++i) {
            float v = std::clamp((static_cast<float>(fitted.words[i]) - lo) / span, 0.0f, 1.0f);
            g.v[i] = f.invert ? 1.0f - v : v;
          }
          return g;
        };
        int typeCells = 0;
        for (const MaskImportFile& f : mi.files) {
          if (f.target == MaskImportFile::Target::Skip) {
            continue;
          }
          std::string error;
          const std::string name = std::filesystem::path(f.path).filename().string();
          if (f.target == MaskImportFile::Target::Splat) {
            for (int c = 0; c < 4 && f.layer + c <= 8; ++c) {
              HeightReadOptions read;
              read.channel = c + 1;
              if (const auto image = ReadHeightImageWith(f.path, w, h, read)) {
                layers.emplace_back(f.layer + c, toGrid(*image, f));
              } else {
                error = image.error();
              }
            }
            report +=
              name + " -> layers " + std::to_string(f.layer) + "-" + std::to_string(std::min(8, f.layer + 3)) + "; ";
            continue;
          }
          HeightReadOptions read;
          read.channel = f.channel;
          const auto image = ReadHeightImageWith(f.path, w, h, read);
          if (!image) {
            error = image.error();
            report += name + ": " + error + "; ";
            continue;
          }
          const field::Grid g = toGrid(*image, f);
          if (f.target == MaskImportFile::Target::Layer) {
            layers.emplace_back(std::clamp(f.layer, 1, 8), g);
            report += name + " -> layer " + std::to_string(f.layer) + "; ";
          } else {
            int tw = 0;
            int th = 0;
            if (mDocument.TerrainTypeCells(tw, th) != nullptr) {
              std::vector<std::uint8_t> cells = mDocument.TerrainTypesNow();
              const std::vector<std::uint8_t> before = cells;
              for (int z = 0; z < th; ++z) {
                for (int x = 0; x < tw; ++x) {
                  const float wx = (x + 0.5f) * static_cast<float>(w - 1) / static_cast<float>(tw);
                  const float wz = (z + 0.5f) * static_cast<float>(h - 1) / static_cast<float>(th);
                  if (SampleField(g, wx, wz) > f.threshold) {
                    std::uint8_t& cell = cells[static_cast<std::size_t>(z) * tw + x];
                    typeCells += cell != static_cast<std::uint8_t>(f.typeCode) ? 1 : 0;
                    cell = static_cast<std::uint8_t>(f.typeCode);
                  }
                }
              }
              if (cells != before) {
                mDocument.ApplyTerrainTypes(cells);
                mDocument.TerrainTypesEdited(before);
              }
            }
            report += name + " -> terrain type " + std::to_string(f.typeCode) + "; ";
          }
        }
        std::string message;
        if (!layers.empty()) {
          static constexpr MaskWriteMode kModes[] = {
            MaskWriteMode::Replace, MaskWriteMode::AddTo, MaskWriteMode::SubtractFrom
          };
          (void)mScene.WriteMasksTogether(layers, kModes[std::clamp(mi.mode, 0, 2)], mi.takeAway, message);
        }
        const std::string status = "Masks: " + report + message +
          (typeCells > 0 ? " Terrain types: " + std::to_string(typeCells) + " cells." : "");
        tools.SetInteropStatus(status);
        gpg::Logf("editor: mask import: %s", status.c_str());
      }
      /** Import / Export > Export package: the folder for Gaea / World Machine; the folder watch. */
      std::map<std::string, long long> mPackageStamps;
      int mMeshAskFrames = 0; // `/meshask`
      bool mMeshImport2Done = false; // `/meshimport2`
      int mMeshAskDone = 0;
      bool mPackageTestDone = false;
      double mPackageWatchAt = 0.0;
      void PackageUpdate()
      {
        EdTools& tools = mShell->Tools();
        EdTools::ExportPackage& p = tools.PackageSettings();
        if (
          fa::vector<fa::string> into; !mPackageTestDone && mScene.Attached() && !mScene.ModelsPending() &&
          moho::CFG_GetArgOption("/exportpkg", 1, &into) && !into.empty()
        ) {
          // `/exportpkg <folder>` (test runs): the package with every item, 32-bit TIFF heights and TIFF masks.
          mPackageTestDone = true;
          std::snprintf(p.folder, sizeof(p.folder), "%s", into[0].c_str());
          p.height = p.water = p.slope = p.flow = p.wear = p.layers = p.types = p.markers = p.playable = p.readme =
            true;
          p.format = 1;
          p.float32 = true;
          p.waterSoft = 4.0f;
          p.markerRadius = 5.0f;
          std::string plan;
          for (const EdTools::PackageFile& file : EdTools::PackagePlan(p, tools.PackageStem())) {
            plan += (plan.empty() ? "" : ", ") + file.file;
          }
          gpg::Logf("editor: export package plan: %s", plan.c_str());
          tools.AskPackage();
        }
        if (tools.TakePackageAsk() && mScene.Attached()) {
          const std::string status = ExportPackageNow(p);
          tools.SetInteropStatus(status);
          gpg::Logf("editor: export package: %s", status.c_str());
          mPackageStamps.clear();
        }
        // The watch: a file whose stamp changed comes in by its name.
        const double now = ImGui::GetTime();
        if (!p.watch || p.folder[0] == '\0' || !mScene.Attached() || now < mPackageWatchAt) {
          return;
        }
        mPackageWatchAt = now + std::max(0.5f, p.interval);
        std::error_code ec;
        for (const auto& item : std::filesystem::directory_iterator(std::filesystem::path(p.folder), ec)) {
          std::string name = item.path().filename().string();
          for (char& c : name) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          const std::string ext = item.path().extension().string();
          if (ext != ".png" && ext != ".tif" && ext != ".tiff" && ext != ".r16" && ext != ".raw" && ext != ".r32") {
            continue;
          }
          const long long stamp =
            static_cast<long long>(std::filesystem::last_write_time(item.path(), ec).time_since_epoch().count());
          const auto kept = mPackageStamps.find(name);
          const bool fresh = kept != mPackageStamps.end() && kept->second != stamp;
          mPackageStamps[name] = stamp;
          if (!fresh) {
            continue; // the first look only notes the stamps
          }
          if (std::string own = tools.PackageStem() + "_"; true) {
            for (char& c : own) {
              c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (name.starts_with(own)) {
              name = name.substr(own.size()); // <stem>_height.png -> height.png
            }
          }
          if (name.starts_with("height")) {
            tools.SetInteropFile(false, item.path().string());
            tools.SetInteropStatus(mScene.InteropImportNow(true));
            gpg::Logf("editor: package watch: %s as the heights", name.c_str());
          } else if (name.starts_with("layer") || name.starts_with("mask")) {
            const int n = std::atoi(name.c_str() + (name[0] == 'l' ? 5 : 4));
            if (n >= 1 && n <= 8 && mScene.ImportMaskLayer(n - 1, item.path())) {
              gpg::Logf("editor: package watch: %s into layer %d", name.c_str(), n);
            }
          }
        }
      }
      std::string ExportPackageNow(
        const EdTools::ExportPackage& p
      )
      {
        // FAF Studio's interopexport.lua: every file named <stem>_<what>, the masks on the heights' sample grid.
        const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
        if (terrain == nullptr || terrain->width < 2) {
          return "No terrain.";
        }
        const std::filesystem::path folder(p.folder);
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        const std::string stem = mShell->Tools().PackageStem();
        const int w = terrain->width;
        const int h = terrain->height;
        const auto [lowIt, highIt] = std::minmax_element(terrain->heights.begin(), terrain->heights.end());
        const float lowest = *lowIt;
        const float highest = *highIt;
        float low = p.fixedRange ? p.low : lowest;
        float high = p.fixedRange ? p.high : highest;
        if (high - low < 0.01f) {
          high = low + 0.01f;
        }
        const std::string hext = EdTools::PackageHeightExtension(p);
        const std::string mext = p.format == 1 ? "tif" : "png";
        const auto fileOf = [&](const std::string& suffix, const std::string& ext) {
          return stem + suffix + "." + ext;
        };
        std::vector<std::string> written;
        std::string error;
        const auto writeMask = [&](const std::string& suffix, const std::vector<float>& values) {
          HeightImage image;
          image.width = w;
          image.height = h;
          image.words.resize(values.size());
          for (std::size_t i = 0; i < values.size(); ++i) {
            image.words[i] = static_cast<std::uint16_t>(std::clamp(std::lround(values[i] * 65535.0f), 0L, 65535L));
          }
          const std::string name = fileOf(suffix, mext);
          if (const auto wrote = WriteHeightImage(folder / name, image, p.mask8)) {
            written.push_back(name);
          } else {
            error = wrote.error();
          }
        };
        auto heights = std::make_shared<field::Grid>(w, h, 1.0f, 0.0f, 0.0f);
        heights->v = terrain->heights;
        const auto run = [&](const char* op, field::OpArgs args, const std::shared_ptr<field::Grid>& input) {
          if (input != nullptr) {
            args.in["a"] = input;
          }
          auto out = std::make_shared<field::Grid>();
          if (const auto ran = field::RunOpCpu(op, args, *out); !ran) {
            error = ran.error();
            return std::shared_ptr<field::Grid>();
          }
          return out;
        };
        const WaterState water = mDocument.WaterNow();
        const float waterLevel = water.enabled ? water.elevation : 0.0f;
        const std::string heightName = fileOf("_height", hext);
        // The sidecar: the range, so the round trip is exact (the import reads it back).
        if (p.height || p.readme) {
          char json[1400];
          (void)std::snprintf(
            json,
            sizeof(json),
            "{\n  \"tool\": \"FAF map editor\",\n  \"file\": \"%s\",\n  \"mode\": \"%s\",\n  \"bits\": %d,\n"
            "  \"float\": %d,\n  \"min\": %.9g,\n  \"max\": %.9g,\n  \"lowest\": %.9g,\n  \"highest\": %.9g,\n"
            "  \"width\": %d,\n  \"height\": %d,\n  \"cells\": %d,\n  \"units_per_sample\": 1,\n"
            "  \"water_elevation\": %.9g,\n"
            "  \"note\": \"normalised: value 0..1 = min..max world units; absolute: 16-bit value / 128 (float: "
            "units)\"\n}\n",
            heightName.c_str(),
            p.normalised ? "normalised" : "absolute",
            p.float32 ? 32 : 16,
            p.float32 ? 1 : 0,
            static_cast<double>(p.normalised ? low : 0.0f),
            static_cast<double>(p.normalised ? high : 65535.0f / 128.0f),
            static_cast<double>(lowest),
            static_cast<double>(highest),
            w,
            h,
            w - 1,
            static_cast<double>(waterLevel)
          );
          const std::string name = fileOf("_height", "json");
          std::ofstream(folder / name, std::ios::binary) << json;
          written.push_back(name);
        }
        if (p.height) {
          if (p.float32) {
            std::vector<float> values(terrain->heights.size());
            for (std::size_t i = 0; i < values.size(); ++i) {
              const float v = terrain->heights[i];
              values[i] = p.normalised ? (v - low) / (high - low) : v;
            }
            if (const auto wrote = WriteFloatImage(folder / heightName, w, h, values)) {
              written.push_back(heightName);
            } else {
              error = wrote.error();
            }
          } else {
            HeightImage image;
            image.width = w;
            image.height = h;
            for (const float v : terrain->heights) {
              const float word = p.normalised ? (v - low) / (high - low) * 65535.0f : v * 128.0f;
              image.words.push_back(static_cast<std::uint16_t>(std::clamp(std::lround(word), 0L, 65535L)));
            }
            if (const auto wrote = WriteHeightImage(folder / heightName, image)) {
              written.push_back(heightName);
            } else {
              error = wrote.error();
            }
          }
        }
        if (p.water) {
          field::OpArgs a;
          a.p.num["level"] = waterLevel;
          a.p.num["soft"] = p.waterSoft;
          if (const auto g = run("water_below", a, heights); g != nullptr) {
            writeMask("_water", g->v);
          }
        }
        if (p.slope) {
          field::OpArgs a;
          a.p.num["radius"] = 1;
          a.p.str["mode"] = "degrees";
          if (const auto g = run("slope", a, heights); g != nullptr) {
            std::vector<float> v(g->v.size());
            for (std::size_t i = 0; i < v.size(); ++i) {
              v[i] = std::clamp(g->v[i] / 90.0f, 0.0f, 1.0f);
            }
            writeMask("_slope", v);
          }
        }
        if (p.flow) {
          field::OpArgs a;
          a.p.num["range"] = 4000;
          a.p.str["mode"] = "log";
          if (const auto g = run("flow", a, heights); g != nullptr) {
            writeMask("_flow", g->v);
          }
        }
        if (p.wear) {
          // Studio's: the curvature (radius 6, gain 25); wear where it is convex, deposit where it is concave.
          field::OpArgs c;
          c.p.num["radius"] = 6;
          c.p.num["gain"] = 25;
          if (const auto curvature = run("curvature", c, heights); curvature != nullptr) {
            field::OpArgs edges;
            edges.p.num["edge0"] = 0.5;
            edges.p.num["edge1"] = 0.9;
            if (const auto wear = run("smoothstep", edges, curvature); wear != nullptr) {
              writeMask("_wear", wear->v);
            }
            field::OpArgs flip;
            flip.p.num["lo"] = 0;
            flip.p.num["hi"] = 1;
            if (const auto inverted = run("invert", flip, curvature); inverted != nullptr) {
              if (const auto deposit = run("smoothstep", edges, inverted); deposit != nullptr) {
                writeMask("_deposit", deposit->v);
              }
            }
          }
        }
        if (p.layers) {
          const ShaderProfile profile = ShaderProfileOf(mScene.TerrainShader());
          for (int layer = 0; layer < std::clamp(profile.painted, 1, 8); ++layer) {
            const std::string name = fileOf("_layer" + std::to_string(layer + 1), mext);
            if (mScene.ExportMaskLayer(layer, folder / name)) {
              written.push_back(name);
            }
          }
        }
        if (p.types) {
          int tw = 0;
          int th = 0;
          if (mDocument.TerrainTypeCells(tw, th) != nullptr) {
            HeightImage image;
            image.width = tw;
            image.height = th;
            for (const std::uint8_t id : mDocument.TerrainTypesNow()) {
              image.words.push_back(static_cast<std::uint16_t>(id * 257));
            }
            const std::string name = fileOf("_terraintypes", "png");
            if (const auto wrote = WriteHeightImage(folder / name, image, true)) { // 8-bit: the type codes as they are
              written.push_back(name);
            } else {
              error = wrote.error();
            }
          }
        }
        if (p.markers) {
          // Every marker as a CSV row (by name), the starts (ARMY_n) and the resources as discs.
          std::vector<const SaveEntry*> sorted;
          for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
            sorted.push_back(&marker);
          }
          std::sort(sorted.begin(), sorted.end(), [](const SaveEntry* a, const SaveEntry* b) {
            return a->name < b->name;
          });
          std::string csv = "name,type,x,y,z\n";
          std::vector<double> starts;
          std::vector<double> resources;
          static const std::regex army(R"(^ARMY_\d+$)");
          for (const SaveEntry* marker : sorted) {
            float mx = 0.0f, my = 0.0f, mz = 0.0f;
            if (!MarkerPosition(*marker, mx, my, mz)) {
              continue;
            }
            const std::string type = MarkerTypeOf(*marker);
            char row[400];
            (void)std::snprintf(
              row,
              sizeof(row),
              "%s,%s,%.3f,%.3f,%.3f\n",
              marker->name.c_str(),
              type.c_str(),
              static_cast<double>(mx),
              static_cast<double>(my),
              static_cast<double>(mz)
            );
            csv += row;
            std::vector<double>* into = std::regex_match(marker->name, army) ? &starts
              : (type == "Mass" || type == "Hydrocarbon")                    ? &resources
                                                                             : nullptr;
            if (into != nullptr) {
              into->insert(into->end(), {mx, mz, p.markerRadius, 1.0});
            }
          }
          const std::string csvName = fileOf("_markers", "csv");
          std::ofstream(folder / csvName, std::ios::binary) << csv;
          written.push_back(csvName);
          for (const auto& [suffix, points] : {std::pair{"_starts", &starts}, std::pair{"_resources", &resources}}) {
            field::OpArgs a;
            a.in["like"] = heights;
            a.p.arr["pts"] = *points;
            a.p.num["feather"] = 0;
            if (const auto g = run("points_mask", a, nullptr); g != nullptr) {
              writeMask(suffix, g->v);
            }
          }
        }
        if (p.playable) {
          std::vector<float> area(terrain->heights.size(), 1.0f);
          if (const std::optional<EdDocument::PlayableRect> rect = mDocument.PlayableArea()) {
            for (int z = 0; z < h; ++z) {
              for (int x = 0; x < w; ++x) {
                area[static_cast<std::size_t>(z) * w + x] =
                  x >= rect->x0 && x <= rect->x1 && z >= rect->z0 && z <= rect->z1 ? 1.0f : 0.0f;
              }
            }
          }
          writeMask("_playable", area);
        }
        if (p.readme) {
          char text[2400];
          (void)std::snprintf(
            text,
            sizeof(text),
            "Terrain export of %s (FAF map editor)\n\n"
            "Map size   : %d x %d world units (%.1f km), 1 sample = 1 world unit\n"
            "Sample grid: %d x %d samples (N + 1; the files hold exactly these samples)\n"
            "Heights    : %.3f to %.3f units on this map; the game holds 0 to 511.99 (16-bit words, 1/128 unit steps)\n"
            "Water level: %.2f units\n\n"
            "Heightmap file (%s)\n  %s\n\n"
            "Masks (%s, %s): 0 = no, 1 = full. _water: 1 under the water surface, a soft edge of %.1f units; _slope: "
            "degrees / 90; _flow: drainage; _wear / _deposit: convex ridges / concave basins; _layerN: the paint of "
            "texture layer N; _terraintypes: the type codes (8-bit); _starts / _resources: discs of %.0f samples; "
            "_markers.csv: every marker (name, type, x, y, z); _playable: the playable area.\n\n"
            "Saved back into this folder with the editor watching it: <name>_height* comes in as the heights, "
            "<name>_layer<n>* / mask<n>* as layer n's paint.\n",
            mDocument.Facts().name.c_str(),
            w - 1,
            h - 1,
            (w - 1) / 51.2,
            w,
            h,
            static_cast<double>(lowest),
            static_cast<double>(highest),
            static_cast<double>(waterLevel),
            heightName.c_str(),
            p.normalised ? ("value 0..1 = " + std::to_string(low) + " .. " + std::to_string(high) +
                            " units (see the .json: min / max). Importing back: normalised with that range.")
                             .c_str()
                         : "absolute: 16-bit value / 128 = units (float files hold the units directly).",
            mext.c_str(),
            p.mask8 ? "8-bit" : "16-bit",
            static_cast<double>(p.waterSoft),
            static_cast<double>(p.markerRadius)
          );
          const std::string name = fileOf("_README_scale", "txt");
          std::ofstream(folder / name, std::ios::binary) << text;
          written.push_back(name);
        }
        std::string list;
        for (const std::string& name : written) {
          list += (list.empty() ? "" : ", ") + name;
        }
        return std::to_string(written.size()) + " files in " + folder.string() + ": " + list +
          (error.empty() ? std::string() : " (" + error + ")");
      }
      /** SC tools > Water: the asks, and Live's re-apply when the water level moved. */
      void WaterMasksUpdate();
      struct WaterApplied
      {
        int layer = 0;
        float level = 0.0f;
        std::vector<std::uint8_t> base;
        std::vector<std::uint8_t> last;
      };
      std::map<int, WaterApplied> mWaterApplied;
      int mWaterLiveFrames = 0;
      int mWaterTestStage = 0;
      int mWaterTestFrames = 0;
      int mWaterTestId = 0;
      int mMaskGenEvaluated = -1;
      /** The map's overlay is the mask generator's (so taking it off leaves a graph node's mask alone). */
      bool mMaskGenOverlay = false;
      int mMaskGenWait = 0;
      std::uint64_t mMaskGenImage = 0;
      std::string mMaskGenArg; // `/maskgen <preset>,<layer>[,add|sub][,free]`
      int mMaskGenFrames = 0;
      /** The Stratum recipes: each layer's kind (once a second while the section is open), Paint the map. */
      void RecipesUpdate();
      int mRecipeFrame = 0;
      int mRecipeArg = -1; // `/recipe <style>` (test runs)
      int mRecipeArgFrames = 0;
      std::uint64_t mRecipeShowImage = 0;
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
      /** The eight strata masks to or from one set of files (`name_1` .. `name_8`); a file dialog asks for the name. */
      void TransferAllMasks(bool exporting);
      /** A derived unit's model from an OBJ, into its mod project (EdScm): what it wrote, or the error. */
      [[nodiscard]] std::expected<std::string, std::string>
      ImportUnitModel(const std::string& unit, const std::filesystem::path& obj);
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
      mScene.SetPathEdit(&mShell->PathsPanel().State());
      mDocument.onEditEnded = [this](const std::string& step) {
        if (mModEdits.size() < 256) {
          mModEdits.push_back(step);
        }
      };
      mScene.gameFileExists = [this](const std::string& path) {
        return GameFileExists(path);
      };
      mScene.SetUnitPreview(&mShell->UnitViewer().Preview());
      mShell->UnitViewer().loadGameIcon = [](const std::string& path, const int side, std::vector<std::uint8_t>& rgba) {
        std::string bytes;
        gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
        if (codec == nullptr || !ReadGameFile(path, bytes)) {
          return false;
        }
        gpg::gal::imaging::DecodeOptions options;
        options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
        options.width = static_cast<std::uint32_t>(side);
        options.height = static_cast<std::uint32_t>(side);
        options.mipLevels = 1;
        gpg::gal::imaging::Image image;
        if (
          FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) || image.subresources.empty() ||
          image.format != DXGI_FORMAT_B8G8R8A8_UNORM
        ) {
          return false;
        }
        const auto& level = image.subresources.front();
        if (level.width != static_cast<std::uint32_t>(side) || level.height != static_cast<std::uint32_t>(side)) {
          return false;
        }
        rgba.resize(static_cast<std::size_t>(side) * side * 4);
        for (int y = 0; y < side; ++y) {
          const std::uint8_t* row = reinterpret_cast<const std::uint8_t*>(image.bytes.data()) + level.offset +
            static_cast<std::size_t>(y) * level.rowPitch;
          for (int x = 0; x < side; ++x) {
            std::uint8_t* p = rgba.data() + (static_cast<std::size_t>(y) * side + x) * 4;
            p[0] = row[x * 4 + 2];
            p[1] = row[x * 4 + 1];
            p[2] = row[x * 4 + 0];
            p[3] = row[x * 4 + 3];
          }
        }
        return true;
      };
      // The mesh terrain's files: the open map's own folder on disk first (new patches aren't in the mounted
      // file system yet), else the game's files.
      edmesh::SetMeshFileReader([this](const std::string& path) {
        std::vector<std::uint8_t> bytes;
        const std::string prefix = "/maps/" + mDocument.FolderName() + "/";
        const std::filesystem::path map = mDocument.MapDiskFile();
        if (!map.empty() && LowerPath(path).starts_with(LowerPath(prefix))) {
          std::ifstream in(map.parent_path() / path.substr(prefix.size()), std::ios::binary);
          if (in) {
            bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            return bytes;
          }
        }
        std::string text;
        if (ReadGameFile(path, text)) {
          bytes.assign(text.begin(), text.end());
        }
        return bytes;
      });
      mScene.readGameFile = [](const std::string& path, std::string& bytes) {
        return ReadGameFile(path, bytes);
      };
      mShell->UnitWizard().gameHasUnit = &EdUnitLabPanel::GameHasUnit;
      mShell->UnitWizard().gameFileExists = [this](const std::string& path) {
        return GameFileExists(path);
      };
      mShell->PathsPanel().ground = [this](const float x, const float z) {
        return mScene.GroundHeightAt(x, z);
      };
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
      // What editor mods change on the map goes through the view (its undo); a mod's tool takes view clicks first.
      mShell->ModHost().writeHeights =
        [this](const int x0, const int z0, const int w, const int h, const std::vector<float>& heights) {
        return mScene.WriteHeightRect(x0, z0, w, h, heights);
      };
      mShell->ModHost().layerAt = [this](const int layer, const float x, const float z) {
        return mScene.LayerWeightAt(layer, x, z);
      };
      // The Check's resources by the build rules: the UEF mass extractor's and hydrocarbon plant's footprints (every
      // faction's are the same size).
      mShell->resourceFit = [this] {
        std::vector<CheckIssue> out;
        for (const EdMapScene::ResourceFit& fit : mScene.ResourceFits("ueb1103", "ueb1102")) {
          const char* const building = fit.mass ? "a mass extractor" : "a hydrocarbon plant";
          if (!fit.problem.empty()) {
            CheckIssue issue;
            issue.level = CheckIssue::Level::Warning;
            issue.marker = fit.marker;
            issue.text = std::string(building) + " can't be built here by the game's rules: " + fit.problem;
            issue.x = fit.x;
            issue.z = fit.z;
            out.push_back(std::move(issue));
          }
          if (fit.props > 0) {
            CheckIssue issue;
            issue.level = CheckIssue::Level::Note;
            issue.marker = fit.marker;
            issue.text = std::to_string(fit.props) + (fit.props == 1 ? " prop stands" : " props stand") + " where " +
              building + " goes (an engineer reclaims them before it builds)";
            issue.x = fit.x;
            issue.z = fit.z;
            out.push_back(std::move(issue));
          }
        }
        return out;
      };
      EdModHost& host = mShell->ModHost();
      host.writeLayer =
        [this](
          const int layer, const int x0, const int z0, const int w, const int h, const std::vector<float>& weights
        ) {
        return mScene.WriteMaskRect(layer, x0, z0, w, h, weights);
      };
      host.paintSize = [this](int& w, int& h) {
        return mScene.MaskSize(w, h);
      };
      host.listObjects = [this](const std::string& kind) {
        const std::vector<EdMapScene::ModObject> found = kind == "props" ? mScene.ModProps()
          : kind == "decals"                                             ? mScene.ModDecals()
                                                                         : mScene.ModUnits();
        auto out = found | std::views::transform([&](const EdMapScene::ModObject& o) {
          return EdModHost::MapObject{o.what, o.name, o.army, o.x, o.y, o.z, o.size};
        }) |
          std::ranges::to<std::vector<EdModHost::MapObject>>();
        return out;
      };
      host.addProp = [this](const std::string& blueprint, const float x, const float z, const float scale) {
        return mScene.ModAddProp(blueprint, x, z, scale);
      };
      host.removeProp = [this](const int index) {
        return mScene.ModRemoveProp(index);
      };
      host.addDecal =
        [this](const std::string& texture, const float x, const float z, const float size, const float heading) {
        return mScene.ModAddDecal(texture, x, z, size, heading);
      };
      host.addUnit =
        [this](const std::string& type, const std::string& army, const float x, const float z, std::string& name) {
        return mScene.ModAddUnit(type, army, x, z, name);
      };
      mScene.viewClickHook = [this](const float x, const float z, const bool shift, const bool ctrl) {
        return mShell->ModHost().ClickTool(x, z, shift, ctrl);
      };
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
      // `/gfxpreset <low|medium|high|ultra>` (test runs): Studio's quality preset over the settings, applied and
      // logged.
      if (fa::vector<fa::string> preset; moho::CFG_GetArgOption("/gfxpreset", 1, &preset) && !preset.empty()) {
        const bool known = mSettings.ApplyGraphicsPreset(preset[0].c_str());
        gpg::Logf(
          "editor: /gfxpreset %s: %s (the settings now match: %s)",
          preset[0].c_str(),
          known ? "applied" : "no such preset",
          mSettings.GraphicsPreset().c_str()
        );
      }
      ApplyGraphicsSettings();
      ApplyGpuSettings();
      // `/gputest` (test runs): the GPU self test, then a blur and a thermal erosion through the field ops, logged with
      // which backend ran them.
      if (moho::CFG_GetArgOption("/gputest", 0, nullptr)) {
        gpg::Logf("editor: /gputest: %s", GpuSelfTestText().c_str());
        auto grid = std::make_shared<field::Grid>(1025, 1025, 1.0f, 0.0f, 0.0f);
        for (int z = 0; z < grid->h; ++z) {
          for (int x = 0; x < grid->w; ++x) {
            grid->At(x, z) =
              20.0f + 8.0f * std::sin(x * 0.05f) * std::cos(z * 0.031f) + (((x * 7 + z * 13) % 17) * 0.1f);
          }
        }
        for (const char* op : {"blur", "thermal"}) {
          field::OpArgs args;
          args.in["a"] = grid;
          args.p.num["radius"] = 6.0;
          args.p.num["iterations"] = 20.0;
          field::Grid gpuOut;
          field::Grid cpuOut;
          std::string error;
          const auto t0 = std::chrono::steady_clock::now();
          const auto ran = field::RunOp(op, args, gpuOut);
          if (!ran) {
            error = ran.error();
          }
          const double runMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
          const auto t1 = std::chrono::steady_clock::now();
          const auto cpu = field::RunOpCpu(op, args, cpuOut);
          if (!cpu) {
            error = cpu.error();
          }
          const double cpuMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t1).count();
          double worst = 0.0;
          if (ran && cpu && gpuOut.v.size() == cpuOut.v.size()) {
            for (std::size_t k = 0; k < cpuOut.v.size(); ++k) {
              worst = std::max(worst, static_cast<double>(std::abs(gpuOut.v[k] - cpuOut.v[k])));
            }
          }
          gpg::Logf(
            "editor: /gputest: %s: RunOp %.1f ms, CPU op %.1f ms, largest difference %.6f%s",
            op,
            runMs,
            cpuMs,
            worst,
            ran ? "" : (" (RunOp failed: " + error + ")").c_str()
          );
        }
        gpg::Logf("editor: /gputest: %s", GpuStatsText(true).c_str());
      }
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
      popouts::Install();
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
      // FAF Studio shipped a sample map (sample_island); the editor makes one: a 5 km two-player island from the
      // Generate workspace's island graph.
      add("file.samplemap", "New sample map (an island)", "File", "", [this] {
        mNewMapSpec = "sample_island,1,2,25,20";
        mSampleMapPending = true;
        gpg::Logf("editor: sample map: making sample_island (5 km, 2 players, the island graph)");
      }, [this]() -> std::string {
        return mPlay.Active() ? "a play is running" : std::string();
      }, {}, "A small map to try the tools on: a 5 km island for two, its ground built by the island graph");
      add("file.updatepreview", "Update the lobby picture on save", "File", "", [this] {
        mUpdatePreviewOnSave = !mUpdatePreviewOnSave;
      }, {}, [this] {
        return mUpdatePreviewOnSave;
      }, "Each save draws the lobby picture anew from the map (else the one the map has is kept, byte for byte)");
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
        if (!gNoFileDialogs && ::GetSaveFileNameW(&dialog) != FALSE) {
          const auto exported = mDocument.ExportPreview(path);
          const bool ok = exported.has_value();
          const std::string& message = ok ? *exported : exported.error();
          (ok ? gpg::Logf : gpg::Warnf)("editor: %s", message.c_str());
          PostStatusMessage(message);
        }
      }, mapOpen, {}, "The map's preview picture, as the lobby shows it, as a PNG");
      add("file.exportpreview512", "Export the lobby preview at 512 px (PNG)...", "File", "", [this] {
        const std::filesystem::path path = AskFile(
          HandleOf(mGame.supcomFrame),
          true,
          L"PNG picture (*.png)\0*.png\0",
          L"png",
          L"Export the lobby preview at 512 px"
        );
        if (!path.empty()) {
          const auto exported = ExportPaintedPreview(path, 512);
          const bool ok = exported.has_value();
          const std::string& message = ok ? *exported : exported.error();
          (ok ? gpg::Logf : gpg::Warnf)("editor: %s", message.c_str());
          PostStatusMessage(message);
        }
      }, mapOpen, {}, "The preview painted afresh at 512 x 512 (its layers' colours under the map's sun), as a PNG");
      add("file.saveas", "Save as new map folder...", "File", "Ctrl+Shift+S", [this] {
        mShell->OpenSaveAs();
      }, mapOpen);
      add(
        "map.preview",
        "Regenerate the lobby preview",
        "Map",
        "",
        [this] {
        const auto drawn = RegeneratePreview();
        const bool ok = drawn.has_value();
        const std::string& message = ok ? *drawn : drawn.error();
        (ok ? gpg::Logf : gpg::Warnf)("editor: %s", message.c_str());
        PostStatusMessage(message);
      },
        mapOpen,
        {},
        "The preview picture the lobby shows, drawn anew from the heights, the sea, the start positions "
        "and the resources (saved with the map)"
      );
      add("texture.masks.export", "Export all layer masks...", "Texture", "", [this] {
        TransferAllMasks(true);
      }, mapOpen, {}, "The eight layers' masks as name_1 .. name_8 (PNG or 16-bit RAW), grey for how much shows");
      add("texture.masks.import", "Import all layer masks...", "Texture", "", [this] {
        TransferAllMasks(false);
      }, mapOpen, {}, "Pick any file of a set name_1 .. name_8: every one there goes into its layer");
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
      add("terrain.flatten", "Flatten map...", "Terrain", "", [this] {
        mFlattenAsk = true;
      }, canEdit, {}, "The whole map to one height, as one undo step");
      add("terrain.paths", "Paths and skeleton...", "Terrain", "", [this] {
        mShell->ShowPaths();
      }, mapOpen, {}, "Kept spline paths (roads, ramps, valleys, ridges, rivers) and the map skeleton generator");
      add("objects.detail", "Detail pass...", "Terrain", "", [this] {
        mShell->ShowDetail();
      }, mapOpen, {}, "Small rocks, stones and decals in classes by slope and clustering, as one undo step");
      add("terrain.erosion", "Erosion...", "Terrain", "", [this] {
        mShell->Tools().OpenErosion();
      }, mapOpen, {}, "A solver run over the whole map: presets, a preview on the map, Apply as one undo step");
      add("edit.find", "Find and replace objects...", "Edit", "Ctrl+F", [this] {
        mFindAsk = true;
      }, mapOpen, {}, "Every object of one type: select them, delete them or change them to another");
      add("edit.duplicate", "Duplicate beside", "Edit", "Ctrl+D", [this] {
        mScene.CtrlKey('D');
      }, canEdit, {}, "A copy of the selection 8 units beside it");
      const auto cameraMarker = [this]() {
        return mScene.SelectedCameraMarker().empty() ? std::string("select a Camera Info marker") : std::string();
      };
      add("marker.viewthrough", "View through this camera", "Edit", "", [this] {
        (void)mScene.LookThroughCamera(mScene.SelectedCameraMarker());
      }, cameraMarker, {}, "The editor's camera goes to the view the selected Camera Info marker keeps");
      add("marker.fromview", "Set the camera marker from the view", "Edit", "", [this] {
        (void)mScene.SetCameraMarkerFromView(mScene.SelectedCameraMarker());
      }, cameraMarker, {}, "The selected Camera Info marker keeps the editor camera's view (one undo step)");
      add("edit.mirror", "Mirror the selection", "Edit", "", [this] {
        const int made = mScene.MirrorSelection();
        PostStatusMessage(
          made > 0 ? "Mirrored: " + std::to_string(made) + " copies"
                   : "Nothing to mirror: select objects, and set a symmetry in the brushes"
        );
      }, canEdit, {}, "Each selected marker, prop, unit and decal copied to its places in the map's symmetry");
      for (int i = 0; i < std::to_underlying(ArrangeOp::Count); ++i) {
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
      add("view.layouts", "Save or load a layout...", "View", "", [this] {
        mShowLayouts = true;
      }, {}, {}, "The panels as they are kept under a name, and loaded again (FAF Studio's save / load layout)");
      // Help: F1 the topic of the panel under the mouse (over the map view, the view's).
      add("help.open", "Help", "Help", "F1", [this] {
        mShell->OpenHelp(MouseOverView() ? std::string("view") : mShell->HelpTopicUnderMouse());
      }, {}, {}, "The help topic of the panel under the mouse");
      add("help.tour", "Tour", "Help", "", [this] {
        mShell->StartTour();
      }, {}, {}, "A few steps around the window");
      add(
        "help.diagnostics",
        "Save diagnostics for a bug report",
        "Help",
        "",
        [this] {
        SaveDiagnostics();
      },
        {},
        {},
        "The build, the renderer, the open map, the settings, the end of the log and the newest crash report "
        "in one text file to attach to a bug report"
      );
      add("help.settingsfolder", "Open the settings folder", "Help", "", [] {
        const std::filesystem::path folder = EditorSettingsFolder();
        (void)::ShellExecuteW(nullptr, L"open", folder.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
      }, {}, {}, "settings.ini, layout.ini, keys.ini and the play setups");
      add(
        "help.resetsettings",
        "Reset user settings",
        "Help",
        "",
        [this] {
        // FAF Studio's Help > Reset user settings: the files are put aside (as <name>.reset) and nothing is written
        // back this run, so the next start has the defaults.
        const std::filesystem::path folder = EditorSettingsFolder();
        ImGui::GetIO().IniFilename = nullptr;
        mSettingsWritable = false;
        mKeysFile.clear();
        const int moved = PutUserSettingsAside(folder);
        gpg::Logf("editor: user settings reset: %d files put aside in %s", moved, folder.string().c_str());
        PostStatusMessage(
          "Settings put aside (" + std::to_string(moved) + " files): start the editor again for the defaults"
        );
      },
        {},
        {},
        "Settings, layout, keys and play setups back to the defaults at the next start (the old files are kept as "
        ".reset)"
      );
      add("view.palette", "Command palette", "View", "Ctrl+K, Ctrl+Shift+P", [] {
        OpenCommandPalette();
      }, {}, {}, "Find any command by a few of its letters");
      add("view.perf", "Performance timing", "View", "", [this] {
        EdPerf::Get().SetOn(!EdPerf::Get().On());
        PostStatusMessage(
          EdPerf::Get().On() ? "Performance timing on: each section of a frame, every 5 s in the log"
                             : "Performance timing off"
        );
        gpg::Logf("editor: performance timing %s", EdPerf::Get().On() ? "on" : "off");
      }, {}, {}, "The time each part of the editor's frame takes, every 5 seconds in the Log panel");
      add("view.names", "Names in the view", "View", "", [this] {
        mScene.SetNamesShown(!mScene.NamesShown());
        PostStatusMessage(mScene.NamesShown() ? "Marker and area names shown in the view" : "Names in the view hidden");
      }, {}, {}, "The markers' and areas' names written beside them (all when close, the selected and hovered far)");
      add("view.frame", "Frame the whole map", "View", "Home", [this] {
        mScene.FrameMap();
      }, mapOpen);
      // Q / E: the selected props turn under the Select tool, else the camera (the first that can run takes the key).
      add("object.turnleft", "Turn the selection left", "Object", "Q", [this] {
        (void)mScene.TurnSelectedProps(-0.2617994f);
      }, [this]() -> std::string {
        return mScene.CanTurnSelectedProps() ? std::string() : "nothing selected under the Select tool";
      });
      add("object.turnright", "Turn the selection right", "Object", "E", [this] {
        (void)mScene.TurnSelectedProps(0.2617994f);
      }, [this]() -> std::string {
        return mScene.CanTurnSelectedProps() ? std::string() : "nothing selected under the Select tool";
      });
      add("view.turnleft", "Turn the camera left", "View", "Q", [this] {
        mScene.StepCamera(-0.2617994f, 1.0f);
      }, mapOpen);
      add("view.turnright", "Turn the camera right", "View", "E", [this] {
        mScene.StepCamera(0.2617994f, 1.0f);
      }, mapOpen);
      add("view.zoomin", "Closer", "View", "PageUp, Z", [this] {
        mScene.StepCamera(0.0f, 0.8f);
      }, mapOpen);
      add("view.zoomout", "Farther", "View", "PageDown, X", [this] {
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
      // Alt+Shift+A (FAF Studio's Alt+A; plain Alt+A stays Select > None as in Blender): a new area at the cursor.
      add("tool.area", "Add an area here", "Tool", "Alt+Shift+A", [this] {
        float x = 0.0f;
        float z = 0.0f;
        if (!mScene.CursorGroundNow(x, z)) {
          PostStatusMessage("Point at the map to add an area there");
          return;
        }
        (void)mCommands.Run("tool.markers");
        mShell->Tools().AskAddAreaAt(x, z);
      }, mapOpen, {}, "A new 64 x 64 area (the save file's AREA_n) round the cursor, in the Markers tool's Areas");
      // Alt+C (FAF Studio): the Markers tool drawing a chain, each marker placed joining it.
      add("tool.chain", "Draw a chain", "Tool", "Alt+C", [this] {
        (void)mCommands.Run("tool.markers");
        mShell->Tools().SetDrawChain(true);
        PostStatusMessage("Draw chain: each marker placed joins " + mShell->Tools().ChainName());
      }, mapOpen, {}, "The Markers tool with Draw chain on: each marker placed joins the chain named in the panel");
      // Map > Snap resource markers to grid (FAF Studio): every mass and hydrocarbon in its cell's middle.
      add(
        "edit.mirrorhalf",
        "Mirror half the map...",
        "Edit",
        "",
        [this] {
        mMirrorHalfAsk = true;
      },
        mapOpen,
        {},
        "A part of the symmetry copied over the rest: which part, what follows, the units' armies, add or replace"
      );
      add("map.snapresources", "Snap resource markers to grid", "Map", "", [this] {
        const std::vector<ResourceSnap> snaps = ResourceSnaps(mDocument.SaveData().Markers());
        for (const ResourceSnap& snap : snaps) {
          const float y = mDocument.Map()->mTerrainRes->GetHeightAt(
            static_cast<std::int32_t>(std::lround(snap.x)), static_cast<std::int32_t>(std::lround(snap.z))
          );
          mScene.EditMarker(snap.name, "position", Vector3Value(snap.x, y, snap.z));
        }
        gpg::Logf("editor: snap resources: %zu markers moved to their cells' middles", snaps.size());
        PostStatusMessage(std::to_string(snaps.size()) + " resource markers snapped to the grid");
      }, mapOpen, {}, "Every mass and hydrocarbon marker moved to the middle of its extractor's cell (x.5)");
      add("map.pullmarkers", "Move stray markers onto the map", "Map", "", [this] {
        // Off the playable area (the whole map without one): to the nearest point 2 units inside, on the ground.
        float x0 = 0.0f, z0 = 0.0f, x1 = 0.0f, z1 = 0.0f;
        mDocument.LayoutArea(x0, z0, x1, z1);
        const LayoutGround ground = LayoutGroundNow();
        EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
        const std::vector<std::string> moved =
          PullMarkersInside(mDocument.SaveData().Markers(), x0, z0, x1, z1, 2.0f, ground.height);
        if (!moved.empty()) {
          mDocument.SaveDataEdited(std::move(before));
        }
        gpg::Logf(
          "editor: stray markers: %zu moved onto the map%s%s",
          moved.size(),
          moved.empty() ? "" : ", the first ",
          moved.empty() ? "" : moved.front().c_str()
        );
        PostStatusMessage(
          moved.empty() ? std::string("No marker is off the map")
                        : std::to_string(moved.size()) + " markers moved onto the map (one undo step)"
        );
      }, canEdit, {}, "Markers outside the playable area (or the map) moved just inside its edge, on the ground");
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
      windowPanel("window.unitwizard", "New unit (wizard)", "UnitWizard");
      windowPanel("window.paths", "Paths", "Paths");
      windowPanel("window.detail", "Detail pass", "DetailPass");
      add("help.selftests", "Self tests and panel checks...", "Help", "", [this] {
        mShowSelfTests = true;
      }, {}, {}, "Checks inside the editor on the open map, the frame budget, the click sweep and the layout check");
      windowPanel("window.unitviewer", "Unit viewer", "UnitViewer");
      windowPanel("window.modproject", "Mod project", "ModProject");
      windowPanel("window.editormods", "Editor mods", "EditorMods");
      windowPanel("window.assets", "Asset browser", "AssetBrowser");
      windowPanel("window.fields", "Fields (op by op)", "Fields");
      windowPanel("window.statistics", "Statistics", "Statistics");
      windowPanel("window.images", "Images", "Images");
      windowPanel("window.mesh", "Mesh terrain", "MeshTerrain");
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
        for (int i = 0; i < std::to_underlying(ArrangeOp::Count); ++i) {
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
      // Window > From editor mods: the entries and panels the running editor mods added.
      EdMenuItem modEntries;
      modEntries.label = "From editor &mods";
      modEntries.provider = [this] {
        std::vector<EdMenuItem> items;
        for (const EdModHost::ModMenu& entry : mShell->ModHost().MenuEntries()) {
          EdMenuItem item;
          item.command = entry.command;
          item.label = entry.label;
          items.push_back(std::move(item));
        }
        if (items.empty()) {
          EdMenuItem none;
          none.command = "window.editormods";
          none.label = "No editor mod added one (Editor mods...)";
          items.push_back(std::move(none));
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
           cmd("file.samplemap"),
           cmd("new.effect"),
           cmd("new.material"),
           cmd("file.open"),
           recent,
           sep(),
           cmd("file.save"),
           cmd("file.saveas"),
           cmd("file.updatepreview"),
           cmd("file.package"),
           cmd("file.exportpreview"),
           cmd("file.exportpreview512"),
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
           cmd("edit.mirror"),
           cmd("edit.mirrorhalf"),
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
           cmd("terrain.flatten"),
           cmd("terrain.paths"),
           cmd("objects.detail"),
           cmd("terrain.sctools"),
           cmd("window.fields"),
           cmd("window.mesh")}
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
           cmd("view.resetlayout"),
           cmd("view.layouts")}
        },
        EdMenu{
          "&Map",
          {cmd("view.info"),
           cmd("view.armies"),
           cmd("view.markers"),
           cmd("view.check"),
           cmd("window.statistics"),
           cmd("window.images"),
           sep(),
           cmd("view.script"),
           cmd("view.adaptive"),
           cmd("view.lighting"),
           sep(),
           cmd("map.preview"),
           cmd("map.resize"),
           cmd("map.snapresources"),
           cmd("map.pullmarkers"),
           sep(),
           cmd("texture.masks.export"),
           cmd("texture.masks.import")}
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
              cmd("window.unitwizard"),
              cmd("window.unitviewer"),
              cmd("window.modproject"),
              cmd("window.editormods")}
           },
           modEntries,
           cmd("window.assets"),
           cmd("view.script")}
        },
        EdMenu{"&Play", {cmd("play.toggle"), cmd("play.pause"), cmd("play.editorview"), playMaps}},
        EdMenu{
          "&Help",
          {cmd("help.open"),
           cmd("help.tour"),
           sep(),
           cmd("view.palette"),
           cmd("settings.keys"),
           sep(),
           cmd("help.diagnostics"),
           cmd("help.selftests"),
           cmd("help.settingsfolder"),
           cmd("help.resetsettings")}
        },
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
      // The points are the panels' window's pixels; ImGui's are the screen's once panels can pop out.
      const ImVec2 origin = ImGui::GetMainViewport()->Pos;
      io.AddMousePosEvent(origin.x + click.x, origin.y + click.y);
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
                if (u.blueprint.contains("0001") && !found) {
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
                if (u.blueprint.contains("0001") && step == 0) {
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
                if (u.blueprint.contains("0001") && step == 0) {
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
                if (u.blueprint.contains("0001") && step == 0) {
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
                if (u.blueprint.contains("0001") && step == 0) {
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
        const EdPerf::Scope perfScene("scene update");
        mScene.Update(
          frameSeconds,
          playIdle,
          mShell->EditorViewInPlay() && moho::WLD_GetFrameAction() == moho::EWldFrameAction::Playing
        );
      }
      KeepViewState();
      KeepToolState();
      KeepSoundToFocus();
      mShell->Tools().SetModelsLoading(mScene.ModelsPending());

      if (mImGuiReady) {
        ApplyUiScale();
        ImGui_ImplWin32_NewFrame();
        popouts::BeforeNewFrame(gPanelWindow);
        FeedUiClicks();
        // `/tipcheck` starts once the map is open and its models are in (the panels are its then).
        if (
          mTipCheckAsked && mDocument.GetState() == EdDocument::State::Open && mScene.Attached() &&
          !mScene.ModelsPending()
        ) {
          mTipCheckAsked = false;
          mTipCheck.Start(180);
        }
        mTipCheck.BeforeNewFrame();
        // `/clicksweep`, `/layoutcheck`, `/selftests` (test runs), once the map is open and its models are in.
        if (
          (mClickSweepAsked || mLayoutCheckAsked || mSelfTestsAsked) &&
          mDocument.GetState() == EdDocument::State::Open && mScene.Attached() && !mScene.ModelsPending() &&
          !mUiQa.Running() && !mSelfTests.Running()
        ) {
          if (mSelfTestsAsked) {
            mSelfTestsAsked = false;
            mSelfTests.RunAll();
          } else if (mClickSweepAsked) {
            mClickSweepAsked = false;
            mUiQa.Start(EdUiQa::Kind::ClickSweep, 120);
          } else {
            mLayoutCheckAsked = false;
            mUiQa.Start(EdUiQa::Kind::LayoutCheck, 120);
          }
        }
        gNoFileDialogs = mUiQa.Running();
        // A named layout asked for: ImGui reads settings (the docks too) only between frames.
        if (!mLayoutToLoad.empty()) {
          const std::filesystem::path file = std::exchange(mLayoutToLoad, {});
          std::ifstream in(file, std::ios::binary);
          const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          if (text.empty()) {
            PostStatusMessage("No layout in " + file.filename().string());
          } else {
            ImGui::LoadIniSettingsFromMemory(text.c_str(), text.size());
            mShell->ApplyShownPanels();
            gpg::Logf("editor: layout loaded from %s (%zu bytes)", file.string().c_str(), text.size());
            PostStatusMessage("Layout " + file.stem().string() + " loaded");
          }
        }
        mUiQa.BeforeNewFrame();
        ImGui::NewFrame();
        mUiQa.DuringFrame();
        popouts::AfterNewFrame();
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
          const EdPerf::Scope perfShell("panels");
          mShell->Draw();
        }
        SyncSettings();
        DrawSettings();
        if (mShowSelfTests) {
          mSelfTests.Draw(mShowSelfTests);
        }
        DrawLayouts();
        // `/layoutsave <file>` (test runs): the panels saved there once the map is up, then loaded back from it.
        if (!mLayoutSaveFile.empty() && mScene.Attached()) {
          ++mLayoutSaveFrames;
          if (mLayoutSaveFrames == 200) {
            // Saved, then one more panel opened (the Paths panel) so the load has something to put back.
            const bool saved = SaveLayoutTo(mLayoutSaveFile);
            std::error_code ec;
            mLayoutSavedPanels = mShell->ShownPanelIds();
            gpg::Logf(
              "editor: /layoutsave: saved %s (%llu bytes), %zu panels open",
              saved ? "yes" : "no",
              static_cast<unsigned long long>(std::filesystem::file_size(mLayoutSaveFile, ec)),
              mLayoutSavedPanels.size()
            );
            for (const std::string& window : mShell->PanelWindows()) {
              if (window.contains("###Paths")) {
                (void)mShell->ShowPanelWindow(window, true);
              }
            }
          } else if (mLayoutSaveFrames == 230) {
            gpg::Logf("editor: /layoutsave: %zu panels open before the load", mShell->ShownPanelIds().size());
            mLayoutToLoad = mLayoutSaveFile;
          } else if (mLayoutSaveFrames == 260) {
            gpg::Logf(
              "editor: /layoutsave: after the load %zu panels open, %s the saved ones",
              mShell->ShownPanelIds().size(),
              mShell->ShownPanelIds() == mLayoutSavedPanels ? "the same as" : "not"
            );
          }
        }
        DrawOverwriteAsk();
        DrawRecover();
        DrawUnsavedQuestion();
        DrawFind();
        DrawFlatten();
        DrawMirrorHalf();
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
            const std::string chord = PanelChordPressed(); !chord.empty() &&
            !PanelsKeepChord(chord, ImGui::GetIO().WantTextInput) && !mShell->Generate().GraphKeepsChord(chord)
          ) {
            (void)RunChord(chord, false);
          }
        }
        if (gComposite && mViewImage != 0) {
          // gViewRect is in the panels' window's pixels; ImGui's are the screen's once panels can pop out.
          const ImVec2 origin = ImGui::GetMainViewport()->Pos;
          const ImVec2 from(
            origin.x + static_cast<float>(gViewRect.left), origin.y + static_cast<float>(gViewRect.top)
          );
          const ImVec2 to(
            origin.x + static_cast<float>(gViewRect.right), origin.y + static_cast<float>(gViewRect.bottom)
          );
          ImGui::GetBackgroundDrawList(ImGui::GetMainViewport())
            ->AddImage(static_cast<ImTextureID>(EdImGuiRenderer::kGameViewImage), from, to);
          // The markers' and areas' names over the view (FAF Studio's labels), under the panels and their windows.
          ImDrawList* const labels = ImGui::GetBackgroundDrawList(ImGui::GetMainViewport());
          labels->PushClipRect(from, to, true);
          // Names that would cover one another (markers on one spot) are stacked upwards.
          std::vector<ImVec4> placed;
          for (const EdMapScene::ViewLabel& label : mScene.ViewLabels()) {
            const ImVec2 size = ImGui::CalcTextSize(label.text.c_str());
            ImVec2 at(std::round(from.x + label.x - size.x * 0.5f), std::round(from.y + label.y - size.y - 4.0f));
            for (int tries = 0; tries < 6; ++tries) {
              bool clear = true;
              for (const ImVec4& r : placed) {
                if (at.x < r.z && at.x + size.x > r.x && at.y < r.w && at.y + size.y > r.y) {
                  at.y = r.y - size.y - 3.0f;
                  clear = false;
                }
              }
              if (clear) {
                break;
              }
            }
            placed.emplace_back(at.x - 3.0f, at.y - 1.0f, at.x + size.x + 3.0f, at.y + size.y + 1.0f);
            labels->AddRectFilled(
              ImVec2(at.x - 3.0f, at.y - 1.0f),
              ImVec2(at.x + size.x + 3.0f, at.y + size.y + 1.0f),
              IM_COL32(0, 0, 0, 150),
              3.0f
            );
            labels->AddText(
              at, IM_COL32((label.rgb >> 16) & 0xFF, (label.rgb >> 8) & 0xFF, label.rgb & 0xFF, 255), label.text.c_str()
            );
          }
          labels->PopClipRect();
        }
        {
          const gpg::gal::RenderProfileScope profilePanels("EdPanelsRender");
          const EdPerf::Scope perfPanels("panels drawn");
          ImGui::Render();
          mTipCheck.AfterRender();
          if (mTipCheck.Done()) {
            mTipCheck = EdTipCheck();
            mShell->RequestExit();
          }
          mUiQa.AfterRender();
          if (mUiQa.Done()) {
            mQaReport = mUiQa.Report();
            mUiQa = EdUiQa();
            WireUiQa();
            // Test runs close once every asked check has run (`/clicksweep /layoutcheck` run one after the other).
            if (mQaExitAfter && !mClickSweepAsked && !mLayoutCheckAsked && !mSelfTestsAsked && !mSelfTests.Running()) {
              mShell->RequestExit();
            }
          }
          mSelfTests.Frame(ImGui::GetIO().DeltaTime);
          if (!mQaReport.empty()) {
            mSelfTests.qaReport = std::move(mQaReport);
            mQaReport.clear();
          }
          if (std::exchange(mSelfTests.askClickSweep, false) && !mUiQa.Running()) {
            mUiQa.Start(EdUiQa::Kind::ClickSweep, 10);
          }
          if (std::exchange(mSelfTests.askLayoutCheck, false) && !mUiQa.Running()) {
            mUiQa.Start(EdUiQa::Kind::LayoutCheck, 10);
          }
          if (
            mSelfTests.Finished() && mQaExitAfter && !mSelfTestsAsked && !mClickSweepAsked && !mLayoutCheckAsked &&
            !mUiQa.Running()
          ) {
            mShell->RequestExit();
          }
          // A frame whose heads were re-made isn't drawn: its draw lists hold the view's and the minimap's copies,
          // which the re-made context freed.
          const bool remade = FitGameView();
          if (!remade) {
            RenderPanels();
          }
          popouts::Render(mRenderer, !remade);
        }
      }

      {
        const gpg::gal::RenderProfileScope profileGame("GameMain");
        const EdPerf::Scope perfGame("game frame (view, sound, sim)");
        mGame.Main();
      }
      if (std::string report; EdPerf::Get().EndFrame(frameSeconds, report)) {
        gpg::Logf("editor: %s", report.c_str());
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
      mTipCheckAsked = moho::CFG_GetArgOption("/tipcheck", 0, nullptr);
      mClickSweepAsked = moho::CFG_GetArgOption("/clicksweep", 0, nullptr);
      // `/perf`: the performance timing on from the start (FAF Studio's).
      if (moho::CFG_GetArgOption("/perf", 0, nullptr)) {
        EdPerf::Get().SetOn(true);
        gpg::Logf("editor: performance timing on (/perf): a report every 5 s");
      }
      mLayoutCheckAsked = moho::CFG_GetArgOption("/layoutcheck", 0, nullptr);
      mSelfTestsAsked = moho::CFG_GetArgOption("/selftests", 0, nullptr);
      if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/layoutsave", 1, &file) && !file.empty()) {
        mLayoutSaveFile = file[0].c_str();
      }
      mQaExitAfter = mClickSweepAsked || mLayoutCheckAsked || mSelfTestsAsked;
      WireUiQa();
      RegisterSelfTests();
      if (
        fa::vector<fa::string> fieldsTest; moho::CFG_GetArgOption("/fieldstest", 1, &fieldsTest) && !fieldsTest.empty()
      ) {
        mFieldsTest = fieldsTest[0].c_str();
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
      if (fa::vector<fa::string> stamp; moho::CFG_GetArgOption("/maskstamptest", 1, &stamp) && !stamp.empty()) {
        mMaskStampArg = stamp[0].c_str();
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
        mSymCheckRepair = spec.contains(":repair");
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
      // The panel's settings, with the map's own sun and sea.
      MapTextureOptions options = mShell->Tools().MapTextureSettings();
      const LightingState lighting = mDocument.LightingNow();
      SunAnglesOf(lighting.sunDirection, options.azimuth, options.altitude);
      options.altitude = std::clamp(options.altitude, 5.0f, 85.0f);
      const WaterState water = mDocument.WaterNow();
      options.waterOn = water.enabled;
      options.waterElevation = water.elevation;
      options.abyss = water.abyss;
      const int mapSize = std::max(terrain->width, terrain->height) - 1;
      const int size =
        mShell->Tools().MapTextureSize() > 0 ? mShell->Tools().MapTextureSize() : std::clamp(mapSize, 64, 1024);
      const auto started = std::chrono::steady_clock::now();
      std::string error;
      const bool fromPaint = target.pack == MapTexturePack::Specular || target.pack == MapTexturePack::Macro;
      std::string kinds;
      std::expected<std::vector<float>, std::string> made = std::unexpected(std::string());
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
          made = std::unexpected("the map's masks couldn't be read");
        } else {
          VisibleWeights(masks.texels.data(), masks.width, masks.height, profile.painted, profile.remapped, paint);
          made = MakePaintTexture(
            terrain->heights,
            terrain->width,
            terrain->height,
            paint,
            target,
            options,
            mShell->Tools().MapPaintSettings(),
            size
          );
        }
      } else {
        made = faf::editor::MakeMapTexture(terrain->heights, terrain->width, terrain->height, target, options, size);
      }
      if (!made) {
        PostStatusMessage("The map-wide texture wasn't made: " + made.error());
        gpg::Warnf("editor: map-wide texture: %s", made.error().c_str());
        return false;
      }
      std::vector<float>& rgba = *made;
      // A small picture for the row: the texture's colour (its alpha as grey where the colour is empty).
      {
        constexpr int kPreview = 96;
        std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kPreview) * kPreview);
        for (int y = 0; y < kPreview; ++y) {
          for (int x = 0; x < kPreview; ++x) {
            const std::size_t at = (static_cast<std::size_t>(y * size / kPreview) * size + x * size / kPreview) * 4;
            const auto c = [&](const int i) {
              return static_cast<std::uint32_t>(
                std::clamp(rgba[at + static_cast<std::size_t>(i)], 0.0f, 1.0f) * 255.0f
              );
            };
            pixels[static_cast<std::size_t>(y) * kPreview + x] = 0xFF000000u | (c(0) << 16) | (c(1) << 8) | c(2);
          }
        }
        const int row = static_cast<int>(kind);
        if (const std::uint64_t old = mShell->Tools().MapTexturePreview(row); old != 0U) {
          EdImGuiRenderer::DestroyImage(old);
        }
        mShell->Tools().SetMapTexturePreview(row, EdImGuiRenderer::CreateImage(kPreview, kPreview, pixels.data()));
      }
      TexImage image;
      image.Reset(size, 4, 0.0f);
      image.data = std::move(rgba);
      const auto encoded = EncodeDds(image, DdsKind::Bgra);
      if (!encoded) {
        PostStatusMessage("The map-wide texture wasn't encoded: " + encoded.error());
        return false;
      }
      const std::vector<std::uint8_t>& dds = *encoded;
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

    std::expected<void, std::string> EditorApp::MaskGenContextOf(
      const std::vector<MaskGenRule>& rules,
      MaskGenContext& context
    )
    {
      const std::shared_ptr<TerrainSource> terrain = mScene.TerrainHeights();
      if (terrain == nullptr || terrain->width < 2) {
        return std::unexpected("no terrain");
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
      // Imported masks: the slots the rules name, read from the files beside the Import / Export heightmap.
      const std::vector<std::string> imported = ImportedMaskFiles(mShell->Tools().InteropFile(false));
      for (const MaskGenRule& rule : rules) {
        const int slot = static_cast<int>(std::lround(rule.Value("slot")));
        if (
          !rule.enabled || rule.type != "named" || slot < 1 || slot > static_cast<int>(imported.size()) ||
          context.imported.contains(slot)
        ) {
          continue;
        }
        const auto read = ReadHeightImage(imported[static_cast<std::size_t>(slot - 1)], 0, 0);
        if (!read) {
          return std::unexpected(imported[static_cast<std::size_t>(slot - 1)] + ": " + read.error());
        }
        const HeightImage& image = *read;
        auto grid = std::make_shared<field::Grid>(
          image.width,
          image.height,
          static_cast<float>(terrain->width - 1) / static_cast<float>(std::max(image.width - 1, 1)),
          0.0f,
          0.0f
        );
        for (std::size_t k = 0; k < image.words.size() && k < grid->v.size(); ++k) {
          grid->v[k] = static_cast<float>(image.words[k]) / 65535.0f;
        }
        context.imported[slot] = grid;
        gpg::Logf(
          "editor: mask generator: imported mask %d is %s (%d x %d)",
          slot,
          imported[static_cast<std::size_t>(slot - 1)].c_str(),
          image.width,
          image.height
        );
      }
      return {};
    }

    void EditorApp::WaterMasksUpdate()
    {
      EdTools& tools = mShell->Tools();
      if (!mScene.Attached()) {
        mWaterApplied.clear();
        return;
      }
      using Ask = EdTools::WaterMaskAsk;
      std::vector<EdTools::WaterMaskDef>& defs = tools.WaterMaskDefs();
      const auto find = [&defs](const int id) -> EdTools::WaterMaskDef* {
        for (EdTools::WaterMaskDef& def : defs) {
          if (def.id == id) {
            return &def;
          }
        }
        return nullptr;
      };
      const auto evaluate = [this](const EdTools::WaterMaskDef& def, field::Grid& mask, std::string& error) {
        const std::vector<MaskGenRule> rules = WaterMaskRules(def.kind, def.width, def.depth, def.soft, def.slope);
        MaskGenContext context;
        if (const auto made = MaskGenContextOf(rules, context); !made) {
          error = made.error();
          return false;
        }
        if (const auto made = EvaluateMaskRules(context, rules, mask); !made) {
          error = made.error();
          return false;
        }
        return true;
      };
      const auto apply = [&](EdTools::WaterMaskDef& def, const bool remove) {
        WaterApplied& kept = mWaterApplied[def.id];
        if (kept.layer != 0 && kept.layer != def.layer && !kept.base.empty()) {
          // Moved to another layer: the old layer gets its own paint back first.
          std::string message;
          (void)mScene.WriteWaterLinkedMask(nullptr, kept.layer, 1.0f, kept.base, kept.last, message);
        }
        kept.layer = def.layer;
        field::Grid mask;
        std::string message;
        if (!remove && !evaluate(def, mask, message)) {
          PostStatusMessage("The water mask wasn't made: " + message);
          return;
        }
        const int changed =
          mScene.WriteWaterLinkedMask(remove ? nullptr : &mask, def.layer, def.strength, kept.base, kept.last, message);
        def.applied = !remove && changed >= 0;
        kept.level = mDocument.WaterNow().elevation;
        PostStatusMessage(message);
        gpg::Logf(
          "editor: water mask %s (L%d) at water level %.2f: %s",
          WaterMaskKindName(def.kind),
          def.layer,
          static_cast<double>(kept.level),
          message.c_str()
        );
      };
      Ask ask = Ask::None;
      int id = 0;
      if (tools.TakeWaterMaskAsk(ask, id)) {
        if (EdTools::WaterMaskDef* const def = find(id); def != nullptr) {
          switch (ask) {
          case Ask::Preview: {
            field::Grid mask;
            std::string error;
            if (!mDocument.WaterNow().enabled) {
              def->cover = "The map has no water.";
            } else if (evaluate(*def, mask, error)) {
              double sum = 0.0;
              for (const float v : mask.v) {
                sum += std::clamp(v, 0.0f, 1.0f);
              }
              char text[96];
              (void)std::snprintf(
                text,
                sizeof(text),
                "Covers %.1f%% of the map at the water level %.1f",
                100.0 * sum / static_cast<double>(std::max<std::size_t>(mask.v.size(), 1)),
                static_cast<double>(mDocument.WaterNow().elevation)
              );
              def->cover = text;
            } else {
              def->cover = error;
            }
            gpg::Logf("editor: water mask %s preview: %s", WaterMaskKindName(def->kind), def->cover.c_str());
            break;
          }
          case Ask::Apply:
            if (!mDocument.WaterNow().enabled) {
              PostStatusMessage("The map has no water (turn it on in the Water tool).");
            } else {
              apply(*def, false);
            }
            break;
          case Ask::Remove:
            apply(*def, true);
            break;
          case Ask::Delete:
            if (def->applied) {
              apply(*def, true);
            }
            mWaterApplied.erase(id);
            defs.erase(
              std::remove_if(
                defs.begin(),
                defs.end(),
                [id](const EdTools::WaterMaskDef& d) {
              return d.id == id;
            }
              ),
              defs.end()
            );
            break;
          default:
            break;
          }
        }
      }
      // Live: a new water level applies every applied mask again (each its own undo step).
      if (tools.WaterMasksLive() && ++mWaterLiveFrames % 30 == 0 && mDocument.WaterNow().enabled) {
        const float level = mDocument.WaterNow().elevation;
        for (EdTools::WaterMaskDef& def : defs) {
          const auto kept = mWaterApplied.find(def.id);
          if (def.applied && kept != mWaterApplied.end() && std::fabs(kept->second.level - level) > 0.01f) {
            apply(def, false);
          }
        }
      }
      // `/watermasks <kind>,<layer>` (test runs): a mask added, previewed, applied; the water raised by 2, applied
      // again by Live; then removed.
      if (
        fa::vector<fa::string> arg; mWaterTestStage < 6 && moho::CFG_GetArgOption("/watermasks", 1, &arg) &&
        !arg.empty() && ++mWaterTestFrames % 60 == 0
      ) {
        const std::string text = arg[0].c_str();
        switch (mWaterTestStage++) {
        case 0:
          mWaterTestId = tools.AddWaterMask(std::atoi(text.c_str()), std::atoi(text.c_str() + text.find(',') + 1));
          tools.AskWaterMask(Ask::Preview, mWaterTestId);
          break;
        case 1:
          tools.AskWaterMask(Ask::Apply, mWaterTestId);
          break;
        case 2: {
          const WaterState before = mDocument.WaterNow();
          WaterState water = before;
          water.elevation += 2.0f;
          mDocument.ApplyWater(water);
          mDocument.WaterEdited(before);
          gpg::Logf("editor: /watermasks: the water raised to %.2f", static_cast<double>(water.elevation));
          break;
        }
        case 4:
          tools.AskWaterMask(Ask::Remove, mWaterTestId);
          break;
        default:
          break;
        }
      }
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
        target.mode = arg.contains(",add") ? MaskWriteMode::AddTo
          : arg.contains(",sub")           ? MaskWriteMode::SubtractFrom
                                           : MaskWriteMode::Replace;
        target.takeAway = arg.contains(",free");
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
        const auto made = MaskGenContextOf(tools.GenRules(), context).and_then([&] {
          return EvaluateMaskRules(context, tools.GenRules(), mask);
        });
        if (!made) {
          error = made.error();
          PostStatusMessage("The mask wasn't made: " + error);
          gpg::Warnf("editor: mask generator: %s", error.c_str());
        } else if (target.toTypes) {
          // A terrain type where the mask is above the threshold (FAF Studio's ApplyToTypes), one undo step.
          int width = 0;
          int height = 0;
          if (mDocument.TerrainTypeCells(width, height) == nullptr || width < 1 || height < 1) {
            PostStatusMessage("The map has no terrain types.");
          } else {
            std::vector<std::uint8_t> cells = mDocument.TerrainTypesNow();
            const std::vector<std::uint8_t> before = cells;
            const float mapW = static_cast<float>(mDocument.Facts().fieldWidth - 1);
            const float mapH = static_cast<float>(mDocument.Facts().fieldHeight - 1);
            int changed = 0;
            for (int z = 0; z < height; ++z) {
              for (int x = 0; x < width; ++x) {
                const float wx = (static_cast<float>(x) + 0.5f) * mapW / static_cast<float>(width);
                const float wz = (static_cast<float>(z) + 0.5f) * mapH / static_cast<float>(height);
                if (SampleField(mask, wx, wz) > target.threshold) {
                  std::uint8_t& cell = cells[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + x];
                  if (cell != static_cast<std::uint8_t>(target.typeCode)) {
                    cell = static_cast<std::uint8_t>(target.typeCode);
                    ++changed;
                  }
                }
              }
            }
            if (changed > 0) {
              mDocument.ApplyTerrainTypes(cells);
              mDocument.TerrainTypesEdited(before);
            }
            const std::string message =
              "Terrain type " + std::to_string(target.typeCode) + " on " + std::to_string(changed) + " cells";
            PostStatusMessage(message);
            gpg::Logf("editor: mask generator: %s", message.c_str());
          }
        } else {
          if (target.water >= 0) {
            // Into one of the water's masks (FAF Studio's "Apply to water mask"), one undo step.
            std::string message;
            const int cells = mScene.WriteGeneratedWaterMask(
              mask,
              static_cast<WaterMask>(std::clamp(target.water, 0, 2)),
              static_cast<int>(target.mode),
              target.strength,
              message
            );
            PostStatusMessage(message);
            gpg::Logf("editor: mask generator: %s (%d cells)", message.c_str(), cells);
            return;
          }
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
      // The map overlay goes with the section and its tick (only the generator's own: the terrain graph's inspector
      // shows a node's mask there too).
      if ((!tools.GenSectionOpen() || !tools.GenShowOnMap()) && mMaskGenOverlay) {
        mScene.SetOverlayMask({});
        mMaskGenOverlay = false;
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
      if (const auto made = MaskGenContextOf(tools.GenRules(), context); !made) {
        tools.SetGenPreview(0, 0.0f, made.error());
        return;
      }
      if (const auto made = EvaluateMaskRules(context, tools.GenRules(), mask); !made) {
        tools.SetGenPreview(0, 0.0f, made.error());
        return;
      }
      // On the map too when asked (FAF Studio draws the preview on the terrain).
      if (tools.GenShowOnMap() || mMaskGenOverlay) {
        mScene.SetOverlayMask(tools.GenShowOnMap() ? mask : field::Grid{});
        mMaskGenOverlay = tools.GenShowOnMap();
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
          mThemeArg.contains(",try") || mThemeArg.contains(",back") ? EdTools::ThemeOp::Try : EdTools::ThemeOp::Apply
        );
      }
      if (!mThemeArg.empty() && mThemeArgFrames == 240 && mThemeArg.contains(",back")) {
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
          tools.AskTypesFromLayers(mTypesFromLayersArg.contains("only"));
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
      const bool biplanar = profile.summary.contains("biplanar");
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
      StrataThemesUpdate(slots);
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
      if (!apply && !tools.RecipeAsked() && (!tools.RecipesOpen() || mRecipeFrame++ % 60 != 0)) {
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
      int showLayer = 0;
      const EdTools::RecipeAsk extra = tools.TakeRecipeAsk(showLayer);
      if (extra == EdTools::RecipeAsk::Assign || extra == EdTools::RecipeAsk::Layered) {
        // Textures from the chosen texture set: Assign fills empty layers with the kinds the map lacks; Layered puts
        // FAF Studio's seven layer mix (grass 2, rock 1, dirt 1, rock 2, wet 1, dirt 2, rock 3) on the painted layers.
        const TextureTheme& set = TextureThemes()[static_cast<std::size_t>(
          std::clamp(tools.ThemeIndex(), 0, static_cast<int>(TextureThemes().size()) - 1)
        )];
        const auto candidate = [&](const GroundKind kind, const int nth) -> std::string {
          int found = 0;
          for (const char* path : set.kinds[static_cast<std::size_t>(kind)]) {
            if (GameFileExists(path) && found++ == nth) {
              return path;
            }
          }
          return {};
        };
        const auto tileOf = [&](const std::string& path) {
          const int pixels = TexturePixels(path);
          return pixels > 0 ? TileForPixels(pixels) : set.size;
        };
        std::vector<std::pair<int, LayerSettings>> layers;
        std::string what;
        if (extra == EdTools::RecipeAsk::Assign) {
          std::array<bool, 9> present{};
          for (int layer = 0; layer <= 8; ++layer) {
            if (textured[static_cast<std::size_t>(layer)]) {
              present[static_cast<std::size_t>(detected[static_cast<std::size_t>(layer)])] = true;
            }
          }
          int slot = 1;
          for (const GroundKind kind : RecipeOrder()) {
            if (present[static_cast<std::size_t>(kind)]) {
              continue;
            }
            while (slot <= profile.painted && slot < static_cast<int>(slots.size()) &&
                   textured[static_cast<std::size_t>(slot)]) {
              ++slot;
            }
            if (slot > profile.painted || slot >= static_cast<int>(slots.size())) {
              break;
            }
            const std::string path = candidate(kind, 0);
            if (path.empty()) {
              continue;
            }
            layers.push_back({slot, LayerSettings{path, "", tileOf(path), tileOf(path)}});
            what += std::string(what.empty() ? "" : ", ") + GroundKindName(kind) + " on " + std::to_string(slot);
            ++slot;
          }
        } else {
          static constexpr std::pair<GroundKind, int> kLayered[] = {
            {GroundKind::Grass, 1},
            {GroundKind::Rock, 0},
            {GroundKind::Dirt, 0},
            {GroundKind::Rock, 1},
            {GroundKind::Wet, 0},
            {GroundKind::Dirt, 1},
            {GroundKind::Rock, 2},
          };
          for (int i = 0; i < 7 && i + 1 <= profile.painted && i + 1 < static_cast<int>(slots.size()); ++i) {
            std::string path = candidate(kLayered[i].first, kLayered[i].second);
            if (path.empty()) {
              path = candidate(kLayered[i].first, 0);
            }
            if (!path.empty()) {
              layers.push_back({i + 1, LayerSettings{path, "", tileOf(path), tileOf(path)}});
              what += std::string(what.empty() ? "" : ", ") + GroundKindName(kLayered[i].first) + " on " +
                std::to_string(i + 1);
            }
          }
          for (std::size_t s = 0; s < RecipeStyles().size(); ++s) {
            if (std::string(RecipeStyles()[s].id) == "layered") {
              tools.SetRecipeStyle(static_cast<int>(s));
            }
          }
        }
        const int changed = layers.empty() ? 0 : mScene.ApplyLayerSettings({}, layers);
        const std::string status = (extra == EdTools::RecipeAsk::Assign ? "Assign textures (" : "Layered textures (") +
          std::string(set.label) + "): " + (what.empty() ? std::string("nothing to give") : what) + "; " +
          std::to_string(changed) + " layers changed";
        tools.SetRecipeResult(status);
        gpg::Logf("editor: stratum recipe: %s", status.c_str());
        mRecipeFrame = 0;
        return;
      }
      if (extra == EdTools::RecipeAsk::Measure) {
        float coverage[8] = {};
        std::string status = "Coverage now:";
        if (mScene.MaskCoverage(coverage)) {
          // Only the layers this shader paints (a 4-layer shader's other bytes repeat the first four).
          const int painted = std::clamp(profile.painted, 1, 8);
          for (int layer = 0; layer < painted; ++layer) {
            char part[32];
            (void)std::snprintf(
              part,
              sizeof(part),
              " %d %.0f %%%s",
              layer + 1,
              static_cast<double>(coverage[layer] * 100.0f),
              layer + 1 < painted ? "," : ""
            );
            status += part;
          }
        } else {
          status = "No paint masks to measure.";
        }
        tools.SetRecipeResult(status);
        gpg::Logf("editor: stratum recipe: %s", status.c_str());
        return;
      }
      if (!apply && extra != EdTools::RecipeAsk::Show) {
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
      const RecipePlan plan = PlanRecipe(kinds, textured, profile.painted, profile.summary.contains("biplanar"));
      MaskGenContext context;
      std::string error;
      if (const auto made = MaskGenContextOf({}, context); !made) {
        PostStatusMessage("The recipe wasn't painted: " + made.error());
        return;
      }
      const WaterState water = mDocument.WaterNow();
      const RecipeStats stats = RecipeStatsOf(terrain->heights, water.elevation, water.enabled);
      std::vector<RecipeRole> roles;
      std::map<int, field::Grid> target;
      std::array<float, 9> shares{};
      std::string message;
      if (extra == EdTools::RecipeAsk::Show) {
        // Show: the layer's visible weight as the recipe resolves it, red over a dark map; nothing is painted.
        auto madeRoles = RecipeRoles(context, plan, stats, tools.RecipeSettings(), tools.RecipeStyle());
        if (madeRoles) {
          roles = std::move(*madeRoles);
        } else {
          error = madeRoles.error();
        }
        if (
          !madeRoles || !ResolveRecipe(context, plan, roles, tools.RecipeSettings(), tools.RecipeStyle(), target, error)
        ) {
          tools.SetRecipeShow(0, "Can't show it: " + error);
          return;
        }
        const auto found = target.find(showLayer);
        if (found == target.end() || found->second.w < 2) {
          tools.SetRecipeShow(0, "Layer " + std::to_string(showLayer) + " isn't in the recipe (no kind, or the base).");
          return;
        }
        constexpr int kSide = 128;
        std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kSide) * kSide);
        double sum = 0.0;
        const float mapSize = static_cast<float>(terrain->width - 1);
        for (int y = 0; y < kSide; ++y) {
          for (int x = 0; x < kSide; ++x) {
            const float v = std::clamp(
              SampleField(found->second, (x + 0.5f) * mapSize / kSide, (y + 0.5f) * mapSize / kSide), 0.0f, 1.0f
            );
            sum += v;
            const auto r = static_cast<std::uint32_t>(40 + v * 215);
            const auto g = static_cast<std::uint32_t>(40 * (1.0f - v));
            pixels[static_cast<std::size_t>(y) * kSide + x] = 0xFF000000u | (r << 16) | (g << 8) | g;
          }
        }
        if (mRecipeShowImage != 0U) {
          EdImGuiRenderer::DestroyImage(mRecipeShowImage);
        }
        mRecipeShowImage = EdImGuiRenderer::CreateImage(kSide, kSide, pixels.data());
        char text[160];
        (void)std::snprintf(
          text,
          sizeof(text),
          "Layer %d (%s): %.0f %% of the map",
          showLayer,
          GroundKindName(kinds[static_cast<std::size_t>(std::clamp(showLayer, 0, 8))]),
          100.0 * sum / (kSide * kSide)
        );
        tools.SetRecipeShow(mRecipeShowImage, text);
        gpg::Logf("editor: stratum recipe: show %s", text);
        return;
      }
      auto madeRoles = RecipeRoles(context, plan, stats, tools.RecipeSettings(), tools.RecipeStyle());
      if (madeRoles) {
        roles = std::move(*madeRoles);
      } else {
        error = madeRoles.error();
      }
      if (
        !madeRoles ||
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
      // Terrain types too, roughness too (FAF Studio's recipe toggles).
      if (tools.RecipeTypesToo()) {
        tools.AskTypesFromLayers(false);
      }
      if (tools.RecipeRoughnessToo()) {
        const std::string shader = mScene.TerrainShader();
        if (shader.starts_with("Terrain1") || shader.starts_with("Terrain2")) {
          TerrainBuildWrites writes;
          writes.atlas = true;
          gpg::Logf("editor: stratum recipe: roughness: %s", MakeAtlasTexture(writes).c_str());
        } else {
          gpg::Logf("editor: stratum recipe: roughness skipped: %s has no roughness atlas", shader.c_str());
        }
      }
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

    std::expected<std::string, std::string> EditorApp::ImportUnitModel(
      const std::string& unit,
      const std::filesystem::path& obj
    )
    {
      EdModPanel& panel = mShell->ModPanel();
      ModProject* const project = panel.Project();
      const auto derived = project != nullptr ? project->derived.find(unit) : decltype(project->derived.end()){};
      if (project == nullptr || derived == project->derived.end()) {
        return std::unexpected("A model from an OBJ is for a derived unit of the open mod project");
      }
      std::ifstream in(obj, std::ios::binary);
      const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      const auto parsed = ParseObj(text);
      if (!parsed) {
        return std::unexpected(obj.filename().string() + ": " + parsed.error());
      }
      const ObjMesh& mesh = *parsed;
      // The OBJ in game units: the model is scaled by the blueprint's UniformScale when drawn, so divided by it here.
      float scale = 1.0f;
      if (moho::RRuleGameRules* const rules = moho::RULE_PeekKept(); rules != nullptr) {
        moho::RResId id{};
        id.name.assign(derived->second.base.c_str());
        if (
          const moho::RUnitBlueprint* const base = rules->GetUnitBlueprint(id);
          base != nullptr && base->Display.UniformScale > 1e-6f
        ) {
          scale = 1.0f / base->Display.UniformScale;
        }
      }
      const auto made =
        ScmFromObj(mesh, unit, scale, "made from " + obj.filename().string() + " by the FAF map editor");
      if (!made) {
        return std::unexpected("No model: " + made.error());
      }
      const std::vector<std::uint8_t>& scm = *made;
      if (
        const auto written =
          ModWriteBinary(*project, panel.Folder(), ModUnitModelFile(unit), std::string(scm.begin(), scm.end()));
        !written
      ) {
        return std::unexpected("No model: " + written.error());
      }
      const ModChanges before = ModChangesOf(*project);
      derived->second.model = true;
      (void)panel.History().Record("model of " + unit, before, ModChangesOf(*project), "", ImGui::GetTime());
      panel.Touch();
      std::string message = "Wrote " + ModUnitModelFile(unit) + " (" + std::to_string(mesh.triangles.size()) +
        " triangles, " + std::to_string(scm.size()) + " bytes)";
      gpg::Logf("editor: %s", message.c_str());
      return message;
    }

    void EditorApp::TransferAllMasks(
      const bool exporting
    )
    {
      const std::filesystem::path file = AskFile(
        HandleOf(mGame.supcomFrame),
        exporting,
        exporting ? L"PNG picture (*.png)\0*.png\0Raw 16-bit (*.raw)\0*.raw\0"
                  : L"Masks (*.png;*.raw;*.r16;*.bmp;*.tif)\0*.png;*.raw;*.r16;*.bmp;*.tif;*.tiff\0All files\0*.*\0",
        L"png",
        exporting ? L"Export the eight layer masks (name_1 .. name_8)" : L"Import layer masks: any file of the set"
      );
      if (file.empty()) {
        return;
      }
      int done = 0;
      for (int layer = 0; layer < 8; ++layer) {
        const std::filesystem::path one = MaskSetFile(file, layer);
        std::error_code ec;
        if (
          exporting ? mScene.ExportMaskLayer(layer, one).has_value()
                    : std::filesystem::exists(one, ec) && mScene.ImportMaskLayer(layer, one).has_value()
        ) {
          ++done;
        }
      }
      const std::string text = std::string(exporting ? "Exported " : "Imported ") + std::to_string(done) +
        " of the 8 layer masks " + (exporting ? "to " : "from ") + MaskSetFile(file, 0).filename().string() + " .. " +
        MaskSetFile(file, 7).filename().string();
      gpg::Logf("editor: %s", text.c_str());
      PostStatusMessage(text);
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
      const wchar_t* const filter = exporting
        ? L"DirectDraw surface (*.dds)\0*.dds\0PNG picture (*.png)\0*.png\0All files\0*.*\0"
        : L"Pictures (*.dds;*.png;*.tga;*.jpg;*.bmp;*.tif)\0*.dds;*.png;*.tga;*.jpg;*.jpeg;*.bmp;*.tif;*.tiff\0"
          L"All files\0*.*\0";
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
        // A PNG: the DDS decoded at its own size (its alpha kept: some shaders pack data there).
        std::string ext = file.extension().string();
        for (char& c : ext) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (ext == ".png") {
          std::uint32_t size[2] = {};
          if (bytes.size() >= 20) {
            std::memcpy(size, bytes.data() + 12, sizeof(size)); // the header's height, then width
          }
          gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
          gpg::gal::imaging::DecodeOptions options;
          options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
          options.width = size[1];
          options.height = size[0];
          options.mipLevels = 1;
          gpg::gal::imaging::Image image;
          std::string error;
          if (
            codec == nullptr || size[0] == 0 || FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) ||
            image.subresources.empty() || image.format != DXGI_FORMAT_B8G8R8A8_UNORM
          ) {
            PostStatusMessage("Can't decode " + current);
            return;
          }
          const auto& level = image.subresources.front();
          std::vector<std::uint32_t> pixels(static_cast<std::size_t>(level.width) * level.height);
          for (std::uint32_t y = 0; y < level.height; ++y) {
            std::memcpy(
              pixels.data() + static_cast<std::size_t>(y) * level.width,
              image.bytes.data() + level.offset + static_cast<std::size_t>(y) * level.rowPitch,
              static_cast<std::size_t>(level.width) * 4U
            );
          }
          const auto wrote =
            WriteColourPng(file, static_cast<int>(level.width), static_cast<int>(level.height), pixels);
          gpg::Logf("editor: map-wide texture %s exported as PNG to %s", current.c_str(), file.string().c_str());
          PostStatusMessage(
            wrote ? "Exported " + file.filename().string() : "Can't write " + file.string() + ": " + wrote.error()
          );
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
      // Import: a DDS as it is (its packing is the shader's), copied into the map's folder; another picture (PNG,
      // TGA, JPEG, BMP, TIFF) decoded at 1024 x 1024 and written as a DDS (BC3, its alpha kept).
      std::ifstream in(file, std::ios::binary);
      std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      std::string name = file.filename().string();
      if (bytes.size() < 128 || !bytes.starts_with("DDS ")) {
        constexpr int kSide = 1024;
        gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
        gpg::gal::imaging::DecodeOptions options;
        options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
        options.width = kSide;
        options.height = kSide;
        options.mipLevels = 1;
        gpg::gal::imaging::Image image;
        if (
          codec == nullptr || bytes.empty() || FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) ||
          image.subresources.empty() || image.format != DXGI_FORMAT_B8G8R8A8_UNORM
        ) {
          PostStatusMessage("Can't read " + file.filename().string() + " as a picture");
          gpg::Warnf("editor: map-wide texture: %s isn't a picture the editor reads", file.string().c_str());
          return;
        }
        const auto& level = image.subresources.front();
        TexImage picture;
        picture.Reset(static_cast<int>(std::min(level.width, level.height)), 4);
        for (int y = 0; y < picture.size; ++y) {
          const std::uint8_t* const row =
            image.bytes.data() + level.offset + static_cast<std::size_t>(y) * level.rowPitch;
          for (int x = 0; x < picture.size; ++x) {
            float* const p = picture.Pixel(x, y);
            p[0] = static_cast<float>(row[x * 4 + 2]) / 255.0f;
            p[1] = static_cast<float>(row[x * 4 + 1]) / 255.0f;
            p[2] = static_cast<float>(row[x * 4 + 0]) / 255.0f;
            p[3] = static_cast<float>(row[x * 4 + 3]) / 255.0f;
          }
        }
        const auto dds = EncodeDds(picture, DdsKind::Bc3);
        if (!dds) {
          PostStatusMessage("Can't make a DDS: " + dds.error());
          return;
        }
        bytes.assign(dds->begin(), dds->end());
        name = file.stem().string() + ".dds";
        gpg::Logf("editor: map-wide texture: %s converted to a %d px DDS", file.string().c_str(), picture.size);
      }
      const std::filesystem::path folder = scmap.parent_path() / "env" / "layers";
      std::error_code ec;
      std::filesystem::create_directories(folder, ec);
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
      if (bake.tile > 0.0f) {
        value.albedoSize = bake.tile;
        value.normalsSize = bake.tile;
      } else if (value.albedoSize <= 1.0f) {
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
        const auto painted = mScene.SetMaskLayer(bake.slot - 1, *bake.mask);
        status += painted ? "; the stratum's mask painted" : "; " + painted.error();
      }
      material.SetStatus(status);
    }

    void EditorApp::SaveDocument()
    {
      if (mDocument.SaveNeedsOverwriteConsent()) {
        mAskOverwrite = true;
        return;
      }
      // The lobby picture drawn anew from the map: a new map's first save, or each save when asked to.
      if (mUpdatePreviewOnSave || mPreviewOnFirstSave) {
        const auto drawn = RegeneratePreview();
        const bool ok = drawn.has_value();
        (ok ? gpg::Logf : gpg::Warnf)(
          "editor: lobby picture for the save%s: %s",
          mPreviewOnFirstSave ? " (the first)" : "",
          (ok ? *drawn : drawn.error()).c_str()
        );
      }
      std::string message;
      // A look being tried isn't saved: the map's own is written, then the tried one put back on the map.
      std::optional<EdDocument::LookEnvironment> tried;
      if (mLookOriginal.has_value()) {
        tried = mDocument.LookEnvironmentNow();
        mDocument.ApplyLookEnvironment(*mLookOriginal);
        gpg::Logf("editor: saving without the look being tried (%s)", mLookTriedName.c_str());
      }
      const auto result = mDocument.Save();
      const bool saved = result.has_value();
      message = saved ? *result : result.error();
      if (tried.has_value()) {
        mDocument.ApplyLookEnvironment(*tried);
      }
      if (saved) {
        mPreviewOnFirstSave = false;
        gpg::Logf("editor: %s", message.c_str());
        PostStatusMessage("Saved " + mDocument.FolderName());
        mShell->ModHost().Notify("save", mDocument.Path());
        if (!mGraphMap.empty() && mGraphMap == mDocument.Path()) {
          if (const std::filesystem::path file = mDocument.TerrainGraphFile(); !file.empty()) {
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            out << mShell->Generate().GraphText();
            (out ? gpg::Logf : gpg::Warnf)(
              "editor: the terrain graph %s %s",
              out ? "saved with the map as" : "couldn't be written to",
              file.filename().string().c_str()
            );
          }
        }
        // Saved: its autosave is behind it now.
        if (!mAutosaveRoot.empty()) {
          RemoveAutosave(mAutosaveRoot / mDocument.FolderName());
          mRecoverable = ListAutosaves(mAutosaveRoot);
        }
      } else {
        gpg::Warnf("editor: %s", message.c_str());
      }
    }

    namespace
    {
      /** The height image dialog (defined with the other file dialogs below). */
      std::filesystem::path AskHeightFile(HWND owner, bool save);
    } // namespace

    void EditorApp::DriveImagesAndMesh()
    {
      // The map's own mods (a file beside it) put into the play setup when the map opens, and the rules built with
      // them, so their units and props are in the palettes while editing (FAF Studio's per-map mods).
      if (mDocument.GetState() == EdDocument::State::Open && mModsMapSeen != mDocument.Path()) {
        mModsMapSeen = mDocument.Path();
        if (const std::filesystem::path file = mDocument.ModsFile(); !file.empty()) {
          std::ifstream in(file, std::ios::binary);
          std::vector<std::string> mods;
          for (std::string line; std::getline(in, line);) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
              line.pop_back();
            }
            if (!line.empty()) {
              mods.push_back(line);
            }
          }
          if (!mods.empty()) {
            mPlay.Setup().mods = mods;
            mPlay.PrepareRules();
            gpg::Logf("editor: the map's %zu mods are on for editing and plays", mods.size());
          }
        }
      }
      // New rules (built with other mods): the palettes are read again from them.
      if (const void* const rules = moho::RULE_PeekKept(); rules != nullptr && rules != mRulesSeen) {
        if (mRulesSeen != nullptr) {
          mShell->Tools().SetUnitTypes({});
          mShell->Tools().SetUnitInfos({});
          mShell->Tools().SetPropBlueprints({});
          gpg::Logf("editor: the rules changed (mods): units and props are listed again");
        }
        mRulesSeen = rules;
      }
      mScene.SetMeshWireShown(mShell->MeshShown());
      // The editor mods' start-up trial ends once the editor has drawn for a while with them.
      if (++mFramesUp == 120) {
        mShell->ModHost().EndTrial();
      }
      // The turned-on editor mods with sim hooks play as sim mods.
      mPlay.extraSimMods = mShell->ModHost().SimHookMods();
      // The mods' Editor.On listeners: a map opened, an undo step ended.
      if (mScene.Attached() && mDocument.Path() != mModMapSeen) {
        mModMapSeen = mDocument.Path();
        mShell->ModHost().Notify("map", mModMapSeen);
      }
      // Each undo step its own event, in order (a mod's own edits during a listener come next frame).
      for (const std::string& step : std::exchange(mModEdits, {})) {
        mShell->ModHost().Notify("edit", step);
      }
      // A mesh terrain map's patches: read when its map is up, again when asked; the view's mode; the checks.
      // `/meshmode <0|1|2>` (test runs): the mesh terrain view's mode (terrain, mesh, both) from the start.
      if (fa::vector<fa::string> mode; moho::CFG_GetArgOption("/meshmode", 1, &mode) && !mode.empty()) {
        static bool taken = false;
        if (!taken) {
          taken = true;
          mShell->mMeshMode = std::clamp(std::atoi(mode[0].c_str()), 0, 2);
        }
      }
      // `/meshwire 0` (test runs): the imported mesh's wire not drawn over the map (Mesh import's "Show over the map").
      if (fa::vector<fa::string> wire; moho::CFG_GetArgOption("/meshwire", 1, &wire) && !wire.empty()) {
        static bool taken = false;
        if (!taken) {
          taken = true;
          mShell->SetMeshShown(std::atoi(wire[0].c_str()) != 0);
        }
      }
      if (static bool cacheSet = false; !cacheSet && !EditorSettingsFolder().empty()) {
        cacheSet = true;
        mScene.SetMeshViewCache(EditorSettingsFolder() / "cache" / "meshview");
      }
      mScene.SetMeshMode(mShell->MeshMode());
      if (mScene.Attached() && mMeshLoadedFor != mDocument.Path()) {
        mMeshLoadedFor = mDocument.Path();
        mShell->SetMeshStatus(mScene.LoadMeshTerrain());
        mShell->SetMeshFindings({});
      } else if (!mScene.Attached()) {
        mMeshLoadedFor.clear();
      }
      mShell->SetMeshMapView(&mScene.MeshMapRef());
      // `/meshask <n,n,...>` (test runs): the Mesh terrain panel's buttons, one every 30 frames once the map is up
      // (1 load, 2 check, 3 save, 4 unset, 5 set, 6 sync map, 7 new from the map).
      if (
        fa::vector<fa::string> asks; mScene.Attached() && !mScene.ModelsPending() &&
        moho::CFG_GetArgOption("/meshask", 1, &asks) && !asks.empty() && ++mMeshAskFrames % 30 == 0 &&
        (mScene.MeshMapRef().Loaded() || mMeshAskFrames > 600)
      ) {
        const std::string list = asks[0].c_str();
        std::size_t at = 0;
        for (int k = 0; k < mMeshAskDone && at != std::string::npos; ++k) {
          at = list.find(',', at);
          at = at == std::string::npos ? at : at + 1;
        }
        if (at != std::string::npos && at < list.size()) {
          const int ask = std::atoi(list.c_str() + at);
          ++mMeshAskDone;
          gpg::Logf("editor: /meshask: %d", ask);
          mShell->AskMeshMore(ask);
        }
      }
      // `/meshimport2 <obj>` (test runs): a second import into the same manifest once the first mesh is in.
      if (
        fa::vector<fa::string> second; !mMeshImport2Done && mScene.MeshMapRef().Loaded() &&
        moho::CFG_GetArgOption("/meshimport2", 1, &second) && !second.empty() && [this] {
        // After every `/meshask` press, when both are given.
        fa::vector<fa::string> asks;
        if (!moho::CFG_GetArgOption("/meshask", 1, &asks) || asks.empty()) {
          return true;
        }
        const std::string list = asks[0].c_str();
        return mMeshAskDone > static_cast<int>(std::count(list.begin(), list.end(), ',')) && mMeshAskFrames % 30 == 15;
      }()
      ) {
        mMeshImport2Done = true;
        gpg::Logf("editor: /meshimport2: %s", second[0].c_str());
        mShell->AskMeshImport(second[0].c_str(), true);
      }
      if (const int more = mShell->TakeMeshMore(); more == 1) {
        mShell->SetMeshStatus(mScene.LoadMeshTerrain());
      } else if (more == 2) {
        std::vector<std::string> findings = mScene.CheckMeshTerrain();
        gpg::Logf("editor: mesh terrain check: %zu findings", findings.size());
        for (const std::string& line : findings) {
          gpg::Logf("editor: mesh terrain check: %s", line.c_str());
        }
        mShell->SetMeshFindings(std::move(findings));
      } else if (more == 3) {
        // Save: the manifest as the panel edited it, into the map's folder, then read again (Sync).
        const edmesh::MeshMap& mesh = mScene.MeshMapRef();
        const std::filesystem::path scmap = mDocument.MapDiskFile();
        if (mesh.manifestPath.empty() || scmap.empty()) {
          mShell->SetMeshStatus("No mesh terrain loaded, or the map has no folder of its own.");
        } else {
          std::string rel = mesh.manifestPath;
          const std::string prefix = "/maps/" + mDocument.FolderName() + "/";
          if (rel.starts_with(prefix)) {
            rel = rel.substr(prefix.size());
          } else {
            rel = "terrain/terrain.lua";
          }
          const std::filesystem::path file = scmap.parent_path() / rel;
          std::error_code ec;
          std::filesystem::create_directories(file.parent_path(), ec);
          std::ofstream(file, std::ios::binary | std::ios::trunc) << mesh.ManifestText();
          gpg::Logf(
            "editor: mesh terrain: manifest saved to %s (%zu materials, %zu patches)",
            file.string().c_str(),
            mesh.materials.size(),
            mesh.patches.size()
          );
          mShell->SetMeshStatus("Saved " + file.string() + "; " + mScene.LoadMeshTerrain());
        }
      } else if (more == 4) {
        // Unset: the scenario no longer names a mesh terrain (the height field is the ground again).
        (void)mDocument.SetScenarioField("TerrainSystem", "heightfield", true);
        mShell->SetMeshStatus(mScene.SetMeshInScenario(false));
      } else if (more == 5) {
        // FAF Studio's toggle writes the scenario only: the panel's manifest (its unsaved edits, or a new one) is what
        // the view draws; with none held, the folder's terrain.lua is read.
        const std::string manifest = "/maps/" + mDocument.FolderName() + "/terrain/terrain.lua";
        (void)mDocument.SetScenarioField("TerrainSystem", "mesh", true);
        (void)mDocument.SetScenarioField("TerrainMesh", manifest, true);
        mShell->SetMeshStatus(
          mScene.MeshMapRef().manifestPath.empty() ? "The scenario names " + manifest + "; " + mScene.LoadMeshTerrain()
                                                   : mScene.SetMeshInScenario(true)
        );
      } else if (more == 6 || more == 7) {
        mShell->SetMeshStatus(mScene.SyncMeshFromMap(more == 7));
      }
      const HWND owner = HandleOf(mGame.supcomFrame);
      ImagesPanelThumbs();
      for (EdShell::ImageAsk ask; mShell->TakeImageAsk(ask);) {
        if (!mScene.Attached()) {
          break;
        }
        std::string message;
        const auto waterExport = [&](const int kind, const std::filesystem::path& file) {
          int width = 0;
          int height = 0;
          const std::uint8_t* const cells = mDocument.WaterMaskCells(static_cast<WaterMask>(kind), width, height);
          if (cells == nullptr) {
            message = "the map has no water masks";
            return false;
          }
          HeightImage image;
          image.width = width;
          image.height = height;
          for (int i = 0; i < width * height; ++i) {
            image.words.push_back(static_cast<std::uint16_t>(cells[i] * 257));
          }
          const auto wrote = WriteHeightImage(file, image);
          message = wrote ? "written to " + file.string() : wrote.error();
          return wrote.has_value();
        };
        const auto waterImport = [&](const int kind, const std::filesystem::path& file) {
          int width = 0;
          int height = 0;
          std::uint8_t* const cells = mDocument.WaterMaskCells(static_cast<WaterMask>(kind), width, height);
          if (cells == nullptr) {
            message = "the map has no water masks";
            return false;
          }
          const auto read = ReadHeightImage(file, width, height);
          if (!read) {
            message = read.error();
            return false;
          }
          const HeightImage image = ResampleHeights(*read, width, height);
          EdDocument::WaterMaskSnapshot before = mDocument.WaterMasksNow();
          for (int i = 0; i < width * height; ++i) {
            cells[i] = static_cast<std::uint8_t>(image.words[static_cast<std::size_t>(i)] >> 8);
          }
          mDocument.WaterMasksChanged(0, 0, width, height);
          mDocument.WaterMasksEdited(std::move(before));
          message = "read from " + file.string() + " (one undo step)";
          return true;
        };
        const auto one = [&](const std::string& what, const bool exportIt, const std::filesystem::path& file) {
          if (what == "heights") {
            const auto done = exportIt ? mScene.ExportHeights(file, 0, 1.0f) : mScene.ImportHeights(file, 1.0f);
            message = done ? *done : done.error();
            return done.has_value();
          }
          if (what == "preview") {
            const auto exported = mDocument.ExportPreview(file);
            message = exported ? *exported : exported.error();
            return exported.has_value();
          }
          if (what.starts_with("mask")) {
            const int layer = std::clamp(std::atoi(what.c_str() + 4), 1, 8) - 1;
            const auto done = exportIt ? mScene.ExportMaskLayer(layer, file) : mScene.ImportMaskLayer(layer, file);
            message = done ? *done : done.error();
            return done.has_value();
          }
          if (what.starts_with("water")) {
            const int kind = std::clamp(std::atoi(what.c_str() + 5), 0, 2);
            return exportIt ? waterExport(kind, file) : waterImport(kind, file);
          }
          if (what == "types") {
            // The terrain types: each cell's id as its grey (id x 257); an import must have the map's size (types
            // can't be blended).
            int width = 0;
            int height = 0;
            if (mDocument.TerrainTypeCells(width, height) == nullptr) {
              message = "the map has no terrain types";
              return false;
            }
            std::vector<std::uint8_t> cells = mDocument.TerrainTypesNow();
            if (exportIt) {
              HeightImage image;
              image.width = width;
              image.height = height;
              for (const std::uint8_t id : cells) {
                image.words.push_back(static_cast<std::uint16_t>(id * 257));
              }
              const auto wrote = WriteHeightImage(file, image);
              message = wrote ? "written to " + file.string() : wrote.error();
              return wrote.has_value();
            }
            const auto read = ReadHeightImage(file, 0, 0);
            if (!read) {
              message = read.error();
              return false;
            }
            const HeightImage& image = *read;
            if (image.width != width || image.height != height) {
              message = "the terrain types are " + std::to_string(width) + " x " + std::to_string(height) +
                "; the image is " + std::to_string(image.width) + " x " + std::to_string(image.height);
              return false;
            }
            const std::vector<std::uint8_t> before = cells;
            for (std::size_t i = 0; i < cells.size() && i < image.words.size(); ++i) {
              cells[i] = static_cast<std::uint8_t>((image.words[i] + 128) / 257);
            }
            mDocument.ApplyTerrainTypes(cells);
            mDocument.TerrainTypesEdited(before);
            message = "read from " + file.string() + " (one undo step)";
            return true;
          }
          message = "nothing called " + what;
          return false;
        };
        if (ask.what == "all") {
          const std::filesystem::path map = mDocument.MapDiskFile();
          if (map.empty()) {
            mShell->SetImageStatus("The map has no folder of its own (save it as a new map first).");
            continue;
          }
          const std::filesystem::path folder = map.parent_path() / "images";
          std::error_code made;
          std::filesystem::create_directories(folder, made);
          int written = 0;
          std::vector<std::pair<std::string, std::string>> all = {
            {"heights", "heights.png"}, {"preview", "preview.png"}, {"types", "terrain_types.png"}
          };
          for (int layer = 1; layer <= 8; ++layer) {
            all.emplace_back("mask" + std::to_string(layer), "mask" + std::to_string(layer) + ".png");
          }
          all.emplace_back("water0", "water_foam.png");
          all.emplace_back("water1", "water_flatness.png");
          all.emplace_back("water2", "water_depthbias.png");
          for (const auto& [what, name] : all) {
            written += one(what, true, folder / name) ? 1 : 0;
          }
          const std::string status =
            std::to_string(written) + " of " + std::to_string(all.size()) + " pictures written to " + folder.string();
          mShell->SetImageStatus(status);
          gpg::Logf("editor: images: %s", status.c_str());
          continue;
        }
        const std::filesystem::path file = AskHeightFile(owner, ask.exportIt);
        if (file.empty()) {
          continue;
        }
        const bool ok = one(ask.what, ask.exportIt, file);
        mShell->SetImageStatus(ask.what + ": " + message);
        (ok ? gpg::Logf : gpg::Warnf)("editor: images: %s: %s", ask.what.c_str(), message.c_str());
      }
      // The Detail pass panel: plan, run (one undo step) or measure; its environment defaults to the map's guess.
      if (mDocument.Map() != nullptr && mScene.Attached()) {
        mShell->SetDetailEnvironment(mScene.DetailEnvironmentGuess());
        DetailRun run;
        if (const int ask = mShell->TakeDetailAsk(run); ask != 0) {
          const std::vector<std::string>& off = mShell->DetailClassesOff();
          if (!off.empty()) {
            for (const char* id : {"small", "stones", "big", "crack", "ground", "cliff"}) {
              if (std::find(off.begin(), off.end(), id) == off.end()) {
                run.only.emplace_back(id);
              }
            }
          }
          mShell->SetDetailText(
            ask == 1     ? mScene.PlanDetailPass(run)
              : ask == 2 ? mScene.RunDetailPass(run)
                         : mScene.MeasureDetailPass()
          );
        }
      } else {
        mShell->ResetDetailEnvironment();
      }
      for (EdShell::MeshAsk ask; mShell->TakeMeshAsk(ask);) {
        std::string text;
        {
          std::ifstream in(ask.file, std::ios::binary);
          text.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }
        const auto mesh = text.empty() ? std::expected<ObjMesh, std::string>(std::unexpect) : ParseObj(text);
        if (!mesh) {
          mShell->SetMeshStatus("Couldn't read " + ask.file + (mesh.error().empty() ? "" : ": " + mesh.error()));
          continue;
        }
        const ObjMesh placed = TransformMesh(*mesh, ask.options);
        const std::filesystem::path map = mDocument.MapDiskFile();
        std::size_t tiles = 0;
        std::size_t failed = 0;
        if (!map.empty()) {
          // Into the mesh terrain map's manifest (FAF Studio's meshimport Commit): the one the Mesh terrain panel
          // holds, else a new one from the map; its settings, materials and sky patches stay, the new patches get free
          // names and go before the sky patches, Replace drops the ground patches first (their files stay on disk).
          const std::filesystem::path folder = map.parent_path() / "terrain";
          std::error_code made;
          std::filesystem::create_directories(folder, made);
          if (mScene.MeshMapRef().manifestPath.empty()) {
            // The map's own manifest first (the scenario's, else the folder's terrain/terrain.lua), a new one only
            // when it has none: an import never writes over a manifest it didn't read.
            (void)mScene.LoadMeshTerrain();
          }
          if (
            const edmesh::MeshMap& had = mScene.MeshMapRef();
            had.manifestPath.empty() || (had.patches.empty() && had.materials.empty() && had.settings.given.empty())
          ) {
            (void)mScene.SyncMeshFromMap(true); // nothing read: a new manifest from the map
          }
          const edmesh::MeshMap& model = mScene.MeshMapRef();
          edmesh::MeshMap next;
          next.settings = model.settings;
          next.materials = model.materials;
          for (const edmesh::Patch& patch : model.patches) {
            if (ask.options.replace && !patch.sky) {
              continue;
            }
            edmesh::Patch entry;
            entry.file = patch.file;
            entry.material = patch.material;
            entry.sky = patch.sky;
            entry.boundsMax[1] = patch.boundsMax[1];
            next.patches.push_back(std::move(entry));
          }
          std::set<std::string> taken;
          int section = 0;
          float meshHigh = -10000.0f;
          for (const edmesh::Patch& patch : next.patches) {
            std::string name = patch.file;
            std::transform(name.begin(), name.end(), name.begin(), [](const unsigned char c) {
              return static_cast<char>(std::tolower(c));
            });
            taken.insert(name);
            if (int n = 0; std::sscanf(name.c_str(), "section%d_", &n) == 1) {
              section = std::max(section, n + 1);
            }
            if (!patch.sky) {
              meshHigh = std::max(meshHigh, patch.boundsMax[1]);
            }
          }
          std::size_t at = next.patches.size();
          for (std::size_t i = 0; i < next.patches.size(); ++i) {
            if (next.patches[i].sky) {
              at = i;
              break;
            }
          }
          const float size = next.settings.size > 0.0f
            ? next.settings.size
            : static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ));
          for (auto& [materialName, part] : SplitByMaterial(placed, ask.options.materialsBy)) {
            int material = -1;
            for (std::size_t m = 0; m < next.materials.size(); ++m) {
              if (next.materials[m].name == materialName) {
                material = static_cast<int>(m);
              }
            }
            if (material < 0) {
              edmesh::Material fresh;
              fresh.name = materialName;
              next.materials.push_back(fresh);
              material = static_cast<int>(next.materials.size()) - 1;
            }
            int serial = 0;
            for (auto& [key, piece] : SplitMesh(part, ask.options)) {
              (void)key;
              piece.uv2Size = ask.options.lightMaskUv == 0 ? size : 0.0f;
              char name[64];
              (void)std::snprintf(name, sizeof(name), "section%02d_%03d.scm", section, serial++);
              const auto made = ScmFromObj(piece, "tile", 1.0f, "FAF map editor mesh terrain");
              if (!made) {
                ++failed;
                continue;
              }
              const std::vector<std::uint8_t>& scm = *made;
              std::ofstream out(folder / name, std::ios::binary | std::ios::trunc);
              out.write(reinterpret_cast<const char*>(scm.data()), static_cast<std::streamsize>(scm.size()));
              for (const auto& triangle : piece.triangles) {
                for (const ObjMesh::Corner& c : triangle) {
                  meshHigh = std::max(meshHigh, piece.positions[static_cast<std::size_t>(c.position)][1]);
                }
              }
              edmesh::Patch entry;
              entry.file = name;
              entry.material = material;
              next.patches.insert(next.patches.begin() + static_cast<std::ptrdiff_t>(at++), std::move(entry));
              ++tiles;
            }
            ++section;
          }
          if (meshHigh > -9999.0f) {
            next.settings.meshHigh = meshHigh + kMeshHighMargin;
            next.settings.given.insert("mesh_high");
          }
          {
            std::ofstream manifest(folder / "terrain.lua", std::ios::binary | std::ios::trunc);
            manifest << next.ManifestText();
          }
          gpg::Logf(
            "editor: mesh terrain import: %zu patches in the manifest (%s), %zu materials",
            next.patches.size(),
            ask.options.replace ? "the ground patches replaced" : "added to the ones there",
            next.materials.size()
          );
          // A mesh terrain map: its scenario names the manifest (TerrainSystem = 'mesh', TerrainMesh), one undo step.
          if (ask.makeMeshMap) {
            const std::string manifest = "/maps/" + mDocument.FolderName() + "/terrain/terrain.lua";
            (void)mDocument.SetScenarioField("TerrainSystem", "mesh", true);
            (void)mDocument.SetScenarioField("TerrainMesh", manifest, true);
          }
          mShell->SetMeshStatus(mScene.LoadMeshTerrain());
        }
        mScene.SetMeshWire(MeshWire(placed, 200000));
        const std::string status = std::to_string(placed.triangles.size()) + " triangles, " + std::to_string(tiles) +
          " tiles written to the map's mesh folder" + (failed > 0 ? " (" + std::to_string(failed) + " too big)" : "") +
          (map.empty() ? " (no map folder: shown only)" : "");
        mShell->SetMeshStatus(status);
        gpg::Logf("editor: mesh terrain: %s", status.c_str());
      }
      // `/meshtest`: once the import is in, the checks and where props would stand.
      if (mMeshTestFrames > 0 && ++mMeshTestFrames == 30) {
        mMeshTestFrames = 0;
        gpg::Logf(
          "editor: /meshtest: the scenario %s TerrainSystem = 'mesh'",
          mDocument.Scenario().contains("TerrainSystem = 'mesh'") ||
              mDocument.Scenario().contains("TerrainSystem = \"mesh\"")
            ? "says"
            : "doesn't say"
        );
        gpg::Logf("editor: /meshtest: load: %s", mScene.LoadMeshTerrain().c_str());
        const std::vector<std::string> findings = mScene.CheckMeshTerrain();
        gpg::Logf("editor: /meshtest: %zu mesh check findings", findings.size());
        for (std::size_t i = 0; i < findings.size() && i < 8; ++i) {
          gpg::Logf("editor: /meshtest:   %s", findings[i].c_str());
        }
        const float w = static_cast<float>(std::max(mDocument.Facts().fieldWidth - 1, 1));
        for (const float f : {0.25f, 0.5f, 0.75f}) {
          gpg::Logf(
            "editor: /meshtest: at %.0f, %.0f a prop stands at %.2f (the height field there: %.2f)",
            static_cast<double>(w * f),
            static_cast<double>(w * f),
            static_cast<double>(mScene.PlacementHeight(w * f, w * f)),
            static_cast<double>(mScene.GroundHeightAt(w * f, w * f))
          );
        }
      }
    }

    void EditorApp::DrawOverwriteAsk()
    {
      constexpr const char* kTitle = "Write over the map there?";
      if (mAskOverwrite) {
        mAskOverwrite = false;
        ImGui::OpenPopup(kTitle);
      }
      const ImGuiViewport* const viewport = ImGui::GetMainViewport();
      ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
      if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
      }
      ImGui::TextUnformatted("This map isn't in your vault's maps folder:");
      ImGui::TextDisabled("%s", mDocument.MapDiskFile().parent_path().string().c_str());
      ImGui::TextUnformatted("Saving writes over its files there (they are backed up first).");
      if (ImGui::Button("Write over it", ImVec2(Em(140.0f), 0.0f))) {
        mDocument.AllowOverwrite();
        gpg::Logf(
          "editor: save: writing over %s (outside the vault) as asked", mDocument.MapDiskFile().string().c_str()
        );
        ImGui::CloseCurrentPopup();
        SaveDocument();
      }
      ImGui::SameLine();
      if (ImGui::Button("Save as...", ImVec2(Em(140.0f), 0.0f))) {
        ImGui::CloseCurrentPopup();
        (void)mCommands.Run("file.saveas");
      }
      ImGui::SameLine();
      if (ImGui::Button("Cancel", ImVec2(Em(140.0f), 0.0f)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        ImGui::CloseCurrentPopup();
      }
      ImGui::EndPopup();
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
      // The heights: written, read, resized, written again for the new map to read.
      const auto exported = mScene.ExportHeights(r.dir / "heights_old.png", 0, 1.0f);
      if (!exported) {
        fail("the heights couldn't be read: " + exported.error());
        return;
      }
      const auto image = ReadHeightImage(r.dir / "heights_old.png", 0, 0);
      if (!image) {
        fail("the heights couldn't be read: " + *exported + image.error());
        return;
      }
      const auto pad = static_cast<std::uint16_t>(std::clamp(std::lround(o.padLevel * 128.0f), 0L, 65535L));
      const HeightImage heights = ResizeImage(*image, r.geometry, o.newWidth + 1, o.newDepth + 1, o.padEdge, pad);
      if (const auto wrote = WriteHeightImage(r.dir / "heights.png", heights); !wrote) {
        fail("the heights couldn't be written: " + wrote.error());
        return;
      }
      // The eight strata's masks alike (the mask grid at its own scale, padded with the edge or nothing).
      for (int layer = 0; layer < 8; ++layer) {
        const std::filesystem::path old = r.dir / ("mask" + std::to_string(layer) + "_old.png");
        if (!mScene.ExportMaskLayer(layer, old)) {
          continue; // (a map without masks yet)
        }
        const auto mask = ReadHeightImage(old, 0, 0);
        if (!mask) {
          continue;
        }
        r.maskWidth =
          std::max(2, static_cast<int>(std::lround(static_cast<double>(mask->width) * o.newWidth / o.oldWidth)));
        r.maskHeight =
          std::max(2, static_cast<int>(std::lround(static_cast<double>(mask->height) * o.newDepth / o.oldDepth)));
        const HeightImage resized = ResizeImage(*mask, r.geometry, r.maskWidth, r.maskHeight, o.padEdge, 0);
        (void)WriteHeightImage(r.dir / ("mask" + std::to_string(layer) + ".png"), resized);
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
      auto save = ResizeSaveText(mDocument.SaveData().Text(), r.geometry, r.report);
      if (!save || save->empty()) {
        fail("the save file couldn't be read: " + (save ? std::string() : save.error()));
        return;
      }
      r.save = std::move(*save);
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
      if (const auto created = mDocument.CreateNew(settings); !created) {
        fail(created.error());
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

    std::expected<std::string, std::string> EditorApp::RegeneratePreview()
    {
      std::vector<std::uint32_t> pixels;
      float width = 0.0f;
      float depth = 0.0f;
      std::size_t dots = 0;
      if (std::string message; !PaintPreview(kPreviewSide, pixels, width, depth, dots, message)) {
        return std::unexpected(message);
      }
      mDocument.SetPreviewRecord(PreviewRecord(width, depth, pixels));
      return "Drew the lobby preview anew (" + std::to_string(dots) +
        " start positions and resources on it, the ground in its layers' colours under the map's sun); saving the map "
        "writes it";
    }

    std::array<std::array<float, 3>, 9> EditorApp::LayerColours()
    {
      // Each layer's albedo texture's average colour (8 x 8 decoded), base first: what the preview paints with.
      std::array<std::array<float, 3>, 9> out{};
      const std::vector<LayerSettings> layers = mScene.LayerSettingsNow();
      gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
      for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = {128.0f, 128.0f, 128.0f};
        std::string bytes;
        if (
          codec == nullptr || i >= layers.size() || layers[i].albedo.empty() || !ReadGameFile(layers[i].albedo, bytes)
        ) {
          continue;
        }
        gpg::gal::imaging::DecodeOptions options;
        options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
        options.width = 8;
        options.height = 8;
        options.mipLevels = 1;
        gpg::gal::imaging::Image image;
        if (
          FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) || image.subresources.empty() ||
          image.format != DXGI_FORMAT_B8G8R8A8_UNORM
        ) {
          continue;
        }
        const auto& level = image.subresources.front();
        double sum[3] = {0.0, 0.0, 0.0};
        std::size_t n = 0;
        for (std::uint32_t y = 0; y < level.height; ++y) {
          const auto* row =
            reinterpret_cast<const std::uint8_t*>(image.bytes.data()) + level.offset + y * level.rowPitch;
          for (std::uint32_t x = 0; x < level.width; ++x, ++n) {
            sum[0] += row[x * 4 + 2];
            sum[1] += row[x * 4 + 1];
            sum[2] += row[x * 4 + 0];
          }
        }
        if (n > 0) {
          out[i] = {static_cast<float>(sum[0] / n), static_cast<float>(sum[1] / n), static_cast<float>(sum[2] / n)};
        }
      }
      return out;
    }

    bool EditorApp::PaintPreview(
      const int side,
      std::vector<std::uint32_t>& pixels,
      float& width,
      float& depth,
      std::size_t& dotCount,
      std::string& message,
      const LightingState* const lighting,
      PreviewGround* const ground
    )
    {
      if (mDocument.GetState() != EdDocument::State::Open || !mScene.Attached()) {
        message = "Open a map first.";
        return false;
      }
      PreviewGround fresh;
      PreviewGround& use = ground != nullptr ? *ground : fresh;
      if (!use.ready) {
        std::error_code ec;
        const std::filesystem::path dir = std::filesystem::temp_directory_path(ec) / "FafEditor";
        std::filesystem::create_directories(dir, ec);
        const std::filesystem::path file = dir / "preview_heights.png";
        const auto exported = mScene.ExportHeights(file, 0, 1.0f);
        if (!exported) {
          message = "The preview needs the heights: " + exported.error();
          return false;
        }
        message = *exported;
        auto read = ReadHeightImage(file, 0, 0);
        if (!read) {
          message = "The preview needs the heights: " + message + read.error();
          return false;
        }
        use.heights = std::move(*read);
        use.colours = LayerColours();
        use.ready = true;
      }
      const HeightImage& heights = use.heights;
      PreviewOptions options;
      const EdDocument::LookEnvironment look = mDocument.LookEnvironmentNow();
      options.water = look.water.enabled;
      options.waterLevel = look.water.elevation;
      // Resources first, start positions on top (as the lobby draws them). The dots are pixels wide, so a look's small
      // picture (under 128 px) leaves them out: they'd cover the ground it shows.
      for (int pass = 0; pass < (side >= 128 ? 2 : 0); ++pass) {
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          float x = 0.0f;
          float y = 0.0f;
          float z = 0.0f;
          if (!MarkerPosition(marker, x, y, z)) {
            continue;
          }
          const std::string type = MarkerTypeOf(marker);
          const bool start = marker.name.starts_with("ARMY_");
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
      width = static_cast<float>(facts.sizeX > 0 ? facts.sizeX : heights.width - 1);
      depth = static_cast<float>(facts.sizeZ > 0 ? facts.sizeZ : heights.height - 1);
      // FAF Studio's preview.lua: the ground in its texture layers' colours (base, then layers 1..8 by their paint),
      // lit by the map's sun and ambience.
      options.side = side;
      const std::array<std::array<float, 3>, 9>& colours = use.colours;
      options.groundColour = [this, &colours](const float x, const float z, float (&rgb)[3]) {
        for (int i = 0; i < 3; ++i) {
          rgb[i] = colours[0][static_cast<std::size_t>(i)];
        }
        for (int layer = 1; layer <= 8; ++layer) {
          const float w = mScene.LayerWeightAt(layer, x, z);
          if (w > 0.0f) {
            for (int i = 0; i < 3; ++i) {
              rgb[i] +=
                (colours[static_cast<std::size_t>(layer)][static_cast<std::size_t>(i)] - rgb[i]) * std::min(w, 1.0f);
            }
          }
        }
        return true;
      };
      const LightingState light = lighting != nullptr ? *lighting : mDocument.LightingNow();
      options.sun = true;
      for (int i = 0; i < 3; ++i) {
        options.sunDirection[i] = light.sunDirection[i];
        options.sunColour[i] = light.sunColor[i];
        options.ambient[i] = light.sunAmbience[i];
      }
      options.multiplier = light.multiplier;
      pixels = PreviewPixels(heights, width, depth, options);
      dotCount = options.dots.size();
      return true;
    }

    std::expected<std::string, std::string> EditorApp::ExportPaintedPreview(
      const std::filesystem::path& file,
      const int side
    )
    {
      std::vector<std::uint32_t> pixels;
      float width = 0.0f;
      float depth = 0.0f;
      std::size_t dots = 0;
      if (std::string message; !PaintPreview(side, pixels, width, depth, dots, message)) {
        return std::unexpected(message);
      }
      if (const auto wrote = WriteColourPng(file, side, side, pixels); !wrote) {
        return std::unexpected(wrote.error());
      }
      return "Exported the lobby preview painted at " + std::to_string(side) + " x " + std::to_string(side) + " to " +
        file.filename().string();
    }

    void EditorApp::RunConsoleLine(
      const std::string& line
    )
    {
      gpg::Logf("> %s", line.c_str());
      if (line.starts_with("sim ")) {
        if (!mPlay.Active()) {
          gpg::Warnf("editor: sim: no game is running (Play first)");
          return;
        }
        moho::CON_Execute(("SimLua " + line.substr(4)).c_str());
        return;
      }
      if (line.starts_with("con ")) {
        moho::CON_Execute(line.substr(4).c_str());
        return;
      }
      LuaPlus::LuaState* const state = moho::USER_GetLuaState();
      lua_State* const L = state != nullptr ? state->GetCState() : nullptr;
      if (L == nullptr) {
        gpg::Warnf("editor: the interface's Lua isn't running yet");
        return;
      }
      const bool print = !line.empty() && line.front() == '=';
      const std::string chunk = print ? "return " + line.substr(1) : line;
      const int top = lua_gettop(L);
      if (luaL_loadbuffer(L, chunk.data(), chunk.size(), "=console") != 0) {
        gpg::Warnf("%s", lua_tostring(L, -1) != nullptr ? lua_tostring(L, -1) : "can't read it");
      } else if (LuaCallProtected(L, 0, print ? 1 : 0) != 0) {
        gpg::Warnf("%s", lua_tostring(L, -1) != nullptr ? lua_tostring(L, -1) : "error");
      } else if (print) {
        const int type = lua_type(L, -1);
        if (type == LUA_TSTRING || type == LUA_TNUMBER) {
          gpg::Logf("= %s", lua_tostring(L, -1));
        } else if (type == LUA_TBOOLEAN) {
          gpg::Logf("= %s", lua_toboolean(L, -1) != 0 ? "true" : "false");
        } else {
          gpg::Logf("= (%s)", lua_typename(L, type));
        }
      }
      lua_settop(L, top);
    }

    void EditorApp::FinishResize()
    {
      PendingResize& r = *mResize;
      if (const auto imported = mScene.ImportHeights(r.dir / "heights.png", 1.0f); !imported) {
        gpg::Warnf("editor: resize: %s", imported.error().c_str());
      }
      for (int layer = 0; layer < 8; ++layer) {
        const std::filesystem::path mask = r.dir / ("mask" + std::to_string(layer) + ".png");
        std::error_code ec;
        if (!std::filesystem::exists(mask, ec)) {
          continue;
        }
        if (const auto imported = mScene.ImportMaskLayer(layer, mask); !imported) {
          gpg::Warnf("editor: resize: %s", imported.error().c_str());
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
      if (const auto drawn = RegeneratePreview(); !drawn) {
        gpg::Warnf("editor: resize: %s", drawn.error().c_str());
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
        if (gNoFileDialogs) {
          gpg::Logf("editor: a file dialog wasn't opened (a QA run is pressing buttons)");
          return {};
        }
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
        if (gNoFileDialogs) {
          gpg::Logf("editor: a file dialog wasn't opened (a QA run is pressing buttons)");
          return {};
        }
        wchar_t path[MAX_PATH] = L"";
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = owner;
        dialog.lpstrFile = path;
        dialog.nMaxFile = MAX_PATH;
        if (save) {
          dialog.lpstrFilter = L"16-bit grey PNG (*.png)\0*.png\0TIFF (*.tif)\0*.tif\0Raw 16-bit (*.raw)\0*.raw\0"
                               L"World Machine (*.r16)\0*.r16\0Floats (*.r32)\0*.r32\0";
          dialog.lpstrDefExt = L"png";
          dialog.lpstrTitle = L"Export the height field";
          dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
          return ::GetSaveFileNameW(&dialog) != FALSE ? std::filesystem::path(path) : std::filesystem::path{};
        }
        dialog.lpstrFilter =
          L"Height images "
          L"(*.png;*.raw;*.r16;*.r32;*.bmp;*.tif;*.tiff)\0*.png;*.raw;*.r16;*.r32;*.bmp;*.tif;*.tiff\0All "
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
            if (name.starts_with("<LOC")) {
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
        tools.SetMapFolder("/maps/" + mDocument.FolderName());
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
        WaterMasksUpdate();
        PackageUpdate();
        MaskImportUpdate();
        DriveRoundSixTest();
        DriveRoundSevenTest();
        DriveRoundEightTest();
        DriveRoundNineTest();
        DriveRoundTenTest();
        DriveRoundElevenTest();
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
          const EdMapScene::ContextPoint& here = mScene.ContextPointNow();
          EdShell::ViewMenuPoint point;
          point.valid = here.valid;
          point.x = here.x;
          point.z = here.z;
          point.height = here.height;
          point.what = here.what;
          point.marker = here.marker;
          point.markerType = here.markerType;
          point.unitArmy = here.unitArmy;
          point.unitName = here.unitName;
          point.armies = mDocument.Armies();
          if (!here.unitArmy.empty()) {
            point.groups = mScene.GroupPathsOf(here.unitArmy);
          }
          point.unitToPlace = mShell->Tools().UnitType();
          point.propToPlace = mShell->Tools().PropBlueprint();
          gpg::Logf(
            "editor: view menu at %.1f, %.1f (height %.2f)%s%s",
            static_cast<double>(point.x),
            static_cast<double>(point.z),
            static_cast<double>(point.height),
            point.what.empty() ? "" : ": ",
            point.what.c_str()
          );
          mShell->OpenViewMenu(selection || !here.what.empty(), std::move(point));
        }
        // Bases > Define from area: the base's marker at the area's middle, the army's units there into its group.
        if (EdMissionPanel::DefineBaseAsk ask; mScene.Attached() && mShell->MissionPanel().TakeDefineBaseAsk(ask)) {
          const std::string marker = ask.name + "_Marker";
          std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
          if (std::none_of(markers.begin(), markers.end(), [&](const SaveEntry& e) {
            return e.name == marker;
          })) {
            EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
            markers.push_back(
              NewMarker(*FindMarkerType("Blank Marker"), marker, ask.x, mScene.GroundHeightAt(ask.x, ask.z), ask.z)
            );
            mDocument.SaveDataEdited(std::move(before));
          }
          const bool grouped = !ask.units.empty() && mScene.MoveUnitsToGroup(ask.army, ask.units, {ask.name});
          gpg::Logf(
            "editor: base %s defined at %.1f, %.1f: marker %s, %zu of %s's units into its group%s",
            ask.name.c_str(),
            static_cast<double>(ask.x),
            static_cast<double>(ask.z),
            marker.c_str(),
            ask.units.size(),
            ask.army.c_str(),
            grouped || ask.units.empty() ? "" : " (not moved)"
          );
        }
        // The view menu's entries that act at its point (place, focus, snap, give, group).
        if (EdShell::ViewMenuPoint at; mScene.Attached()) {
          EdShell::ViewMenuAction action;
          if (mShell->TakeViewMenuAction(at, action)) {
            RunViewMenuAction(at, action);
          }
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
            tools.AskAirGrid(std::atoi(text.c_str()), !text.contains("keep"));
          }
        }
        if (int count = 0; true) {
          bool replace = true;
          if (tools.TakeAirGrid(count, replace)) {
            mScene.FillPathGrid(tools.PathGridKind(), count, replace);
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
            if (mDocument.Adaptive()) {
              (void)ParseAdaptiveTables(mDocument.TablesText(), tables);
            }
            const std::vector<ScenarioTeam> teams = mDocument.Teams();
            const int slots = teams.empty() ? 1 : static_cast<int>(teams.front().armies.size());
            tables.maxPlayers = mDocument.Adaptive() ? std::max(tables.maxPlayers, slots) : slots;
            std::vector<std::vector<std::string>>& byArmy =
              marker.starts_with("Hydrocarbon") ? tables.hydroArmy : tables.mexArmy;
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
            asked.what = text.starts_with("position") ? PropertyEdit::What::Position
              : text.starts_with("heading")           ? PropertyEdit::What::Heading
              : text.starts_with("size")              ? PropertyEdit::What::Size
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
                if (name.size() > 8 && name.ends_with("_prop.bp")) {
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
          // `/checksettings <base radius>,<blocked share>,<unit class>,<validators>,<symmetry>,<paths>` (test runs):
          // the Check's settings before `/check` runs it.
          if (fa::vector<fa::string> spec; moho::CFG_GetArgOption("/checksettings", 1, &spec) && !spec.empty()) {
            TerrainCheckSettings settings;
            int unitClass = 2, validators = 1, symmetry = 1, paths = 1;
            (void)std::sscanf(
              spec[0].c_str(),
              "%f,%f,%d,%d,%d,%d",
              &settings.startRadius,
              &settings.blockedShare,
              &unitClass,
              &validators,
              &symmetry,
              &paths
            );
            mShell->SetCheckSettings(settings, unitClass, validators != 0, symmetry != 0, paths != 0);
            gpg::Logf(
              "editor: check settings: base radius %.0f, blocked share %.2f, unit class %d, validators %d, symmetry "
              "%d, "
              "paths %d",
              static_cast<double>(settings.startRadius),
              static_cast<double>(settings.blockedShare),
              unitClass,
              validators,
              symmetry,
              paths
            );
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
            const auto packaged = mDocument.WritePackage(plan, written);
            const bool ok = packaged.has_value();
            (ok ? gpg::Logf : gpg::Warnf)("editor: %s", (ok ? *packaged : packaged.error()).c_str());
          }
          if (fa::vector<fa::string> layer; moho::CFG_GetArgOption("/pathing", 1, &layer)) {
            mShell->Tools().ShowPathing() = true;
            const std::string layerName = !layer.empty() ? std::string(layer[0].c_str()) : std::string();
            mShell->Tools().PathingLayer() = layerName == "ships" ? 1
              : layerName == "hover"                              ? 2
              : layerName == "amphibious"                         ? 3
                                                                  : 0;
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
              if (std::string(map->mProps->mEntries[i].mBlueprintPath.c_str()).contains(wanted)) {
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
            if (mScene.ConvertLayers(shader, options, report) && options.textures) {
              ConvertTextures(shader, report);
            }
            tools.SetConversionReport(std::move(report));
          }
        }
        // `/convertlayers <shader>[,move|merge|drop][,undo]` (test runs): a conversion, logged; with undo, Undo and
        // Redo checked against the masks and shader before and after.
        if (!mConvertLayersArg.empty() && mScene.Attached() && ++mConvertLayersFrames == 140) {
          const std::string arg = std::exchange(mConvertLayersArg, {});
          const std::string shader = arg.substr(0, arg.find(','));
          LayerConvertOptions options;
          options.lost = arg.contains(",merge") ? LostLayers::Merge
            : arg.contains(",drop")             ? LostLayers::Drop
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
          options.textures = arg.contains(",textures");
          const bool converted = mScene.ConvertLayers(shader, options, report);
          const std::uint64_t after = hash();
          if (converted && options.textures) {
            ConvertTextures(shader, report);
            for (const std::string& line : report) {
              gpg::Logf("editor: convert test: %s", line.c_str());
            }
          }
          gpg::Logf(
            "editor: convert test: %s -> %s %s, masks %016llx -> %016llx",
            shaderBefore.c_str(),
            shader.c_str(),
            converted ? "converted" : "refused",
            static_cast<unsigned long long>(before),
            static_cast<unsigned long long>(after)
          );
          if (converted && arg.contains(",undo")) {
            // With textures the atlas or the alpha copies are a step of their own after the conversion's.
            const int steps = options.textures ? 2 : 1;
            bool undone = true;
            for (int i = 0; i < steps; ++i) {
              undone = mScene.Undo() && undone;
            }
            const bool backAgain = hash() == before && mScene.TerrainShader() == shaderBefore;
            bool redone = true;
            for (int i = 0; i < steps; ++i) {
              redone = mScene.Redo() && redone;
            }
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
          const auto cleared = mScene.ClearMaskLayer(tools.MaskLayer());
          report(cleared.has_value(), cleared ? *cleared : cleared.error());
          break;
        }
        case EdTools::MaskOp::Fill: {
          const auto filled = mScene.FillMaskLayer(tools.MaskLayer());
          report(filled.has_value(), filled ? *filled : filled.error());
          break;
        }
        case EdTools::MaskOp::Import:
          if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), false); !file.empty()) {
            const auto imported = mScene.ImportMaskLayer(tools.MaskLayer(), file);
            report(imported.has_value(), imported ? *imported : imported.error());
          }
          break;
        case EdTools::MaskOp::Export:
          if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), true); !file.empty()) {
            const auto exported = mScene.ExportMaskLayer(tools.MaskLayer(), file);
            report(exported.has_value(), exported ? *exported : exported.error());
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
      // `/flattentest <height>` (test runs): Flatten map to that height, its range logged, then undone.
      if (!mFlattenTestDone && mScene.Attached() && ++mFlattenTestFrames == 120) {
        mFlattenTestDone = true;
        if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/flattentest", 1, &value) && !value.empty()) {
          float low = 0.0f, high = 0.0f, mean = 0.0f;
          (void)mScene.HeightRange(low, high, mean);
          gpg::Logf("editor: flatten test: before %.2f .. %.2f, mean %.2f", low, high, mean);
          const auto flattened = mScene.FlattenWhole(static_cast<float>(std::atof(value[0].c_str())));
          (void)mScene.HeightRange(low, high, mean);
          gpg::Logf(
            "editor: flatten test: %s; now %.2f .. %.2f", flattened ? flattened->c_str() : "refused", low, high
          );
          const bool undone = mCommands.Run("edit.undo");
          (void)mScene.HeightRange(low, high, mean);
          gpg::Logf(
            "editor: flatten test: undo %s; now %.2f .. %.2f, mean %.2f", undone ? "ran" : "refused", low, high, mean
          );
        }
      }
      // `/maskstamptest <layer>,<x0>,<z0>,<x1>,<z1>,<spacing>` (test runs): a texture stamp stroke along a line, the
      // brush's shape as it is (a library image with /brushshape).
      if (!mMaskStampArg.empty() && mScene.Attached() && ++mMaskStampFrames == 140) {
        int layer = 1;
        float x0 = 0.0f, z0 = 0.0f, x1 = 0.0f, z1 = 0.0f, spacing = 0.6f;
        (void)std::sscanf(mMaskStampArg.c_str(), "%d,%f,%f,%f,%f,%f", &layer, &x0, &z0, &x1, &z1, &spacing);
        tools.SetMaskStamp(true, spacing);
        mScene.TestMaskStamp(layer - 1, x0, z0, x1, z1);
        tools.SetMaskStamp(false, 0.6f);
        mMaskStampArg.clear();
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
        if (auto image = ReadHeightImage(mStampArg, 0, 0)) {
          HeightStamp stamp;
          stamp.width = image->width;
          stamp.height = image->height;
          stamp.words = std::move(image->words);
          tools.SetStamp(std::move(stamp), std::filesystem::path(mStampArg).filename().string());
        } else {
          gpg::Warnf("editor: /stamp: %s", image.error().c_str());
        }
        mStampArg.clear();
      }
      if (mHeightDialog && mScene.Attached() && ++mHeightFileFrames == 120) {
        tools.RequestImport();
      }
      // The brush library's folder, once; the Import button copies picked images into it.
      if (tools.BrushFolder().empty()) {
        if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
          // FAF Studio's five ready-made images, the first time.
          std::string error;
          if (const int shipped = WriteShippedBrushImages(folder / "brushes", error); shipped > 0 || !error.empty()) {
            gpg::Logf(
              "editor: brush library: %d ready-made images written%s%s",
              shipped,
              error.empty() ? "" : ": ",
              error.c_str()
            );
          }
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
          if (auto image = ReadHeightImage(file, 0, 0)) {
            HeightStamp stamp;
            stamp.width = image->width;
            stamp.height = image->height;
            stamp.words = std::move(image->words);
            gpg::Logf("editor: stamp image %s (%d x %d)", file.string().c_str(), stamp.width, stamp.height);
            tools.SetStamp(std::move(stamp), file.filename().string());
          } else {
            gpg::Warnf("editor: the stamp image didn't load: %s", image.error().c_str());
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
          std::expected<void, std::string> read;
          if (!in || !(read = WaterFromScmwtr(text, water))) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? read.error().c_str() : "can't read it");
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
      DriveUnitTest();
      TestUnitInGame();
      DriveReseatTest();
      if (std::string unit; mShell->UnitLab().TakeModelAsk(unit)) {
        const std::filesystem::path obj = AskFile(
          HandleOf(mGame.supcomFrame),
          false,
          L"Wavefront OBJ (*.obj)\0*.obj\0All files\0*.*\0",
          L"obj",
          L"A model for the unit"
        );
        if (!obj.empty()) {
          const auto model = ImportUnitModel(unit, obj);
          PostStatusMessage(model ? *model : model.error());
        }
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
        if (std::string(ero[0].c_str()).contains(",masks")) {
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
          std::expected<LightingState, std::string> lighting = std::unexpected(std::string());
          if (
            !ReadGameFile(scenario, text) ||
            !std::regex_search(text, path, std::regex(R"(\bmap\s*=\s*['"]([^'"]+\.scmap)['"])"))
          ) {
            gpg::Warnf("editor: %s names no map file", scenario.c_str());
          } else if (!ReadGameFile(path[1].str(), bytes) || !(lighting = LightingFromScmap(bytes))) {
            gpg::Warnf(
              "editor: %s: %s",
              path[1].str().c_str(),
              lighting.error().empty() ? "can't read it" : lighting.error().c_str()
            );
          } else {
            const LightingState before = mDocument.LightingNow();
            mDocument.ApplyLighting(*lighting);
            mDocument.LightingEdited(before);
            gpg::Logf(
              "editor: lighting from %s: multiplier %.2f, sun colour %.2f %.2f %.2f, fog %.0f to %.0f",
              path[1].str().c_str(),
              static_cast<double>(lighting->multiplier),
              static_cast<double>(lighting->sunColor[0]),
              static_cast<double>(lighting->sunColor[1]),
              static_cast<double>(lighting->sunColor[2]),
              static_cast<double>(lighting->fogStart),
              static_cast<double>(lighting->fogEnd)
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
          std::expected<void, std::string> read;
          if (!in || !(read = LightingFromScmlighting(text, lighting))) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? read.error().c_str() : "can't read it");
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
          const auto result = in ? mScene.ImportMarkerFile(text)
                                 : std::expected<MarkerImport, std::string>(std::unexpected("can't read it"));
          if (!result) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), result.error().c_str());
          } else {
            gpg::Logf(
              "editor: %zu markers imported from %s (%s to %s), %d path links, %d of a type the editor doesn't place "
              "left out",
              result->names.size(),
              importFile.string().c_str(),
              result->names.empty() ? "-" : result->names.front().c_str(),
              result->names.empty() ? "-" : result->names.back().c_str(),
              result->links,
              result->skipped
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
          const auto imported = in ? mScene.ImportUnitFile(text, tools.UnitArmy(), names, moved)
                                   : std::expected<void, std::string>(std::unexpected("can't read it"));
          if (!imported) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), imported.error().c_str());
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
              const auto layersRead = LayersFromScmst(text, shader, layers);
              read = layersRead.has_value();
              if (!read) {
                error = layersRead.error();
              }
              for (int i = 0; read && i < 10; ++i) {
                changes.emplace_back(i, layers[static_cast<std::size_t>(i)]);
              }
            } else if (read) {
              LayerSettings layer;
              const auto layerRead = LayerFromScmsl(text, layer);
              read = layerRead.has_value();
              if (!read) {
                error = layerRead.error();
              }
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
          std::expected<std::vector<PropPaintEntry>, std::string> read = std::unexpected(std::string());
          if (!in || !(read = PaintSetFromProppaintset(text))) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? read.error().c_str() : "can't read it");
          } else {
            std::vector<PropPaintEntry>& entries = *read;
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
          std::expected<void, std::string> read;
          if (!in || !(read = SkyboxFromScmskybox(text, sky))) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? read.error().c_str() : "can't read it");
          } else {
            // Made for another map: fitted to this one's size.
            const float ratio = RescaleSkybox(
              sky, static_cast<float>(mDocument.Facts().sizeX), static_cast<float>(mDocument.Facts().sizeZ)
            );
            if (ratio != 1.0f) {
              gpg::Logf("editor: the imported sky fitted to this map: %.2f times its size", static_cast<double>(ratio));
            }
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
            if (patterns) {
              const auto read =
                in ? ParseWavePatterns(text) : std::expected<std::vector<WavePattern>, std::string>(std::unexpect);
              if (!read) {
                gpg::Warnf("editor: %s: %s", path.string().c_str(), in ? read.error().c_str() : "can't read it");
              } else {
                tools.AddWavePatterns(*read);
                gpg::Logf("editor: %zu wave patterns from %s", read->size(), path.string().c_str());
              }
              continue;
            }
            const auto waves =
              in ? WavesFromScmwaves(text) : std::expected<std::vector<WaveRecord>, std::string>(std::unexpect);
            if (!waves) {
              gpg::Warnf("editor: %s: %s", path.string().c_str(), in ? waves.error().c_str() : "can't read it");
              continue;
            }
            std::vector<WaveRecord> before = mDocument.WavesNow();
            mDocument.ApplyWaves(*waves);
            mDocument.WavesEdited(std::move(before));
            gpg::Logf(
              "editor: %zu wave generators imported from %s (in place of the map's)",
              waves->size(),
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
            std::vector<ShorePoint> picked = PickShorePoints(found, settings.density, settings.spacing, seed);
            if (settings.symmetric) {
              const HeightBrush brush = tools.CurrentHeightBrush();
              std::vector<ShorePoint> mirrored;
              const float apart = std::max(1.0f, settings.spacing);
              const auto crowded = [&](const float x, const float z) {
                for (const ShorePoint& p : mirrored) {
                  if (std::hypot(p.x - x, p.z - z) < apart) {
                    return true;
                  }
                }
                return false;
              };
              for (const ShorePoint& point : picked) {
                float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies], ax[kMaxSymmetryCopies], az[kMaxSymmetryCopies];
                const int copies = HeightBrushCentres(
                  field->width, field->height, point.x, point.z, brush.symmetry, brush.turns, cx, cz
                );
                (void)HeightBrushCentres(
                  field->width,
                  field->height,
                  point.x + std::cos(point.heading),
                  point.z + std::sin(point.heading),
                  brush.symmetry,
                  brush.turns,
                  ax,
                  az
                );
                if (crowded(point.x, point.z)) {
                  continue; // (another place's copy is here already)
                }
                for (int c = 0; c < copies; ++c) {
                  if (c > 0 && crowded(cx[c], cz[c])) {
                    continue;
                  }
                  mirrored.push_back({cx[c], cz[c], std::atan2(az[c] - cz[c], ax[c] - cx[c])});
                }
              }
              picked = std::move(mirrored);
            }
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
          if (entry.name == tools.UnitArmy() && ParseUnitGroup(entry.Get("Units"), root)) {
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
          // x0,z0,x1,z1[,x2,z2...]: every further point goes on from the last end (Alt+Shift+drag).
          std::vector<float> ends;
          std::string list = value[0].c_str();
          while (!list.empty()) {
            ends.push_back(static_cast<float>(std::atof(list.c_str())));
            const std::size_t comma = list.find(',');
            list = comma == std::string::npos ? std::string() : list.substr(comma + 1);
          }
          ends.resize(std::max<std::size_t>(ends.size() & ~1uz, 4), 0.0f);
          mScene.SetRuler(ends[0], ends[1], ends[2], ends[3]);
          for (std::size_t i = 4; i + 1 < ends.size(); i += 2) {
            mScene.ContinueRuler(ends[i], ends[i + 1]);
          }
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
      if (importAsked) {
        // One import (FAF Studio had two): the file goes to Import / Export, read with its words as heights times the
        // tool's scale, over the whole map; that window shows it and can change the mapping, region and filter.
        if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), false); !file.empty()) {
          ImportSettings& s = tools.InteropSettings();
          s.mapping = ImportSettings::Mapping::Absolute;
          s.scale = tools.HeightScale();
          s.blend = ImportSettings::Blend::Replace;
          s.strength = 1.0f;
          s.region = false;
          tools.SetInteropFile(false, file.string());
          tools.OpenInterop();
          tools.AskInterop(EdTools::InteropAsk::Import);
          gpg::Logf("editor: heights import of %s through Import / Export", file.string().c_str());
        }
      }
      if (exportAsked) {
        if (const std::filesystem::path file = AskHeightFile(HandleOf(mGame.supcomFrame), true); !file.empty()) {
          const auto exported = mScene.ExportHeights(file, tools.ExportWidth(), tools.HeightScale());
          report(exported.has_value(), exported ? *exported : exported.error());
        }
      }
      if ((!mHeightExportFile.empty() || !mHeightImportFile.empty()) && ++mHeightFileFrames == 120) {
        if (!mHeightExportFile.empty()) {
          const auto exported = mScene.ExportHeights(mHeightExportFile, tools.ExportWidth(), tools.HeightScale());
          report(exported.has_value(), exported ? *exported : exported.error());
        }
        if (!mHeightImportFile.empty()) {
          const auto imported = mScene.ImportHeights(mHeightImportFile, tools.HeightScale());
          report(imported.has_value(), imported ? *imported : imported.error());
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
        // Any size: "7.5km" for the width (and the depth), the terrain the one that holds it (NewMapPlayable).
        const auto km = [](const std::string& part) {
          return part.size() > 2 && part.ends_with("km") ? static_cast<float>(std::atof(part.c_str())) : 0.0f;
        };
        if (parts.size() >= 2 && km(parts[1]) > 0.0f) {
          settings.widthKm = km(parts[1]);
          settings.depthKm = parts.size() >= 6 && km(parts[5]) > 0.0f ? km(parts[5]) : settings.widthKm;
          settings.sizeZ = -1;
          if (const std::optional<std::array<int, 4>> area = NewMapPlayable(settings)) {
            gpg::Logf(
              "editor: /newmap: %.1f x %.1f km: terrain %d x %d, playable area %d, %d to %d, %d",
              static_cast<double>(settings.widthKm),
              static_cast<double>(settings.depthKm),
              NewMapWidth(settings),
              NewMapDepth(settings),
              (*area)[0],
              (*area)[1],
              (*area)[2],
              (*area)[3]
            );
          }
        }
        mNewMapSpec.clear();
        if (const auto created = mDocument.CreateNew(settings)) {
          gpg::Logf("editor: %s", created->c_str());
        } else {
          gpg::Warnf("editor: %s", created.error().c_str());
        }
      }
      const bool finished = mDocument.Poll();
      // A new map folder made: mounted at /maps/<folder> as the game's init mounts the vault's, listed, opened.
      std::filesystem::path folder;
      std::string scenario;
      if (finished && mDocument.TakeCreated(folder, scenario)) {
        mPreviewOnFirstSave = true;
        if (mSampleMapPending) {
          mSampleMapPending = false;
          mSampleBuildDue = true;
        }
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
      for (std::string command; mLog.TakeCommand(command);) {
        RunConsoleLine(command);
      }
      // The Check panel's fixes: the marker moved (on the ground there), one undo step each.
      for (std::string marker; mScene.Attached();) {
        float x = 0.0f;
        float z = 0.0f;
        if (!mShell->TakeCheckFix(marker, x, z)) {
          break;
        }
        const float y = mDocument.Map()->mTerrainRes->GetHeightAt(
          static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
        );
        mScene.EditMarker(marker, "position", Vector3Value(x, y, z));
        gpg::Logf(
          "editor: check fix: %s moved to %.1f, %.1f", marker.c_str(), static_cast<double>(x), static_cast<double>(z)
        );
      }
      // Terrain > Fields: its source is the map's heights; "Put on the map" writes the top of its stack (one step).
      {
        EdFieldsPanel& fields = mShell->Fields();
        static bool sourced = false;
        if (!sourced) {
          sourced = true;
          // The particle editor's effect templates from the module itself (computed tables too), in the UI's Lua.
          EdParticleEditor::SetTemplateSource([]() {
            std::vector<EffectTemplate> out;
            LuaPlus::LuaState* const state = moho::USER_GetLuaState();
            if (state == nullptr) {
              return out;
            }
            try {
              const LuaPlus::LuaObject module = moho::SCR_Import(state, "/lua/EffectTemplates.lua");
              if (!module.IsTable()) {
                return out;
              }
              for (LuaPlus::LuaTableIterator entry(module, 1); entry.IsValid(); entry.Next()) {
                const LuaPlus::LuaObject key = entry.GetKey();
                const LuaPlus::LuaObject value = entry.GetValue();
                if (!key.IsString() || !value.IsTable()) {
                  continue;
                }
                EffectTemplate effect;
                effect.name = key.GetString();
                for (LuaPlus::LuaTableIterator item(value, 1); item.IsValid(); item.Next()) {
                  const LuaPlus::LuaObject path = item.GetValue();
                  if (path.IsString() && std::string(path.GetString()).contains("/effects/")) {
                    effect.paths.emplace_back(path.GetString());
                  }
                }
                if (!effect.paths.empty()) {
                  out.push_back(std::move(effect));
                }
              }
            } catch (const std::exception& error) {
              gpg::Warnf("editor: effect templates: %s", error.what());
            }
            gpg::Logf("editor: effect templates: %zu from the module", out.size());
            return out;
          });
          // One pool (FAF Studio's library had its own beside the engine's): the field library's jobs started on the
          // main thread run on CUserWorkerPool; from other threads (graph previews) its own pool stays.
          field::SetParallelBackend([](const int count, const std::function<void(int)>& fn) {
            if (!moho::CUserWorkerPool::IsDispatcherThread() || moho::CUserWorkerPool::ConfiguredWorkerCount() == 0) {
              return false;
            }
            moho::CUserWorkerPool::Get().ParallelFor(
              static_cast<std::size_t>(count), 1U, [&fn](const std::size_t begin, const std::size_t end) {
              for (std::size_t i = begin; i < end; ++i) {
                fn(static_cast<int>(i));
              }
            }
            );
            return true;
          });
          fields.SetGroundSource([this](field::Grid& out) {
            TerrainGround ground;
            if (!mScene.Attached() || mScene.ModelsPending() || !mScene.GraphGround(ground) || !ground.heights) {
              return false;
            }
            out = field::Grid(ground.width, ground.height, 1.0f, 0.0f, 0.0f);
            out.v = *ground.heights;
            return out.Count() == out.v.size() && out.Count() > 0;
          });
        }
        if (field::Grid heights; fields.TakeCommit(heights) && mScene.Attached()) {
          const std::string status = mScene.ApplyGraphBuild(heights, true, TerrainBuildWrites{});
          gpg::Logf("editor: fields: put on the map: %s", status.c_str());
          PostStatusMessage("Fields: the result is on the map (one undo step)");
        }
        // Generate into the map (FAF Studio's fieldgen.lua): relief, mask, mix, water kept; Preview or Apply.
        {
          std::vector<std::string> areaNames;
          for (const SaveEntry& a : mDocument.SaveData().Areas()) {
            areaNames.push_back(a.name);
          }
          fields.SetAreaNames(std::move(areaNames));
        }
        // Fill the map's "density from the mask generator's rules": the rules evaluated over the map.
        static bool rulesWired = false;
        if (!rulesWired) {
          rulesWired = true;
          mScene.SetMaskRulesSource([this](field::Grid& out) {
            const std::vector<MaskGenRule>& rules = mShell->Tools().GenRules();
            MaskGenContext context;
            return !rules.empty() && MaskGenContextOf(rules, context).has_value() &&
              EvaluateMaskRules(context, rules, out).has_value();
          });
        }
        if (EdFieldsPanel::QuickGenSettings q; mScene.Attached()) {
          bool applyIt = false;
          if (fields.TakeQuickGen(q, applyIt)) {
            RunQuickGen(fields, q, applyIt);
          }
        }
        if (field::Grid mask; mScene.Attached()) {
          int layer = 1;
          if (fields.TakeLayerCommit(mask, layer)) {
            std::string message;
            const int changed = mScene.WriteGeneratedMask(mask, layer, MaskWriteMode::Replace, 1.0f, false, message);
            gpg::Logf("editor: fields: commit to layer %d: %s (%d)", layer, message.c_str(), changed);
            PostStatusMessage("Fields: " + message);
          }
        }
        // `/fieldstest <op>;<key=value,...>` (test runs): that op on the map's heights, put on the map.
        if (
          !mFieldsTest.empty() && mDocument.GetState() == EdDocument::State::Open && mScene.Attached() &&
          !mScene.ModelsPending() && ++mFieldsTestFrames > 90
        ) {
          const std::size_t semicolon = mFieldsTest.find(';');
          const std::string op = mFieldsTest.substr(0, semicolon);
          std::string params = semicolon == std::string::npos ? std::string() : mFieldsTest.substr(semicolon + 1);
          for (char& c : params) {
            c = c == ',' ? '\n' : c;
          }
          const auto status = fields.RunForTest(op, params);
          const bool ok = status.has_value();
          (ok ? gpg::Logf : gpg::Warnf)("editor: fields test: %s", (ok ? *status : status.error()).c_str());
          mFieldsTest.clear();
        }
      }
      DriveImagesAndMesh();
      // The coop shim mod in the vault's mods folder (played with coop maps, EdPlay::WriteCoopShim): written once a
      // run, only when a coop map is open, so the vault gets it only when it is used.
      {
        static bool shimWritten = false;
        std::string mapType;
        if (
          !shimWritten && !mDocument.VaultFolder().empty() && mDocument.GetState() == EdDocument::State::Open &&
          ReadScenarioField(mDocument.Scenario(), "type", mapType) && mapType == "campaign_coop"
        ) {
          shimWritten = true;
          if (const auto shim = EdPlay::WriteCoopShim(mDocument.VaultFolder() / "mods"); shim) {
            gpg::Logf(
              "editor: coop shim written to %s", (mDocument.VaultFolder() / "mods" / "EditorCoopShim").string().c_str()
            );
          } else {
            gpg::Warnf("editor: coop shim: %s", shim.error().c_str());
          }
        }
      }
      // The sample map open: its ground from the island graph (Generate's Build, one undo step).
      if (mSampleBuildDue && mDocument.GetState() == EdDocument::State::Open && mScene.Attached()) {
        mSampleBuildDue = false;
        if (mShell->Generate().OpenShipped("island")) {
          // The graph builds while the Generate workspace shows it.
          for (std::size_t w = 0; w < Workspaces().size(); ++w) {
            if (std::string(Workspaces()[w].key) == "generate") {
              mShell->SwitchWorkspace(static_cast<int>(w));
            }
          }
          mShell->Generate().AskBuild();
          gpg::Logf("editor: sample map: the island graph builds the ground");
        } else {
          gpg::Warnf("editor: sample map: the island graph isn't there");
        }
      }
      // The game's marker templates (FAF's /lua/MarkerTemplates.lua, mods' types too), once the files are there.
      if (!mMarkerTemplatesRead && mDocument.GetState() == EdDocument::State::Open) {
        mMarkerTemplatesRead = true;
        if (std::string text; ReadGameFile("/lua/MarkerTemplates.lua", text)) {
          gpg::Logf("editor: %d marker types from the game's MarkerTemplates.lua", AddMarkerTemplates(text));
        }
      }
      // An asset dragged from the browser and let go over the map: it becomes the tool's, and the tool gets a click
      // there (sent to the view's window, as the panels pass the mouse on; the real cursor isn't touched).
      if (EdAssetBrowser::DropAsk drop; mShell->Assets().TakeDrop(drop) && gViewWindow != nullptr) {
        const ImVec2 origin = ImGui::GetMainViewport()->Pos;
        const POINT at{
          static_cast<LONG>(std::lround(drop.x - origin.x)), static_cast<LONG>(std::lround(drop.y - origin.y))
        };
        bool over = ::PtInRect(&gViewRect, at) != FALSE;
        for (const RECT& covered : gOverView) {
          over = over && ::PtInRect(&covered, at) == FALSE;
        }
        if (over && mScene.Attached()) {
          mShell->Assets().Pick(drop.entry);
          const LPARAM point = MAKELPARAM(at.x - gViewRect.left, at.y - gViewRect.top);
          (void)::SendMessageW(gViewWindow, WM_LBUTTONDOWN, MK_LBUTTON, point);
          (void)::SendMessageW(gViewWindow, WM_LBUTTONUP, 0, point);
          gpg::Logf("editor: %s dropped on the map", drop.entry.name.c_str());
        }
      }
      // A terrain graph built on the open map goes with it when it is saved.
      if (mShell->Generate().TakeBuilt() && mDocument.GetState() == EdDocument::State::Open) {
        mGraphMap = mDocument.Path();
      }
      // A map that has one: its graph opens in Generate.
      if (finished && mDocument.GetState() == EdDocument::State::Open && mGraphOpenedFor != mDocument.Path()) {
        mGraphOpenedFor = mDocument.Path();
        std::error_code ec;
        if (
          const std::filesystem::path file = mDocument.TerrainGraphFile();
          !file.empty() && std::filesystem::exists(file, ec) && mShell->Generate().OpenFile(file)
        ) {
          mGraphMap = mDocument.Path();
          gpg::Logf("editor: the map's terrain graph opened in Generate (%s)", file.filename().string().c_str());
        }
      }
      if (
        mResize.has_value() && !mResize->scenario.empty() && mScene.Attached() &&
        mDocument.GetState() == EdDocument::State::Open && mDocument.Path() == mResize->scenario &&
        ++mResize->frames == 30
      ) {
        FinishResize();
      }
      {
        const EdPerf::Scope perfTools("tool updates");
        DriveHeightFiles();
      }
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
        if (const auto saved = mDocument.SaveAsNewFolder(mSaveAsFolder)) {
          gpg::Logf("editor: %s", saved->c_str());
        } else {
          gpg::Warnf("editor: %s", saved.error().c_str());
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
      const std::shared_ptr<gpg::gal::RenderTarget>& output
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
        mMiniRetired.reset();
        mMiniSurfaceRetired.reset();
        if (!mMiniCopy || mMiniCopyWidth != width || mMiniCopyHeight != height) {
          mMiniRetired = std::move(mMiniCopy);
          mMiniSurfaceRetired = std::move(mMiniSurface);
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
        const ImGuiViewport* const mainViewport = ImGui::GetMainViewport();
        const ImVec2 origin = mainViewport->Pos;
        for (const ImGuiWindow* const window : ImGui::GetCurrentContext()->Windows) {
          // A panel in a window of its own (popped out) is a window above the frame: no hole for it.
          if (window->Viewport != nullptr && window->Viewport != mainViewport) {
            continue;
          }
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
            static_cast<LONG>(window->Pos.x - origin.x) - x,
            static_cast<LONG>(window->Pos.y - origin.y) - y,
            static_cast<LONG>(window->Pos.x - origin.x + window->Size.x + 1.0f) - x,
            static_cast<LONG>(window->Pos.y - origin.y + window->Size.y + 1.0f) - y
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
      // The pop-outs' heads follow their windows (a size taken once a drag ends).
      gpg::gal::DeviceContext popoutSizes(*active);
      if (
        popouts::WantHeadSizes(popoutSizes) || gameHead.mWidth != static_cast<std::uint32_t>(width) ||
        gameHead.mHeight != static_cast<std::uint32_t>(height) ||
        panelHead.mWidth != static_cast<std::uint32_t>(clientWidth) ||
        panelHead.mHeight != static_cast<std::uint32_t>(clientHeight)
      ) {
        gpg::gal::DeviceContext context(popoutSizes);
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
        mMiniRetired.reset();
        mMiniSurfaceRetired.reset();
        mMiniCopyWidth = 0;
        mMiniCopyHeight = 0;
        mShell->Tools().SetMinimapImage(0);
        // The particle editor's own view too (its image was drawn after a resize: a freed target).
        mShell->ParticleEditor().Viewport().DropTargets();
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

    // Started without arguments (a double click): FAF's game data is found as FAF Studio's start finds it, FAF's
    // init_faf.lua next to the exe or in the FAF client's folders (doc/EdUserFiles), unless the exe's own
    // SupComDataPath.lua (the game's default) is there.
    static std::vector<std::string> startArgs;
    static std::vector<char*> startArgv;
    {
      const std::vector<std::string> args(__argv, __argv + __argc);
      wchar_t exePath[MAX_PATH] = {};
      (void)::GetModuleFileNameW(nullptr, exePath, MAX_PATH);
      const std::filesystem::path exeFolder = std::filesystem::path(exePath).parent_path();
      std::error_code ignored;
      if (!HasInitArgument(args) && !std::filesystem::exists(exeFolder / "SupComDataPath.lua", ignored)) {
        const char* const programData = std::getenv("ProgramData");
        const std::filesystem::path found = FindInitFile(
          InitFileCandidates(
            exeFolder, programData != nullptr ? std::filesystem::path(programData) : std::filesystem::path()
          ),
          [](const std::filesystem::path& file) {
          std::error_code error;
          return std::filesystem::is_regular_file(file, error);
        }
        );
        if (found.empty()) {
          (void)::MessageBoxW(
            nullptr,
            L"The map editor couldn't find Forged Alliance Forever's game data (init_faf.lua).\n\n"
            L"Install the FAF client and run a game once, or start the editor with /init <init file>.",
            L"FAF map editor",
            MB_ICONERROR | MB_OK
          );
          return 1;
        }
        startArgs = args;
        startArgs.emplace_back("/init");
        startArgs.push_back(found.string());
        for (std::string& argument : startArgs) {
          startArgv.push_back(argument.data());
        }
        startArgv.push_back(nullptr);
        __argc = static_cast<int>(startArgs.size());
        __argv = startArgv.data();
        (void)::SetCurrentDirectoryW(found.parent_path().wstring().c_str());
      }
    }

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

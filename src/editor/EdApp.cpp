#include "editor/EdApp.h"
#include "editor/EdPath.h"
#include "editor/view/EdPropThumbnails.h"
#include "editor/doc/EdAdaptiveTables.h"
#include <iterator>
#include <fstream>
#include <regex>
#include "moho/resource/blueprints/RUnitBlueprint.h"

#include <Windows.h>
#include <windowsx.h>
#include <ShlObj.h>
#include <commdlg.h>

#include <algorithm>
#include <optional>
#include <cstdio>
#include <array>
#include <chrono>
#include <deque>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "editor/EdLog.h"
#include "editor/doc/EdWaterPreset.h"
#include "editor/EdMemTrace.h"
#include "editor/EdPlay.h"
#include "editor/ui/EdHelp.h"
#include "editor/EdShell.h"
#include "editor/ui/EdFonts.h"
#include "moho/render/AmbientOcclusionRenderer.h"
#include <cstring>
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdRoundTrip.h"
#include "editor/doc/EdUnitWrecks.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "editor/tools/EdHeightFile.h"
#include "editor/view/EdMapScene.h"
#include "gpg/core/diagnostics/CrashHooks.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_win32.h"
#include "moho/app/CScApp.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/misc/SessionStartup.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CVFSImpl.h"
#include "moho/ui/IUIManager.h"

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
    [[nodiscard]] bool MouseIsTheViews(const POINT at)
    {
      if (!gComposite || gViewWindow == nullptr || ::PtInRect(&gViewRect, at) == FALSE) {
        return false;
      }
      if (ImGui::GetCurrentContext() != nullptr && (ImGui::GetCurrentContext()->ActiveId != 0 || ImGui::GetTopMostPopupModal() != nullptr)) {
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
    [[nodiscard]] bool VaultUsable(const std::filesystem::path& folder)
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
    void MountVaultMaps(const std::filesystem::path& vault)
    {
      const auto lower = [](std::string text) {
        std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
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
      gpg::Logf("editor: mounted %zu map folders of the vault the init file doesn't mount (first: %s)", folders.size(),
                folders.front().first.string().c_str());
    }

    void OnMenuCommand(UINT command);
    bool OnViewportMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam);
    void OnMenuOpening(HMENU menu);
    [[nodiscard]] bool SessionActive();

    /**
     * The game's viewport keeps its own input (mouse and keys reach the game as in the game); only F5, the
     * editor's Play/Stop, stops here, whatever a player's own key bindings say.
     */
    LRESULT CALLBACK EditorViewportProc(const HWND window, const UINT message, const WPARAM wParam, const LPARAM lParam)
    {
      if ((message == WM_KEYDOWN || message == WM_KEYUP) && wParam == VK_F5) {
        if (message == WM_KEYDOWN && (lParam & (1 << 30)) == 0) {
          OnMenuCommand(kMenuPlayStop);
        }
        return 0;
      }
      // Between plays the opened map's camera takes the mouse (EdMapScene).
      if (OnViewportMessage(window, message, wParam, lParam)) {
        return 0;
      }
      return ::CallWindowProcW(gViewportProc, window, message, wParam, lParam);
    }

    /** The panels' window: its input is ImGui's; a click takes the keyboard focus from the game. */
    LRESULT CALLBACK PanelWindowProc(const HWND window, const UINT message, const WPARAM wParam, const LPARAM lParam)
    {
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
      if (ImGui::GetCurrentContext() != nullptr && ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam) != 0) {
        return 1;
      }
      if (message == WM_ERASEBKGND) {
        return 1;
      }
      return ::DefWindowProcW(window, message, wParam, lParam);
    }

    /** moho::gAppBeforeDeviceCreate: the panels' window, under the game's viewport, and its head. */
    void AddPanelHead(gpg::gal::DeviceContext& context, void* const frameWindow)
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
      gPanelWindow = ::CreateWindowExW(0, kPanelWindowClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, width, height,
                                       frame, nullptr, instance, nullptr);
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
    LRESULT CALLBACK EditorFrameProc(const HWND window, const UINT message, const WPARAM wParam, const LPARAM lParam)
    {
      if (message == WM_CLOSE) {
        gWindowClosing = true;
        if (wxTheApp != nullptr) {
          wxTheApp->ExitMainLoop();
        }
        return 0;
      }
      if (message == WM_COMMAND && HIWORD(wParam) == 0 && LOWORD(wParam) >= kMenuExit) {
        OnMenuCommand(LOWORD(wParam));
        return 0;
      }
      if (message == WM_INITMENUPOPUP) {
        OnMenuOpening(reinterpret_cast<HMENU>(wParam));
        return 0;
      }
      // Alt alone opens the menu bar; during play the game has Alt (its own bindings), so only a click does.
      if (message == WM_SYSCOMMAND && (wParam & 0xFFF0U) == SC_KEYMENU && lParam == 0 && SessionActive()) {
        return 0;
      }
      return ::CallWindowProcW(gFrameProc, window, message, wParam, lParam);
    }

    /** UTF-8 to the window's text. */
    [[nodiscard]] std::wstring Widen(const std::string& text)
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

    [[nodiscard]] HWND HandleOf(const wxWindow* const window)
    {
      return window != nullptr ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window->GetHandle())) : nullptr;
    }

    namespace
    {
      std::filesystem::path AskFile(HWND owner, bool save, const wchar_t* filter, const wchar_t* extension, const wchar_t* title);
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
      bool AppDoSuppressWindowsKeys() const override { return mGame.AppDoSuppressWindowsKeys(); }

      void HandleMenuCommand(UINT command);
      void UpdateMenu();
      bool HandleViewportMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
      {
        if (message == WM_KEYDOWN && wParam == 'S' && (::GetKeyState(VK_CONTROL) & 0x8000) != 0) {
          SaveDocument();
          return true;
        }
        if (message == WM_KEYDOWN && wParam == 'N' && (::GetKeyState(VK_CONTROL) & 0x8000) != 0) {
          mShell->OpenNewMap();
          return true;
        }
        if (message == WM_KEYDOWN && wParam == 'O' && (::GetKeyState(VK_CONTROL) & 0x8000) != 0) {
          mShell->Browser().Show();
          return true;
        }
        return mScene.OnWindowMessage(window, message, wParam, lParam);
      }
      [[nodiscard]] bool SessionActive() const { return mPlay.Active(); }

    private:
      void SetUpImGui();
      void BuildMenu(HWND frame);
      void UpdateTitle();
      void RenderPanels();
      void FitGameView();
      void ReadOpenCommandLine();
      void DriveOpens();

      HMENU mMenuBar = nullptr;
      HMENU mViewMenu = nullptr;
      HMENU mEditMenu = nullptr;
      HMENU mFileMenu = nullptr;
      HMENU mPlayMenu = nullptr;
      HMENU mMapMenu = nullptr;
      HMENU mRecentMenu = nullptr;
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
      // `/masklayer <1-8>` and `/maskrule <layer>,<low>,<high>` (test runs): the Texture tool on that layer;
      // a height rule applied to the whole map once the map has been shown for 120 frames.
      int mMaskLayerArg = -1;
      std::string mMaskRuleArg;
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
      [[nodiscard]] bool mViewStepsAsideForDialog() const
      {
        return mImGuiReady && ImGui::GetTopMostPopupModal() != nullptr;
      }
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
      /** `/waterpick <n>[,seed|outline]` or `/waterpick new` (test runs): a body chosen, and what a click in the view does. */
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
      };
      std::vector<UiClick> mUiClicks;
      int mUiClickFrame = 0;
      void FeedUiClicks();
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
      std::string mIniPath;
      bool mImGuiReady = false;
    };

    bool EditorApp::Init()
    {
      // Direct3D 12, then Vulkan; /d3d12 or /vulkan alone. Nothing older (moho::gAppRenderers).
      using gpg::gal::DeviceApi;
      if (moho::CFG_GetArgOption("/vulkan", 0, nullptr)) {
        moho::gAppRenderers = {DeviceApi::Vulkan};
      } else if (moho::CFG_GetArgOption("/d3d12", 0, nullptr)) {
        moho::gAppRenderers = {DeviceApi::Direct3D12};
      } else {
        moho::gAppRenderers = {DeviceApi::Direct3D12, DeviceApi::Vulkan};
      }
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
        ::MessageBoxW(nullptr, L"Neither Direct3D 12 nor Vulkan started, or the game data could not be read. See the log.",
                      kTitle, MB_OK | MB_ICONERROR);
        return false;
      }
      // The game starts its first session or the main menu on its first frame (CScApp::Main); the editor
      // starts sessions itself, from Play.
      mGame.initialized = 1;

      const HWND frame = HandleOf(mGame.supcomFrame);
      const HWND viewport = HandleOf(moho::ren_Viewport);
      const gpg::gal::DeviceContext* const context = gpg::gal::Device::GetInstance()->GetDeviceContext();
      if (frame == nullptr || viewport == nullptr || gPanelWindow == nullptr || context->GetHeadCount() <= static_cast<int>(kPanelHead)) {
        gpg::Warnf("editor: the game window, its viewport or the panels' window is missing");
        return false;
      }
      const char* const api = context->mDeviceType == DeviceApi::Vulkan ? "Vulkan" : "Direct3D 12";
      mBaseTitle = std::wstring(kTitle) + L" [" + std::wstring(api, api + std::char_traits<char>::length(api)) + L"]";
      ::SetWindowTextW(frame, mBaseTitle.c_str());
      mShownTitle = mBaseTitle;

      gViewportProc = reinterpret_cast<WNDPROC>(::SetWindowLongPtrW(viewport, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&EditorViewportProc)));
      gFrameProc = reinterpret_cast<WNDPROC>(::SetWindowLongPtrW(frame, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&EditorFrameProc)));

      SetUpImGui();
      if (!mRenderer.Init()) {
        ::MessageBoxW(nullptr, L"The editor's panels could not be set up on this device. See the log.", kTitle, MB_OK | MB_ICONERROR);
        return false;
      }
      mImGuiReady = true;
      EdImGuiRenderer::SetGameViewSource([]() { return gViewSurface; });
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
      } else if (PWSTR documents = nullptr; SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &documents))) {
        mDocument.SetVaultFolder(std::filesystem::path(documents) / "My Games" / "Gas Powered Games" / "Supreme Commander Forged Alliance");
        ::CoTaskMemFree(documents);
        if (!clientVault.empty()) {
          gpg::Logf("editor: the FAF client's vault %s isn't writable by this Windows user", clientVault.string().c_str());
        }
      }
      gpg::Logf("editor: the vault is %s", mDocument.VaultFolder().string().c_str());
      MountVaultMaps(mDocument.VaultFolder());
      mPlay.FindMaps();
      mPlay.ReadCommandLine();
      mShell = new EdShell(mLog, mPlay, mDocument);
      if (!mPendingFafTokenFile.empty()) {
        mShell->Browser().Faf().SetTokenFile(mPendingFafTokenFile);
        mShell->Browser().Faf().SetPictureCache(mPendingFafTokenFile.parent_path() / "cache" / "maps");
      }
      mDocument.SetBeforeDrop([this] { mScene.Detach(); });
      mScene.SetTools(&mShell->Tools());
      mShell->Tools().SetPropPictures([this](const std::string& blueprint) { return mPropThumbnails.Get(blueprint); });
      ReadOpenCommandLine();
      gEditorApp = this;
      BuildMenu(frame);
      // The game view's ambient occlusion makes its GPU programs on first use, which the editor's own view never
      // is: made now, so the first Play's first frame doesn't wait for them (WPE.15).
      const auto warmStart = std::chrono::steady_clock::now();
      if (moho::AmbientOcclusionRenderer::Get().IsActive()) {
        gpg::Logf("editor: game view's ambient occlusion made ahead in %.2f s",
                  std::chrono::duration<double>(std::chrono::steady_clock::now() - warmStart).count());
      }
      gpg::Logf("editor: ready on %s", api);
      return true;
    }

    void EditorApp::SetUpImGui()
    {
      IMGUI_CHECKVERSION();
      ImGui::CreateContext();
      ImGuiIO& io = ImGui::GetIO();
      io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
      const std::filesystem::path settings = EditorSettingsFolder();
      if (settings.empty()) {
        io.IniFilename = nullptr;
      } else {
        mIniPath = (settings / "layout.ini").string();
        io.IniFilename = mIniPath.c_str();
      }

      ImGui::StyleColorsDark();
      ImGuiStyle& style = ImGui::GetStyle();
      style.WindowRounding = 2.0f;
      style.FrameRounding = 3.0f;
      style.TabRounding = 3.0f;
      style.Colors[ImGuiCol_WindowBg] = ImVec4(0.110f, 0.122f, 0.145f, 0.97f);
      // Popups, menus and tooltips: opaque, so the panel under them doesn't show through.
      style.Colors[ImGuiCol_PopupBg] = ImVec4(0.090f, 0.100f, 0.122f, 1.0f);
      style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.18f, 0.20f, 0.24f, 1.0f);
      style.Colors[ImGuiCol_Header] = ImVec4(0.89f, 0.58f, 0.26f, 0.30f);
      style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.89f, 0.58f, 0.26f, 0.45f);
      style.Colors[ImGuiCol_CheckMark] = ImVec4(0.89f, 0.58f, 0.26f, 1.0f);
      style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.89f, 0.58f, 0.26f, 1.0f);

      const float dpiScale = ImGui_ImplWin32_GetDpiScaleForHwnd(gPanelWindow);
      style.ScaleAllSizes(dpiScale);
      style.FontScaleDpi = dpiScale;
      io.ConfigDpiScaleFonts = true;

      std::error_code error;
      const std::filesystem::path segoe = "C:\\Windows\\Fonts\\segoeui.ttf";
      if (std::filesystem::exists(segoe, error)) {
        (void)io.Fonts->AddFontFromFileTTF(segoe.string().c_str(), 16.0f);
      }
      // Headings and codes (the FAF sign-in's): Segoe UI Bold and Consolas, when Windows has them.
      if (const std::filesystem::path bold = "C:\\Windows\\Fonts\\segoeuib.ttf"; std::filesystem::exists(bold, error)) {
        gBoldFont = io.Fonts->AddFontFromFileTTF(bold.string().c_str(), 16.0f);
      }
      if (const std::filesystem::path mono = "C:\\Windows\\Fonts\\consola.ttf"; std::filesystem::exists(mono, error)) {
        gMonoFont = io.Fonts->AddFontFromFileTTF(mono.string().c_str(), 16.0f);
      }
      ImGui_ImplWin32_Init(gPanelWindow);
    }

    void EditorApp::BuildMenu(const HWND frame)
    {
      HMENU file = ::CreatePopupMenu();
      ::AppendMenuW(file, MF_STRING, kMenuNew, L"&New map...\tCtrl+N");
      ::AppendMenuW(file, MF_STRING, kMenuOpen, L"&Open map...\tCtrl+O");
      // Open Recent, as VS Code has it: the maps opened last, newest first; filled each time File opens.
      mRecentMenu = ::CreatePopupMenu();
      ::AppendMenuW(file, MF_POPUP, reinterpret_cast<UINT_PTR>(mRecentMenu), L"Open &Recent");
      ::AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
      ::AppendMenuW(file, MF_STRING, kMenuSave, L"&Save\tCtrl+S");
      ::AppendMenuW(file, MF_STRING, kMenuSaveAs, L"Save as new map &folder...");
      ::AppendMenuW(file, MF_STRING, kMenuPackage, L"&Package for the FAF vault...");
      mFileMenu = file;
      ::AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
      ::AppendMenuW(file, MF_STRING, kMenuExit, L"E&xit");

      mViewMenu = ::CreatePopupMenu();
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuTools, L"&Tools");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuMap, L"&Map");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuInfo, L"&Info");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuMarkers, L"Mar&kers");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuCheck, L"&Check");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuScript, L"&Script");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuLighting, L"&Lighting");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuArmies, L"&Armies");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuProperties, L"P&roperties");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuMaterialEditor, L"Mat&erial Editor");
      ::AppendMenuW(mViewMenu, MF_SEPARATOR, 0, nullptr);
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuFullHelp, L"&Full help text");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuLog, L"&Log");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuPanelsWhilePlaying, L"&Panels while playing");
      ::AppendMenuW(mViewMenu, MF_SEPARATOR, 0, nullptr);
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuResetLayout, L"&Reset layout");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuImGuiDemo, L"ImGui &demo");

      mMapMenu = ::CreatePopupMenu();
      const std::vector<std::string>& maps = mPlay.Maps();
      for (std::size_t i = 0; i < maps.size(); ++i) {
        const std::wstring label = Widen(mPlay.Titles()[i]) + L"  (" + Widen(MapDisplayName(maps[i])) + L")";
        ::AppendMenuW(mMapMenu, MF_STRING | ((i % 32U == 0U && i != 0U) ? MF_MENUBARBREAK : 0U), kMenuFirstMap + i, label.c_str());
      }
      mPlayMenu = ::CreatePopupMenu();
      ::AppendMenuW(mPlayMenu, MF_STRING, kMenuPlayStop, L"&Play\tF5");
      ::AppendMenuW(mPlayMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(mMapMenu), L"&Map");

      mMenuBar = ::CreateMenu();
      ::AppendMenuW(mMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"&File");
      mEditMenu = ::CreatePopupMenu();
      ::AppendMenuW(mEditMenu, MF_STRING, kMenuUndo, L"&Undo\tCtrl+Z");
      ::AppendMenuW(mEditMenu, MF_STRING, kMenuRedo, L"&Redo\tCtrl+Y");
      ::AppendMenuW(mEditMenu, MF_SEPARATOR, 0, nullptr);
      ::AppendMenuW(mEditMenu, MF_STRING, kMenuDelete, L"&Delete selection\tDel");
      ::AppendMenuW(mMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(mEditMenu), L"&Edit");
      ::AppendMenuW(mMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(mViewMenu), L"&View");
      ::AppendMenuW(mMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(mPlayMenu), L"&Play");
      ::SetMenu(frame, mMenuBar);
      // The client area loses the menu's height; the game's frame resizes its viewport and the device to it
      // (WSupComFrame's size handler), so the game's interface lays out below the menu.
      ::SetWindowPos(frame, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
      ::DrawMenuBar(frame);
    }

    void EditorApp::UpdateMenu()
    {
      const auto check = [&](const UINT id, const bool on) { ::CheckMenuItem(mViewMenu, id, MF_BYCOMMAND | (on ? MF_CHECKED : MF_UNCHECKED)); };
      check(kMenuTools, mShell->ShowTools());
      check(kMenuMap, mShell->ShowMap());
      check(kMenuInfo, mShell->ShowInfo());
      check(kMenuMarkers, mShell->ShowMarkers());
      check(kMenuCheck, mShell->ShowCheck());
      check(kMenuScript, mShell->ShowScript());
      check(kMenuLighting, mShell->ShowLighting());
      check(kMenuArmies, mShell->ShowArmies());
      check(kMenuProperties, mShell->ShowProperties());
      check(kMenuMaterialEditor, mShell->ShowMaterialEditor());
      check(kMenuFullHelp, FullHelpText());
      check(kMenuLog, mShell->ShowLog());
      check(kMenuPanelsWhilePlaying, mShell->PanelsWhilePlaying());
      check(kMenuImGuiDemo, mShell->ShowDemo());

      const bool active = mPlay.Active();
      // Open Recent: the recent maps the game still lists, with their titles.
      while (::GetMenuItemCount(mRecentMenu) > 0) {
        (void)::DeleteMenu(mRecentMenu, 0, MF_BYPOSITION);
      }
      mRecentShown.clear();
      const bool busy = active || mDocument.GetState() == EdDocument::State::Loading;
      for (const std::string& recent : mDocument.RecentMaps()) {
        const std::vector<std::string>& maps = mPlay.Maps();
        for (std::size_t i = 0; i < maps.size(); ++i) {
          if (_stricmp(maps[i].c_str(), recent.c_str()) != 0) {
            continue;
          }
          const UINT id = kMenuFirstRecent + static_cast<UINT>(mRecentShown.size());
          const bool current = mDocument.GetState() == EdDocument::State::Open && _stricmp(mDocument.Path().c_str(), recent.c_str()) == 0;
          std::wstring label = Widen(mPlay.Titles()[i]) + L"  (" + Widen(MapDisplayName(maps[i])) + L")";
          if (mRecentShown.size() < 9) {
            label = L"&" + std::to_wstring(mRecentShown.size() + 1) + L"  " + label;
          }
          ::AppendMenuW(mRecentMenu, MF_STRING | (busy ? MF_GRAYED : 0U) | (current ? MF_CHECKED : 0U), id, label.c_str());
          mRecentShown.push_back(maps[i]);
          break;
        }
      }
      if (mRecentShown.empty()) {
        ::AppendMenuW(mRecentMenu, MF_STRING | MF_GRAYED, 0, L"(no maps opened yet)");
      } else {
        ::AppendMenuW(mRecentMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(mRecentMenu, MF_STRING, kMenuClearRecent, L"&Clear recently opened");
      }
      ::ModifyMenuW(mPlayMenu, kMenuPlayStop, MF_BYCOMMAND | MF_STRING | ((active || mPlay.CanPlay()) ? MF_ENABLED : MF_GRAYED),
                    kMenuPlayStop, active ? L"&Stop\tF5" : L"&Play\tF5");
      const int count = static_cast<int>(mPlay.Maps().size());
      for (int i = 0; i < count; ++i) {
        ::CheckMenuItem(mMapMenu, kMenuFirstMap + i, MF_BYCOMMAND | (i == mPlay.Selected() ? MF_CHECKED : MF_UNCHECKED));
        ::EnableMenuItem(mMapMenu, kMenuFirstMap + i, MF_BYCOMMAND | (active ? MF_GRAYED : MF_ENABLED));
      }
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
      if (step == 1 || (click.doubleClick && step == 3)) {
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, true);
        gpg::Logf("editor: test click at %.0f,%.0f%s", click.x, click.y, click.doubleClick && step == 3 ? " (second)" : "");
      } else if (step == 2 || (click.doubleClick && step == 4)) {
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
      }
    }

    void EditorApp::HandleMenuCommand(const UINT command)
    {
      switch (command) {
      case kMenuExit:
        mShell->RequestExit();
        return;
      case kMenuTools:
        mShell->ShowTools() = !mShell->ShowTools();
        return;
      case kMenuMap:
        mShell->ShowMap() = !mShell->ShowMap();
        return;
      case kMenuFullHelp:
        FullHelpText() = !FullHelpText();
        break;
      case kMenuArmies:
        mShell->ShowArmies() = !mShell->ShowArmies();
        break;
      case kMenuProperties:
        mShell->ShowProperties() = !mShell->ShowProperties();
        break;
      case kMenuLighting:
        mShell->ShowLighting() = !mShell->ShowLighting();
        break;
      case kMenuMaterialEditor:
        mShell->ShowMaterialEditor() = !mShell->ShowMaterialEditor();
        break;
      case kMenuScript:
        mShell->ShowScript() = !mShell->ShowScript();
        break;
      case kMenuCheck:
        mShell->ShowCheck() = !mShell->ShowCheck();
        break;
      case kMenuMarkers:
        mShell->ShowMarkers() = !mShell->ShowMarkers();
        break;
      case kMenuInfo:
        mShell->ShowInfo() = !mShell->ShowInfo();
        break;
      case kMenuSave:
        SaveDocument();
        break;
      case kMenuNew:
        mShell->OpenNewMap();
        break;
      case kMenuOpen:
        mShell->Browser().Show();
        break;
      case kMenuClearRecent:
        mDocument.ClearRecentMaps();
        break;
      case kMenuSaveAs:
        mShell->OpenSaveAs();
        break;
      case kMenuPackage:
        mShell->OpenPackage();
        break;
      case kMenuUndo:
        (void)mScene.Undo();
        break;
      case kMenuRedo:
        (void)mScene.Redo();
        break;
      case kMenuDelete:
        mScene.DeleteSelected();
        break;
      case kMenuLog:
        mShell->ShowLog() = !mShell->ShowLog();
        return;
      case kMenuPanelsWhilePlaying:
        mShell->PanelsWhilePlaying() = !mShell->PanelsWhilePlaying();
        return;
      case kMenuResetLayout:
        mShell->ResetLayout();
        return;
      case kMenuImGuiDemo:
        mShell->ShowDemo() = !mShell->ShowDemo();
        return;
      case kMenuPlayStop:
        if (mPlay.Active()) {
          mPlay.Stop();
        } else if (mPlay.CanPlay()) {
          mPlay.Play();
        }
        return;
      default:
        if (command >= kMenuFirstRecent && command < kMenuFirstRecent + mRecentShown.size() && !mPlay.Active() &&
            mDocument.GetState() != EdDocument::State::Loading) {
          const std::string scenario = mRecentShown[command - kMenuFirstRecent];
          const std::vector<std::string>& maps = mPlay.Maps();
          for (std::size_t i = 0; i < maps.size(); ++i) {
            if (maps[i] == scenario) {
              mPlay.Select(static_cast<int>(i));
              (void)mDocument.Open(scenario);
              gpg::Logf("editor: File > Open Recent: %s", scenario.c_str());
            }
          }
          return;
        }
        if (command >= kMenuFirstMap && command < kMenuFirstMap + mPlay.Maps().size() && !mPlay.Active()) {
          mPlay.Select(static_cast<int>(command - kMenuFirstMap));
        }
        return;
      }
    }

    void EditorApp::UpdateTitle()
    {
      std::wstring title = mBaseTitle;
      if (mPlay.Active() && !mPlay.Maps().empty()) {
        const std::size_t at = static_cast<std::size_t>(mPlay.Selected());
        title += L" - " + Widen(mPlay.StateText()) + L" " + Widen(mPlay.Titles()[at]) + L" (" + Widen(MapDisplayName(mPlay.Maps()[at])) + L")";
      }
      if (title != mShownTitle) {
        mShownTitle = title;
        ::SetWindowTextW(HandleOf(mGame.supcomFrame), title.c_str());
      }
    }

    bool OnViewportMessage(const HWND window, const UINT message, const WPARAM wParam, const LPARAM lParam)
    {
      return gEditorApp != nullptr && gEditorApp->HandleViewportMessage(window, message, wParam, lParam);
    }

    void OnMenuCommand(const UINT command)
    {
      if (gEditorApp != nullptr) {
        gEditorApp->HandleMenuCommand(command);
      }
    }

    void OnMenuOpening(const HMENU menu)
    {
      (void)menu;
      if (gEditorApp != nullptr) {
        gEditorApp->UpdateMenu();
      }
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
        gpg::Warnf("editor: the editor stopped for %.2f s (frame %llu)", static_cast<double>(frameSeconds),
                   static_cast<unsigned long long>(mFramesRun));
      }
      ++mFramesRun;
      mLastFrame = now;
      mScene.Update(frameSeconds, moho::WLD_GetFrameAction() == moho::EWldFrameAction::Inactive);

      if (mImGuiReady) {
        ImGui_ImplWin32_NewFrame();
        FeedUiClicks();
        ImGui::NewFrame();
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
          if (comma != std::string::npos &&
              mPropThumbnails.Save(mThumbDumpArg.substr(0, comma), mThumbDumpArg.substr(comma + 1), blueprint)) {
            gpg::Logf("editor: thumbnail of %s saved to %s", blueprint.c_str(), mThumbDumpArg.substr(comma + 1).c_str());
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
          const std::filesystem::path file = AskFile(HandleOf(mGame.supcomFrame), false, L"Map scenario (*_scenario.lua)\0*_scenario.lua\0", L"lua",
                                                     L"Open a map from a folder: pick its _scenario.lua");
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
          if (fa::vector<fa::string> file; moho::CFG_GetArgOption("/materialopen", 1, &file) && !file.empty()) {
            mShell->ShowMaterialEditor() = true;
            (void)mShell->MaterialEditor().OpenFile(std::filesystem::path(file[0].c_str()));
          }
          if (fa::vector<fa::string> type; moho::CFG_GetArgOption("/materialselect", 1, &type) && !type.empty()) {
            mShell->ShowMaterialEditor() = true;
            mShell->MaterialEditor().SelectFirst(type[0].c_str());
          }
          mShell->MaterialEditor().SetTerrainSource([this] { return mScene.TerrainHeights(); });
        }
        {
          // A vault map's own folder keeps its graphs; the game's own maps (in its install folder) don't get any.
          const std::filesystem::path scmap = mDocument.MapDiskFile();
          const std::string vault = mDocument.VaultFolder().lexically_normal().string();
          const std::string folder = scmap.parent_path().lexically_normal().string();
          const bool inVault = !scmap.empty() && !vault.empty() && folder.size() > vault.size() && _strnicmp(folder.c_str(), vault.c_str(), vault.size()) == 0;
          mShell->MaterialEditor().SetMapFolder(inVault ? scmap.parent_path() : std::filesystem::path());
        }
        mShell->Draw();
        // `/focuspanel <window>` (test runs): that panel in front, a while after the map opened (opening fronts Info).
        if (mFocusPanelFrames < 90 && mDocument.GetState() == EdDocument::State::Open) {
          if (fa::vector<fa::string> panel; ++mFocusPanelFrames == 60 && moho::CFG_GetArgOption("/focuspanel", 1, &panel) && !panel.empty()) {
            ImGui::SetWindowFocus(panel[0].c_str());
            gpg::Logf("editor: /focuspanel %s", panel[0].c_str());
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
        // Undo and redo from the panels too (the viewport's keys go to the scene directly); the material editor
        // keeps its own.
        if (!ImGui::GetIO().WantTextInput && !mShell->MaterialEditor().Focused()) {
          if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_S)) {
            SaveDocument();
          } else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_N)) {
            mShell->OpenNewMap();
          } else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Z)) {
            (void)mScene.Undo();
          } else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Y) || ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_Z)) {
            (void)mScene.Redo();
          }
        }
        if (gComposite && mViewImage != 0 && !mViewStepsAsideForDialog()) {
          const ImVec2 from(static_cast<float>(gViewRect.left), static_cast<float>(gViewRect.top));
          const ImVec2 to(static_cast<float>(gViewRect.right), static_cast<float>(gViewRect.bottom));
          ImGui::GetBackgroundDrawList()->AddImage(static_cast<ImTextureID>(EdImGuiRenderer::kGameViewImage), from, to);
        }
        ImGui::Render();
        FitGameView();
        RenderPanels();
      }

      mGame.Main();

      // Lua asked the app to quit (ExitApplication from a game menu) while the window stays open: that ends the
      // session, not the editor.
      if (!wxGetApp().KeepGoing() && !gWindowClosing && !mShell->ExitRequested() && !mPlay.QuitRequested()) {
        wxGetApp().SetKeepGoing();
        mPlay.Stop();
      }
      if ((mShell->ExitRequested() || mPlay.QuitRequested()) && wxGetApp().KeepGoing()) {
        wxTheApp->ExitMainLoop();
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
            mUiClicks.push_back({-1.0f, -1.0f, false, static_cast<char>(std::toupper(static_cast<unsigned char>(point[1])))});
            continue;
          }
          const bool twice = !point.empty() && point[0] == 'd';
          if (twice) {
            point.erase(0, 1);
          }
          const std::size_t comma = point.find(',');
          if (comma != std::string::npos) {
            mUiClicks.push_back({static_cast<float>(std::atof(point.c_str())), static_cast<float>(std::atof(point.c_str() + comma + 1)), twice});
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
      std::transform(wanted.begin(), wanted.end(), wanted.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      const std::vector<std::string>& maps = mPlay.Maps();
      for (std::size_t i = 0; i < maps.size(); ++i) {
        std::string folder = MapDisplayName(maps[i]);
        std::transform(folder.begin(), folder.end(), folder.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (folder == wanted) {
          mPlay.Select(static_cast<int>(i));
          const bool started = mDocument.Open(maps[i]);
          (started ? gpg::Logf : gpg::Warnf)("editor: /open %s: %s %s", args[0].c_str(), started ? "opening" : "can't open", maps[i].c_str());
          return;
        }
      }
      gpg::Warnf("editor: /open %s: no such map", args[0].c_str());
    }

    void EditorApp::SaveDocument()
    {
      std::string message;
      if (mDocument.Save(message)) {
        gpg::Logf("editor: %s", message.c_str());
      } else {
        gpg::Warnf("editor: %s", message.c_str());
      }
    }

    namespace
    {
      /** A Windows file dialog for one kind of file; empty when cancelled. */
      std::filesystem::path AskFile(const HWND owner, const bool save, const wchar_t* const filter, const wchar_t* const extension,
                                    const wchar_t* const title)
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
        dialog.Flags = save ? (OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR) : (OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR);
        const BOOL chosen = save ? ::GetSaveFileNameW(&dialog) : ::GetOpenFileNameW(&dialog);
        return chosen != FALSE ? std::filesystem::path(path) : std::filesystem::path{};
      }

      /** The Windows file dialog for a height image; empty when cancelled. */
      std::filesystem::path AskHeightFile(const HWND owner, const bool save)
      {
        wchar_t path[MAX_PATH] = L"";
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = owner;
        dialog.lpstrFile = path;
        dialog.nMaxFile = MAX_PATH;
        if (save) {
          dialog.lpstrFilter = L"16-bit grey PNG (*.png)\0*.png\0Raw 16-bit (*.raw)\0*.raw\0World Machine (*.r16)\0*.r16\0";
          dialog.lpstrDefExt = L"png";
          dialog.lpstrTitle = L"Export the height field";
          dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
          return ::GetSaveFileNameW(&dialog) != FALSE ? std::filesystem::path(path) : std::filesystem::path{};
        }
        dialog.lpstrFilter = L"Height images (*.png;*.raw;*.r16;*.bmp;*.tif;*.tiff)\0*.png;*.raw;*.r16;*.bmp;*.tif;*.tiff\0All files\0*.*\0";
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
          for (const auto& [id, entry] : rules->GetUnitBlueprints()) {
            moho::RResId resId{};
            resId.name.assign(id.c_str());
            const moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(resId);
            std::string name = blueprint != nullptr ? blueprint->mBlueprintLabel.c_str() : "";
            if (name.rfind("<LOC", 0) == 0) {
              const std::size_t close = name.find('>');
              name = close == std::string::npos ? std::string() : name.substr(close + 1);
            }
            types.emplace_back(id.c_str(), name);
          }
          std::sort(types.begin(), types.end());
          tools.SetUnitTypes(std::move(types));
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
        tools.SetPropTool(comma == std::string::npos ? std::string{} : mPropToolArg.substr(comma + 1), std::atoi(mPropToolArg.c_str()));
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
        mPropThumbnails.Pump(3);
        // `/rdcapture <frame>`: run under RenderDoc (renderdoccmd capture ...), that frame of the editor is captured,
        // through RenderDoc's in-app API (RENDERDOC_GetAPI, version 1.0.0; TriggerCapture is its table's 16th entry).
        if (mRdCaptureFrame < 0) {
          fa::vector<fa::string> value;
          mRdCaptureFrame = moho::CFG_GetArgOption("/rdcapture", 1, &value) && !value.empty() ? std::atoi(value[0].c_str()) : 0;
        }
        if (mRdCaptureFrame > 0 && ++mRdFrames == mRdCaptureFrame) {
          if (const HMODULE renderDoc = ::GetModuleHandleA("renderdoc.dll"); renderDoc != nullptr) {
            using GetApi = int(__cdecl*)(int, void**);
            if (const auto getApi = reinterpret_cast<GetApi>(::GetProcAddress(renderDoc, "RENDERDOC_GetAPI")); getApi != nullptr) {
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
        // `/adaptive <marker>,<army>` (test runs): ties a mass or hydrocarbon marker to an army in the adaptive tables, once
        // (the map becomes adaptive first when it isn't).
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
            std::vector<std::vector<std::string>>& byArmy = marker.rfind("Hydrocarbon", 0) == 0 ? tables.hydroArmy : tables.mexArmy;
            if (army >= 1) {
              byArmy.resize(std::max(byArmy.size(), static_cast<std::size_t>(army)));
              byArmy[static_cast<std::size_t>(army - 1)].push_back(marker);
            }
            mDocument.SetTablesText(WithAdaptiveTables(mDocument.TablesText(), tables));
            gpg::Logf("editor: adaptive: %s spawns with ARMY_%d (tables %s)", marker.c_str(), army, mDocument.Facts().tablesPath.c_str());
          }
        }
        // `/propedit <position|heading|size>,<a>[,<b>,<c>]` (test runs): one edit of the selection, once it has one.
        if (!mPropEditArgDone && tools.SelectionPropertiesNow().kind != SelectionProperties::Kind::None) {
          mPropEditArgDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/propedit", 1, &value) && !value.empty()) {
            const std::string text = value[0].c_str();
            PropertyEdit asked;
            asked.what = text.rfind("position", 0) == 0 ? PropertyEdit::What::Position
                         : text.rfind("heading", 0) == 0 ? PropertyEdit::What::Heading
                         : text.rfind("size", 0) == 0    ? PropertyEdit::What::Size
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
        }
        // The Water panel: its change on the map at once, one undo step when the drag ends.
        tools.SetWater(mDocument.WaterNow());
        if (WaterState water; true) {
          bool final = false;
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
                gpg::Logf("editor: water: %s, level %.2f, deep %.2f, abyss %.2f", water.enabled ? "on" : "off", static_cast<double>(water.elevation),
                          static_cast<double>(water.deep), static_cast<double>(water.abyss));
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
            tools.WaterBodyPick() = mode == "seed" ? EdTools::WaterPick::Seed : mode == "outline" ? EdTools::WaterPick::Outline : EdTools::WaterPick::None;
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
          gpg::Logf("editor: water set: %s, level %.2f, deep %.2f, abyss %.2f", water.enabled ? "on" : "off", static_cast<double>(water.elevation),
                    static_cast<double>(water.deep), static_cast<double>(water.abyss));
          mWaterSetArg.clear();
        }
        tools.SetUnitSelectionCount(mScene.UnitSelectionCount());
        tools.SetUnitSelection(mScene.UnitSelection());
        if (!mUnitToolArg.empty()) {
          const std::size_t first = mUnitToolArg.find(',');
          const std::size_t second = first == std::string::npos ? std::string::npos : mUnitToolArg.find(',', first + 1);
          tools.SetUnitTool(mUnitToolArg.substr(0, first), first == std::string::npos ? std::string() : mUnitToolArg.substr(first + 1, second - first - 1),
                            second != std::string::npos && mUnitToolArg.substr(second + 1) == "select");
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
              int used = std::snprintf(summary, sizeof(summary), "%d props: %.0f mass, %.0f energy. %d give none, %d have no blueprint.",
                                       reclaim.props, reclaim.mass, reclaim.energy, reclaim.none, reclaim.unknown);
              if (wrecks.startCount > 0 && used > 0 && used < static_cast<int>(sizeof(summary))) {
                used += std::snprintf(summary + used, sizeof(summary) - static_cast<std::size_t>(used),
                                      " Unit wrecks from the start: %d, %.0f mass, %.0f energy.", wrecks.startCount, wrecks.startMass,
                                      wrecks.startEnergy);
              }
              if (wrecks.scriptCount > 0 && used > 0 && used < static_cast<int>(sizeof(summary))) {
                (void)std::snprintf(summary + used, sizeof(summary) - static_cast<std::size_t>(used),
                                    " The script's wreck groups, all on: %d more, %.0f mass, %.0f energy (lobby options decide).",
                                    wrecks.scriptCount, wrecks.scriptMass, wrecks.scriptEnergy);
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
                (void)std::snprintf(line, sizeof(line), "%.0f  %d x %s", static_cast<double>(row.mass * static_cast<float>(row.count)), row.count,
                                    name.c_str());
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
        if (!mFrameMarkerArg.empty()) {
          const std::size_t at = mFrameMarkerArg.find('@');
          mScene.FrameMarker(mFrameMarkerArg.substr(0, at),
                             at == std::string::npos ? 140.0f : static_cast<float>(std::atof(mFrameMarkerArg.c_str() + at + 1)));
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
        // The playable area: the panel shows it and asks for changes; `/playablearea x0,z0,x1,z1` (or `none`) for test runs.
        if (const moho::CHeightField* const field = mDocument.Map()->mTerrainRes->GetHeightField(); field != nullptr) {
          const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea();
          tools.SetPlayableArea(area ? std::optional<std::array<int, 4>>(std::array<int, 4>{area->x0, area->z0, area->x1, area->z1}) : std::nullopt,
                                field->width - 1, field->height - 1);
        }
        if (std::optional<std::array<int, 4>> change; tools.TakePlayableAreaChange(change)) {
          mScene.ChangePlayableArea(change ? std::optional<EdDocument::PlayableRect>(EdDocument::PlayableRect{(*change)[0], (*change)[1], (*change)[2], (*change)[3]})
                                           : std::nullopt);
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
        if (tools.TextureToolActive()) {
          tools.SetShaders(mScene.TerrainShaders(), mScene.TerrainShader());
        }
        if (!mShaderArg.empty()) {
          mScene.ChangeTerrainShader(std::exchange(mShaderArg, {}));
        }
        if (std::string shader; tools.TakeShaderChange(shader)) {
          mScene.ChangeTerrainShader(shader);
        }
        switch (tools.TakeMaskOp()) {
        case EdTools::MaskOp::Clear: {
          std::string message;
          report(mScene.ClearMaskLayer(tools.MaskLayer(), message), message);
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
      }
      if (mMaskLayerArg >= 0) {
        // `/layerweight` (test runs): the paint layer's weight shown.
        tools.SetShowLayerWeight(moho::CFG_GetArgOption("/layerweight", 0, nullptr));
        tools.SetMaskLayer(mMaskLayerArg);
        mMaskLayerArg = -1;
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
      if (mBrushModeArg >= 0) {
        tools.SetBrushMode(mBrushModeArg);
        mBrushModeArg = -1;
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
          importFile = AskFile(HandleOf(mGame.supcomFrame), false, L"Water settings (*.scmwtr)\0*.scmwtr\0All files\0*.*\0", L"scmwtr",
                               L"Import water settings");
        }
        if (tools.TakeWaterExport()) {
          exportFile = AskFile(HandleOf(mGame.supcomFrame), true, L"Water settings (*.scmwtr)\0*.scmwtr\0", L"scmwtr", L"Export water settings");
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
                gpg::Logf("editor: water texture %d: %s (was %s)", i, water.textures[i].c_str(), before.textures[i].c_str());
              }
            }
            mDocument.ApplyWater(water);
            mDocument.WaterEdited(before);
            gpg::Logf("editor: water settings imported from %s: colour %.3f %.3f %.3f, sun reflection %.2f", importFile.string().c_str(),
                      static_cast<double>(water.shader.mWaterColor[0]), static_cast<double>(water.shader.mWaterColor[1]),
                      static_cast<double>(water.shader.mWaterColor[2]), static_cast<double>(water.shader.mSunReflectionAmount));
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
      // The Lighting panel's "from another map", or `/lightingfrom <map folder>` for test runs: that map's lighting, read
      // from its .scmap.
      {
        std::string scenario = mShell->TakeLightingFromMap();
        if (mScene.Attached() && !mLightingFromDone) {
          mLightingFromDone = true;
          if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/lightingfrom", 1, &value) && !value.empty()) {
            std::string wanted = value[0].c_str();
            std::transform(wanted.begin(), wanted.end(), wanted.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
            for (const std::string& map : mPlay.Maps()) {
              std::string folder = MapDisplayName(map);
              std::transform(folder.begin(), folder.end(), folder.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
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
          if (!ReadGameFile(scenario, text) || !std::regex_search(text, path, std::regex(R"(\bmap\s*=\s*['"]([^'"]+\.scmap)['"])"))) {
            gpg::Warnf("editor: %s names no map file", scenario.c_str());
          } else if (!ReadGameFile(path[1].str(), bytes) || !LightingFromScmap(bytes, lighting, error)) {
            gpg::Warnf("editor: %s: %s", path[1].str().c_str(), error.empty() ? "can't read it" : error.c_str());
          } else {
            const LightingState before = mDocument.LightingNow();
            mDocument.ApplyLighting(lighting);
            mDocument.LightingEdited(before);
            gpg::Logf("editor: lighting from %s: multiplier %.2f, sun colour %.2f %.2f %.2f, fog %.0f to %.0f", path[1].str().c_str(),
                      static_cast<double>(lighting.multiplier), static_cast<double>(lighting.sunColor[0]), static_cast<double>(lighting.sunColor[1]),
                      static_cast<double>(lighting.sunColor[2]), static_cast<double>(lighting.fogStart), static_cast<double>(lighting.fogEnd));
          }
        }
      }
      // The Lighting panel's settings file, or `/lightingimport <file>`, `/lightingexport <file>` for test runs.
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (mShell->TakeLightingImport()) {
          importFile = AskFile(HandleOf(mGame.supcomFrame), false, L"Lighting settings (*.scmlighting)\0*.scmlighting\0All files\0*.*\0",
                               L"scmlighting", L"Import lighting settings");
        }
        if (mShell->TakeLightingExport()) {
          exportFile = AskFile(HandleOf(mGame.supcomFrame), true, L"Lighting settings (*.scmlighting)\0*.scmlighting\0", L"scmlighting",
                               L"Export lighting settings");
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
            gpg::Logf("editor: lighting imported from %s: multiplier %.2f, sun colour %.2f %.2f %.2f, fog %.0f to %.0f", importFile.string().c_str(),
                      static_cast<double>(lighting.multiplier), static_cast<double>(lighting.sunColor[0]), static_cast<double>(lighting.sunColor[1]),
                      static_cast<double>(lighting.sunColor[2]), static_cast<double>(lighting.fogStart), static_cast<double>(lighting.fogEnd));
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
          importFile = AskFile(HandleOf(mGame.supcomFrame), false, L"Markers (*.fafmapmarkers)\0*.fafmapmarkers\0All files\0*.*\0",
                               L"fafmapmarkers", L"Import markers");
        }
        if (tools.TakeMarkerFileExport()) {
          exportFile = AskFile(HandleOf(mGame.supcomFrame), true, L"Markers (*.fafmapmarkers)\0*.fafmapmarkers\0", L"fafmapmarkers",
                               L"Export markers");
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
          const std::string text = MarkersToFafmapmarkers(mDocument.SaveData().Markers(), names, size, std::max(mDocument.Facts().fieldHeight - 1, 0));
          std::ofstream out(exportFile, std::ios::binary | std::ios::trunc);
          out.write(text.data(), static_cast<std::streamsize>(text.size()));
          const std::size_t count = names.empty() ? mDocument.SaveData().Markers().size() : names.size();
          (out ? gpg::Logf : gpg::Warnf)("editor: %zu markers (%s) exported to %s", count, names.empty() ? "all" : "the selected",
                                        exportFile.string().c_str());
        }
        if (!importFile.empty() && mDocument.GetState() == EdDocument::State::Open) {
          std::ifstream in(importFile, std::ios::binary);
          const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
          MarkerImport result;
          std::string error;
          if (!in || !mScene.ImportMarkerFile(text, result, error)) {
            gpg::Warnf("editor: %s: %s", importFile.string().c_str(), in ? error.c_str() : "can't read it");
          } else {
            gpg::Logf("editor: %zu markers imported from %s (%s to %s), %d path links, %d of a type the editor doesn't place left out",
                      result.names.size(), importFile.string().c_str(), result.names.empty() ? "-" : result.names.front().c_str(),
                      result.names.empty() ? "-" : result.names.back().c_str(), result.links, result.skipped);
          }
        }
      }
      // The Units tool's units file, or `/unitsimport <file>`, `/unitsexport <file>` for test runs (the Units tool's army).
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (tools.TakeUnitFileImport()) {
          importFile = AskFile(HandleOf(mGame.supcomFrame), false, L"Units (*.scunits)\0*.scunits\0All files\0*.*\0", L"scunits",
                               L"Import units");
        }
        if (tools.TakeUnitFileExport()) {
          exportFile = AskFile(HandleOf(mGame.supcomFrame), true, L"Units (*.scunits)\0*.scunits\0", L"scunits", L"Export units");
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
          (out ? gpg::Logf : gpg::Warnf)("editor: %zu units (%s) exported to %s", units.size(),
                                        mScene.UnitSelectionCount() > 0 ? "the selected" : tools.UnitArmy().c_str(), exportFile.string().c_str());
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
            gpg::Logf("editor: %zu units imported from %s into %s (%s to %s)%s", names.size(), importFile.string().c_str(),
                      tools.UnitArmy().c_str(), names.front().c_str(), names.back().c_str(), moved ? ", moved onto this map" : "");
          }
        }
      }
      // The Texture tool's layer files, or `/layerimport <slot>,<file>`, `/layerexport <slot>,<file>`, `/layersetimport <file>`,
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
          static const char* const kSwitches[4] = {"/layersetexport", "/layerexport", "/layersetimport", "/layerimport"};
          static const EdTools::LayerFileAsk kAsks[4] = {EdTools::LayerFileAsk::ExportSet, EdTools::LayerFileAsk::ExportLayer,
                                                         EdTools::LayerFileAsk::ImportSet, EdTools::LayerFileAsk::ImportLayer};
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
            const std::string text = set ? LayersToScmst(mScene.TerrainShader(), layers) : LayerToScmsl(layers[static_cast<std::size_t>(slot)]);
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            if (set) {
              (out ? gpg::Logf : gpg::Warnf)("editor: the layer set (%s) exported to %s", mScene.TerrainShader().c_str(), file.string().c_str());
            } else {
              (out ? gpg::Logf : gpg::Warnf)("editor: layer %d (%s) exported to %s", slot, layers[static_cast<std::size_t>(slot)].albedo.c_str(),
                                            file.string().c_str());
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
              gpg::Logf("editor: %s imported from %s: %d change%s (one undo step)", set ? "a layer set" : "a layer", file.string().c_str(),
                        changed, changed == 1 ? "" : "s");
            }
          }
        }
      }
      // The Props tool's paint list, or `/paintset <file>` (into the list) and `/paintsetexport <file>` for test runs.
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (tools.TakePaintSetImport()) {
          importFile = AskFile(HandleOf(mGame.supcomFrame), false, L"Prop paint sets (*.proppaintset)\0*.proppaintset\0All files\0*.*\0",
                               L"proppaintset", L"Import a prop paint set");
        }
        if (tools.TakePaintSetExport()) {
          exportFile = AskFile(HandleOf(mGame.supcomFrame), true, L"Prop paint sets (*.proppaintset)\0*.proppaintset\0", L"proppaintset",
                               L"Export the paint list");
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
                gpg::Warnf("editor: %s: no prop blueprint %s; Scatter skips it until it is there", importFile.string().c_str(), entry.blueprint.c_str());
                ++unknown;
              }
            }
            gpg::Logf("editor: paint list from %s: %zu props (%d unknown)", importFile.string().c_str(), entries.size(), unknown);
            tools.SetPaintList(std::move(entries));
          }
        }
        if (!exportFile.empty()) {
          const std::string text = PaintSetToProppaintset(tools.PaintList());
          std::ofstream out(exportFile, std::ios::binary | std::ios::trunc);
          out.write(text.data(), static_cast<std::streamsize>(text.size()));
          (out ? gpg::Logf : gpg::Warnf)("editor: paint list (%zu props) exported to %s", tools.PaintList().size(), exportFile.string().c_str());
        }
      }
      // The Lighting panel's sky file, or `/skyboximport <file>`, `/skyboxexport <file>` for test runs.
      {
        std::filesystem::path importFile;
        std::filesystem::path exportFile;
        if (mShell->TakeSkyboxImport()) {
          importFile = AskFile(HandleOf(mGame.supcomFrame), false, L"Sky (*.scmskybox)\0*.scmskybox\0All files\0*.*\0", L"scmskybox",
                               L"Import a sky");
        }
        if (mShell->TakeSkyboxExport()) {
          exportFile = AskFile(HandleOf(mGame.supcomFrame), true, L"Sky (*.scmskybox)\0*.scmskybox\0", L"scmskybox", L"Export the sky");
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
          (out ? gpg::Logf : gpg::Warnf)("editor: the sky (%zu planets, cirrus %s) exported to %s", sky.planets.size(), sky.cirrusTexture.c_str(),
                                        exportFile.string().c_str());
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
            gpg::Logf("editor: sky imported from %s: dome %.0f, %zu planets, zenith %.2f %.2f %.2f", importFile.string().c_str(),
                      static_cast<double>(sky.scale), sky.planets.size(), static_cast<double>(sky.zenithColor[0]),
                      static_cast<double>(sky.zenithColor[1]), static_cast<double>(sky.zenithColor[2]));
          }
        }
      }
      // The Water panel's waves, or `/waves <pattern>,<depth>,<density %>[,<spacing>]`, `/wavesclear`, `/wavesexport <file>`,
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
            return moho::CFG_GetArgOption(option, 1, &value) && !value.empty() ? std::filesystem::path(value[0].c_str()) : std::filesystem::path();
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
              path = AskFile(owner, true, L"Waves (*.scmwaves)\0*.scmwaves\0", L"scmwaves", L"Export the wave generators");
            }
            if (!path.empty()) {
              const std::vector<WaveRecord> waves = mDocument.WavesNow();
              const std::string text = WavesToScmwaves(waves);
              std::ofstream out(path, std::ios::binary | std::ios::trunc);
              out.write(text.data(), static_cast<std::streamsize>(text.size()));
              (out ? gpg::Logf : gpg::Warnf)("editor: %zu wave generators exported to %s", waves.size(), path.string().c_str());
            }
          } else if (what == EdTools::WaveAsk::Import || what == EdTools::WaveAsk::LoadPatterns) {
            const bool patterns = what == EdTools::WaveAsk::LoadPatterns;
            if (path.empty()) {
              path = patterns ? AskFile(owner, false, L"Wave patterns (*.lua)\0*.lua\0All files\0*.*\0", L"lua", L"Load wave patterns")
                              : AskFile(owner, false, L"Waves (*.scmwaves)\0*.scmwaves\0All files\0*.*\0", L"scmwaves", L"Import wave generators");
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
            gpg::Logf("editor: %zu wave generators imported from %s (in place of the map's)", waves.size(), path.string().c_str());
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
            std::vector<float> heights(static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height));
            for (int z = 0; z < field->height; ++z) {
              for (int x = 0; x < field->width; ++x) {
                heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(x)] =
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
            gpg::Logf("editor: %zu %s waves added along the shore (%zu places at depth %.2f, %.0f%% of them, spacing %.1f), %d now",
                      picked.size(), settings.pattern.name.c_str(), found.size(), static_cast<double>(settings.depth),
                      static_cast<double>(settings.density * 100.0f), static_cast<double>(settings.spacing), mDocument.WaveCount());
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
        if (const EdTools::GroupAsk ask = tools.TakeGroupAsk(path, name); ask != EdTools::GroupAsk::None && mDocument.GetState() == EdDocument::State::Open) {
          mScene.ChangeUnitGroups(tools.UnitArmy(), ask, path, name);
          mUnitTreeFrames = 0;
        }
        if (EdTools::UnitWreckAsk wreck; tools.TakeUnitWreck(wreck) && mDocument.GetState() == EdDocument::State::Open) {
          mScene.SetUnitsWreck(wreck.army, wreck.names, wreck.wreck);
          mUnitTreeFrames = 0;
        }
        if (EdTools::UnitGroupAsk group; tools.TakeUnitGroup(group) && mDocument.GetState() == EdDocument::State::Open) {
          if (group.select) {
            mScene.SelectUnits(std::move(group.units));
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
          const EdTools::GroupAsk ask = verb == "add" ? EdTools::GroupAsk::Add : verb == "rename" ? EdTools::GroupAsk::Rename
                                        : verb == "remove" ? EdTools::GroupAsk::Remove : verb == "move" ? EdTools::GroupAsk::MoveSelected
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
          vfs->MountDirectoryLate(folder, ("/maps/" + folder.filename().string()).c_str());
        }
        mPlay.FindMaps();
        (void)mDocument.Open(scenario);
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
        gpg::Logf("editor: round trip of the drawn %s: %s%s", MapDisplayName(mDocument.Path()).c_str(),
                  trip.ok ? "same data, stable" : trip.differences.c_str(), trip.sameAsOriginal ? ", same bytes as the original" : "");
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
            gpg::Logf("editor: round trip %s: %s%s%s", MapDisplayName(mDocument.Path()).c_str(), trip.ok ? "same data" : trip.differences.c_str(),
                      trip.hasDiskFile ? (trip.sameAsOriginal ? ", same bytes as the original" : ", other bytes than the original") : "",
                      trip.stable ? "" : ", NOT stable");
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
        gpg::Logf("editor: round trip: %d of %d maps read back with the same data; %d of the %d with a file of their own "
                  "saved to the same bytes",
                  mRoundTripOk, mOpenAllOpened, mRoundTripSameBytes, mRoundTripDiskFiles);
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
      // presented: copied into a target the panels draw under themselves. Not while a dialog hides the view.
      mViewImage = 0;
      gViewSurface = nullptr;
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      moho::CD3DDevice* const d3d = moho::D3D_GetDevice();
      const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
      if (!gComposite || d3d == nullptr || context == nullptr || context->GetHeadCount() < 1 || d3d->GetResources() == nullptr ||
          (mImGuiReady && ImGui::GetTopMostPopupModal() != nullptr)) {
        return;
      }
      const gpg::gal::Head& game = context->GetHead(0);
      if (game.mWidth == 0 || game.mHeight == 0) {
        return;
      }
      if (!mViewCopy || mViewCopyWidth != game.mWidth || mViewCopyHeight != game.mHeight) {
        mViewCopy.reset();
        moho::ID3DDeviceResources::RenderTargetHandle target;
        (void)d3d->GetResources()->CreateRenderTarget(target, static_cast<int>(game.mWidth), static_cast<int>(game.mHeight), 2);
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
      device->StretchRect(output->surface, copy, nullptr, nullptr);
      mViewImage = EdImGuiRenderer::TargetImage(copy.get());
      mViewSurface = copy;
      gViewSurface = copy.get();
    }

    void EditorApp::FitGameView()
    {
      const HWND frame = HandleOf(mGame.supcomFrame);
      const HWND view = HandleOf(moho::ren_Viewport);
      moho::CD3DDevice* const d3d = moho::D3D_GetDevice();
      if (frame == nullptr || view == nullptr || d3d == nullptr || ::IsIconic(frame) != FALSE) {
        return;
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
      const bool modal = mImGuiReady && (ImGui::GetTopMostPopupModal() != nullptr || (!gComposite && mShell != nullptr && mShell->Browser().Open()));
      std::vector<RECT> holes;
      if (mImGuiReady && !modal) {
        for (const ImGuiWindow* const window : ImGui::GetCurrentContext()->Windows) {
          // A window not docked into the layout (the Maps window, the Material Editor, any panel pulled out) floats over
          // the view and takes the mouse there; the dock space's own host window (behind everything) doesn't.
          const bool undocked = (window->Flags & ImGuiWindowFlags_NoBringToFrontOnFocus) == 0 &&
                                (window->DockNode == nullptr || ImGui::DockNodeGetRootNode(window->DockNode)->IsFloatingNode());
          const bool floating = undocked || std::strncmp(window->Name, EdMapBrowser::kWindowName, std::strlen(EdMapBrowser::kWindowName)) == 0;
          if (!window->WasActive || window->Hidden ||
              ((window->Flags & (ImGuiWindowFlags_Tooltip | ImGuiWindowFlags_Popup | ImGuiWindowFlags_ChildMenu)) == 0 && !floating) ||
              (window->Flags & ImGuiWindowFlags_ChildWindow) != 0) {
            continue;
          }
          RECT hole{static_cast<LONG>(window->Pos.x) - x, static_cast<LONG>(window->Pos.y) - y,
                    static_cast<LONG>(window->Pos.x + window->Size.x + 1.0f) - x, static_cast<LONG>(window->Pos.y + window->Size.y + 1.0f) - y};
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
      if (viewRect.left != x || viewRect.top != y || viewRect.right - viewRect.left != width || viewRect.bottom - viewRect.top != height) {
        moho::ren_Viewport->SetSize(x, y, width, height);
      }

      // The heads follow: the game's head 0 the viewport, the panels' head the client area. The game's own frame
      // handler sets head 0 to the whole client area when the window is resized; this puts it back.
      const gpg::gal::DeviceContext* const active = gpg::gal::Device::GetInstance()->GetDeviceContext();
      if (active->GetHeadCount() <= static_cast<int>(kPanelHead)) {
        return;
      }
      const gpg::gal::Head& gameHead = active->GetHead(0);
      const gpg::gal::Head& panelHead = active->GetHead(kPanelHead);
      if (gameHead.mWidth != static_cast<std::uint32_t>(width) || gameHead.mHeight != static_cast<std::uint32_t>(height) ||
          panelHead.mWidth != static_cast<std::uint32_t>(clientWidth) || panelHead.mHeight != static_cast<std::uint32_t>(clientHeight)) {
        gpg::gal::DeviceContext context(*active);
        context.GetHead(0).mWidth = static_cast<std::uint32_t>(width);
        context.GetHead(0).mHeight = static_cast<std::uint32_t>(height);
        context.GetHead(kPanelHead).mWidth = static_cast<std::uint32_t>(clientWidth);
        context.GetHead(kPanelHead).mHeight = static_cast<std::uint32_t>(clientHeight);
        d3d->Clear();
        (void)d3d->InitContext(&context);
      }
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
      delete mShell;
      mShell = nullptr;
      // The opened map's textures go while the device is up.
      mDocument.Close();
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
    void EditorDieHandler(const char* const message)
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

#include "editor/EdApp.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

#include <Windows.h>
#include <ShlObj.h>
#include <commdlg.h>

#include <algorithm>
#include <optional>
#include <cstdio>
#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "editor/EdLog.h"
#include "editor/EdMemTrace.h"
#include "editor/EdPlay.h"
#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdRoundTrip.h"
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
#include "moho/misc/StartupHelpers.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/d3d/CD3DDevice.h"
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
      kMenuPanelsWhilePlaying = 1104,
      kMenuResetLayout = 1105,
      kMenuImGuiDemo = 1106,
      kMenuPlayStop = 1201,
      kMenuSave = 1002,
      kMenuSaveAs = 1003,
      kMenuNew = 1004,
      kMenuUndo = 1301,
      kMenuRedo = 1302,
      kMenuDelete = 1303,
      kMenuFirstMap = 2000,
    };

    class EditorApp;
    EditorApp* gEditorApp = nullptr;
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
      int mBrowseArg = -1;
      // `/shader <name>` with `/open` (test runs): the map's terrain shader changed once it is shown.
      std::string mShaderArg;
      std::string mPlayableAreaArg;
      std::string mMarkerToolArg;
      /** `/framemarker <name>[@distance]` (test runs): the camera goes to that marker once the map is shown. */
      std::string mFrameMarkerArg;
      /** `/waterset <on>,<level>,<deep>,<abyss>` (test runs): the sea set as one edit once the map is shown. */
      std::string mWaterSetArg;
      bool mWaterDragging = false;
      WaterState mWaterBefore;
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
      if (fa::vector<fa::string> args; moho::CFG_GetArgOption("/logtimes", 1, &args) && !args.empty()) {
        mLog.WriteTimesTo(args[0].c_str());
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
      // `/playsetups <file>` (test runs) reads and writes the play setups there instead.
      if (fa::vector<fa::string> args; moho::CFG_GetArgOption("/playsetups", 1, &args) && !args.empty()) {
        mPlay.SetSetupsFile(args[0].c_str());
      } else if (const std::filesystem::path folder = EditorSettingsFolder(); !folder.empty()) {
        mPlay.SetSetupsFile((folder / "play_setups.ini").string());
      }
      mPlay.FindMaps();
      mPlay.ReadCommandLine();
      mShell = new EdShell(mLog, mPlay, mDocument);
      mDocument.SetBeforeDrop([this] { mScene.Detach(); });
      // The vault, as init_faf.lua finds it without the client's custom path: Documents\My Games\...;
      // `/vault <folder>` sets another (the FAF client's custom vault, or a test folder).
      if (fa::vector<fa::string> vault; moho::CFG_GetArgOption("/vault", 1, &vault) && !vault.empty()) {
        mDocument.SetVaultFolder(vault[0].c_str());
      } else if (PWSTR documents = nullptr; SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &documents))) {
        mDocument.SetVaultFolder(std::filesystem::path(documents) / "My Games" / "Gas Powered Games" / "Supreme Commander Forged Alliance");
        ::CoTaskMemFree(documents);
      }
      gpg::Logf("editor: the vault is %s", mDocument.VaultFolder().string().c_str());
      mScene.SetTools(&mShell->Tools());
      ReadOpenCommandLine();
      gEditorApp = this;
      BuildMenu(frame);
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
      ImGui_ImplWin32_Init(gPanelWindow);
    }

    void EditorApp::BuildMenu(const HWND frame)
    {
      HMENU file = ::CreatePopupMenu();
      ::AppendMenuW(file, MF_STRING, kMenuNew, L"&New map...\tCtrl+N");
      ::AppendMenuW(file, MF_STRING | MF_GRAYED, 0, L"&Open map...\tCtrl+O");
      ::AppendMenuW(file, MF_STRING, kMenuSave, L"&Save\tCtrl+S");
      ::AppendMenuW(file, MF_STRING, kMenuSaveAs, L"Save as new map &folder...");
      mFileMenu = file;
      ::AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
      ::AppendMenuW(file, MF_STRING, kMenuExit, L"E&xit");

      mViewMenu = ::CreatePopupMenu();
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuTools, L"&Tools");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuMap, L"&Map");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuInfo, L"&Info");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuMarkers, L"Mar&kers");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuCheck, L"&Check");
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
      check(kMenuLog, mShell->ShowLog());
      check(kMenuPanelsWhilePlaying, mShell->PanelsWhilePlaying());
      check(kMenuImGuiDemo, mShell->ShowDemo());

      const bool active = mPlay.Active();
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
      case kMenuSaveAs:
        mShell->OpenSaveAs();
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
      mLastFrame = now;
      mScene.Update(frameSeconds, moho::WLD_GetFrameAction() == moho::EWldFrameAction::Inactive);

      if (mImGuiReady) {
        ImGui_ImplWin32_NewFrame();
        FeedUiClicks();
        ImGui::NewFrame();
        mShell->Draw();
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
        // Undo and redo from the panels too (the viewport's keys go to the scene directly).
        if (!ImGui::GetIO().WantTextInput) {
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
      if (fa::vector<fa::string> marker; moho::CFG_GetArgOption("/framemarker", 1, &marker) && !marker.empty()) {
        mFrameMarkerArg = marker[0].c_str();
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
          (void)mDocument.Open(maps[i]);
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
        tools.SetDecalSelectionCount(mScene.DecalSelectionCount());
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
        if (!mUnitToolArg.empty()) {
          const std::size_t first = mUnitToolArg.find(',');
          const std::size_t second = first == std::string::npos ? std::string::npos : mUnitToolArg.find(',', first + 1);
          tools.SetUnitTool(mUnitToolArg.substr(0, first), first == std::string::npos ? std::string() : mUnitToolArg.substr(first + 1, second - first - 1),
                            second != std::string::npos && mUnitToolArg.substr(second + 1) == "select");
          mUnitToolArg.clear();
        }
        if (tools.PropsToolActive()) {
          tools.SetPropDetails(mScene.PropDetails(tools.PropBlueprint()));
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
          if (moho::CFG_GetArgOption("/check", 0, nullptr)) {
            mShell->RequestCheck();
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
        tools.SetMarkerSelection(mScene.SelectedMarkers());
        tools.SetArmies(mDocument.Armies(), mDocument.ExtraArmies());
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

      // A modal dialog of the panels (New map, Save as, the texture browser) would be hidden behind the game's
      // view, which is a window of its own over the panels' window: while one is open the view's window region
      // is empty, so the dialog shows through. Hiding the window instead would stop its paint, and the panels'
      // head is presented with it.
      const bool modal = mImGuiReady && ImGui::GetTopMostPopupModal() != nullptr;
      if (modal != mViewStepsAside) {
        mViewStepsAside = modal;
        ::SetWindowRgn(view, modal ? ::CreateRectRgn(0, 0, 0, 0) : nullptr, TRUE);
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

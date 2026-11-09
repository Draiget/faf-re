#include "editor/EdApp.h"

#include <Windows.h>

#include <algorithm>
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
#include "editor/ui/EdImGuiRenderer.h"
#include "editor/view/EdMapScene.h"
#include "gpg/core/diagnostics/CrashHooks.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/Error.hpp"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "moho/app/CScApp.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/misc/SessionStartup.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/sim/RRuleGameRules.h"
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
      kMenuPanelsWhilePlaying = 1104,
      kMenuResetLayout = 1105,
      kMenuImGuiDemo = 1106,
      kMenuPlayStop = 1201,
      kMenuUndo = 1301,
      kMenuRedo = 1302,
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
      ::AppendMenuW(file, MF_STRING | MF_GRAYED, 0, L"&New map...\tCtrl+N");
      ::AppendMenuW(file, MF_STRING | MF_GRAYED, 0, L"&Open map...\tCtrl+O");
      ::AppendMenuW(file, MF_STRING | MF_GRAYED, 0, L"&Save\tCtrl+S");
      ::AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
      ::AppendMenuW(file, MF_STRING, kMenuExit, L"E&xit");

      mViewMenu = ::CreatePopupMenu();
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuTools, L"&Tools");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuMap, L"&Map");
      ::AppendMenuW(mViewMenu, MF_STRING, kMenuInfo, L"&Info");
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
      case kMenuInfo:
        mShell->ShowInfo() = !mShell->ShowInfo();
        break;
      case kMenuUndo:
        (void)mScene.Undo();
        break;
      case kMenuRedo:
        (void)mScene.Redo();
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
        ImGui::NewFrame();
        mShell->Draw();
        // Undo and redo from the panels too (the viewport's keys go to the scene directly).
        if (!ImGui::GetIO().WantTextInput) {
          if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Z)) {
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
      // `/openall` (test runs): every map opened in turn, then a summary, then the editor closes.
      if (moho::CFG_GetArgOption("/openall", 0, nullptr)) {
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

    void EditorApp::DriveOpens()
    {
      const bool finished = mDocument.Poll();
      if (!mOpenAll) {
        return;
      }
      if (finished) {
        if (mDocument.GetState() == EdDocument::State::Open && mDocument.Error().empty()) {
          ++mOpenAllOpened;
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

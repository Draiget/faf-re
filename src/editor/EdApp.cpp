#include "editor/EdApp.h"

#include <Windows.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "editor/EdLog.h"
#include "editor/EdPlay.h"
#include "editor/EdShell.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "moho/app/CScApp.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/IEdRenderHook.h"
#include "moho/render/WRenViewport.h"

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

    /** Draws the editor's ImGui frame at the end of the game's UI pass (`WRenViewport::RenderUI`). */
    class EdRenderHook final : public moho::IEdRenderHook
    {
    public:
      explicit EdRenderHook(EdImGuiRenderer& renderer)
        : mRenderer(renderer)
      {}

      void Render() override { mRenderer.Render(ImGui::GetDrawData()); }

    private:
      EdImGuiRenderer& mRenderer;
    };

    // The window procedures the editor put in front of the game's, and what they replaced.
    WNDPROC gViewportProc = nullptr;
    WNDPROC gFrameProc = nullptr;
    bool gWindowClosing = false;

    [[nodiscard]] bool IsMouseMessage(const UINT message)
    {
      return (message >= WM_MOUSEFIRST && message <= WM_MOUSELAST) || message == WM_MOUSEHOVER || message == WM_MOUSELEAVE;
    }

    [[nodiscard]] bool IsKeyboardMessage(const UINT message)
    {
      return (message >= WM_KEYFIRST && message <= WM_KEYLAST) || message == WM_SYSKEYDOWN || message == WM_SYSKEYUP;
    }

    /**
     * The game viewport's input goes to ImGui first. What ImGui takes (the mouse over a panel, the keyboard in
     * a text field) stops there; the rest reaches the game as before.
     */
    LRESULT CALLBACK EditorViewportProc(const HWND window, const UINT message, const WPARAM wParam, const LPARAM lParam)
    {
      if (ImGui::GetCurrentContext() != nullptr) {
        const ImGuiIO& io = ImGui::GetIO();
        // The cursor is the game's unless it is over a panel.
        if (message != WM_SETCURSOR || io.WantCaptureMouse) {
          (void)ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam);
        }
        if ((IsMouseMessage(message) && io.WantCaptureMouse) || (IsKeyboardMessage(message) && io.WantCaptureKeyboard) ||
            (message == WM_CHAR && io.WantTextInput) || (message == WM_SETCURSOR && io.WantCaptureMouse)) {
          return message == WM_SETCURSOR ? TRUE : 0;
        }
      }
      return ::CallWindowProcW(gViewportProc, window, message, wParam, lParam);
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
      return ::CallWindowProcW(gFrameProc, window, message, wParam, lParam);
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

    private:
      void SetUpImGui();

      CScApp mGame;
      EdLog mLog;
      EdImGuiRenderer mRenderer;
      EdRenderHook mHook{mRenderer};
      EdPlay mPlay;
      EdShell* mShell = nullptr;
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
      if (frame == nullptr || viewport == nullptr) {
        gpg::Warnf("editor: the game window is missing");
        return false;
      }
      const gpg::gal::DeviceContext* const context = gpg::gal::Device::GetInstance()->GetDeviceContext();
      const char* const api = context->mDeviceType == DeviceApi::Vulkan ? "Vulkan" : "Direct3D 12";
      const std::wstring title = std::wstring(kTitle) + L" [" + std::wstring(api, api + std::char_traits<char>::length(api)) + L"]";
      ::SetWindowTextW(frame, title.c_str());

      gViewportProc = reinterpret_cast<WNDPROC>(::SetWindowLongPtrW(viewport, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&EditorViewportProc)));
      gFrameProc = reinterpret_cast<WNDPROC>(::SetWindowLongPtrW(frame, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&EditorFrameProc)));

      SetUpImGui();
      if (!mRenderer.Init()) {
        ::MessageBoxW(nullptr, L"The editor's panels could not be set up on this device. See the log.", kTitle, MB_OK | MB_ICONERROR);
        return false;
      }
      mImGuiReady = true;
      moho::ED_SetHook(&mHook);
      mPlay.FindMaps();
      mPlay.ReadCommandLine();
      mShell = new EdShell(mLog, mPlay);
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

      const HWND viewport = HandleOf(moho::ren_Viewport);
      const float dpiScale = ImGui_ImplWin32_GetDpiScaleForHwnd(viewport);
      style.ScaleAllSizes(dpiScale);
      style.FontScaleDpi = dpiScale;
      io.ConfigDpiScaleFonts = true;

      std::error_code error;
      const std::filesystem::path segoe = "C:\\Windows\\Fonts\\segoeui.ttf";
      if (std::filesystem::exists(segoe, error)) {
        (void)io.Fonts->AddFontFromFileTTF(segoe.string().c_str(), 16.0f);
      }
      ImGui_ImplWin32_Init(viewport);
    }

    void EditorApp::Main()
    {
      // Stop, and the game's own way out of a session (its menu's exit, a defeat screen's "exit"), end the
      // session here, before CScApp::Main runs WLD_Frame: the game would go on to its main menu.
      mPlay.BeforeGameFrame();

      if (mImGuiReady) {
        ImGuiIO& io = ImGui::GetIO();
        // The game owns the cursor's look except over a panel.
        if (io.WantCaptureMouse) {
          io.ConfigFlags &= ~ImGuiConfigFlags_NoMouseCursorChange;
        } else {
          io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
        }
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        mShell->Draw();
        ImGui::Render();
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

    void EditorApp::Destroy()
    {
      moho::ED_SetHook(nullptr);
      if (mImGuiReady) {
        mRenderer.Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        mImGuiReady = false;
      }
      delete mShell;
      mShell = nullptr;
      if (const HWND viewport = HandleOf(moho::ren_Viewport); viewport != nullptr && gViewportProc != nullptr) {
        (void)::SetWindowLongPtrW(viewport, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(gViewportProc));
      }
      if (const HWND frame = HandleOf(mGame.supcomFrame); frame != nullptr && gFrameProc != nullptr) {
        (void)::SetWindowLongPtrW(frame, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(gFrameProc));
      }
      mGame.Destroy();
      exitValue = mGame.exitValue;
    }
  } // namespace

  int RunEditor()
  {
    EditorApp app;
    moho::WIN_AppExecute(&app);
    return app.exitValue;
  }
} // namespace faf::editor

#include "editor/EdApp.h"

#include <Windows.h>
#include <objbase.h>

#include <cfloat>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <string>

#include "editor/EdDevice.h"
#include "editor/EdLog.h"
#include "editor/EdShell.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Error.hpp"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "moho/app/IWinApp.h"
#include "moho/app/WinApp.h"
#include "moho/core/ThreadPlacement.h"
#include "moho/misc/StartupHelpers.h"
#include "platform/X87Precision.h"

// imgui_impl_win32.h leaves this declaration to the application.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace faf::editor
{
  namespace
  {
    constexpr wchar_t kWindowClass[] = L"FafMapEditor";
    constexpr char kTitle[] = "FAF Map Editor";

    /** The common services every engine app sets up (`IWinApp::AppInitCommonServices`), as headless has them. */
    class EditorApp final : public moho::IWinApp
    {
    public:
      EditorApp()
        : moho::IWinApp("SupCom", "SupremeCommander")
      {}

      bool Init() override { return AppInitCommonServices(); }
      void Main() override {}
      void Destroy() override {}
    };

    void ShowError(const std::string& text)
    {
      ::MessageBoxA(nullptr, text.c_str(), kTitle, MB_OK | MB_ICONERROR);
    }

    void EditorDieHandler(const char* const message)
    {
      ShowError(std::string("The engine stopped: ") + (message != nullptr ? message : "Die()"));
      ::ExitProcess(3);
    }

    /** What the window procedure hands to the frame loop. */
    struct WindowEvents
    {
      bool resized = false;
      std::uint32_t width = 0U;
      std::uint32_t height = 0U;
    };
    WindowEvents gWindowEvents;

    LRESULT CALLBACK EditorWindowProc(const HWND window, const UINT message, const WPARAM wParam, const LPARAM lParam)
    {
      if (ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam) != 0) {
        return 1;
      }
      switch (message) {
      case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) {
          gWindowEvents.width = LOWORD(lParam);
          gWindowEvents.height = HIWORD(lParam);
          gWindowEvents.resized = true;
        }
        return 0;
      case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0U) == SC_KEYMENU) {
          return 0; // Alt alone doesn't open the window menu
        }
        break;
      case WM_DPICHANGED: {
        const auto* const suggested = reinterpret_cast<const RECT*>(lParam);
        ::SetWindowPos(
          window, nullptr, suggested->left, suggested->top, suggested->right - suggested->left,
          suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE
        );
        return 0;
      }
      case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
      default:
        break;
      }
      return ::DefWindowProcW(window, message, wParam, lParam);
    }

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

    void SetUpImGui(const HWND window, std::string& iniPath)
    {
      IMGUI_CHECKVERSION();
      ImGui::CreateContext();
      ImGuiIO& io = ImGui::GetIO();
      io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
      const std::filesystem::path settings = EditorSettingsFolder();
      if (settings.empty()) {
        io.IniFilename = nullptr;
      } else {
        iniPath = (settings / "layout.ini").string();
        io.IniFilename = iniPath.c_str();
      }

      ImGui::StyleColorsDark();
      ImGuiStyle& style = ImGui::GetStyle();
      style.WindowRounding = 2.0f;
      style.FrameRounding = 3.0f;
      style.TabRounding = 3.0f;
      style.Colors[ImGuiCol_WindowBg] = ImVec4(0.110f, 0.122f, 0.145f, 1.0f);
      style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.18f, 0.20f, 0.24f, 1.0f);
      style.Colors[ImGuiCol_Header] = ImVec4(0.89f, 0.58f, 0.26f, 0.30f);
      style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.89f, 0.58f, 0.26f, 0.45f);
      style.Colors[ImGuiCol_CheckMark] = ImVec4(0.89f, 0.58f, 0.26f, 1.0f);
      style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.89f, 0.58f, 0.26f, 1.0f);

      const float dpiScale = ImGui_ImplWin32_GetDpiScaleForHwnd(window);
      style.ScaleAllSizes(dpiScale);
      style.FontScaleDpi = dpiScale;
      io.ConfigDpiScaleFonts = true;

      std::error_code error;
      const std::filesystem::path segoe = "C:\\Windows\\Fonts\\segoeui.ttf";
      if (std::filesystem::exists(segoe, error)) {
        (void)io.Fonts->AddFontFromFileTTF(segoe.string().c_str(), 16.0f);
      }
      ImGui_ImplWin32_Init(window);
    }

    [[nodiscard]] std::wstring WindowTitle(const EdDevice& device)
    {
      const std::string title = std::string(kTitle) + " [" + device.ApiName() + "]";
      return std::wstring(title.begin(), title.end());
    }
  } // namespace

  int RunEditor()
  {
    ImGui_ImplWin32_EnableDpiAwareness();
    (void)gpg::SetDieHandler(&EditorDieHandler);
    EdLog log;

    // `WinMain` / `CScApp::CScApp`, then `CScApp::Init`'s common part, as headless does it.
    moho::APP_InitializeIdentity();
    (void)::CoInitialize(nullptr);
    moho::PLAT_Init();
    if (!moho::CFG_GetArgOption("/init", 1, nullptr)) {
      gpg::Warnf("editor: no /init <file>; the game data comes from SupComDataPath.lua next to the exe, if there is one");
    }
    EditorApp app;
    if (!app.Init()) {
      ShowError("The engine's services did not start (see the log).");
      return 3;
    }
    platform::SetX87PrecisionControl(_PC_24);
    moho::PlaceCurrentThread(moho::EThreadRole::Main);

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_CLASSDC;
    windowClass.lpfnWndProc = &EditorWindowProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.lpszClassName = kWindowClass;
    (void)::RegisterClassExW(&windowClass);
    const HWND window = ::CreateWindowExW(
      0, kWindowClass, L"FAF Map Editor", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1600, 1000, nullptr, nullptr,
      windowClass.hInstance, nullptr
    );
    if (window == nullptr) {
      ShowError("The editor window could not be created.");
      return 4;
    }
    ::ShowWindow(window, moho::CFG_GetArgOption("/windowed", 0, nullptr) ? SW_SHOWNORMAL : SW_SHOWMAXIMIZED);
    ::UpdateWindow(window);
    RECT client{};
    ::GetClientRect(window, &client);

    EdDevice device;
    if (!device.Create(window, static_cast<std::uint32_t>(client.right - client.left), static_cast<std::uint32_t>(client.bottom - client.top))) {
      ShowError("Neither Direct3D 12 nor Vulkan started; the editor needs one of them.\n\n" + device.Failures());
      ::DestroyWindow(window);
      return 5;
    }
    ::SetWindowTextW(window, WindowTitle(device).c_str());
    gWindowEvents.resized = false;

    std::string iniPath;
    SetUpImGui(window, iniPath);
    EdImGuiRenderer renderer;
    if (!renderer.Init()) {
      ShowError("The editor's UI could not be set up on this device (see the log).");
      return 6;
    }
    EdShell shell(device, log);

    int exitCode = 0;
    try {
      bool running = true;
      while (running) {
        MSG message{};
        while (::PeekMessageW(&message, nullptr, 0U, 0U, PM_REMOVE)) {
          ::TranslateMessage(&message);
          ::DispatchMessageW(&message);
          if (message.message == WM_QUIT) {
            running = false;
          }
        }
        if (!running) {
          break;
        }
        if (::IsIconic(window)) {
          ::Sleep(16);
          continue;
        }
        if (gWindowEvents.resized) {
          gWindowEvents.resized = false;
          device.Resize(gWindowEvents.width, gWindowEvents.height);
        }

        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        const bool keepRunning = shell.Draw();
        ImGui::Render();
        if (!keepRunning) {
          break;
        }

        device.BeginFrame(0xFF0D0F12U);
        renderer.Render(ImGui::GetDrawData());
        device.EndFrame();
      }
    } catch (const gpg::gal::Error& error) {
      ShowError(std::string("The renderer stopped: ") + error.what());
      exitCode = 7;
    } catch (const std::exception& error) {
      ShowError(std::string("The editor stopped: ") + error.what());
      exitCode = 7;
    }

    renderer.Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    device.Destroy();
    if (::IsWindow(window) != FALSE) {
      ::DestroyWindow(window);
    }
    ::UnregisterClassW(kWindowClass, windowClass.hInstance);
    return exitCode;
  }
} // namespace faf::editor

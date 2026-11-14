#include "editor/ui/EdPopouts.h"

#include "editor/ui/EdImGuiRenderer.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Head.hpp"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_internal.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>

namespace faf::editor::popouts
{
  namespace
  {
    constexpr const wchar_t* kPopoutClass = L"FafEditorPopout";

    /**
     * imgui_impl_win32.cpp's ImGui_ImplWin32_ViewportData (ImGui 1.92.4, cmake/FafDependencies.cmake), which the
     * backend keeps in each viewport's PlatformUserData; a pooled window takes the place of the one it made.
     */
    struct BackendViewportData
    {
      HWND Hwnd;
      HWND HwndParent;
      bool HwndOwned;
      DWORD DwStyle;
      DWORD DwExStyle;
    };

    struct Slot
    {
      HWND window = nullptr;
      std::uint32_t head = 0;
      ImGuiViewport* viewport = nullptr;
      std::uint32_t seenWidth = 0;
      std::uint32_t seenHeight = 0;
      std::chrono::steady_clock::time_point seenSince{};
    };

    std::vector<Slot>& Pool()
    {
      static std::vector<Slot> pool;
      return pool;
    }

    /** Viewports ImGui made while every pooled window was out: their windows go back inside. */
    std::vector<ImGuiID>& Homeless()
    {
      static std::vector<ImGuiID> ids;
      return ids;
    }

    WNDPROC gPlatformProc = nullptr;
    void (*gBackendCreate)(ImGuiViewport*) = nullptr;
    void (*gBackendDestroy)(ImGuiViewport*) = nullptr;
    void (*gBackendShow)(ImGuiViewport*) = nullptr;
    int gEditorMonitorTag = 0; // its address marks the "monitor" that is the editor's window
    bool gToldFull = false;

    Slot* SlotOf(
      const ImGuiViewport* const viewport
    )
    {
      for (Slot& slot : Pool()) {
        if (slot.viewport == viewport && viewport != nullptr) {
          return &slot;
        }
      }
      return nullptr;
    }

    LRESULT CALLBACK PopoutProc(
      const HWND window,
      const UINT message,
      const WPARAM wParam,
      const LPARAM lParam
    )
    {
      // Handed out, the window is ImGui's (its platform window procedure reads the context from the property).
      if (gPlatformProc != nullptr && ::GetPropA(window, "IMGUI_CONTEXT") != nullptr) {
        return ::CallWindowProcW(gPlatformProc, window, message, wParam, lParam);
      }
      if (message == WM_CLOSE) {
        return 0; // a pooled window is only ever hidden
      }
      return ::DefWindowProcW(window, message, wParam, lParam);
    }

    void CreatePooled(
      ImGuiViewport* const viewport
    )
    {
      gBackendCreate(viewport);
      auto* const data = static_cast<BackendViewportData*>(viewport->PlatformUserData);
      Slot* slot = nullptr;
      for (Slot& candidate : Pool()) {
        if (candidate.viewport == nullptr) {
          slot = &candidate;
          break;
        }
      }
      if (slot == nullptr || data == nullptr || data->Hwnd == nullptr) {
        Homeless().push_back(viewport->ID);
        return;
      }
      ::DestroyWindow(data->Hwnd);
      data->Hwnd = slot->window;
      data->HwndOwned = false;
      ::SetWindowLongPtrW(slot->window, GWL_STYLE, static_cast<LONG_PTR>(data->DwStyle));
      ::SetWindowLongPtrW(slot->window, GWL_EXSTYLE, static_cast<LONG_PTR>(data->DwExStyle));
      ::SetWindowLongPtrW(slot->window, GWLP_HWNDPARENT, reinterpret_cast<LONG_PTR>(data->HwndParent));
      RECT rect{
        static_cast<LONG>(viewport->Pos.x),
        static_cast<LONG>(viewport->Pos.y),
        static_cast<LONG>(viewport->Pos.x + viewport->Size.x),
        static_cast<LONG>(viewport->Pos.y + viewport->Size.y)
      };
      ::AdjustWindowRectEx(&rect, data->DwStyle, FALSE, data->DwExStyle);
      ::SetWindowPos(
        slot->window,
        nullptr,
        rect.left,
        rect.top,
        rect.right - rect.left,
        rect.bottom - rect.top,
        SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED
      );
      ::SetPropA(slot->window, "IMGUI_CONTEXT", ImGui::GetCurrentContext());
      viewport->PlatformHandle = viewport->PlatformHandleRaw = slot->window;
      viewport->PlatformRequestResize = false;
      slot->viewport = viewport;
      slot->seenSince = std::chrono::steady_clock::now();
      gpg::Logf("editor: pop-out window %u for a panel", static_cast<unsigned>(slot->head));
    }

    void DestroyPooled(
      ImGuiViewport* const viewport
    )
    {
      if (Slot* const slot = SlotOf(viewport); slot != nullptr) {
        ::ShowWindow(slot->window, SW_HIDE);
        ::RemovePropA(slot->window, "IMGUI_CONTEXT");
        ::SetWindowLongPtrW(slot->window, GWLP_HWNDPARENT, 0);
        slot->viewport = nullptr;
      }
      auto& homeless = Homeless();
      homeless.erase(std::remove(homeless.begin(), homeless.end(), viewport->ID), homeless.end());
      gBackendDestroy(viewport); // HwndOwned is false for a pooled window: it isn't destroyed
    }

    void ShowPooled(
      ImGuiViewport* const viewport
    )
    {
      const auto& homeless = Homeless();
      if (std::find(homeless.begin(), homeless.end(), viewport->ID) != homeless.end()) {
        return;
      }
      gBackendShow(viewport);
    }

    [[nodiscard]] bool OnAMonitor(
      const ImVec2 pos,
      const ImVec2 size
    )
    {
      for (const ImGuiPlatformMonitor& monitor : ImGui::GetPlatformIO().Monitors) {
        if (monitor.PlatformHandle == &gEditorMonitorTag) {
          continue;
        }
        const ImRect a(pos, ImVec2(pos.x + size.x, pos.y + size.y));
        const ImRect b(
          monitor.MainPos, ImVec2(monitor.MainPos.x + monitor.MainSize.x, monitor.MainPos.y + monitor.MainSize.y)
        );
        if (a.Overlaps(b)) {
          return true;
        }
      }
      return false;
    }
  } // namespace

  int Capacity() noexcept
  {
    return static_cast<int>(Pool().size());
  }

  std::uint32_t HeadExtent(
    const int size
  ) noexcept
  {
    return static_cast<std::uint32_t>(std::max(size, 8));
  }

  void AddHeads(
    gpg::gal::DeviceContext& context,
    void* const frame,
    const int count,
    const std::uint32_t firstHead
  )
  {
    const HINSTANCE instance = ::GetModuleHandleW(nullptr);
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_DBLCLKS;
    windowClass.lpfnWndProc = &PopoutProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.lpszClassName = kPopoutClass;
    (void)::RegisterClassExW(&windowClass);
    for (int i = 0; i < count; ++i) {
      Slot slot;
      slot.window = ::CreateWindowExW(
        WS_EX_TOOLWINDOW,
        kPopoutClass,
        L"",
        WS_POPUP,
        0,
        0,
        64,
        64,
        static_cast<HWND>(frame),
        nullptr,
        instance,
        nullptr
      );
      if (slot.window == nullptr) {
        break;
      }
      gpg::gal::Head head{};
      head.mWindowed = false; // a window (the flag is the full-screen one)
      head.mWidth = 64U;
      head.mHeight = 64U;
      head.framesPerSecond = 60U;
      head.mHandle = frame;
      head.mWindow = slot.window;
      context.AddHead(head);
      slot.head = firstHead + static_cast<std::uint32_t>(i);
      Pool().push_back(slot);
    }
  }

  void Install()
  {
    if (Pool().empty()) {
      return;
    }
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    io.BackendFlags |= ImGuiBackendFlags_RendererHasViewports;
    WNDCLASSEXW platformClass{};
    platformClass.cbSize = sizeof(platformClass);
    if (::GetClassInfoExW(::GetModuleHandleW(nullptr), L"ImGui Platform", &platformClass) != FALSE) {
      gPlatformProc = platformClass.lpfnWndProc;
    }
    ImGuiPlatformIO& platform = ImGui::GetPlatformIO();
    gBackendCreate = platform.Platform_CreateWindow;
    gBackendDestroy = platform.Platform_DestroyWindow;
    gBackendShow = platform.Platform_ShowWindow;
    if (
      gPlatformProc == nullptr || gBackendCreate == nullptr || gBackendDestroy == nullptr || gBackendShow == nullptr
    ) {
      io.ConfigFlags &= ~ImGuiConfigFlags_ViewportsEnable;
      gpg::Warnf("editor: pop-out windows are off (ImGui's Windows backend has no platform windows)");
      return;
    }
    platform.Platform_CreateWindow = &CreatePooled;
    platform.Platform_DestroyWindow = &DestroyPooled;
    platform.Platform_ShowWindow = &ShowPooled;
    // `/popouttest` (test runs): every floating panel gets a window of its own, as a drag out of the window would.
    if (moho::CFG_GetArgOption("/popouttest", 0, nullptr)) {
      io.ConfigViewportsNoAutoMerge = true;
      gpg::Logf("editor: pop-out test: every floating panel in a window of its own");
    }
    gpg::Logf("editor: pop-out windows: up to %d panels out of the window", Capacity());
  }

  void BeforeNewFrame(
    void* const panelWindow
  )
  {
    if ((ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable) == 0) {
      return;
    }
    ImGuiPlatformIO& platform = ImGui::GetPlatformIO();
    for (int i = platform.Monitors.Size - 1; i >= 0; --i) {
      if (platform.Monitors[i].PlatformHandle == &gEditorMonitorTag) {
        platform.Monitors.erase(platform.Monitors.Data + i);
      }
    }
    const HWND window = static_cast<HWND>(panelWindow);
    RECT client{};
    if (window == nullptr || ::GetClientRect(window, &client) == FALSE || client.right <= 0 || client.bottom <= 0) {
      return;
    }
    ::MapWindowPoints(window, nullptr, reinterpret_cast<POINT*>(&client), 2);
    ImGuiPlatformMonitor own;
    own.MainPos = own.WorkPos = ImVec2(static_cast<float>(client.left), static_cast<float>(client.top));
    own.MainSize = own.WorkSize =
      ImVec2(static_cast<float>(client.right - client.left), static_cast<float>(client.bottom - client.top));
    own.DpiScale = ImGui_ImplWin32_GetDpiScaleForHwnd(window);
    own.PlatformHandle = &gEditorMonitorTag;
    platform.Monitors.push_front(own);
  }

  void AfterNewFrame()
  {
    if ((ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable) == 0) {
      return;
    }
    const ImGuiViewport* const main = ImGui::GetMainViewport();
    const ImVec2 inside(main->Pos.x + main->Size.x * 0.3f, main->Pos.y + main->Size.y * 0.25f);
    for (const ImGuiID id : Homeless()) {
      auto* const viewport = static_cast<ImGuiViewportP*>(ImGui::FindViewportByID(id));
      if (viewport != nullptr && viewport->Window != nullptr) {
        ImGui::SetWindowPos(viewport->Window, inside, ImGuiCond_Always);
        if (!gToldFull) {
          gToldFull = true;
          gpg::Warnf("editor: pop-out windows: at most %d panels can be out of the window at once", Capacity());
        }
      }
    }
    // A panel kept out on a monitor that is gone comes back inside.
    for (Slot& slot : Pool()) {
      auto* const viewport = static_cast<ImGuiViewportP*>(slot.viewport);
      if (viewport != nullptr && viewport->Window != nullptr && !OnAMonitor(viewport->Pos, viewport->Size)) {
        ImGui::SetWindowPos(viewport->Window, inside, ImGuiCond_Always);
      }
    }
  }

  bool WantHeadSizes(
    gpg::gal::DeviceContext& context
  )
  {
    bool changed = false;
    const auto now = std::chrono::steady_clock::now();
    const bool buttonDown = (::GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    for (Slot& slot : Pool()) {
      if (slot.viewport == nullptr || context.GetHeadCount() <= static_cast<int>(slot.head)) {
        continue;
      }
      RECT client{};
      ::GetClientRect(slot.window, &client);
      const std::uint32_t width = HeadExtent(client.right);
      const std::uint32_t height = HeadExtent(client.bottom);
      if (width != slot.seenWidth || height != slot.seenHeight) {
        slot.seenWidth = width;
        slot.seenHeight = height;
        slot.seenSince = now;
      }
      gpg::gal::Head& head = context.GetHead(slot.head);
      if (
        (head.mWidth != width || head.mHeight != height) && !buttonDown &&
        now - slot.seenSince >= std::chrono::milliseconds(250)
      ) {
        head.mWidth = width;
        head.mHeight = height;
        changed = true;
      }
    }
    return changed;
  }

  void Render(
    EdImGuiRenderer& renderer,
    const bool draw
  )
  {
    if ((ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable) == 0) {
      return;
    }
    ImGui::UpdatePlatformWindows();
    if (!draw) {
      return;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    const gpg::gal::DeviceContext* const context = device->GetDeviceContext();
    for (const Slot& slot : Pool()) {
      if (
        slot.viewport == nullptr || slot.viewport->DrawData == nullptr ||
        (slot.viewport->Flags & ImGuiViewportFlags_IsMinimized) != 0 ||
        context->GetHeadCount() <= static_cast<int>(slot.head)
      ) {
        continue;
      }
      const gpg::gal::Head& head = context->GetHead(slot.head);
      device->ClearTarget(device->GetHeadOutputContext(slot.head));
      device->BeginScene();
      D3DVIEWPORT9 port{};
      port.Width = head.mWidth;
      port.Height = head.mHeight;
      port.MaxZ = 1.0f;
      device->SetViewport(&port);
      device->Clear(true, false, false, 0xFF1C1F25U, 1.0f, 0);
      renderer.Render(slot.viewport->DrawData);
      device->EndScene();
    }
  }

  bool IsOut(
    const char* const windowName
  )
  {
    if ((ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable) == 0) {
      return false;
    }
    const ImGuiWindow* const window = ImGui::FindWindowByName(windowName);
    return window != nullptr && window->Viewport != nullptr && SlotOf(window->Viewport) != nullptr;
  }

  std::vector<std::string> OutNames()
  {
    std::vector<std::string> names;
    for (const Slot& slot : Pool()) {
      const auto* const viewport = static_cast<const ImGuiViewportP*>(slot.viewport);
      if (viewport != nullptr && viewport->Window != nullptr) {
        names.emplace_back(viewport->Window->Name);
      }
    }
    return names;
  }
} // namespace faf::editor::popouts

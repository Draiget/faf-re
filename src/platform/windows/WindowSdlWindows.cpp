// Engine addition (issue #407): what the SDL3 window layer (src/platform/sdl/WindowSdl.cpp) needs
// on Windows. The engine's own Win32 calls (GetKeyState, GetWindowRect, ClipCursor, the clipboard)
// work on the SDL window's HWND as they did on wx's, so nothing is published here. Two messages
// the retail window procedures handled are taken before SDL's: WM_SETCURSOR over the client area
// (WD3DViewport::MSWWindowProc, 0x00430B90) and the system-menu items the engine adds
// (WSupComFrame::MSWWindowProc, 0x008CDD40).

#include "platform/sdl/WindowSdlPlatform.h"

#include <string>

#include <SDL3/SDL.h>

#include <windows.h>
#include <commctrl.h>

#include "platform/Window.h"

namespace
{
  constexpr UINT_PTR kSubclassId = 0x46414653u; // 'FAFS'
  constexpr wchar_t kChildWindowClass[] = L"FafChildWindow";

  [[nodiscard]] bool IsChildHwnd(
    HWND const hwnd
  )
  {
    return hwnd != nullptr && (::GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_CHILD) != 0;
  }

  [[nodiscard]] HWND HwndOf(
    SDL_Window* const window
  )
  {
    if (window == nullptr) {
      return nullptr;
    }
    return static_cast<HWND>(
      SDL_GetPointerProperty(SDL_GetWindowProperties(window), SDL_PROP_WINDOW_WIN32_HWND_POINTER, nullptr)
    );
  }

  [[nodiscard]] std::wstring Wide(
    const char* const utf8
  )
  {
    if (utf8 == nullptr || *utf8 == '\0') {
      return {};
    }
    const int length = ::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    std::wstring wide(static_cast<std::size_t>(length > 0 ? length : 1), L'\0');
    (void)::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide.data(), length);
    wide.resize(wide.size() - 1u);
    return wide;
  }

  LRESULT CALLBACK SubclassProc(
    HWND const window,
    UINT const message,
    WPARAM const wParam,
    LPARAM const lParam,
    UINT_PTR const subclassId,
    DWORD_PTR const referenceData
  )
  {
    (void)subclassId;
    auto* const sdlWindow = reinterpret_cast<SDL_Window*>(referenceData);
    switch (message) {
    case WM_SETCURSOR:
      // SDL would put its own cursor back; the engine's cursor code sets the game's here, as the
      // viewport's window procedure did.
      if (LOWORD(lParam) == HTCLIENT && platform::window::sdl::CallCursorRequestHandler(sdlWindow)) {
        return TRUE;
      }
      break;
    case WM_SYSCOMMAND:
      // Items the engine added to the caption menu have ids below the system's (0xF000 and up).
      if (wParam != 0u && wParam < 0xF000u) {
        platform::window::Event event{};
        event.type = platform::window::EventType::SystemCommand;
        event.window = sdlWindow;
        event.command = static_cast<int>(wParam);
        platform::window::sdl::QueueEvent(event);
        return 0;
      }
      break;
    case WM_NCDESTROY:
      (void)::RemoveWindowSubclass(window, &SubclassProc, kSubclassId);
      break;
    default:
      break;
    }
    return ::DefSubclassProc(window, message, wParam, lParam);
  }
} // namespace

namespace platform::window::sdl
{
  void OnInit()
  {
    // wx's full-screen frame stayed up when another program took the keyboard.
    (void)SDL_SetHint(SDL_HINT_VIDEO_MINIMIZE_ON_FOCUS_LOSS, "0");
  }

  void OnShutdown() {}

  void OnCreateProperties(
    const unsigned int properties
  )
  {
    // Direct3D takes the HWND; Vulkan makes a Win32 surface from it (VulkanSurface.cpp), so SDL
    // needn't load the Vulkan loader for the window.
    (void)properties;
  }

  void OnWindowCreated(
    SDL_Window* const window
  )
  {
    HWND const hwnd = HwndOf(window);
    if (hwnd == nullptr) {
      return;
    }
    (void)::SetWindowSubclass(hwnd, &SubclassProc, kSubclassId, reinterpret_cast<DWORD_PTR>(window));
    if (IsChildHwnd(hwnd)) {
      return;
    }
    // The game's icon, the named resource IDI_WIN_FAICON (MohoResources.rc), as WSupComFrame's
    // constructor (0x008CD8C0) put it on the main frame.
    HINSTANCE const instance = ::GetModuleHandleW(nullptr);
    if (
      auto* const big = static_cast<HICON>(::LoadImageW(
        instance, L"IDI_WIN_FAICON", IMAGE_ICON, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON), 0
      ));
      big != nullptr
    ) {
      (void)::SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(big));
    }
    if (
      auto* const small = static_cast<HICON>(::LoadImageW(
        instance, L"IDI_WIN_FAICON", IMAGE_ICON, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON), 0
      ));
      small != nullptr
    ) {
      (void)::SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(small));
    }
  }

  void OnWindowDestroyed(
    SDL_Window* const window
  )
  {
    if (HWND const hwnd = HwndOf(window); hwnd != nullptr) {
      (void)::RemoveWindowSubclass(hwnd, &SubclassProc, kSubclassId);
    }
  }

  void OnWindowRectChanged(
    SDL_Window* const window
  )
  {
    (void)window;
  }

  void OnWindowMinimized(
    SDL_Window* const window,
    const bool minimized
  )
  {
    (void)window;
    (void)minimized;
  }

  void OnFocusChanged(
    SDL_Window* const window
  )
  {
    (void)window;
  }

  void OnDisplaysChanged() {}

  void OnKey(
    const int virtualKey,
    const bool down
  )
  {
    // GetKeyState reads Windows' own keyboard state.
    (void)virtualKey;
    (void)down;
  }

  void OnCursorMoved(
    const int screenX,
    const int screenY
  )
  {
    (void)screenX;
    (void)screenY;
  }

  void* NativeHandleOf(
    SDL_Window* const window
  )
  {
    return HwndOf(window);
  }

  // A Win32 child window, as wx 2.4.2 made the engine's child windows (the viewport), handed to SDL
  // to report its input (SDL_PROP_WINDOW_CREATE_WIN32_HWND_POINTER). No background brush, so
  // nothing is painted under the renderer, and no class cursor, so WM_SETCURSOR decides.
  SDL_Window* CreateChild(
    SDL_Window* const parent,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    HWND const parentHwnd = HwndOf(parent);
    if (parentHwnd == nullptr) {
      return nullptr;
    }
    HINSTANCE const instance = ::GetModuleHandleW(nullptr);
    static const bool registered = [instance]() {
      WNDCLASSEXW windowClass{};
      windowClass.cbSize = sizeof(windowClass);
      windowClass.style = CS_DBLCLKS;
      windowClass.lpfnWndProc = &::DefWindowProcW;
      windowClass.hInstance = instance;
      windowClass.lpszClassName = kChildWindowClass;
      return ::RegisterClassExW(&windowClass) != 0;
    }();
    if (!registered) {
      return nullptr;
    }
    HWND const hwnd = ::CreateWindowExW(
      0,
      kChildWindowClass,
      L"",
      WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
      x,
      y,
      width > 0 ? width : 1,
      height > 0 ? height : 1,
      parentHwnd,
      nullptr,
      instance,
      nullptr
    );
    if (hwnd == nullptr) {
      return nullptr;
    }
    SDL_PropertiesID const properties = SDL_CreateProperties();
    (void)SDL_SetPointerProperty(properties, SDL_PROP_WINDOW_CREATE_WIN32_HWND_POINTER, hwnd);
    SDL_Window* const window = SDL_CreateWindowWithProperties(properties);
    SDL_DestroyProperties(properties);
    if (window == nullptr) {
      (void)::DestroyWindow(hwnd);
    }
    return window;
  }

  bool IsChild(
    SDL_Window* const window
  )
  {
    return IsChildHwnd(HwndOf(window));
  }

  bool SetChildBounds(
    SDL_Window* const window,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    HWND const hwnd = HwndOf(window);
    if (!IsChildHwnd(hwnd)) {
      return false;
    }
    RECT current{};
    (void)::GetWindowRect(hwnd, &current);
    (void)::MapWindowPoints(nullptr, ::GetParent(hwnd), reinterpret_cast<POINT*>(&current), 2);
    const int newX = x != -1 ? x : current.left;
    const int newY = y != -1 ? y : current.top;
    const int newWidth = width != -1 ? width : current.right - current.left;
    const int newHeight = height != -1 ? height : current.bottom - current.top;
    (void)::SetWindowPos(hwnd, nullptr, newX, newY, newWidth, newHeight, SWP_NOZORDER | SWP_NOACTIVATE);
    return true;
  }

  bool GetChildBounds(
    SDL_Window* const window,
    int* const x,
    int* const y,
    int* const width,
    int* const height
  )
  {
    HWND const hwnd = HwndOf(window);
    if (!IsChildHwnd(hwnd)) {
      return false;
    }
    RECT client{};
    (void)::GetClientRect(hwnd, &client);
    POINT origin{0, 0};
    (void)::ClientToScreen(hwnd, &origin);
    if (x != nullptr) {
      *x = origin.x;
    }
    if (y != nullptr) {
      *y = origin.y;
    }
    if (width != nullptr) {
      *width = client.right - client.left;
    }
    if (height != nullptr) {
      *height = client.bottom - client.top;
    }
    return true;
  }

  void DestroyChildNative(
    void* const native
  )
  {
    if (native != nullptr && ::IsWindow(static_cast<HWND>(native)) != FALSE) {
      (void)::DestroyWindow(static_cast<HWND>(native));
    }
  }

  void SetKeyboardFocus(
    SDL_Window* const window
  )
  {
    // wxWindow::SetFocus (wx 2.4.2 src/msw/window.cpp) is ::SetFocus on the window's HWND.
    if (HWND const hwnd = HwndOf(window); hwnd != nullptr) {
      (void)::SetFocus(hwnd);
    }
  }

  void AddSystemMenuItem(
    SDL_Window* const window,
    const int command,
    const char* const utf8Label
  )
  {
    HMENU const menu = ::GetSystemMenu(HwndOf(window), FALSE);
    if (menu == nullptr) {
      return;
    }
    const std::wstring label = Wide(utf8Label);
    (void)::AppendMenuW(menu, MF_STRING, static_cast<UINT_PTR>(command), label.c_str());
  }
} // namespace platform::window::sdl

// Engine addition (issues #256, #407): what the SDL3 window layer (src/platform/sdl/WindowSdl.cpp)
// needs on POSIX systems. The engine's Win32 window, cursor, clipboard and message-box calls go
// to the POSIX <Windows.h> (src/platform/posix/Win32WindowPosix.cpp), which answers from the state
// published here and acts through the hooks set here.

#include "platform/sdl/WindowSdlPlatform.h"

#include <cstdint>
#include <string>
#include <vector>

#include <SDL3/SDL.h>

#include <Windows.h>

#include "platform/Window.h"
#include "platform/posix/Win32WindowPosix.h"

namespace
{
  [[nodiscard]] SDL_Window* AsWindow(
    void* const handle
  )
  {
    return static_cast<SDL_Window*>(handle);
  }

  // --- The Win32 calls routed here (Win32WindowPosix.h) ------------------------------------

  void WarpCursor(
    const int x,
    const int y
  )
  {
    (void)SDL_WarpMouseGlobal(static_cast<float>(x), static_cast<float>(y));
  }

  void Focus(
    void* const window
  )
  {
    if (window != nullptr) {
      (void)SDL_RaiseWindow(AsWindow(window));
    }
  }

  void ShowWindowCommand(
    void* const window,
    const int command
  )
  {
    if (window == nullptr) {
      return;
    }
    switch (command) {
    case SW_HIDE:
      (void)SDL_HideWindow(AsWindow(window));
      break;
    case SW_MINIMIZE:
    case SW_SHOWMINIMIZED:
      (void)SDL_MinimizeWindow(AsWindow(window));
      break;
    case SW_SHOWMAXIMIZED:
      (void)SDL_MaximizeWindow(AsWindow(window));
      break;
    case SW_RESTORE:
      (void)SDL_RestoreWindow(AsWindow(window));
      break;
    default:
      (void)SDL_ShowWindow(AsWindow(window));
      break;
    }
  }

  void SetWindowPosition(
    void* const window,
    const int x,
    const int y,
    const int width,
    const int height,
    const unsigned int flags
  )
  {
    if (window == nullptr) {
      return;
    }
    if ((flags & SWP_NOMOVE) == 0u) {
      (void)SDL_SetWindowPosition(AsWindow(window), x, y);
    }
    if ((flags & SWP_NOSIZE) == 0u) {
      (void)SDL_SetWindowSize(AsWindow(window), width, height);
    }
  }

  // The first window made is the main one, the cursor clip's window.
  SDL_Window* gMainWindow = nullptr;

  void ClipCursor(
    const bool clip,
    const int left,
    const int top,
    const int right,
    const int bottom
  )
  {
    if (gMainWindow == nullptr) {
      return;
    }
    if (!clip) {
      (void)SDL_SetWindowMouseRect(gMainWindow, nullptr);
      return;
    }
    int windowX = 0;
    int windowY = 0;
    (void)SDL_GetWindowPosition(gMainWindow, &windowX, &windowY);
    const SDL_Rect rect{left - windowX, top - windowY, right - left, bottom - top};
    (void)SDL_SetWindowMouseRect(gMainWindow, &rect);
  }

  void SetTitleHook(
    void* const window,
    const char* const utf8Title
  )
  {
    platform::window::SetTitle(window, utf8Title);
  }

  void ScreenSaver(
    const bool allowed
  )
  {
    (void)(allowed ? SDL_EnableScreenSaver() : SDL_DisableScreenSaver());
  }

  void* CreateCursor(
    const unsigned int* const bgraBottomUp,
    const int hotspotX,
    const int hotspotY
  )
  {
    SDL_Surface* const surface = SDL_CreateSurface(32, 32, SDL_PIXELFORMAT_ARGB8888);
    if (surface == nullptr) {
      return nullptr;
    }
    // B,G,R,A bytes are ARGB8888 words on a little-endian machine; rows arrive bottom-up.
    for (int row = 0; row < 32; ++row) {
      auto* const destination =
        reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(surface->pixels) + row * surface->pitch);
      const unsigned int* const source = bgraBottomUp + (31 - row) * 32;
      for (int column = 0; column < 32; ++column) {
        destination[column] = source[column];
      }
    }
    SDL_Cursor* const cursor = SDL_CreateColorCursor(surface, hotspotX, hotspotY);
    SDL_DestroySurface(surface);
    return cursor;
  }

  void DestroyCursor(
    void* const cursor
  )
  {
    SDL_DestroyCursor(static_cast<SDL_Cursor*>(cursor));
  }

  void SetCursorHook(
    void* const cursor
  )
  {
    (void)SDL_SetCursor(cursor != nullptr ? static_cast<SDL_Cursor*>(cursor) : SDL_GetDefaultCursor());
  }

  void ShowCursorHook(
    const bool shown
  )
  {
    (void)(shown ? SDL_ShowCursor() : SDL_HideCursor());
  }

  bool MessageBoxHook(
    void* const window,
    const char* const utf8Text,
    const char* const utf8Caption,
    const bool yesNo
  )
  {
    if (!yesNo) {
      (void)SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, utf8Caption, utf8Text, AsWindow(window));
      return true;
    }
    const SDL_MessageBoxButtonData buttons[] = {
      {SDL_MESSAGEBOX_BUTTON_ESCAPEKEY_DEFAULT, 0, "No"},
      {SDL_MESSAGEBOX_BUTTON_RETURNKEY_DEFAULT, 1, "Yes"},
    };
    SDL_MessageBoxData data{};
    data.flags = SDL_MESSAGEBOX_INFORMATION;
    data.window = AsWindow(window);
    data.title = utf8Caption;
    data.message = utf8Text;
    data.numbuttons = 2;
    data.buttons = buttons;
    int chosen = 0;
    return SDL_ShowMessageBox(&data, &chosen) && chosen == 1;
  }

  bool SetClipboardText(
    const char* const utf8Text
  )
  {
    return SDL_SetClipboardText(utf8Text);
  }

  std::string GetClipboardText()
  {
    char* const text = SDL_GetClipboardText();
    std::string result = text != nullptr ? text : "";
    SDL_free(text);
    return result;
  }

  bool OpenUrlHook(
    const char* const utf8Url
  )
  {
    return SDL_OpenURL(utf8Url);
  }

  bool EventsPending()
  {
    return platform::window::HasEvents();
  }
} // namespace

namespace platform::window::sdl
{
  void OnInit()
  {
    platform::posix::gWarpCursorHook = &WarpCursor;
    platform::posix::gFocusHook = &Focus;
    platform::posix::gShowWindowHook = &ShowWindowCommand;
    platform::posix::gSetWindowPosHook = &SetWindowPosition;
    platform::posix::gClipCursorHook = &ClipCursor;
    platform::posix::gSetWindowTitleHook = &SetTitleHook;
    platform::posix::gScreenSaverHook = &ScreenSaver;
    platform::posix::gCreateCursorHook = &CreateCursor;
    platform::posix::gDestroyCursorHook = &DestroyCursor;
    platform::posix::gSetCursorHook = &SetCursorHook;
    platform::posix::gShowCursorHook = &ShowCursorHook;
    platform::posix::gMessageBoxHook = &MessageBoxHook;
    platform::posix::gSetClipboardTextHook = &SetClipboardText;
    platform::posix::gGetClipboardTextHook = &GetClipboardText;
    platform::posix::gOpenUrlHook = &OpenUrlHook;
    platform::posix::gWindowEventsPendingHook = &EventsPending;
  }

  void OnShutdown()
  {
    platform::posix::gWindowEventsPendingHook = nullptr;
    gMainWindow = nullptr;
  }

  void OnCreateProperties(
    const unsigned int properties
  )
  {
    // The Vulkan backend makes its surface from the SDL window here (VulkanSurface.cpp).
    (void)SDL_SetBooleanProperty(properties, SDL_PROP_WINDOW_CREATE_VULKAN_BOOLEAN, true);
  }

  void OnWindowCreated(
    SDL_Window* const window
  )
  {
    if (gMainWindow == nullptr) {
      gMainWindow = window;
    }
  }

  void OnWindowDestroyed(
    SDL_Window* const window
  )
  {
    if (gMainWindow == window) {
      gMainWindow = nullptr;
    }
    platform::posix::ForgetWindow(window);
  }

  // What GetWindowRect, GetClientRect and the cursor's screen position answer from.
  void OnWindowRectChanged(
    SDL_Window* const window
  )
  {
    int x = 0;
    int y = 0;
    int width = 0;
    int height = 0;
    platform::window::GetBounds(window, &x, &y, &width, &height);
    platform::posix::SetWindowScreenRect(window, x, y, x + width, y + height);
  }

  void OnWindowMinimized(
    SDL_Window* const window,
    const bool minimized
  )
  {
    platform::posix::SetWindowMinimized(window, minimized);
  }

  void OnFocusChanged(
    SDL_Window* const window
  )
  {
    platform::posix::SetFocusedWindow(window);
  }

  void OnDisplaysChanged()
  {
    int count = 0;
    SDL_DisplayID* const displays = SDL_GetDisplays(&count);
    std::vector<int> rects;
    const SDL_DisplayID primary = SDL_GetPrimaryDisplay();
    // The primary first, as SetMonitors expects.
    for (int pass = 0; pass < 2 && displays != nullptr; ++pass) {
      for (int index = 0; index < count; ++index) {
        if ((pass == 0) != (displays[index] == primary)) {
          continue;
        }
        SDL_Rect bounds{};
        if (SDL_GetDisplayBounds(displays[index], &bounds)) {
          rects.insert(rects.end(), {bounds.x, bounds.y, bounds.x + bounds.w, bounds.y + bounds.h});
        }
      }
    }
    SDL_free(displays);
    platform::posix::SetMonitors(rects.data(), static_cast<int>(rects.size() / 4u));
  }

  void OnKey(
    const int virtualKey,
    const bool down
  )
  {
    platform::posix::SetKeyDown(virtualKey, down);
  }

  void OnCursorMoved(
    const int screenX,
    const int screenY
  )
  {
    platform::posix::SetCursorScreenPos(screenX, screenY);
  }

  void* NativeHandleOf(
    SDL_Window* const window
  )
  {
    return window;
  }

  // No child windows: the engine's child windows share their parent's (Shell.cpp).
  SDL_Window* CreateChild(
    SDL_Window* const parent,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    (void)parent;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    return nullptr;
  }

  bool IsChild(
    SDL_Window* const window
  )
  {
    (void)window;
    return false;
  }

  bool SetChildBounds(
    SDL_Window* const window,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    (void)window;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    return false;
  }

  bool GetChildBounds(
    SDL_Window* const window,
    int* const x,
    int* const y,
    int* const width,
    int* const height
  )
  {
    (void)window;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    return false;
  }

  void DestroyChildNative(
    void* const native
  )
  {
    (void)native;
  }

  void SetKeyboardFocus(
    SDL_Window* const window
  )
  {
    // The desktop gives the keyboard to the window the user picks.
    (void)window;
  }

  void AddSystemMenuItem(
    SDL_Window* const window,
    const int command,
    const char* const utf8Label
  )
  {
    // No caption menu on these desktops.
    (void)window;
    (void)command;
    (void)utf8Label;
  }
} // namespace platform::window::sdl

#pragma once

// Engine addition (issue #256): the native windows and their input, for platforms where the engine's
// wxWindows 2.4.2 shell has no port. Windows keeps wx's own windows; the Linux client
// (src/platform/posix/WindowSdl.cpp, SDL3) creates its windows here and the wx stand-in
// (src/platform/posix/wx) turns these events into wx events. Nothing here knows about wx.
//
// All calls are made on the main thread, as the window system requires.

#include <cstdint>

namespace platform::window
{
  // A native window. On Linux an SDL_Window*, which the Vulkan backend makes its surface from.
  using Handle = void*;

  enum class EventType : std::uint8_t
  {
    None,         // nothing for the engine (an event the window system keeps to itself)
    CloseRequested,
    Moved,        // x, y: the window's new screen position
    Resized,      // width, height: the new client size in pixels
    Minimized,
    Restored,     // shown again after Minimized, or un-maximized
    Maximized,
    FocusGained,
    FocusLost,
    Exposed,      // the window needs drawing
    MouseEnter,
    MouseLeave,
    MouseMove,    // x, y: client coordinates in pixels
    MouseDown,    // button, clicks (2 for a double click), x, y
    MouseUp,      // button, x, y
    MouseWheel,   // wheel (notches, positive away from the user), x, y
    KeyDown,      // virtualKey, repeat
    KeyUp,        // virtualKey
    Text,         // codepoint: one typed character
    DisplaysChanged,
  };

  // Mouse buttons, as wx numbers them.
  enum MouseButton : int
  {
    kButtonLeft = 1,
    kButtonMiddle = 2,
    kButtonRight = 3,
  };

  enum Modifier : std::uint32_t
  {
    kModifierShift = 1u << 0,
    kModifierControl = 1u << 1,
    kModifierAlt = 1u << 2,
    kModifierMeta = 1u << 3,
  };

  enum ButtonsDown : std::uint32_t
  {
    kLeftDown = 1u << 0,
    kMiddleDown = 1u << 1,
    kRightDown = 1u << 2,
  };

  struct Event
  {
    EventType type = EventType::None;
    Handle window = nullptr;
    int x = 0;
    int y = 0;
    int width = 0;
    int height = 0;
    int button = 0;
    int clicks = 0;
    float wheel = 0.0f;
    // A Windows virtual-key code (VK_*, 'A'..'Z', '0'..'9'): the engine's key bindings and
    // GetKeyState speak them.
    int virtualKey = 0;
    bool repeat = false;
    std::uint32_t codepoint = 0;
    std::uint32_t modifiers = 0;   // Modifier bits
    std::uint32_t buttonsDown = 0; // ButtonsDown bits, after this event
  };

  // Starts the window system; false (with the reason in the log) when there is none, as without a
  // display. Also routes the Win32 window, cursor, clipboard and message-box calls the engine makes
  // (src/platform/posix/Win32WindowPosix.h) to it.
  [[nodiscard]] bool Init();
  void Shutdown();
  [[nodiscard]] bool IsInitialized();

  // A top-level window, hidden until Show. x or y -1: centred. Null when it can't be made.
  [[nodiscard]] Handle CreateTopLevel(const char* utf8Title, int x, int y, int width, int height, bool resizable);
  void Destroy(Handle window);
  void Show(Handle window, bool show);
  void SetTitle(Handle window, const char* utf8Title);
  // -1 keeps a coordinate or a dimension.
  void SetBounds(Handle window, int x, int y, int width, int height);
  void Maximize(Handle window);
  void Minimize(Handle window);
  void Restore(Handle window);
  void SetFullscreen(Handle window, bool fullscreen);
  void Raise(Handle window);
  // Screen position and client size in pixels.
  void GetBounds(Handle window, int* x, int* y, int* width, int* height);

  // Events, without waiting: HasEvents reads what the window system has queued.
  [[nodiscard]] bool HasEvents();
  [[nodiscard]] bool PollEvent(Event& event);
} // namespace platform::window

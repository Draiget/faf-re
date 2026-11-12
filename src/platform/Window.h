#pragma once

// Engine addition (issues #256, #407): the native windows and their input, on every platform.
// One implementation on SDL3 (src/platform/sdl/WindowSdl.cpp), with what one system alone needs in
// src/platform/windows/WindowSdlWindows.cpp and src/platform/posix/WindowSdlPosix.cpp. The
// application shell (src/platform/shell) turns these events into the engine's window events.
//
// All calls are made on the main thread, as the window system requires.

#include <cstdint>
#include <string>

namespace platform::window
{
  // A native window: an SDL_Window*.
  using Handle = void*;

  enum class EventType : std::uint8_t
  {
    None, // nothing for the engine (an event the window system keeps to itself)
    CloseRequested,
    Moved,   // x, y: the window's new screen position
    Resized, // width, height: the new client size in pixels
    Minimized,
    Restored, // shown again after Minimized, or un-maximized
    Maximized,
    FocusGained,
    FocusLost,
    Exposed, // the window needs drawing
    MouseEnter,
    MouseLeave,
    MouseMove,  // x, y: client coordinates in pixels
    MouseDown,  // button, clicks (2 for a double click), x, y
    MouseUp,    // button, x, y
    MouseWheel, // wheel (notches, positive away from the user), x, y
    KeyDown,    // virtualKey, repeat
    KeyUp,      // virtualKey
    Text,       // codepoint: one typed character
    DisplaysChanged,
    SystemCommand, // command: an item the engine added to the window's system menu (AddSystemMenuItem)
    Quit,          // the system asks the program to end (Windows' WM_QUIT, a terminal's Ctrl+C)
  };

  // Mouse buttons, as the engine's mouse events number them (the 2.4.2 window library's numbers).
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
    // GetKeyState speak them. The side mouse buttons arrive as VK_XBUTTON1 and VK_XBUTTON2 key
    // presses, as FAF's patch to the retail window procedure made them (WD3DViewport.cpp).
    int virtualKey = 0;
    bool repeat = false;
    std::uint32_t codepoint = 0;
    std::uint32_t modifiers = 0;   // Modifier bits
    std::uint32_t buttonsDown = 0; // ButtonsDown bits, after this event
    int command = 0;               // SystemCommand's item
  };

  // Starts the window system; false (with the reason in the log) when there is none, as without a
  // display.
  [[nodiscard]] bool Init();
  void Shutdown();
  [[nodiscard]] bool IsInitialized();

  // A top-level window, hidden until Show. x, y: the frame's (outer) screen position, as the retail
  // window library placed frames; -1: centred. width, height: the client size. Null when it can't
  // be made.
  [[nodiscard]] Handle CreateTopLevel(const char* utf8Title, int x, int y, int width, int height, bool resizable);
  // A window inside `parent`'s client area at x, y (relative to it), shown, with input of its own,
  // as the window library's child windows were on Windows (the game's viewport, the map editor's view of it). Null
  // where the system has none; the engine's child then shares its parent's window.
  [[nodiscard]] Handle CreateChild(Handle parent, int x, int y, int width, int height);
  void Destroy(Handle window);
  void Show(Handle window, bool show);
  void SetTitle(Handle window, const char* utf8Title);
  // -1 keeps a coordinate or a dimension. x, y: the screen position, or for a child window its
  // position in the parent's client area.
  void SetBounds(Handle window, int x, int y, int width, int height);
  void Maximize(Handle window);
  void Minimize(Handle window);
  void Restore(Handle window);
  void SetFullscreen(Handle window, bool fullscreen);
  void Raise(Handle window);
  // Screen position (of the client area) and client size in pixels.
  void GetBounds(Handle window, int* x, int* y, int* width, int* height);
  // The keyboard goes to this window (the window library's SetFocus); nothing where the window system decides.
  void SetKeyboardFocus(Handle window);

  // A top-level window's frame (outer) position on the screen, borders and caption included, as
  // the retail window library reported and took it (the Windows.Main.x/y preferences hold it).
  void GetFramePosition(Handle window, int* x, int* y);
  void SetFramePosition(Handle window, int x, int y);
  // True while one of the program's windows has the keyboard.
  [[nodiscard]] bool HasKeyboardFocus();

  // What the renderers and the system's own window calls take: the HWND on Windows, the window
  // itself elsewhere (Vulkan makes its surface from the SDL_Window there). Null for null.
  [[nodiscard]] void* NativeHandle(Handle window);
  // The window whose NativeHandle is `native`, or null.
  [[nodiscard]] Handle FromNativeHandle(void* native);

  // Adds an item to the window's system menu (Windows' caption menu); choosing it sends a
  // SystemCommand event with `command`. Nothing where the desktop has no such menu.
  void AddSystemMenuItem(Handle window, int command, const char* utf8Label);

  // Current cursor in client pixels. False outside the client area or without mouse/keyboard focus.
  // Uses window-local input, including on Wayland where desktop cursor positions are unavailable.
  [[nodiscard]] bool GetMousePosition(Handle window, int& x, int& y);

  // Continuous camera-drag input on the focused window; no desktop cursor warping.
  [[nodiscard]] bool SetRelativeMouseMode(bool enabled);
  // Consume motion in client pixels, retaining fractional pixels for the next sample.
  [[nodiscard]] bool GetRelativeMouseDelta(int& x, int& y);

  // Events, without waiting: HasEvents reads what the window system has queued.
  [[nodiscard]] bool HasEvents();
  [[nodiscard]] bool PollEvent(Event& event);

  // Sees every event before PollEvent returns it; true keeps it from the engine. One filter.
  using EventFilter = bool (*)(const Event& event);
  void SetEventFilter(EventFilter filter);

  // Asked when the system wants the cursor set over a window's client area (Windows'
  // WM_SETCURSOR): true when the engine has set it, false to leave it to the window system.
  using CursorRequestHandler = bool (*)(Handle window);
  void SetCursorRequestHandler(CursorRequestHandler handler);

  // The system's folder picker (SDL_ShowOpenFolderDialog), titled `utf8Title`, starting in
  // `utf8Path`. Any thread may ask; the caller waits until the user chose or cancelled (SDL's
  // dialog answers through a callback, which this waits for). True with the chosen folder in
  // `utf8Path`; false when cancelled or without a window system, `utf8Path` unchanged.
  bool PickFolder(const char* utf8Title, std::string& utf8Path);

  // A borderless window centred on the primary display showing the PNG file scaled to
  // width x height, above other windows, until HideSplash. False when the file can't be read.
  bool ShowSplash(const char* utf8PngPath, int width, int height);
  void HideSplash();

  // Typed text is reported for this window from now on (on by default for every window), with
  // the input method's candidate window placed near the client rectangle given.
  void SetTextInputArea(Handle window, int x, int y, int width, int height);
} // namespace platform::window

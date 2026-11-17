#pragma once

// Engine addition (issue #407): what src/platform/sdl/WindowSdl.cpp asks of the system it runs on.
// src/platform/windows/WindowSdlWindows.cpp and src/platform/posix/WindowSdlPosix.cpp implement it;
// the shared file holds nothing that only one system needs.

struct SDL_Window;

namespace platform::window
{
  struct Event;
}

namespace platform::window::sdl
{
  // After SDL_Init, and before SDL_Quit.
  void OnInit();
  void OnShutdown();
  // The SDL_PropertiesID a top-level window is about to be made from: what the system adds.
  void OnCreateProperties(unsigned int properties);
  // A window was made (still hidden), or is about to be destroyed.
  void OnWindowCreated(SDL_Window* window);
  void OnWindowDestroyed(SDL_Window* window);
  // The window moved or changed size; it was minimized or shown again.
  void OnWindowRectChanged(SDL_Window* window);
  void OnWindowMinimized(SDL_Window* window, bool minimized);
  void OnFocusChanged(SDL_Window* window); // null: none of ours has the keyboard
  void OnDisplaysChanged();
  // A Windows virtual-key code (or VK_LBUTTON, VK_MBUTTON, VK_RBUTTON) went down or up.
  void OnKey(int virtualKey, bool down);
  // A key going down with these SDL modifiers (SDL_Keymod) is the system's or the app's shortcut, not
  // game input: on macOS anything pressed with Command (Cmd+Q, Cmd+H, Cmd+M, Cmd+Tab, ...), as Windows
  // keeps Windows-key combinations from the game. Its release still reaches the game. False elsewhere.
  [[nodiscard]] bool IsSystemShortcut(int virtualKey, unsigned int sdlModifiers);
  // The cursor moved to this screen position.
  void OnCursorMoved(int screenX, int screenY);
  // A child window (platform::window::CreateChild), or null where the system has none. Its
  // geometry is the system's: SetChildBounds and GetChildBounds answer false for other windows.
  [[nodiscard]] SDL_Window* CreateChild(SDL_Window* parent, int x, int y, int width, int height);
  [[nodiscard]] bool IsChild(SDL_Window* window);
  [[nodiscard]] bool SetChildBounds(SDL_Window* window, int x, int y, int width, int height);
  [[nodiscard]] bool GetChildBounds(SDL_Window* window, int* x, int* y, int* width, int* height);
  // Drawing into a top-level window leaves out its child windows' areas, or doesn't (Windows'
  // WS_CLIPCHILDREN, which SDL sets on every window it makes). Nothing elsewhere.
  void SetClipChildren(SDL_Window* window, bool clip);
  // After SDL_DestroyWindow: the native window of a child, which SDL leaves to its maker.
  void DestroyChildNative(void* native);
  void SetKeyboardFocus(SDL_Window* window);
  // platform::window::NativeHandle and AddSystemMenuItem.
  [[nodiscard]] void* NativeHandleOf(SDL_Window* window);
  void AddSystemMenuItem(SDL_Window* window, int command, const char* utf8Label);

  // Sees each SDL event (an SDL_Event*) before it is translated; true takes it from the engine.
  // The developer windows' Dear ImGui (src/platform/sdl/ToolWindow.cpp) sets it.
  using ToolEventHook = bool (*)(const void* sdlEvent);
  void SetToolEventHook(ToolEventHook hook);

  // From the system file: an event the system reported outside SDL's queue (a system-menu
  // command), returned by the next PollEvent.
  void QueueEvent(const Event& event);
  // The handler platform::window::SetCursorRequestHandler set, or null.
  [[nodiscard]] bool CallCursorRequestHandler(SDL_Window* window);
  // A size the engine gives in pixels (as GetBounds reports it) in SDL's window units, which are
  // points on a display with more than one pixel per point (a Retina display's 2.0), for
  // SDL_SetWindowSize. The same number where pixels and window units match (Windows).
  [[nodiscard]] int PixelsToWindowUnits(SDL_Window* window, int pixels);
} // namespace platform::window::sdl

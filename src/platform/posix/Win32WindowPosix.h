#pragma once

// Engine addition (issue #255): what the Linux window system (issue #256, SDL3) tells the Win32
// window, cursor and key-state calls of platform/posix/win32/Windows.h. Win32WindowPosix.cpp keeps
// the state; these functions update it from the window system's events.

namespace platform::posix
{
  // A window's rectangle in screen coordinates, as GetWindowRect reports it.
  void SetWindowScreenRect(void* window, int left, int top, int right, int bottom);
  // The window is gone: GetWindowRect fails for it and a capture on it ends.
  void ForgetWindow(void* window);
  // The cursor's screen position, as GetCursorPos reports it.
  void SetCursorScreenPos(int x, int y);
  // A Windows virtual-key code went down or up, for GetKeyState.
  void SetKeyDown(int virtualKey, bool down);
  // Called by SetCursorPos so the window system can move the real cursor.
  extern void (*gWarpCursorHook)(int x, int y);
  // Called by SetFocus and ShowWindow so the window system can act on the real window.
  extern void (*gFocusHook)(void* window);
  extern void (*gShowWindowHook)(void* window, int command);
  // The window system has events: wakes a MsgWaitForMultipleObjectsEx in the main loop.
  void WakeMessageWait();
} // namespace platform::posix

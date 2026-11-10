#pragma once

// Engine addition (issue #255): what the Linux window system (issue #256, SDL3) tells the Win32
// window, cursor and key-state calls of platform/posix/win32/Windows.h. Win32WindowPosix.cpp keeps
// the state; these functions update it from the window system's events.

#include <string>

namespace platform::posix
{
  // Shows a message box (MessageBoxW); returns true for Yes (a yes/no box) or OK.
  extern bool (*gMessageBoxHook)(void* window, const char* utf8Text, const char* utf8Caption, bool yesNo);
  // The game's cursor (gpg/gal/backends/common/WindowsCursor.cpp): a 32x32 colour cursor from
  // B,G,R,A pixels in rows bottom-up (a DIB's order) with its hotspot; returns the window system's
  // cursor as the HICON/HCURSOR the engine keeps, or null.
  extern void* (*gCreateCursorHook)(const unsigned int* bgraBottomUp, int hotspotX, int hotspotY);
  // DestroyIcon on such a cursor.
  extern void (*gDestroyCursorHook)(void* cursor);
  // SetCursor's new cursor (null: none), and ShowCursor crossing between shown and hidden.
  extern void (*gSetCursorHook)(void* cursor);
  extern void (*gShowCursorHook)(bool shown);
  // Opens a URL the engine already checked (moho::OpenAllowedUrlByWx) with the desktop's handler:
  // gOpenUrlHook when the window system set one, else `xdg-open <url>` in the background.
  extern bool (*gOpenUrlHook)(const char* utf8Url);
  void OpenUrl(const char* utf8Url);
  // The clipboard's text in UTF-8 (WIN_CopyToClipboard, WIN_GetClipboardText).
  extern bool (*gSetClipboardTextHook)(const char* utf8Text);
  extern std::string (*gGetClipboardTextHook)();
  // A window's rectangle in screen coordinates, as GetWindowRect reports it.
  void SetWindowScreenRect(void* window, int left, int top, int right, int bottom);
  // The window is gone: GetWindowRect fails for it and a capture on it ends.
  void ForgetWindow(void* window);
  // The cursor's screen position, as GetCursorPos reports it.
  void SetCursorScreenPos(int x, int y);
  // A Windows virtual-key code went down or up, for GetKeyState.
  void SetKeyDown(int virtualKey, bool down);
  // The window the desktop gave the keyboard to (null: none of ours), for GetFocus and
  // GetForegroundWindow. Unlike SetFocus it doesn't ask the window system for anything.
  void SetFocusedWindow(void* window);
  // The window was minimized or restored, for IsIconic.
  void SetWindowMinimized(void* window, bool minimized);
  // Called by SetWindowTextA/W with the new title in UTF-8.
  extern void (*gSetWindowTitleHook)(void* window, const char* utf8Title);
  // Called by SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE): may the screensaver start.
  extern void (*gScreenSaverHook)(bool allowed);
  // Called by SetCursorPos so the window system can move the real cursor.
  extern void (*gWarpCursorHook)(int x, int y);
  // Called by SetFocus and ShowWindow so the window system can act on the real window.
  extern void (*gFocusHook)(void* window);
  extern void (*gShowWindowHook)(void* window, int command);
  // Called by SetWindowPos (flags are SWP_*: SWP_NOMOVE and SWP_NOSIZE say which half applies).
  extern void (*gSetWindowPosHook)(void* window, int x, int y, int width, int height, unsigned int flags);
  // Called by ClipCursor: confine the real cursor to the screen rectangle, or free it (clip false).
  extern void (*gClipCursorHook)(bool clip, int left, int top, int right, int bottom);
  // The window system has events: wakes a MsgWaitForMultipleObjectsEx in the main loop.
  void WakeMessageWait();
  // Reads the window system's input and says whether events are queued: with it set,
  // MsgWaitForMultipleObjectsEx looks every few milliseconds and ends its wait for them.
  extern bool (*gWindowEventsPendingHook)();
  // The monitors, `count` rectangles of four ints each (left, top, right, bottom, screen
  // coordinates), the primary first: MonitorFromPoint and GetMonitorInfoW answer from them.
  void SetMonitors(const int* rects, int count);
} // namespace platform::posix

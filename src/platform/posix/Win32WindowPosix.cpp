// Engine addition (issue #255): the Win32 window, cursor and keyboard-state calls the Linux
// client's UI code makes (declared in platform/posix/win32/Windows.h), answered from state the
// window system keeps here. The window system itself (SDL3) is issue #256: it will report window
// rectangles, the cursor position, key states and capture through the functions in
// platform/posix/Win32WindowPosix.h. Until then windows have no rectangle and no key is down.

#include "platform/posix/Win32WindowPosix.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <csignal>
#include <cstdio>

#include <execinfo.h>
#include <spawn.h>
#include <unistd.h> // environ

#include <Windows.h>

namespace
{
  struct WindowState
  {
    std::mutex mutex;
    std::unordered_map<HWND, RECT> windowRects;  // screen rectangle of each window
    POINT cursor{};
    HWND capture = nullptr;
    HWND focus = nullptr;
    std::unordered_set<HWND> hidden;  // windows ShowWindow hid or minimized
    std::unordered_set<HWND> minimized;  // windows minimized by ShowWindow or the window system
    HCURSOR cursorShape = nullptr;
    int cursorShowCount = 0;
    std::array<bool, 256> keysDown{};
    std::array<bool, 256> keysToggled{};
  };

  WindowState& State()
  {
    static WindowState state;
    return state;
  }
} // namespace

namespace platform::posix
{
  void SetWindowScreenRect(void* const window, const int left, const int top, const int right, const int bottom)
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    state.windowRects[window] = RECT{left, top, right, bottom};
  }

  void ForgetWindow(void* const window)
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    state.windowRects.erase(window);
    if (state.capture == window) {
      state.capture = nullptr;
    }
  }

  void SetCursorScreenPos(const int x, const int y)
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    state.cursor = POINT{x, y};
  }

  void SetKeyDown(const int virtualKey, const bool down)
  {
    if (virtualKey < 0 || virtualKey >= 256) {
      return;
    }
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    if (down && !state.keysDown[static_cast<std::size_t>(virtualKey)]) {
      state.keysToggled[static_cast<std::size_t>(virtualKey)] = !state.keysToggled[static_cast<std::size_t>(virtualKey)];
    }
    state.keysDown[static_cast<std::size_t>(virtualKey)] = down;
  }

  void SetFocusedWindow(void* const window)
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    state.focus = static_cast<HWND>(window);
  }

  void SetWindowMinimized(void* const window, const bool minimized)
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    if (minimized) {
      state.minimized.insert(window);
    } else {
      state.minimized.erase(window);
    }
  }

  void* (*gCreateCursorHook)(const unsigned int* bgraBottomUp, int hotspotX, int hotspotY) = nullptr;
  void (*gDestroyCursorHook)(void* cursor) = nullptr;
  void (*gSetCursorHook)(void* cursor) = nullptr;
  void (*gShowCursorHook)(bool shown) = nullptr;
  bool (*gOpenUrlHook)(const char* utf8Url) = nullptr;
  bool (*gWindowEventsPendingHook)() = nullptr;

  void OpenUrl(const char* const utf8Url)
  {
    if (utf8Url == nullptr || utf8Url[0] == '\0') {
      return;
    }
    if (gOpenUrlHook != nullptr && gOpenUrlHook(utf8Url)) {
      return;
    }
    // The URL is one argument of its own: no shell sees it.
    char program[] = "xdg-open";
    std::string url = utf8Url;
    char* const arguments[] = {program, url.data(), nullptr};
    pid_t child = 0;
    if (::posix_spawnp(&child, program, nullptr, nullptr, arguments, environ) != 0) {
      std::fprintf(stderr, "OpenUrl: could not start xdg-open\n");
    }
    // The child is not waited for; SIGCHLD's default disposition leaves a zombie until exit,
    // which is harmless for the few links a session opens.
  }

  bool (*gMessageBoxHook)(void* window, const char* utf8Text, const char* utf8Caption, bool yesNo) = nullptr;
  bool (*gSetClipboardTextHook)(const char* utf8Text) = nullptr;
  std::string (*gGetClipboardTextHook)() = nullptr;
  void (*gSetWindowTitleHook)(void* window, const char* utf8Title) = nullptr;
  void (*gScreenSaverHook)(bool allowed) = nullptr;
  void (*gWarpCursorHook)(int x, int y) = nullptr;
  void (*gFocusHook)(void* window) = nullptr;
  void (*gShowWindowHook)(void* window, int command) = nullptr;
  void (*gSetWindowPosHook)(void* window, int x, int y, int width, int height, unsigned int flags) = nullptr;
  void (*gClipCursorHook)(bool clip, int left, int top, int right, int bottom) = nullptr;
} // namespace platform::posix

BOOL GetCursorPos(POINT* const point)
{
  if (point == nullptr) {
    return FALSE;
  }
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  *point = state.cursor;
  return TRUE;
}

BOOL SetCursorPos(const int x, const int y)
{
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    state.cursor = POINT{x, y};
  }
  if (platform::posix::gWarpCursorHook != nullptr) {
    platform::posix::gWarpCursorHook(x, y);
  }
  return TRUE;
}

BOOL GetWindowRect(const HWND window, RECT* const rect)
{
  if (rect == nullptr) {
    return FALSE;
  }
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  const auto found = state.windowRects.find(window);
  if (found == state.windowRects.end()) {
    *rect = RECT{};
    return FALSE;
  }
  *rect = found->second;
  return TRUE;
}

BOOL GetClientRect(const HWND window, RECT* const rect)
{
  RECT screen{};
  if (!GetWindowRect(window, &screen)) {
    if (rect != nullptr) {
      *rect = RECT{};
    }
    return FALSE;
  }
  *rect = RECT{0, 0, screen.right - screen.left, screen.bottom - screen.top};
  return TRUE;
}

BOOL ScreenToClient(const HWND window, POINT* const point)
{
  RECT screen{};
  if (point == nullptr || !GetWindowRect(window, &screen)) {
    return FALSE;
  }
  point->x -= screen.left;
  point->y -= screen.top;
  return TRUE;
}

BOOL ClientToScreen(const HWND window, POINT* const point)
{
  RECT screen{};
  if (point == nullptr || !GetWindowRect(window, &screen)) {
    return FALSE;
  }
  point->x += screen.left;
  point->y += screen.top;
  return TRUE;
}

HWND SetCapture(const HWND window)
{
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  const HWND previous = state.capture;
  state.capture = window;
  return previous;
}

BOOL ReleaseCapture()
{
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  state.capture = nullptr;
  return TRUE;
}

HWND GetCapture()
{
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  return state.capture;
}

SHORT GetKeyState(const int virtualKey)
{
  if (virtualKey < 0 || virtualKey >= 256) {
    return 0;
  }
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  // The high bit: the key is down; the low bit: a toggle key (Caps Lock, Num Lock) is on.
  SHORT result = 0;
  if (state.keysDown[static_cast<std::size_t>(virtualKey)]) {
    result = static_cast<SHORT>(result | static_cast<SHORT>(0x8000));
  }
  if (state.keysToggled[static_cast<std::size_t>(virtualKey)]) {
    result = static_cast<SHORT>(result | 1);
  }
  return result;
}

SHORT GetAsyncKeyState(const int virtualKey)
{
  return static_cast<SHORT>(GetKeyState(virtualKey) & static_cast<SHORT>(0x8000));
}

HCURSOR SetCursor(const HCURSOR cursor)
{
  HCURSOR previous = nullptr;
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    previous = state.cursorShape;
    state.cursorShape = cursor;
  }
  if (platform::posix::gSetCursorHook != nullptr) {
    platform::posix::gSetCursorHook(cursor);
  }
  return previous;
}

int ShowCursor(const BOOL show)
{
  int count = 0;
  bool crossed = false;
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    const bool wasShown = state.cursorShowCount >= 0;
    state.cursorShowCount += show ? 1 : -1;
    count = state.cursorShowCount;
    crossed = wasShown != (count >= 0);
  }
  // Windows shows the cursor while the count is 0 or more.
  if (crossed && platform::posix::gShowCursorHook != nullptr) {
    platform::posix::gShowCursorHook(count >= 0);
  }
  return count;
}

BOOL DestroyIcon(const HICON icon)
{
  if (icon == nullptr) {
    return FALSE;
  }
  if (platform::posix::gDestroyCursorHook != nullptr) {
    platform::posix::gDestroyCursorHook(icon);
  }
  return TRUE;
}

namespace
{
  struct Monitors
  {
    std::mutex mutex;
    std::vector<RECT> rects;  // screen rectangles; the first is the primary
  };

  Monitors& AllMonitors()
  {
    static Monitors monitors;
    return monitors;
  }

  // The squared distance from `point` to `rect` (0 inside).
  long long DistanceSquared(const POINT point, const RECT& rect)
  {
    const long long dx = point.x < rect.left ? rect.left - point.x : (point.x >= rect.right ? point.x - rect.right + 1 : 0);
    const long long dy = point.y < rect.top ? rect.top - point.y : (point.y >= rect.bottom ? point.y - rect.bottom + 1 : 0);
    return dx * dx + dy * dy;
  }
} // namespace

void platform::posix::SetMonitors(const int* const rects, const int count)
{
  Monitors& monitors = AllMonitors();
  const std::lock_guard<std::mutex> lock(monitors.mutex);
  monitors.rects.clear();
  for (int index = 0; index < count; ++index) {
    monitors.rects.push_back(RECT{rects[index * 4], rects[index * 4 + 1], rects[index * 4 + 2], rects[index * 4 + 3]});
  }
}

// A monitor handle is its index plus one.
HMONITOR MonitorFromPoint(const POINT point, const DWORD flags)
{
  Monitors& monitors = AllMonitors();
  const std::lock_guard<std::mutex> lock(monitors.mutex);
  if (monitors.rects.empty()) {
    return nullptr;
  }
  std::size_t nearest = 0;
  long long nearestDistance = -1;
  for (std::size_t index = 0; index < monitors.rects.size(); ++index) {
    const long long distance = DistanceSquared(point, monitors.rects[index]);
    if (distance == 0) {
      return reinterpret_cast<HMONITOR>(index + 1);
    }
    if (nearestDistance < 0 || distance < nearestDistance) {
      nearest = index;
      nearestDistance = distance;
    }
  }
  if (flags == MONITOR_DEFAULTTONEAREST) {
    return reinterpret_cast<HMONITOR>(nearest + 1);
  }
  return flags == MONITOR_DEFAULTTOPRIMARY ? reinterpret_cast<HMONITOR>(std::size_t{1}) : nullptr;
}

BOOL GetMonitorInfoW(const HMONITOR monitor, MONITORINFO* const info)
{
  if (info == nullptr || monitor == nullptr) {
    return FALSE;
  }
  Monitors& monitors = AllMonitors();
  const std::lock_guard<std::mutex> lock(monitors.mutex);
  const std::size_t index = reinterpret_cast<std::size_t>(monitor) - 1;
  if (index >= monitors.rects.size()) {
    return FALSE;
  }
  info->rcMonitor = monitors.rects[index];
  info->rcWork = monitors.rects[index];  // the window system doesn't report panels apart
  info->dwFlags = index == 0 ? MONITORINFOF_PRIMARY : 0u;
  return TRUE;
}

BOOL ClipCursor(const RECT* const rect)
{
  if (platform::posix::gClipCursorHook != nullptr) {
    platform::posix::gClipCursorHook(rect != nullptr, rect != nullptr ? rect->left : 0, rect != nullptr ? rect->top : 0,
                                     rect != nullptr ? rect->right : 0, rect != nullptr ? rect->bottom : 0);
  }
  return TRUE;
}

HWND SetFocus(const HWND window)
{
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  const HWND previous = state.focus;
  state.focus = window;
  if (platform::posix::gFocusHook != nullptr) {
    platform::posix::gFocusHook(window);
  }
  return previous;
}

HWND GetFocus()
{
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  return state.focus;
}

HWND GetForegroundWindow()
{
  return GetFocus();
}

BOOL IsDebuggerPresent()
{
  std::FILE* const status = std::fopen("/proc/self/status", "r");
  if (status == nullptr) {
    return FALSE;
  }
  char line[256];
  long tracer = 0;
  while (std::fgets(line, sizeof(line), status) != nullptr) {
    if (std::sscanf(line, "TracerPid: %ld", &tracer) == 1) {
      break;
    }
  }
  std::fclose(status);
  return tracer != 0 ? TRUE : FALSE;
}

void DebugBreak()
{
  (void)::raise(SIGTRAP);
}

BOOL ShowWindow(const HWND window, const int command)
{
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    if (command == SW_HIDE || command == SW_MINIMIZE || command == SW_SHOWMINIMIZED) {
      state.hidden.insert(window);
    } else {
      state.hidden.erase(window);
    }
    if (command == SW_MINIMIZE || command == SW_SHOWMINIMIZED) {
      state.minimized.insert(window);
    } else if (command != SW_HIDE) {
      state.minimized.erase(window);
    }
  }
  if (platform::posix::gShowWindowHook != nullptr) {
    platform::posix::gShowWindowHook(window, command);
  }
  return TRUE;
}

BOOL IsIconic(const HWND window)
{
  if (window == nullptr) {
    return FALSE;
  }
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  return state.minimized.count(window) != 0 ? TRUE : FALSE;
}

HWND GetAncestor(const HWND window, const UINT flags)
{
  (void)flags;
  return window;
}

BOOL SetWindowTextA(const HWND window, const char* const text)
{
  if (window == nullptr || text == nullptr) {
    return FALSE;
  }
  if (platform::posix::gSetWindowTitleHook != nullptr) {
    platform::posix::gSetWindowTitleHook(window, text);
  }
  return TRUE;
}

BOOL SetWindowTextW(const HWND window, const wchar_t* const text)
{
  if (text == nullptr) {
    return FALSE;
  }
  // The window system takes UTF-8.
  std::string utf8;
  for (const wchar_t* character = text; *character != L'\0'; ++character) {
    const std::uint32_t code = static_cast<std::uint32_t>(*character);
    if (code < 0x80u) {
      utf8 += static_cast<char>(code);
    } else if (code < 0x800u) {
      utf8 += static_cast<char>(0xC0u | (code >> 6));
      utf8 += static_cast<char>(0x80u | (code & 0x3Fu));
    } else if (code < 0x10000u) {
      utf8 += static_cast<char>(0xE0u | (code >> 12));
      utf8 += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
      utf8 += static_cast<char>(0x80u | (code & 0x3Fu));
    } else {
      utf8 += static_cast<char>(0xF0u | (code >> 18));
      utf8 += static_cast<char>(0x80u | ((code >> 12) & 0x3Fu));
      utf8 += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
      utf8 += static_cast<char>(0x80u | (code & 0x3Fu));
    }
  }
  return SetWindowTextA(window, utf8.c_str());
}

namespace
{
  std::atomic<bool> gScreenSaverActive{true};
} // namespace

BOOL SystemParametersInfoW(const UINT action, const UINT parameter, void* const data, const UINT winIni)
{
  (void)winIni;
  switch (action) {
    case SPI_GETSCREENSAVEACTIVE:
      if (data == nullptr) {
        return FALSE;
      }
      *static_cast<BOOL*>(data) = gScreenSaverActive.load() ? TRUE : FALSE;
      return TRUE;
    case SPI_SETSCREENSAVEACTIVE:
      gScreenSaverActive.store(parameter != 0u);
      if (platform::posix::gScreenSaverHook != nullptr) {
        platform::posix::gScreenSaverHook(parameter != 0u);
      }
      return TRUE;
    case SPI_GETFONTSMOOTHING:
    case SPI_GETFONTSMOOTHINGTYPE:
    case SPI_GETFONTSMOOTHINGCONTRAST:
    case SPI_GETFONTSMOOTHINGORIENTATION:
      // Glyphs come from FreeType (GdiOverFreeType.cpp), which these settings don't change.
      if (data == nullptr) {
        return FALSE;
      }
      *static_cast<UINT*>(data) = 0u;
      return TRUE;
    default:
      return FALSE;
  }
}

int MessageBoxW(const HWND window, const wchar_t* const text, const wchar_t* const caption, const UINT type)
{
  const auto utf8 = [](const wchar_t* const wide) {
    std::string out;
    for (const wchar_t* character = wide; character != nullptr && *character != L'\0'; ++character) {
      const std::uint32_t code = static_cast<std::uint32_t>(*character);
      if (code < 0x80u) {
        out += static_cast<char>(code);
      } else if (code < 0x800u) {
        out += static_cast<char>(0xC0u | (code >> 6));
        out += static_cast<char>(0x80u | (code & 0x3Fu));
      } else {
        out += static_cast<char>(0xE0u | ((code >> 12) & 0x0Fu));
        out += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
        out += static_cast<char>(0x80u | (code & 0x3Fu));
      }
    }
    return out;
  };
  const std::string utf8Text = utf8(text);
  const std::string utf8Caption = utf8(caption);
  const bool yesNo = (type & MB_TYPEMASK) == MB_YESNO;
  if (platform::posix::gMessageBoxHook != nullptr) {
    return platform::posix::gMessageBoxHook(window, utf8Text.c_str(), utf8Caption.c_str(), yesNo) ? (yesNo ? IDYES : IDOK)
                                                                                                    : (yesNo ? IDNO : IDOK);
  }
  std::fprintf(stderr, "[%s] %s\n", utf8Caption.c_str(), utf8Text.c_str());
  std::fflush(stderr);
  return yesNo ? IDNO : IDOK;
}

BOOL IsWindowVisible(const HWND window)
{
  if (window == nullptr) {
    return FALSE;
  }
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  return state.hidden.count(window) == 0 ? TRUE : FALSE;
}

BOOL SetWindowPos(
  const HWND window, const HWND insertAfter, const int x, const int y, const int width, const int height, const UINT flags
)
{
  (void)insertAfter;  // stacking order is the window system's
  {
    WindowState& state = State();
    const std::lock_guard<std::mutex> lock(state.mutex);
    RECT& rect = state.windowRects[window];
    if ((flags & SWP_NOMOVE) == 0u) {
      const LONG currentWidth = rect.right - rect.left;
      const LONG currentHeight = rect.bottom - rect.top;
      rect.left = x;
      rect.top = y;
      rect.right = x + currentWidth;
      rect.bottom = y + currentHeight;
    }
    if ((flags & SWP_NOSIZE) == 0u) {
      rect.right = rect.left + width;
      rect.bottom = rect.top + height;
    }
  }
  if (platform::posix::gSetWindowPosHook != nullptr) {
    platform::posix::gSetWindowPosHook(window, x, y, width, height, flags);
  }
  return TRUE;
}

namespace
{
  // Set when the window system has events for the main loop (WakeMessageWait).
  HANDLE MessageWakeEvent()
  {
    static const HANDLE event = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    return event;
  }
} // namespace

void platform::posix::WakeMessageWait()
{
  (void)::SetEvent(MessageWakeEvent());
}

DWORD MsgWaitForMultipleObjectsEx(
  const DWORD count, const HANDLE* const handles, const DWORD milliseconds, const DWORD wakeMask, const DWORD flags
)
{
  (void)wakeMask;
  (void)flags;
  // The caller's handles, then the window system's wake event at index `count`, as Windows
  // reports a queued message with WAIT_OBJECT_0 + count.
  std::vector<HANDLE> all(handles, handles + count);
  all.push_back(MessageWakeEvent());
  const DWORD all_count = static_cast<DWORD>(all.size());
  if (platform::posix::gWindowEventsPendingHook == nullptr) {
    return ::WaitForMultipleObjects(all_count, all.data(), FALSE, milliseconds);
  }
  // The window system reads its input only when asked (SDL pumps on the main thread), so the
  // wait looks for window events every few milliseconds, as a queued message ends it on Windows.
  constexpr DWORD kSliceMs = 4;
  if (platform::posix::gWindowEventsPendingHook()) {
    return WAIT_OBJECT_0 + count;
  }
  DWORD waited = 0;
  for (;;) {
    const DWORD slice = milliseconds == INFINITE ? kSliceMs : (std::min)(kSliceMs, milliseconds - waited);
    const DWORD result = ::WaitForMultipleObjects(all_count, all.data(), FALSE, slice);
    if (result != WAIT_TIMEOUT) {
      return result;
    }
    if (platform::posix::gWindowEventsPendingHook()) {
      return WAIT_OBJECT_0 + count;
    }
    if (milliseconds != INFINITE) {
      waited += slice;
      if (waited >= milliseconds) {
        return WAIT_TIMEOUT;
      }
    }
  }
}

USHORT RtlCaptureStackBackTrace(const DWORD skip, const DWORD count, void** const frames, DWORD* const hash)
{
  void* buffer[128];
  const int captured = ::backtrace(buffer, 128);
  USHORT written = 0;
  // buffer[0] is this function.
  for (int index = 1 + static_cast<int>(skip); index < captured && written < count; ++index) {
    frames[written++] = buffer[index];
  }
  if (hash != nullptr) {
    *hash = 0;
  }
  return written;
}

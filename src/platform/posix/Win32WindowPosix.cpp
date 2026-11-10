// Engine addition (issue #255): the Win32 window, cursor and keyboard-state calls the Linux
// client's UI code makes (declared in platform/posix/win32/Windows.h), answered from state the
// window system keeps here. The window system itself (SDL3) is issue #256: it will report window
// rectangles, the cursor position, key states and capture through the functions in
// platform/posix/Win32WindowPosix.h. Until then windows have no rectangle and no key is down.

#include "platform/posix/Win32WindowPosix.h"

#include <array>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <csignal>
#include <cstdio>

#include <execinfo.h>

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
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  const HCURSOR previous = state.cursorShape;
  state.cursorShape = cursor;
  return previous;
}

int ShowCursor(const BOOL show)
{
  WindowState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  state.cursorShowCount += show ? 1 : -1;
  return state.cursorShowCount;
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
  }
  if (platform::posix::gShowWindowHook != nullptr) {
    platform::posix::gShowWindowHook(window, command);
  }
  return TRUE;
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
  return ::WaitForMultipleObjects(static_cast<DWORD>(all.size()), all.data(), FALSE, milliseconds);
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

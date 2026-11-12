// Engine addition (issues #255, #407, #415): the code behind the application shell's headers
// (Shell.h): the event table search and the handler chain, the mouse button tests and the key code
// conversions of the window library the retail binary linked, and the delivery of the window
// system's events (platform/Window.h) as the shell's events.

#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "platform/Window.h"

#include "platform/shell/app.h"
#include "platform/shell/dc.h"
#include "platform/shell/event.h"
#include "platform/shell/frame.h"
#include "platform/shell/string.h"
#include "platform/shell/window.h"

static ShellBrush sBlackBrush;
ShellBrush* gShellBlackBrush = &sBlackBrush;
ShellBrush gShellNullBrush;

// --- Event tables --------------------------------------------------------------------------

const ShellEventTableEntry ShellEvtHandler::sm_eventTableEntries[] = {
  DECLARE_EVENT_TABLE_ENTRY(SHELL_EVT_NULL, 0, 0, nullptr, nullptr)
};
const ShellEventTable ShellEvtHandler::sm_eventTable = {nullptr, &ShellEvtHandler::sm_eventTableEntries[0]};

const ShellEventTable* ShellEvtHandler::GetEventTable() const
{
  return &ShellEvtHandler::sm_eventTable;
}

ShellEvtHandler::~ShellEvtHandler()
{
  // The 2.4.2 window library unlinks a handler from its neighbours when it is destroyed.
  if (m_previousHandler != nullptr) {
    m_previousHandler->m_nextHandler = m_nextHandler;
  }
  if (m_nextHandler != nullptr) {
    m_nextHandler->m_previousHandler = m_previousHandler;
  }
}

bool ShellEvtHandler::SearchEventTable(
  const ShellEventTable& table,
  ShellEvent& event
)
{
  const ShellEventType eventType = event.GetEventType();
  const int eventId = event.GetId();
  for (const ShellEventTableEntry* entry = table.entries; entry->m_fn != nullptr; ++entry) {
    if (entry->m_eventType != eventType) {
      continue;
    }
    const int firstId = entry->m_id;
    const int lastId = entry->m_lastId;
    if (
      firstId == -1 || (lastId == -1 && eventId == firstId) || (lastId != -1 && eventId >= firstId && eventId <= lastId)
    ) {
      event.Skip(false);
      event.m_callbackUserData = entry->m_callbackUserData;
      (this->*reinterpret_cast<ShellEventFunction>(entry->m_fn))(event);
      return !event.GetSkipped();
    }
  }
  return false;
}

bool ShellEvtHandler::ProcessEvent(
  ShellEvent& event
)
{
  if (GetEvtHandlerEnabled()) {
    for (const ShellEventTable* table = GetEventTable(); table != nullptr; table = table->baseTable) {
      if (SearchEventTable(*table, event)) {
        return true;
      }
    }
  }
  if (m_nextHandler != nullptr) {
    return m_nextHandler->ProcessEvent(event);
  }
  return false;
}

// --- Mouse buttons (1 left, 2 middle, 3 right, -1 any) ----------------------------------------

bool ShellMouseEvent::ButtonDClick(
  const int but
) const
{
  switch (but) {
  case -1:
    return LeftDClick() || MiddleDClick() || RightDClick();
  case 1:
    return LeftDClick();
  case 2:
    return MiddleDClick();
  case 3:
    return RightDClick();
  default:
    return false;
  }
}

bool ShellMouseEvent::ButtonDown(
  const int but
) const
{
  switch (but) {
  case -1:
    return LeftDown() || MiddleDown() || RightDown();
  case 1:
    return LeftDown();
  case 2:
    return MiddleDown();
  case 3:
    return RightDown();
  default:
    return false;
  }
}

bool ShellMouseEvent::ButtonUp(
  const int but
) const
{
  switch (but) {
  case -1:
    return LeftUp() || MiddleUp() || RightUp();
  case 1:
    return LeftUp();
  case 2:
    return MiddleUp();
  case 3:
    return RightUp();
  default:
    return false;
  }
}

bool ShellMouseEvent::Button(
  const int but
) const
{
  switch (but) {
  case -1:
    return ButtonUp(-1) || ButtonDown(-1) || ButtonDClick(-1);
  case 1:
    return LeftDown() || LeftUp() || LeftDClick();
  case 2:
    return MiddleDown() || MiddleUp() || MiddleDClick();
  case 3:
    return RightDown() || RightUp() || RightDClick();
  default:
    return false;
  }
}

bool ShellMouseEvent::ButtonIsDown(
  const int but
) const
{
  switch (but) {
  case -1:
    return LeftIsDown() || MiddleIsDown() || RightIsDown();
  case 1:
    return LeftIsDown();
  case 2:
    return MiddleIsDown();
  case 3:
    return RightIsDown();
  default:
    return false;
  }
}

int ShellMouseEvent::GetButton() const
{
  for (int i = 1; i <= 3; ++i) {
    if (Button(i)) {
      return i;
    }
  }
  return -1;
}

// --- Windows ---------------------------------------------------------------------------------

const ShellPoint kShellDefaultPosition(-1, -1);
const ShellSize kShellDefaultSize(-1, -1);

namespace
{
  // The window that gets its top-level window's keyboard and mouse events (Window::SetFocus).
  ShellWindow* sFocusWindow = nullptr;
  // The Window of each window system window (top-level windows and native children), for
  // delivering its events.
  std::unordered_map<void*, ShellWindow*> sNativeWindows;
  // Whether one of the program's windows has the keyboard, and the frame told it got it.
  bool sAppActive = false;
  ShellWindow* sActivatedFrame = nullptr;

  [[nodiscard]] std::string Utf8(
    const ShellString& text
  )
  {
    std::string utf8;
    for (const wchar_t character : text) {
      const std::uint32_t code = static_cast<std::uint32_t>(character);
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
    return utf8;
  }
} // namespace

ShellWindow::ShellWindow(
  ShellWindow* const parent,
  const ShellWindowID id,
  const ShellPoint& pos,
  const ShellSize& size,
  const long style,
  const wchar_t* const name
)
  : m_parent(parent)
{
  (void)id;
  (void)style;
  (void)name;
  m_screenX = pos.x < 0 ? 0 : pos.x;
  m_screenY = pos.y < 0 ? 0 : pos.y;
  m_clientWidth = size.x < 0 ? 0 : size.x;
  m_clientHeight = size.y < 0 ? 0 : size.y;
  if (parent != nullptr) {
    parent->m_children.push_back(this);
    const int width = size.x < 0 ? parent->m_clientWidth : size.x;
    const int height = size.y < 0 ? parent->m_clientHeight : size.y;
    if (
      void* const child = parent->m_platformWindow != nullptr
        ? platform::window::CreateChild(
            parent->m_platformWindow, pos.x < 0 ? 0 : pos.x, pos.y < 0 ? 0 : pos.y, width, height
          )
        : nullptr;
      child != nullptr
    ) {
      // A native window of its own inside the parent's (Windows), as the 2.4.2 window library made it.
      m_nativeChild = true;
      m_shown = true;
      m_platformWindow = child;
      m_handle = reinterpret_cast<ShellNativeHandle>(platform::window::NativeHandle(child));
      sNativeWindows[child] = this;
      platform::window::GetBounds(child, &m_screenX, &m_screenY, &m_clientWidth, &m_clientHeight);
      return;
    }
    // A child fills its parent's native window, from the same origin.
    m_handle = parent->m_handle;
    m_platformWindow = parent->m_platformWindow;
    m_screenX = parent->m_screenX;
    m_screenY = parent->m_screenY;
    m_clientWidth = width;
    m_clientHeight = height;
  }
}

void ShellWindow::SetTopLevel(
  void* const platformWindow
)
{
  m_topLevel = true;
  m_platformWindow = platformWindow;
  m_handle = reinterpret_cast<ShellNativeHandle>(platform::window::NativeHandle(platformWindow));
}

bool ShellWindow::Destroy()
{
  delete this;
  return true;
}

bool ShellWindow::Show(
  const bool show
)
{
  const bool changed = m_shown != show;
  m_shown = show;
  if ((m_topLevel || m_nativeChild) && m_platformWindow != nullptr) {
    platform::window::Show(m_platformWindow, show);
  }
  return changed;
}

ShellPoint ShellWindow::GetPosition() const
{
  if (m_topLevel && m_platformWindow != nullptr) {
    int x = 0;
    int y = 0;
    platform::window::GetFramePosition(m_platformWindow, &x, &y);
    return ShellPoint(x, y);
  }
  return ShellPoint(m_screenX, m_screenY);
}

void ShellWindow::SetFocus()
{
  sFocusWindow = this;
  if ((m_topLevel || m_nativeChild) && m_platformWindow != nullptr) {
    platform::window::SetKeyboardFocus(m_platformWindow);
  }
}

ShellWindow* ShellWindow::FindFocus()
{
  return sFocusWindow;
}

void ShellWindow::SetSize(
  const int width,
  const int height
)
{
  SetSize(-1, -1, width, height);
}

void ShellWindow::SetSize(
  const int x,
  const int y,
  const int width,
  const int height,
  const int sizeFlags
)
{
  (void)sizeFlags;
  if (m_nativeChild && m_platformWindow != nullptr) {
    // x, y in the parent's client area, as the 2.4.2 window library placed child windows.
    platform::window::SetBounds(m_platformWindow, x, y, width, height);
    platform::window::GetBounds(m_platformWindow, &m_screenX, &m_screenY, &m_clientWidth, &m_clientHeight);
    return;
  }
  if (m_topLevel && m_platformWindow != nullptr) {
    // x, y place the frame (the retail window library's top-level position); width, height are
    // the client size. The window system decides; its answer is what the window has.
    if (x != -1 || y != -1) {
      int frameX = 0;
      int frameY = 0;
      platform::window::GetFramePosition(m_platformWindow, &frameX, &frameY);
      platform::window::SetFramePosition(m_platformWindow, x != -1 ? x : frameX, y != -1 ? y : frameY);
    }
    platform::window::SetBounds(m_platformWindow, -1, -1, width, height);
    int screenX = 0;
    int screenY = 0;
    int clientWidth = 0;
    int clientHeight = 0;
    platform::window::GetBounds(m_platformWindow, &screenX, &screenY, &clientWidth, &clientHeight);
    SetClientArea(screenX, screenY, clientWidth, clientHeight);
    for (ShellWindow* const child : m_children) {
      if (!child->IsNativeChild()) {
        child->SetClientArea(screenX, screenY, clientWidth, clientHeight);
      }
    }
    return;
  }
  if (x != -1) {
    m_screenX = x;
  }
  if (y != -1) {
    m_screenY = y;
  }
  if (width != -1) {
    m_clientWidth = width;
  }
  if (height != -1) {
    m_clientHeight = height;
  }
}

ShellWindow::~ShellWindow()
{
  if (sFocusWindow == this) {
    sFocusWindow = nullptr;
  }
  if (sActivatedFrame == this) {
    sActivatedFrame = nullptr;
  }
  if (m_parent != nullptr) {
    std::vector<ShellWindow*>& siblings = m_parent->m_children;
    siblings.erase(std::remove(siblings.begin(), siblings.end(), this), siblings.end());
  }
  for (ShellWindow* const child : m_children) {
    child->m_parent = nullptr; // the engine deletes its own windows
  }
  if ((m_topLevel || m_nativeChild) && m_platformWindow != nullptr) {
    sNativeWindows.erase(m_platformWindow);
    platform::window::Destroy(m_platformWindow);
  }
  // The 2.4.2 window library deletes the handlers still pushed onto a window it destroys.
  while (m_eventHandler != nullptr && m_eventHandler != this) {
    ShellEvtHandler* const handler = m_eventHandler;
    m_eventHandler = handler->GetNextHandler();
    handler->SetNextHandler(nullptr);
    handler->SetPreviousHandler(nullptr);
    delete handler;
  }
}

void ShellWindow::PushEventHandler(
  ShellEvtHandler* const handler
)
{
  ShellEvtHandler* const handlerOld = GetEventHandler();
  handler->SetNextHandler(handlerOld);
  if (handlerOld != nullptr) {
    handlerOld->SetPreviousHandler(handler);
  }
  SetEventHandler(handler);
}

ShellEvtHandler* ShellWindow::PopEventHandler(
  const bool deleteHandler
)
{
  ShellEvtHandler* const handlerA = GetEventHandler();
  if (handlerA == nullptr || handlerA == this) {
    return nullptr;
  }
  ShellEvtHandler* const handlerB = handlerA->GetNextHandler();
  handlerA->SetNextHandler(nullptr);
  if (handlerB != nullptr) {
    handlerB->SetPreviousHandler(nullptr);
  }
  SetEventHandler(handlerB);
  if (deleteHandler) {
    delete handlerA;
    return nullptr;
  }
  return handlerA;
}

void ShellWindow::GetClientSize(
  int* const width,
  int* const height
) const
{
  if (width != nullptr) {
    *width = m_clientWidth;
  }
  if (height != nullptr) {
    *height = m_clientHeight;
  }
}

ShellSize ShellWindow::GetClientSize() const
{
  return ShellSize(m_clientWidth, m_clientHeight);
}

void ShellWindow::ScreenToClient(
  int* const x,
  int* const y
) const
{
  if (x != nullptr) {
    *x -= m_screenX;
  }
  if (y != nullptr) {
    *y -= m_screenY;
  }
}

ShellPoint ShellWindow::ScreenToClient(
  const ShellPoint& point
) const
{
  return ShellPoint(point.x - m_screenX, point.y - m_screenY);
}

void ShellWindow::SetClientArea(
  const int screenX,
  const int screenY,
  const int width,
  const int height
)
{
  m_screenX = screenX;
  m_screenY = screenY;
  m_clientWidth = width;
  m_clientHeight = height;
}

// --- The application -------------------------------------------------------------------------

ShellApp* gShellApp = nullptr;

ShellApp::ShellApp()
{
  gShellApp = this;
}

ShellApp::~ShellApp()
{
  if (gShellApp == this) {
    gShellApp = nullptr;
  }
}

// --- Top-level windows ----------------------------------------------------------------------

ShellTopLevelWindow::ShellTopLevelWindow(
  ShellWindow* const parent,
  const ShellWindowID id,
  const ShellString& title,
  const ShellPoint& pos,
  const ShellSize& size,
  const long style,
  const wchar_t* const name
)
  : ShellWindow(nullptr, id, pos, size, style, name)
  , m_title(title)
  , m_windowStyle(style)
{
  // The 2.4.2 window library frames with a parent are still desktop windows; the parent only owns them.
  (void)parent;
  void* const native = platform::window::CreateTopLevel(
    Utf8(title).c_str(), pos.x, pos.y, size.x, size.y, (style & SHELL_RESIZE_BORDER) != 0
  );
  if (native == nullptr) {
    return; // no window system: the window keeps its requested area, as before
  }
  SetTopLevel(native);
  sNativeWindows[native] = this;
  int screenX = 0;
  int screenY = 0;
  int clientWidth = 0;
  int clientHeight = 0;
  platform::window::GetBounds(native, &screenX, &screenY, &clientWidth, &clientHeight);
  SetClientArea(screenX, screenY, clientWidth, clientHeight);
}

void ShellTopLevelWindow::Maximize(
  const bool maximize
)
{
  m_maximized = maximize;
  if (GetPlatformWindow() != nullptr) {
    (maximize ? platform::window::Maximize : platform::window::Restore)(GetPlatformWindow());
  }
}

void ShellTopLevelWindow::Iconize(
  const bool iconize
)
{
  m_iconized = iconize;
  if (GetPlatformWindow() != nullptr) {
    (iconize ? platform::window::Minimize : platform::window::Restore)(GetPlatformWindow());
  }
}

bool ShellTopLevelWindow::ShowFullScreen(
  const bool show,
  const long style
)
{
  (void)style;
  m_fullScreen = show;
  if (GetPlatformWindow() != nullptr) {
    platform::window::SetFullscreen(GetPlatformWindow(), show);
  }
  return true;
}

void ShellTopLevelWindow::SetTitle(
  const ShellString& title
)
{
  m_title = title;
  if (GetPlatformWindow() != nullptr) {
    platform::window::SetTitle(GetPlatformWindow(), Utf8(title).c_str());
  }
}

// --- Window events: what the 2.4.2 window library on Windows sent for the same messages ----------------------

namespace
{
  // The window a native window's input goes to: the focused window when it is this one or one of
  // its children sharing it (the game's viewport), else its first such child, else itself.
  [[nodiscard]] ShellWindow* InputTarget(
    ShellWindow* const top
  )
  {
    if (
      sFocusWindow != nullptr &&
      (sFocusWindow == top || (sFocusWindow->GetParent() == top && !sFocusWindow->IsNativeChild()))
    ) {
      return sFocusWindow;
    }
    for (ShellWindow* const child : top->GetChildren()) {
      if (!child->IsNativeChild()) {
        return child;
      }
    }
    return top;
  }

  void Deliver(
    ShellWindow* const window,
    ShellEvent& event
  )
  {
    event.SetEventObject(window);
    if (ShellEvtHandler* const handler = window->GetEventHandler(); handler != nullptr) {
      (void)handler->ProcessEvent(event);
    }
  }

  // Native children follow their parent's moves (their screen origin) and, as Frame::OnSize did
  // for a frame's only child, fill its client area when it is the only child.
  void FollowParent(
    ShellWindow* const top,
    const bool resized
  )
  {
    const std::vector<ShellWindow*>& children = top->GetChildren();
    for (ShellWindow* const child : children) {
      if (!child->IsNativeChild()) {
        continue;
      }
      if (resized && children.size() == 1u) {
        const ShellSize size = top->GetClientSize();
        child->SetSize(0, 0, size.x, size.y);
        ShellSizeEvent childEvent(size.x, size.y);
        Deliver(child, childEvent);
        continue;
      }
      int screenX = 0;
      int screenY = 0;
      int width = 0;
      int height = 0;
      platform::window::GetBounds(child->GetPlatformWindow(), &screenX, &screenY, &width, &height);
      child->SetClientArea(screenX, screenY, width, height);
    }
  }

  void FillModifiers(
    const std::uint32_t modifiers,
    bool& control,
    bool& shift,
    bool& alt,
    bool& meta
  )
  {
    control = (modifiers & platform::window::kModifierControl) != 0;
    shift = (modifiers & platform::window::kModifierShift) != 0;
    alt = (modifiers & platform::window::kModifierAlt) != 0;
    meta = (modifiers & platform::window::kModifierMeta) != 0;
  }

  void DeliverMouse(
    ShellWindow* const top,
    const platform::window::Event& source,
    const ShellEventType type
  )
  {
    ShellWindow* const target = InputTarget(top);
    ShellMouseEvent event(type);
    event.m_x = source.x;
    event.m_y = source.y;
    event.m_leftDown = (source.buttonsDown & platform::window::kLeftDown) != 0;
    event.m_middleDown = (source.buttonsDown & platform::window::kMiddleDown) != 0;
    event.m_rightDown = (source.buttonsDown & platform::window::kRightDown) != 0;
    FillModifiers(source.modifiers, event.m_controlDown, event.m_shiftDown, event.m_altDown, event.m_metaDown);
    if (type == SHELL_EVT_MOUSEWHEEL) {
      // WM_MOUSEWHEEL: 120 per notch, three lines each (the Windows default).
      event.m_wheelRotation = static_cast<int>(std::lround(source.wheel * 120.0f));
      event.m_wheelDelta = 120;
      event.m_linesPerAction = 3;
    }
    Deliver(target, event);
  }

  void DeliverKey(
    ShellWindow* const top,
    const ShellEventType type,
    const long keyCode,
    const platform::window::Event& source,
    const bool controlOverride
  )
  {
    ShellWindow* const target = InputTarget(top);
    ShellKeyEvent event(type);
    event.m_keyCode = keyCode;
    FillModifiers(source.modifiers, event.m_controlDown, event.m_shiftDown, event.m_altDown, event.m_metaDown);
    event.m_controlDown = event.m_controlDown || controlOverride;
    // WM_KEYDOWN's wParam and lParam: the virtual key, and bit 30 when the key was already down.
    event.m_rawCode = static_cast<ShellUint32>(source.virtualKey);
    event.m_rawFlags = source.repeat ? (1u << 30) : 0u;
    Deliver(target, event);
  }

  // The 2.4.2 window library (src/msw/window.cpp) sends a char event for a key Windows gives no WM_CHAR for, with
  // its window-library code, besides the key-down; and turns WM_CHAR 1..26 (Ctrl+letter) into the code with
  // ControlDown. SDL reports typed text apart (EventType::Text); these are the keys it doesn't.
  void DeliverCharForKey(
    ShellWindow* const top,
    const platform::window::Event& source
  )
  {
    const int virtualKey = source.virtualKey;
    const bool control = (source.modifiers & platform::window::kModifierControl) != 0;
    switch (virtualKey) {
    case VK_BACK:
      DeliverKey(top, SHELL_EVT_CHAR, SHELL_KEY_BACK, source, false);
      return;
    case VK_TAB:
      DeliverKey(top, SHELL_EVT_CHAR, SHELL_KEY_TAB, source, false);
      return;
    case VK_RETURN:
      DeliverKey(top, SHELL_EVT_CHAR, SHELL_KEY_RETURN, source, false);
      return;
    case VK_ESCAPE:
      DeliverKey(top, SHELL_EVT_CHAR, SHELL_KEY_ESCAPE, source, false);
      return;
    default:
      break;
    }
    if (control && virtualKey >= 'A' && virtualKey <= 'Z') {
      DeliverKey(top, SHELL_EVT_CHAR, virtualKey - 'A' + 1, source, true);
      return;
    }
    // Keys that type nothing: arrows, function keys, navigation, modifiers.
    const bool typesText = virtualKey == VK_SPACE || (virtualKey >= '0' && virtualKey <= '9') ||
      (virtualKey >= 'A' && virtualKey <= 'Z') || (virtualKey >= VK_NUMPAD0 && virtualKey <= VK_DIVIDE) ||
      (virtualKey >= VK_OEM_1 && virtualKey <= VK_OEM_3) || (virtualKey >= VK_OEM_4 && virtualKey <= VK_OEM_7);
    if (!typesText) {
      if (const int code = ShellKeyFromVirtualKey(virtualKey); code != 0) {
        DeliverKey(top, SHELL_EVT_CHAR, code, source, false);
      }
    }
  }

  void DeliverWindowEvent(
    const platform::window::Event& source
  )
  {
    using platform::window::EventType;
    if (source.type == EventType::Quit) {
      if (gShellApp != nullptr) {
        gShellApp->ExitMainLoop(); // what App::DoMessage did on WM_QUIT
      }
      return;
    }
    const auto found = sNativeWindows.find(source.window);
    if (found == sNativeWindows.end()) {
      return;
    }
    ShellWindow* const top = found->second;
    // Window state belongs to top-level windows; a native child has input, size and paint.
    ShellTopLevelWindow* const frame = top->IsTopLevel() ? static_cast<ShellTopLevelWindow*>(top) : nullptr;
    switch (source.type) {
    case EventType::CloseRequested: {
      ShellCloseEvent event(SHELL_EVT_CLOSE_WINDOW);
      event.SetCanVeto(true);
      Deliver(top, event);
      return;
    }
    case EventType::Moved: {
      const ShellSize size = top->GetClientSize();
      top->SetClientArea(source.x, source.y, size.x, size.y);
      for (ShellWindow* const child : top->GetChildren()) {
        if (!child->IsNativeChild()) {
          child->SetClientArea(source.x, source.y, size.x, size.y);
        }
      }
      FollowParent(top, false);
      ShellMoveEvent event(source.x, source.y);
      Deliver(top, event);
      return;
    }
    case EventType::Resized: {
      int screenX = 0;
      int screenY = 0;
      platform::window::GetBounds(source.window, &screenX, &screenY, nullptr, nullptr);
      top->SetClientArea(screenX, screenY, source.width, source.height);
      ShellSizeEvent event(source.width, source.height);
      Deliver(top, event);
      for (ShellWindow* const child : top->GetChildren()) {
        if (child->IsNativeChild()) {
          continue;
        }
        child->SetClientArea(screenX, screenY, source.width, source.height);
        ShellSizeEvent childEvent(source.width, source.height);
        Deliver(child, childEvent);
      }
      FollowParent(top, true);
      return;
    }
    case EventType::Minimized:
      if (frame != nullptr) {
        frame->NoteIconized(true);
      }
      return;
    case EventType::Maximized:
    case EventType::Restored: {
      if (frame == nullptr) {
        return;
      }
      // Windows' WM_SIZE carried the new state (SIZE_MAXIMIZED, SIZE_RESTORED) with the size; the
      // window system may report the state after the size, so the size event follows the state.
      frame->NoteIconized(false);
      frame->NoteMaximized(source.type == EventType::Maximized);
      const ShellSize size = top->GetClientSize();
      ShellSizeEvent event(size.x, size.y);
      Deliver(top, event);
      return;
    }
    case EventType::FocusGained:
    case EventType::FocusLost: {
      // WM_ACTIVATEAPP: the keyboard came to the program or left it. A move between its own
      // windows (the frame and its viewport, a developer window) is neither.
      const bool active = source.type == EventType::FocusGained || platform::window::HasKeyboardFocus();
      if (active == sAppActive) {
        return;
      }
      sAppActive = active;
      ShellWindow* receiver = active ? top : sActivatedFrame;
      while (receiver != nullptr && !receiver->IsTopLevel()) {
        receiver = receiver->GetParent();
      }
      sActivatedFrame = active ? receiver : nullptr;
      if (receiver != nullptr) {
        ShellActivateEvent event(active);
        Deliver(receiver, event);
      }
      return;
    }
    case EventType::SystemCommand:
      if (frame != nullptr) {
        frame->OnSystemCommand(source.command);
      }
      return;
    case EventType::Exposed:
      if (top->IsNativeChild()) {
        ShellPaintEvent event;
        Deliver(top, event);
        return;
      }
      for (ShellWindow* const child : top->GetChildren()) {
        if (!child->IsNativeChild()) {
          ShellPaintEvent event;
          Deliver(child, event);
        }
      }
      return;
    case EventType::MouseEnter:
      DeliverMouse(top, source, SHELL_EVT_ENTER_WINDOW);
      return;
    case EventType::MouseLeave:
      DeliverMouse(top, source, SHELL_EVT_LEAVE_WINDOW);
      return;
    case EventType::MouseMove:
      DeliverMouse(top, source, SHELL_EVT_MOTION);
      return;
    case EventType::MouseDown: {
      // Windows sends a double-click message in place of the second press.
      const bool doubleClick = source.clicks >= 2;
      switch (source.button) {
      case platform::window::kButtonLeft:
        DeliverMouse(top, source, doubleClick ? SHELL_EVT_LEFT_DCLICK : SHELL_EVT_LEFT_DOWN);
        break;
      case platform::window::kButtonMiddle:
        DeliverMouse(top, source, doubleClick ? SHELL_EVT_MIDDLE_DCLICK : SHELL_EVT_MIDDLE_DOWN);
        break;
      case platform::window::kButtonRight:
        DeliverMouse(top, source, doubleClick ? SHELL_EVT_RIGHT_DCLICK : SHELL_EVT_RIGHT_DOWN);
        break;
      default:
        break;
      }
      return;
    }
    case EventType::MouseUp:
      switch (source.button) {
      case platform::window::kButtonLeft:
        DeliverMouse(top, source, SHELL_EVT_LEFT_UP);
        break;
      case platform::window::kButtonMiddle:
        DeliverMouse(top, source, SHELL_EVT_MIDDLE_UP);
        break;
      case platform::window::kButtonRight:
        DeliverMouse(top, source, SHELL_EVT_RIGHT_UP);
        break;
      default:
        break;
      }
      return;
    case EventType::MouseWheel:
      DeliverMouse(top, source, SHELL_EVT_MOUSEWHEEL);
      return;
    case EventType::KeyDown: {
      // The 2.4.2 window library HandleKeyDown: the window-library code of a special key, else the virtual key itself.
      const int code = ShellKeyFromVirtualKey(source.virtualKey);
      DeliverKey(top, SHELL_EVT_KEY_DOWN, code != 0 ? code : source.virtualKey, source, false);
      DeliverCharForKey(top, source);
      return;
    }
    case EventType::KeyUp: {
      const int code = ShellKeyFromVirtualKey(source.virtualKey);
      DeliverKey(top, SHELL_EVT_KEY_UP, code != 0 ? code : source.virtualKey, source, false);
      return;
    }
    case EventType::Text:
      DeliverKey(top, SHELL_EVT_CHAR, static_cast<long>(source.codepoint), source, false);
      return;
    default:
      return;
    }
  }
} // namespace

bool ShellApp::Pending()
{
  return platform::window::HasEvents();
}

void ShellApp::Dispatch()
{
  platform::window::Event event;
  if (platform::window::PollEvent(event)) {
    DeliverWindowEvent(event);
  }
}

void ShellApp::CleanUp()
{
  delete gShellApp; // the destructor clears TheApp
}

int ShellEntry(
  const ShellInstanceHandle instance,
  const ShellInstanceHandle previousInstance,
  char* const commandLine,
  const int showCommand,
  const bool enterLoop
)
{
  (void)instance;
  (void)previousInstance;
  (void)commandLine;
  (void)showCommand;
  if (gShellApp == nullptr) {
    if (const ShellApp::InitializerFunction create = ShellApp::GetInitializerFunction(); create != nullptr) {
      (void)create(); // the constructor sets TheApp
    }
  }
  if (gShellApp == nullptr || !gShellApp->OnInit()) {
    return -1;
  }
  // The engine runs its own loop (enterLoop false); nothing here runs one for it.
  (void)enterLoop;
  return 0;
}

void ShellApp::ExitMainLoop()
{
  m_keepGoing = FALSE;
}

const ShellString kShellEmptyString;
const wchar_t* kShellFrameName = L"frame";

ShellPoint ShellGetMousePosition()
{
  POINT point{};
  (void)::GetCursorPos(&point);
  return ShellPoint(point.x, point.y);
}

// --- Key codes (the 2.4.2 window library src/msw/window.cpp) --------------------------------------------------

int ShellKeyFromVirtualKey(
  const int keySym
)
{
  switch (keySym) {
  case VK_CANCEL:
    return SHELL_KEY_CANCEL;
  case VK_BACK:
    return SHELL_KEY_BACK;
  case VK_TAB:
    return SHELL_KEY_TAB;
  case VK_CLEAR:
    return SHELL_KEY_CLEAR;
  case VK_RETURN:
    return SHELL_KEY_RETURN;
  case VK_SHIFT:
    return SHELL_KEY_SHIFT;
  case VK_CONTROL:
    return SHELL_KEY_CONTROL;
  case VK_MENU:
    return SHELL_KEY_MENU;
  case VK_PAUSE:
    return SHELL_KEY_PAUSE;
  case VK_CAPITAL:
    return SHELL_KEY_CAPITAL;
  case VK_SPACE:
    return SHELL_KEY_SPACE;
  case VK_ESCAPE:
    return SHELL_KEY_ESCAPE;
  case VK_PRIOR:
    return SHELL_KEY_PRIOR;
  case VK_NEXT:
    return SHELL_KEY_NEXT;
  case VK_END:
    return SHELL_KEY_END;
  case VK_HOME:
    return SHELL_KEY_HOME;
  case VK_LEFT:
    return SHELL_KEY_LEFT;
  case VK_UP:
    return SHELL_KEY_UP;
  case VK_RIGHT:
    return SHELL_KEY_RIGHT;
  case VK_DOWN:
    return SHELL_KEY_DOWN;
  case VK_SELECT:
    return SHELL_KEY_SELECT;
  case VK_PRINT:
    return SHELL_KEY_PRINT;
  case VK_EXECUTE:
    return SHELL_KEY_EXECUTE;
  case VK_INSERT:
    return SHELL_KEY_INSERT;
  case VK_DELETE:
    return SHELL_KEY_DELETE;
  case VK_HELP:
    return SHELL_KEY_HELP;
  case VK_NUMPAD0:
    return SHELL_KEY_NUMPAD0;
  case VK_NUMPAD1:
    return SHELL_KEY_NUMPAD1;
  case VK_NUMPAD2:
    return SHELL_KEY_NUMPAD2;
  case VK_NUMPAD3:
    return SHELL_KEY_NUMPAD3;
  case VK_NUMPAD4:
    return SHELL_KEY_NUMPAD4;
  case VK_NUMPAD5:
    return SHELL_KEY_NUMPAD5;
  case VK_NUMPAD6:
    return SHELL_KEY_NUMPAD6;
  case VK_NUMPAD7:
    return SHELL_KEY_NUMPAD7;
  case VK_NUMPAD8:
    return SHELL_KEY_NUMPAD8;
  case VK_NUMPAD9:
    return SHELL_KEY_NUMPAD9;
  case VK_MULTIPLY:
    return SHELL_KEY_NUMPAD_MULTIPLY;
  case VK_ADD:
    return SHELL_KEY_NUMPAD_ADD;
  case VK_SUBTRACT:
    return SHELL_KEY_NUMPAD_SUBTRACT;
  case VK_DECIMAL:
    return SHELL_KEY_NUMPAD_DECIMAL;
  case VK_DIVIDE:
    return SHELL_KEY_NUMPAD_DIVIDE;
  case VK_F1:
    return SHELL_KEY_F1;
  case VK_F2:
    return SHELL_KEY_F2;
  case VK_F3:
    return SHELL_KEY_F3;
  case VK_F4:
    return SHELL_KEY_F4;
  case VK_F5:
    return SHELL_KEY_F5;
  case VK_F6:
    return SHELL_KEY_F6;
  case VK_F7:
    return SHELL_KEY_F7;
  case VK_F8:
    return SHELL_KEY_F8;
  case VK_F9:
    return SHELL_KEY_F9;
  case VK_F10:
    return SHELL_KEY_F10;
  case VK_F11:
    return SHELL_KEY_F11;
  case VK_F12:
    return SHELL_KEY_F12;
  case VK_F13:
    return SHELL_KEY_F13;
  case VK_F14:
    return SHELL_KEY_F14;
  case VK_F15:
    return SHELL_KEY_F15;
  case VK_F16:
    return SHELL_KEY_F16;
  case VK_F17:
    return SHELL_KEY_F17;
  case VK_F18:
    return SHELL_KEY_F18;
  case VK_F19:
    return SHELL_KEY_F19;
  case VK_F20:
    return SHELL_KEY_F20;
  case VK_F21:
    return SHELL_KEY_F21;
  case VK_F22:
    return SHELL_KEY_F22;
  case VK_F23:
    return SHELL_KEY_F23;
  case VK_F24:
    return SHELL_KEY_F24;
  case VK_NUMLOCK:
    return SHELL_KEY_NUMLOCK;
  case VK_SCROLL:
    return SHELL_KEY_SCROLL;
  case VK_OEM_1:
    return ';';
  case VK_OEM_PLUS:
    return '+';
  case VK_OEM_COMMA:
    return ',';
  case VK_OEM_MINUS:
    return '-';
  case VK_OEM_PERIOD:
    return '.';
  case VK_OEM_2:
    return '/';
  case VK_OEM_3:
    return '~';
  case VK_OEM_4:
    return '[';
  case VK_OEM_5:
    return '\\';
  case VK_OEM_6:
    return ']';
  case VK_OEM_7:
    return '\'';
  default:
    return 0;
  }
}

int ShellKeyToVirtualKey(
  const int id,
  bool* const isVirtual
)
{
  *isVirtual = true;
  switch (id) {
  case SHELL_KEY_CANCEL:
    return VK_CANCEL;
  case SHELL_KEY_CLEAR:
    return VK_CLEAR;
  case SHELL_KEY_SHIFT:
    return VK_SHIFT;
  case SHELL_KEY_CONTROL:
    return VK_CONTROL;
  case SHELL_KEY_MENU:
    return VK_MENU;
  case SHELL_KEY_PAUSE:
    return VK_PAUSE;
  case SHELL_KEY_PRIOR:
    return VK_PRIOR;
  case SHELL_KEY_NEXT:
    return VK_NEXT;
  case SHELL_KEY_END:
    return VK_END;
  case SHELL_KEY_HOME:
    return VK_HOME;
  case SHELL_KEY_LEFT:
    return VK_LEFT;
  case SHELL_KEY_UP:
    return VK_UP;
  case SHELL_KEY_RIGHT:
    return VK_RIGHT;
  case SHELL_KEY_DOWN:
    return VK_DOWN;
  case SHELL_KEY_SELECT:
    return VK_SELECT;
  case SHELL_KEY_PRINT:
    return VK_PRINT;
  case SHELL_KEY_EXECUTE:
    return VK_EXECUTE;
  case SHELL_KEY_INSERT:
    return VK_INSERT;
  case SHELL_KEY_DELETE:
    return VK_DELETE;
  case SHELL_KEY_HELP:
    return VK_HELP;
  case SHELL_KEY_NUMPAD0:
    return VK_NUMPAD0;
  case SHELL_KEY_NUMPAD1:
    return VK_NUMPAD1;
  case SHELL_KEY_NUMPAD2:
    return VK_NUMPAD2;
  case SHELL_KEY_NUMPAD3:
    return VK_NUMPAD3;
  case SHELL_KEY_NUMPAD4:
    return VK_NUMPAD4;
  case SHELL_KEY_NUMPAD5:
    return VK_NUMPAD5;
  case SHELL_KEY_NUMPAD6:
    return VK_NUMPAD6;
  case SHELL_KEY_NUMPAD7:
    return VK_NUMPAD7;
  case SHELL_KEY_NUMPAD8:
    return VK_NUMPAD8;
  case SHELL_KEY_NUMPAD9:
    return VK_NUMPAD9;
  case SHELL_KEY_NUMPAD_MULTIPLY:
    return VK_MULTIPLY;
  case SHELL_KEY_NUMPAD_ADD:
    return VK_ADD;
  case SHELL_KEY_NUMPAD_SUBTRACT:
    return VK_SUBTRACT;
  case SHELL_KEY_NUMPAD_DECIMAL:
    return VK_DECIMAL;
  case SHELL_KEY_NUMPAD_DIVIDE:
    return VK_DIVIDE;
  case SHELL_KEY_F1:
    return VK_F1;
  case SHELL_KEY_F2:
    return VK_F2;
  case SHELL_KEY_F3:
    return VK_F3;
  case SHELL_KEY_F4:
    return VK_F4;
  case SHELL_KEY_F5:
    return VK_F5;
  case SHELL_KEY_F6:
    return VK_F6;
  case SHELL_KEY_F7:
    return VK_F7;
  case SHELL_KEY_F8:
    return VK_F8;
  case SHELL_KEY_F9:
    return VK_F9;
  case SHELL_KEY_F10:
    return VK_F10;
  case SHELL_KEY_F11:
    return VK_F11;
  case SHELL_KEY_F12:
    return VK_F12;
  case SHELL_KEY_F13:
    return VK_F13;
  case SHELL_KEY_F14:
    return VK_F14;
  case SHELL_KEY_F15:
    return VK_F15;
  case SHELL_KEY_F16:
    return VK_F16;
  case SHELL_KEY_F17:
    return VK_F17;
  case SHELL_KEY_F18:
    return VK_F18;
  case SHELL_KEY_F19:
    return VK_F19;
  case SHELL_KEY_F20:
    return VK_F20;
  case SHELL_KEY_F21:
    return VK_F21;
  case SHELL_KEY_F22:
    return VK_F22;
  case SHELL_KEY_F23:
    return VK_F23;
  case SHELL_KEY_F24:
    return VK_F24;
  case SHELL_KEY_NUMLOCK:
    return VK_NUMLOCK;
  case SHELL_KEY_SCROLL:
    return VK_SCROLL;
  default:
    *isVirtual = false;
    return id;
  }
}

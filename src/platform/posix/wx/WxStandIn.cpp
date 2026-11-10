// Engine addition (issue #255): the code behind the wx stand-in headers (wx/defs.h in this
// folder) for the Linux client: wx 2.4.2's event table search and handler chain
// (src/common/event.cpp, src/common/wincmn.cpp), its mouse button tests, and its key code
// conversions (src/msw/window.cpp). The window system that feeds them is issue #256.

#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "platform/Window.h"
#include "platform/posix/Win32WindowPosix.h"

#include <wx/app.h>
#include <wx/dc.h>
#include <wx/event.h>
#include <wx/frame.h>
#include <wx/string.h>
#include <wx/window.h>

static wxBrush sBlackBrush;
wxBrush* wxBLACK_BRUSH = &sBlackBrush;
wxBrush wxNullBrush;

// --- Event tables --------------------------------------------------------------------------

const wxEventTableEntry wxEvtHandler::sm_eventTableEntries[] = {
  DECLARE_EVENT_TABLE_ENTRY(wxEVT_NULL, 0, 0, nullptr, nullptr)};
const wxEventTable wxEvtHandler::sm_eventTable = {nullptr, &wxEvtHandler::sm_eventTableEntries[0]};

const wxEventTable* wxEvtHandler::GetEventTable() const
{
  return &wxEvtHandler::sm_eventTable;
}

wxEvtHandler::~wxEvtHandler()
{
  // wx 2.4.2 unlinks a handler from its neighbours when it is destroyed.
  if (m_previousHandler != nullptr) {
    m_previousHandler->m_nextHandler = m_nextHandler;
  }
  if (m_nextHandler != nullptr) {
    m_nextHandler->m_previousHandler = m_previousHandler;
  }
}

bool wxEvtHandler::SearchEventTable(const wxEventTable& table, wxEvent& event)
{
  const wxEventType eventType = event.GetEventType();
  const int eventId = event.GetId();
  for (const wxEventTableEntry* entry = table.entries; entry->m_fn != nullptr; ++entry) {
    if (entry->m_eventType != eventType) {
      continue;
    }
    const int firstId = entry->m_id;
    const int lastId = entry->m_lastId;
    if (firstId == -1 || (lastId == -1 && eventId == firstId) ||
        (lastId != -1 && eventId >= firstId && eventId <= lastId)) {
      event.Skip(false);
      event.m_callbackUserData = entry->m_callbackUserData;
      (this->*reinterpret_cast<wxEventFunction>(entry->m_fn))(event);
      return !event.GetSkipped();
    }
  }
  return false;
}

bool wxEvtHandler::ProcessEvent(wxEvent& event)
{
  if (GetEvtHandlerEnabled()) {
    for (const wxEventTable* table = GetEventTable(); table != nullptr; table = table->baseTable) {
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

bool wxMouseEvent::ButtonDClick(const int but) const
{
  switch (but) {
    case -1: return LeftDClick() || MiddleDClick() || RightDClick();
    case 1: return LeftDClick();
    case 2: return MiddleDClick();
    case 3: return RightDClick();
    default: return false;
  }
}

bool wxMouseEvent::ButtonDown(const int but) const
{
  switch (but) {
    case -1: return LeftDown() || MiddleDown() || RightDown();
    case 1: return LeftDown();
    case 2: return MiddleDown();
    case 3: return RightDown();
    default: return false;
  }
}

bool wxMouseEvent::ButtonUp(const int but) const
{
  switch (but) {
    case -1: return LeftUp() || MiddleUp() || RightUp();
    case 1: return LeftUp();
    case 2: return MiddleUp();
    case 3: return RightUp();
    default: return false;
  }
}

bool wxMouseEvent::Button(const int but) const
{
  switch (but) {
    case -1: return ButtonUp(-1) || ButtonDown(-1) || ButtonDClick(-1);
    case 1: return LeftDown() || LeftUp() || LeftDClick();
    case 2: return MiddleDown() || MiddleUp() || MiddleDClick();
    case 3: return RightDown() || RightUp() || RightDClick();
    default: return false;
  }
}

bool wxMouseEvent::ButtonIsDown(const int but) const
{
  switch (but) {
    case -1: return LeftIsDown() || MiddleIsDown() || RightIsDown();
    case 1: return LeftIsDown();
    case 2: return MiddleIsDown();
    case 3: return RightIsDown();
    default: return false;
  }
}

int wxMouseEvent::GetButton() const
{
  for (int i = 1; i <= 3; ++i) {
    if (Button(i)) {
      return i;
    }
  }
  return -1;
}

// --- Windows ---------------------------------------------------------------------------------

const wxPoint wxDefaultPosition(-1, -1);
const wxSize wxDefaultSize(-1, -1);

namespace
{
  // The window that gets its top-level window's keyboard and mouse events (wxWindow::SetFocus).
  wxWindow* sFocusWindow = nullptr;
  // Each native window's top-level wxWindow, for delivering its events.
  std::unordered_map<WXWidget, wxTopLevelWindow*> sTopLevels;

  [[nodiscard]] std::string Utf8(const wxString& text)
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

  [[nodiscard]] void* NativeOf(const WXWidget handle)
  {
    return reinterpret_cast<void*>(handle);
  }
} // namespace

wxWindow::wxWindow(
  wxWindow* const parent,
  const wxWindowID id,
  const wxPoint& pos,
  const wxSize& size,
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
    // A child fills its parent's native window, from the same origin.
    parent->m_children.push_back(this);
    m_handle = parent->m_handle;
    m_screenX = parent->m_screenX;
    m_screenY = parent->m_screenY;
    if (size.x < 0) {
      m_clientWidth = parent->m_clientWidth;
    }
    if (size.y < 0) {
      m_clientHeight = parent->m_clientHeight;
    }
  }
}

void wxWindow::SetTopLevel(const WXWidget handle)
{
  m_topLevel = true;
  m_handle = handle;
}

bool wxWindow::Destroy()
{
  delete this;
  return true;
}

bool wxWindow::Show(const bool show)
{
  const bool changed = m_shown != show;
  m_shown = show;
  if (m_topLevel && m_handle != 0) {
    platform::window::Show(NativeOf(m_handle), show);
  }
  return changed;
}

void wxWindow::SetFocus()
{
  sFocusWindow = this;
}

wxWindow* wxWindow::FindFocus()
{
  return sFocusWindow;
}

void wxWindow::SetSize(const int width, const int height)
{
  SetSize(-1, -1, width, height);
}

void wxWindow::SetSize(const int x, const int y, const int width, const int height, const int sizeFlags)
{
  (void)sizeFlags;
  if (m_topLevel && m_handle != 0) {
    // The window system decides; its answer is what the window has.
    platform::window::SetBounds(NativeOf(m_handle), x, y, width, height);
    int screenX = 0;
    int screenY = 0;
    int clientWidth = 0;
    int clientHeight = 0;
    platform::window::GetBounds(NativeOf(m_handle), &screenX, &screenY, &clientWidth, &clientHeight);
    SetClientArea(screenX, screenY, clientWidth, clientHeight);
    for (wxWindow* const child : m_children) {
      child->SetClientArea(screenX, screenY, clientWidth, clientHeight);
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

wxWindow::~wxWindow()
{
  if (sFocusWindow == this) {
    sFocusWindow = nullptr;
  }
  if (m_parent != nullptr) {
    std::vector<wxWindow*>& siblings = m_parent->m_children;
    siblings.erase(std::remove(siblings.begin(), siblings.end(), this), siblings.end());
  }
  for (wxWindow* const child : m_children) {
    child->m_parent = nullptr; // the engine deletes its own windows
  }
  if (m_topLevel && m_handle != 0) {
    sTopLevels.erase(m_handle);
    platform::window::Destroy(NativeOf(m_handle));
  }
  // wx 2.4.2 deletes the handlers still pushed onto a window it destroys.
  while (m_eventHandler != nullptr && m_eventHandler != this) {
    wxEvtHandler* const handler = m_eventHandler;
    m_eventHandler = handler->GetNextHandler();
    handler->SetNextHandler(nullptr);
    handler->SetPreviousHandler(nullptr);
    delete handler;
  }
}

void wxWindow::PushEventHandler(wxEvtHandler* const handler)
{
  wxEvtHandler* const handlerOld = GetEventHandler();
  handler->SetNextHandler(handlerOld);
  if (handlerOld != nullptr) {
    handlerOld->SetPreviousHandler(handler);
  }
  SetEventHandler(handler);
}

wxEvtHandler* wxWindow::PopEventHandler(const bool deleteHandler)
{
  wxEvtHandler* const handlerA = GetEventHandler();
  if (handlerA == nullptr || handlerA == this) {
    return nullptr;
  }
  wxEvtHandler* const handlerB = handlerA->GetNextHandler();
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

void wxWindow::GetClientSize(int* const width, int* const height) const
{
  if (width != nullptr) {
    *width = m_clientWidth;
  }
  if (height != nullptr) {
    *height = m_clientHeight;
  }
}

wxSize wxWindow::GetClientSize() const
{
  return wxSize(m_clientWidth, m_clientHeight);
}

void wxWindow::ScreenToClient(int* const x, int* const y) const
{
  if (x != nullptr) {
    *x -= m_screenX;
  }
  if (y != nullptr) {
    *y -= m_screenY;
  }
}

wxPoint wxWindow::ScreenToClient(const wxPoint& point) const
{
  return wxPoint(point.x - m_screenX, point.y - m_screenY);
}

void wxWindow::SetClientArea(const int screenX, const int screenY, const int width, const int height)
{
  m_screenX = screenX;
  m_screenY = screenY;
  m_clientWidth = width;
  m_clientHeight = height;
}

// --- The application -------------------------------------------------------------------------

wxApp* wxTheApp = nullptr;

wxApp::wxApp()
{
  wxTheApp = this;
}

wxApp::~wxApp()
{
  if (wxTheApp == this) {
    wxTheApp = nullptr;
  }
}

// --- Top-level windows ----------------------------------------------------------------------

wxTopLevelWindow::wxTopLevelWindow(
  wxWindow* const parent,
  const wxWindowID id,
  const wxString& title,
  const wxPoint& pos,
  const wxSize& size,
  const long style,
  const wchar_t* const name
)
  : wxWindow(nullptr, id, pos, size, style, name)
  , m_title(title)
  , m_windowStyle(style)
{
  // wx 2.4.2 frames with a parent are still desktop windows; the parent only owns them.
  (void)parent;
  void* const native = platform::window::CreateTopLevel(
    Utf8(title).c_str(), pos.x, pos.y, size.x, size.y, (style & wxRESIZE_BORDER) != 0
  );
  if (native == nullptr) {
    return; // no window system: the window keeps its requested area, as before
  }
  const WXWidget handle = reinterpret_cast<WXWidget>(native);
  SetTopLevel(handle);
  sTopLevels[handle] = this;
  int screenX = 0;
  int screenY = 0;
  int clientWidth = 0;
  int clientHeight = 0;
  platform::window::GetBounds(native, &screenX, &screenY, &clientWidth, &clientHeight);
  SetClientArea(screenX, screenY, clientWidth, clientHeight);
}

void wxTopLevelWindow::Maximize(const bool maximize)
{
  m_maximized = maximize;
  if (GetHandle() != 0) {
    (maximize ? platform::window::Maximize : platform::window::Restore)(NativeOf(GetHandle()));
  }
}

void wxTopLevelWindow::Iconize(const bool iconize)
{
  m_iconized = iconize;
  if (GetHandle() != 0) {
    (iconize ? platform::window::Minimize : platform::window::Restore)(NativeOf(GetHandle()));
  }
}

bool wxTopLevelWindow::ShowFullScreen(const bool show, const long style)
{
  (void)style;
  m_fullScreen = show;
  if (GetHandle() != 0) {
    platform::window::SetFullscreen(NativeOf(GetHandle()), show);
  }
  return true;
}

void wxTopLevelWindow::SetTitle(const wxString& title)
{
  m_title = title;
  if (GetHandle() != 0) {
    platform::window::SetTitle(NativeOf(GetHandle()), Utf8(title).c_str());
  }
}

// --- Window events: what wx 2.4.2 on Windows sent for the same messages ----------------------

namespace
{
  // The window a top-level window's input goes to: the focused window when it is this one or one
  // of its children (the game's viewport), else its first child, else itself.
  [[nodiscard]] wxWindow* InputTarget(wxTopLevelWindow* const top)
  {
    if (sFocusWindow != nullptr && (sFocusWindow == top || sFocusWindow->GetParent() == top)) {
      return sFocusWindow;
    }
    if (!top->GetChildren().empty()) {
      return top->GetChildren().front();
    }
    return top;
  }

  void Deliver(wxWindow* const window, wxEvent& event)
  {
    event.SetEventObject(window);
    if (wxEvtHandler* const handler = window->GetEventHandler(); handler != nullptr) {
      (void)handler->ProcessEvent(event);
    }
  }

  void FillModifiers(const std::uint32_t modifiers, bool& control, bool& shift, bool& alt, bool& meta)
  {
    control = (modifiers & platform::window::kModifierControl) != 0;
    shift = (modifiers & platform::window::kModifierShift) != 0;
    alt = (modifiers & platform::window::kModifierAlt) != 0;
    meta = (modifiers & platform::window::kModifierMeta) != 0;
  }

  void DeliverMouse(wxTopLevelWindow* const top, const platform::window::Event& source, const wxEventType type)
  {
    wxWindow* const target = InputTarget(top);
    wxMouseEvent event(type);
    event.m_x = source.x;
    event.m_y = source.y;
    event.m_leftDown = (source.buttonsDown & platform::window::kLeftDown) != 0;
    event.m_middleDown = (source.buttonsDown & platform::window::kMiddleDown) != 0;
    event.m_rightDown = (source.buttonsDown & platform::window::kRightDown) != 0;
    FillModifiers(source.modifiers, event.m_controlDown, event.m_shiftDown, event.m_altDown, event.m_metaDown);
    if (type == wxEVT_MOUSEWHEEL) {
      // WM_MOUSEWHEEL: 120 per notch, three lines each (the Windows default).
      event.m_wheelRotation = static_cast<int>(std::lround(source.wheel * 120.0f));
      event.m_wheelDelta = 120;
      event.m_linesPerAction = 3;
    }
    Deliver(target, event);
  }

  void DeliverKey(wxTopLevelWindow* const top, const wxEventType type, const long keyCode, const platform::window::Event& source,
                  const bool controlOverride)
  {
    wxWindow* const target = InputTarget(top);
    wxKeyEvent event(type);
    event.m_keyCode = keyCode;
    FillModifiers(source.modifiers, event.m_controlDown, event.m_shiftDown, event.m_altDown, event.m_metaDown);
    event.m_controlDown = event.m_controlDown || controlOverride;
    // WM_KEYDOWN's wParam and lParam: the virtual key, and bit 30 when the key was already down.
    event.m_rawCode = static_cast<wxUint32>(source.virtualKey);
    event.m_rawFlags = source.repeat ? (1u << 30) : 0u;
    Deliver(target, event);
  }

  // wx 2.4.2 (src/msw/window.cpp) sends a char event for a key Windows gives no WM_CHAR for, with
  // its wx code, besides the key-down; and turns WM_CHAR 1..26 (Ctrl+letter) into the code with
  // ControlDown. SDL reports typed text apart (EventType::Text); these are the keys it doesn't.
  void DeliverCharForKey(wxTopLevelWindow* const top, const platform::window::Event& source)
  {
    const int virtualKey = source.virtualKey;
    const bool control = (source.modifiers & platform::window::kModifierControl) != 0;
    switch (virtualKey) {
      case VK_BACK: DeliverKey(top, wxEVT_CHAR, WXK_BACK, source, false); return;
      case VK_TAB: DeliverKey(top, wxEVT_CHAR, WXK_TAB, source, false); return;
      case VK_RETURN: DeliverKey(top, wxEVT_CHAR, WXK_RETURN, source, false); return;
      case VK_ESCAPE: DeliverKey(top, wxEVT_CHAR, WXK_ESCAPE, source, false); return;
      default: break;
    }
    if (control && virtualKey >= 'A' && virtualKey <= 'Z') {
      DeliverKey(top, wxEVT_CHAR, virtualKey - 'A' + 1, source, true);
      return;
    }
    // Keys that type nothing: arrows, function keys, navigation, modifiers.
    const bool typesText = virtualKey == VK_SPACE || (virtualKey >= '0' && virtualKey <= '9') ||
      (virtualKey >= 'A' && virtualKey <= 'Z') || (virtualKey >= VK_NUMPAD0 && virtualKey <= VK_DIVIDE) ||
      (virtualKey >= VK_OEM_1 && virtualKey <= VK_OEM_3) || (virtualKey >= VK_OEM_4 && virtualKey <= VK_OEM_7);
    if (!typesText) {
      if (const int code = wxCharCodeMSWToWX(virtualKey); code != 0) {
        DeliverKey(top, wxEVT_CHAR, code, source, false);
      }
    }
  }

  void DeliverWindowEvent(const platform::window::Event& source)
  {
    using platform::window::EventType;
    const auto found = sTopLevels.find(reinterpret_cast<WXWidget>(source.window));
    if (found == sTopLevels.end()) {
      return;
    }
    wxTopLevelWindow* const top = found->second;
    switch (source.type) {
      case EventType::CloseRequested: {
        wxCloseEvent event(wxEVT_CLOSE_WINDOW);
        event.SetCanVeto(true);
        Deliver(top, event);
        return;
      }
      case EventType::Moved: {
        const wxSize size = top->GetClientSize();
        top->SetClientArea(source.x, source.y, size.x, size.y);
        for (wxWindow* const child : top->GetChildren()) {
          child->SetClientArea(source.x, source.y, size.x, size.y);
        }
        wxMoveEvent event(source.x, source.y);
        Deliver(top, event);
        return;
      }
      case EventType::Resized: {
        const wxPoint position = top->GetPosition();
        top->SetClientArea(position.x, position.y, source.width, source.height);
        wxSizeEvent event(source.width, source.height);
        Deliver(top, event);
        for (wxWindow* const child : top->GetChildren()) {
          child->SetClientArea(position.x, position.y, source.width, source.height);
          wxSizeEvent childEvent(source.width, source.height);
          Deliver(child, childEvent);
        }
        return;
      }
      case EventType::Minimized:
        top->NoteIconized(true);
        return;
      case EventType::Maximized:
        top->NoteIconized(false);
        top->NoteMaximized(true);
        return;
      case EventType::Restored:
        top->NoteIconized(false);
        top->NoteMaximized(false);
        return;
      case EventType::FocusGained:
        platform::posix::SetFocusedWindow(source.window);
        return;
      case EventType::FocusLost:
        platform::posix::SetFocusedWindow(nullptr);
        return;
      case EventType::Exposed:
        for (wxWindow* const child : top->GetChildren()) {
          wxPaintEvent event;
          Deliver(child, event);
        }
        return;
      case EventType::MouseEnter:
        DeliverMouse(top, source, wxEVT_ENTER_WINDOW);
        return;
      case EventType::MouseLeave:
        DeliverMouse(top, source, wxEVT_LEAVE_WINDOW);
        return;
      case EventType::MouseMove:
        DeliverMouse(top, source, wxEVT_MOTION);
        return;
      case EventType::MouseDown: {
        // Windows sends a double-click message in place of the second press.
        const bool doubleClick = source.clicks >= 2;
        switch (source.button) {
          case platform::window::kButtonLeft: DeliverMouse(top, source, doubleClick ? wxEVT_LEFT_DCLICK : wxEVT_LEFT_DOWN); break;
          case platform::window::kButtonMiddle: DeliverMouse(top, source, doubleClick ? wxEVT_MIDDLE_DCLICK : wxEVT_MIDDLE_DOWN); break;
          case platform::window::kButtonRight: DeliverMouse(top, source, doubleClick ? wxEVT_RIGHT_DCLICK : wxEVT_RIGHT_DOWN); break;
          default: break;
        }
        return;
      }
      case EventType::MouseUp:
        switch (source.button) {
          case platform::window::kButtonLeft: DeliverMouse(top, source, wxEVT_LEFT_UP); break;
          case platform::window::kButtonMiddle: DeliverMouse(top, source, wxEVT_MIDDLE_UP); break;
          case platform::window::kButtonRight: DeliverMouse(top, source, wxEVT_RIGHT_UP); break;
          default: break;
        }
        return;
      case EventType::MouseWheel:
        DeliverMouse(top, source, wxEVT_MOUSEWHEEL);
        return;
      case EventType::KeyDown: {
        // wx 2.4.2 HandleKeyDown: the wx code of a special key, else the virtual key itself.
        const int code = wxCharCodeMSWToWX(source.virtualKey);
        DeliverKey(top, wxEVT_KEY_DOWN, code != 0 ? code : source.virtualKey, source, false);
        DeliverCharForKey(top, source);
        return;
      }
      case EventType::KeyUp: {
        const int code = wxCharCodeMSWToWX(source.virtualKey);
        DeliverKey(top, wxEVT_KEY_UP, code != 0 ? code : source.virtualKey, source, false);
        return;
      }
      case EventType::Text:
        DeliverKey(top, wxEVT_CHAR, static_cast<long>(source.codepoint), source, false);
        return;
      default:
        return;
    }
  }
} // namespace

bool wxApp::Pending()
{
  return platform::window::HasEvents();
}

void wxApp::Dispatch()
{
  platform::window::Event event;
  if (platform::window::PollEvent(event)) {
    DeliverWindowEvent(event);
  }
}

void wxApp::CleanUp()
{
  delete wxTheApp; // the destructor clears wxTheApp
}

int wxEntry(
  const WXHINSTANCE instance, const WXHINSTANCE previousInstance, char* const commandLine, const int showCommand,
  const bool enterLoop
)
{
  (void)instance;
  (void)previousInstance;
  (void)commandLine;
  (void)showCommand;
  if (wxTheApp == nullptr) {
    if (const wxApp::InitializerFunction create = wxApp::GetInitializerFunction(); create != nullptr) {
      (void)create(); // the constructor sets wxTheApp
    }
  }
  if (wxTheApp == nullptr || !wxTheApp->OnInit()) {
    return -1;
  }
  // The engine runs its own loop (enterLoop false); nothing here runs one for it.
  (void)enterLoop;
  return 0;
}

void wxApp::ExitMainLoop()
{
  m_keepGoing = FALSE;
}

const wxString wxEmptyString;
const wchar_t* wxFrameNameStr = L"frame";

wxPoint wxGetMousePosition()
{
  POINT point{};
  (void)::GetCursorPos(&point);
  return wxPoint(point.x, point.y);
}

// --- Key codes (wx 2.4.2 src/msw/window.cpp) --------------------------------------------------

int wxCharCodeMSWToWX(const int keySym)
{
  switch (keySym) {
    case VK_CANCEL: return WXK_CANCEL;
    case VK_BACK: return WXK_BACK;
    case VK_TAB: return WXK_TAB;
    case VK_CLEAR: return WXK_CLEAR;
    case VK_RETURN: return WXK_RETURN;
    case VK_SHIFT: return WXK_SHIFT;
    case VK_CONTROL: return WXK_CONTROL;
    case VK_MENU: return WXK_MENU;
    case VK_PAUSE: return WXK_PAUSE;
    case VK_CAPITAL: return WXK_CAPITAL;
    case VK_SPACE: return WXK_SPACE;
    case VK_ESCAPE: return WXK_ESCAPE;
    case VK_PRIOR: return WXK_PRIOR;
    case VK_NEXT: return WXK_NEXT;
    case VK_END: return WXK_END;
    case VK_HOME: return WXK_HOME;
    case VK_LEFT: return WXK_LEFT;
    case VK_UP: return WXK_UP;
    case VK_RIGHT: return WXK_RIGHT;
    case VK_DOWN: return WXK_DOWN;
    case VK_SELECT: return WXK_SELECT;
    case VK_PRINT: return WXK_PRINT;
    case VK_EXECUTE: return WXK_EXECUTE;
    case VK_INSERT: return WXK_INSERT;
    case VK_DELETE: return WXK_DELETE;
    case VK_HELP: return WXK_HELP;
    case VK_NUMPAD0: return WXK_NUMPAD0;
    case VK_NUMPAD1: return WXK_NUMPAD1;
    case VK_NUMPAD2: return WXK_NUMPAD2;
    case VK_NUMPAD3: return WXK_NUMPAD3;
    case VK_NUMPAD4: return WXK_NUMPAD4;
    case VK_NUMPAD5: return WXK_NUMPAD5;
    case VK_NUMPAD6: return WXK_NUMPAD6;
    case VK_NUMPAD7: return WXK_NUMPAD7;
    case VK_NUMPAD8: return WXK_NUMPAD8;
    case VK_NUMPAD9: return WXK_NUMPAD9;
    case VK_MULTIPLY: return WXK_NUMPAD_MULTIPLY;
    case VK_ADD: return WXK_NUMPAD_ADD;
    case VK_SUBTRACT: return WXK_NUMPAD_SUBTRACT;
    case VK_DECIMAL: return WXK_NUMPAD_DECIMAL;
    case VK_DIVIDE: return WXK_NUMPAD_DIVIDE;
    case VK_F1: return WXK_F1;
    case VK_F2: return WXK_F2;
    case VK_F3: return WXK_F3;
    case VK_F4: return WXK_F4;
    case VK_F5: return WXK_F5;
    case VK_F6: return WXK_F6;
    case VK_F7: return WXK_F7;
    case VK_F8: return WXK_F8;
    case VK_F9: return WXK_F9;
    case VK_F10: return WXK_F10;
    case VK_F11: return WXK_F11;
    case VK_F12: return WXK_F12;
    case VK_F13: return WXK_F13;
    case VK_F14: return WXK_F14;
    case VK_F15: return WXK_F15;
    case VK_F16: return WXK_F16;
    case VK_F17: return WXK_F17;
    case VK_F18: return WXK_F18;
    case VK_F19: return WXK_F19;
    case VK_F20: return WXK_F20;
    case VK_F21: return WXK_F21;
    case VK_F22: return WXK_F22;
    case VK_F23: return WXK_F23;
    case VK_F24: return WXK_F24;
    case VK_NUMLOCK: return WXK_NUMLOCK;
    case VK_SCROLL: return WXK_SCROLL;
    case VK_OEM_1: return ';';
    case VK_OEM_PLUS: return '+';
    case VK_OEM_COMMA: return ',';
    case VK_OEM_MINUS: return '-';
    case VK_OEM_PERIOD: return '.';
    case VK_OEM_2: return '/';
    case VK_OEM_3: return '~';
    case VK_OEM_4: return '[';
    case VK_OEM_5: return '\\';
    case VK_OEM_6: return ']';
    case VK_OEM_7: return '\'';
    default: return 0;
  }
}

int wxCharCodeWXToMSW(const int id, bool* const isVirtual)
{
  *isVirtual = true;
  switch (id) {
    case WXK_CANCEL: return VK_CANCEL;
    case WXK_CLEAR: return VK_CLEAR;
    case WXK_SHIFT: return VK_SHIFT;
    case WXK_CONTROL: return VK_CONTROL;
    case WXK_MENU: return VK_MENU;
    case WXK_PAUSE: return VK_PAUSE;
    case WXK_PRIOR: return VK_PRIOR;
    case WXK_NEXT: return VK_NEXT;
    case WXK_END: return VK_END;
    case WXK_HOME: return VK_HOME;
    case WXK_LEFT: return VK_LEFT;
    case WXK_UP: return VK_UP;
    case WXK_RIGHT: return VK_RIGHT;
    case WXK_DOWN: return VK_DOWN;
    case WXK_SELECT: return VK_SELECT;
    case WXK_PRINT: return VK_PRINT;
    case WXK_EXECUTE: return VK_EXECUTE;
    case WXK_INSERT: return VK_INSERT;
    case WXK_DELETE: return VK_DELETE;
    case WXK_HELP: return VK_HELP;
    case WXK_NUMPAD0: return VK_NUMPAD0;
    case WXK_NUMPAD1: return VK_NUMPAD1;
    case WXK_NUMPAD2: return VK_NUMPAD2;
    case WXK_NUMPAD3: return VK_NUMPAD3;
    case WXK_NUMPAD4: return VK_NUMPAD4;
    case WXK_NUMPAD5: return VK_NUMPAD5;
    case WXK_NUMPAD6: return VK_NUMPAD6;
    case WXK_NUMPAD7: return VK_NUMPAD7;
    case WXK_NUMPAD8: return VK_NUMPAD8;
    case WXK_NUMPAD9: return VK_NUMPAD9;
    case WXK_NUMPAD_MULTIPLY: return VK_MULTIPLY;
    case WXK_NUMPAD_ADD: return VK_ADD;
    case WXK_NUMPAD_SUBTRACT: return VK_SUBTRACT;
    case WXK_NUMPAD_DECIMAL: return VK_DECIMAL;
    case WXK_NUMPAD_DIVIDE: return VK_DIVIDE;
    case WXK_F1: return VK_F1;
    case WXK_F2: return VK_F2;
    case WXK_F3: return VK_F3;
    case WXK_F4: return VK_F4;
    case WXK_F5: return VK_F5;
    case WXK_F6: return VK_F6;
    case WXK_F7: return VK_F7;
    case WXK_F8: return VK_F8;
    case WXK_F9: return VK_F9;
    case WXK_F10: return VK_F10;
    case WXK_F11: return VK_F11;
    case WXK_F12: return VK_F12;
    case WXK_F13: return VK_F13;
    case WXK_F14: return VK_F14;
    case WXK_F15: return VK_F15;
    case WXK_F16: return VK_F16;
    case WXK_F17: return VK_F17;
    case WXK_F18: return VK_F18;
    case WXK_F19: return VK_F19;
    case WXK_F20: return VK_F20;
    case WXK_F21: return VK_F21;
    case WXK_F22: return VK_F22;
    case WXK_F23: return VK_F23;
    case WXK_F24: return VK_F24;
    case WXK_NUMLOCK: return VK_NUMLOCK;
    case WXK_SCROLL: return VK_SCROLL;
    default:
      *isVirtual = false;
      return id;
  }
}

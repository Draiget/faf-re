// Engine addition (issue #255): the code behind the wx stand-in headers (wx/defs.h in this
// folder) for the Linux client: wx 2.4.2's event table search and handler chain
// (src/common/event.cpp, src/common/wincmn.cpp), its mouse button tests, and its key code
// conversions (src/msw/window.cpp). The window system that feeds them is issue #256.

#include <Windows.h>

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
  return changed;
}

void wxWindow::SetSize(const int width, const int height)
{
  m_clientWidth = width;
  m_clientHeight = height;
}

void wxWindow::SetSize(const int x, const int y, const int width, const int height, const int sizeFlags)
{
  (void)sizeFlags;
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

bool wxApp::Pending()
{
  return false;
}

void wxApp::Dispatch() {}

void wxApp::ExitMainLoop()
{
  m_keepGoing = FALSE;
}

const wxString wxEmptyString;
const wchar_t* wxFrameNameStr = L"frame";

wxPoint wxGetMousePosition()
{
  return wxPoint(0, 0);
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

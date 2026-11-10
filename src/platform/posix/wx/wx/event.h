#pragma once

// Engine addition (issue #255): wx 2.4.2's events and static event tables (wx/event.h), for the
// Linux client. See wx/defs.h in this folder. The event type numbers are wx 2.4.2's
// (wxEVT_FIRST + n); the table search follows src/common/event.cpp.

#include <wx/defs.h>
#include <wx/object.h>

class wxEvent;
class wxEvtHandler;

enum
{
  wxEVT_NULL = 0,
  wxEVT_FIRST = 10000,

  wxEVT_LEFT_DOWN = wxEVT_FIRST + 100,
  wxEVT_LEFT_UP = wxEVT_FIRST + 101,
  wxEVT_MIDDLE_DOWN = wxEVT_FIRST + 102,
  wxEVT_MIDDLE_UP = wxEVT_FIRST + 103,
  wxEVT_RIGHT_DOWN = wxEVT_FIRST + 104,
  wxEVT_RIGHT_UP = wxEVT_FIRST + 105,
  wxEVT_MOTION = wxEVT_FIRST + 106,
  wxEVT_ENTER_WINDOW = wxEVT_FIRST + 107,
  wxEVT_LEAVE_WINDOW = wxEVT_FIRST + 108,
  wxEVT_LEFT_DCLICK = wxEVT_FIRST + 109,
  wxEVT_MIDDLE_DCLICK = wxEVT_FIRST + 110,
  wxEVT_RIGHT_DCLICK = wxEVT_FIRST + 111,
  wxEVT_MOUSEWHEEL = wxEVT_FIRST + 115,
  wxEVT_SET_FOCUS = wxEVT_FIRST + 112,
  wxEVT_KILL_FOCUS = wxEVT_FIRST + 113,

  wxEVT_SIZE = wxEVT_FIRST + 400,
  wxEVT_MOVE = wxEVT_FIRST + 401,
  wxEVT_CLOSE_WINDOW = wxEVT_FIRST + 402,
  wxEVT_ACTIVATE = wxEVT_FIRST + 409,
  wxEVT_PAINT = wxEVT_FIRST + 416,
  wxEVT_ERASE_BACKGROUND = wxEVT_FIRST + 417,

  wxEVT_CHAR = wxEVT_FIRST + 212,
  wxEVT_CHAR_HOOK = wxEVT_FIRST + 213,
  wxEVT_KEY_DOWN = wxEVT_FIRST + 215,
  wxEVT_KEY_UP = wxEVT_FIRST + 216
};

enum
{
  wxMOUSE_BTN_ANY = -1,
  wxMOUSE_BTN_NONE = -1,
  wxMOUSE_BTN_LEFT = 0,
  wxMOUSE_BTN_MIDDLE = 1,
  wxMOUSE_BTN_RIGHT = 2
};

class wxEvent : public wxObject
{
public:
  explicit wxEvent(const int id = 0, const wxEventType eventType = wxEVT_NULL)
    : m_eventType(eventType)
    , m_id(id)
  {}

  void SetEventType(const wxEventType type) { m_eventType = type; }
  wxEventType GetEventType() const { return m_eventType; }
  wxObject* GetEventObject() const { return m_eventObject; }
  void SetEventObject(wxObject* const object) { m_eventObject = object; }
  long GetTimestamp() const { return m_timeStamp; }
  void SetTimestamp(const long timeStamp = 0) { m_timeStamp = timeStamp; }
  int GetId() const { return m_id; }
  void SetId(const int id) { m_id = id; }
  void Skip(const bool skip = true) { m_skipped = skip; }
  bool GetSkipped() const { return m_skipped; }
  // wx 2.4.2 queues copies of events posted across threads; the stand-in only dispatches
  // directly, so no copy is ever made.
  virtual wxEvent* Clone() const { return nullptr; }

  wxObject* m_eventObject = nullptr;
  wxEventType m_eventType = wxEVT_NULL;
  long m_timeStamp = 0;
  int m_id = 0;
  wxObject* m_callbackUserData = nullptr;
  bool m_skipped = false;
  bool m_isCommandEvent = false;
};

class wxKeyEvent : public wxEvent
{
public:
  explicit wxKeyEvent(const wxEventType keyType = wxEVT_NULL)
    : wxEvent(0, keyType)
  {}

  bool ControlDown() const { return m_controlDown; }
  bool MetaDown() const { return m_metaDown; }
  bool AltDown() const { return m_altDown; }
  bool ShiftDown() const { return m_shiftDown; }
  bool HasModifiers() const { return ControlDown() || AltDown(); }
  int GetKeyCode() const { return static_cast<int>(m_keyCode); }
  wxUint32 GetRawKeyCode() const { return m_rawCode; }
  wxUint32 GetRawKeyFlags() const { return m_rawFlags; }
  wxCoord GetX() const { return m_x; }
  wxCoord GetY() const { return m_y; }
  long KeyCode() const { return m_keyCode; }

  wxCoord m_x = 0;
  wxCoord m_y = 0;
  long m_keyCode = 0;
  bool m_controlDown = false;
  bool m_shiftDown = false;
  bool m_altDown = false;
  bool m_metaDown = false;
  bool m_scanCode = false;
  // On Windows the virtual-key code and the WM_KEYDOWN lParam (bit 30: the key was already
  // down). The window system (issue #256) fills them the same way.
  wxUint32 m_rawCode = 0;
  wxUint32 m_rawFlags = 0;
};

class wxMouseEvent : public wxEvent
{
public:
  explicit wxMouseEvent(const wxEventType mouseType = wxEVT_NULL)
    : wxEvent(0, mouseType)
  {}

  // src/common/event.cpp 2.4.2: buttons are numbered 1 (left), 2 (middle), 3 (right) here,
  // -1 for any.
  bool IsButton() const { return Button(wxMOUSE_BTN_ANY); }
  bool ButtonDown(int but = wxMOUSE_BTN_ANY) const;
  bool ButtonDClick(int but = wxMOUSE_BTN_ANY) const;
  bool ButtonUp(int but = wxMOUSE_BTN_ANY) const;
  bool Button(int but) const;
  bool ButtonIsDown(int but) const;
  int GetButton() const;

  bool ControlDown() const { return m_controlDown; }
  bool MetaDown() const { return m_metaDown; }
  bool AltDown() const { return m_altDown; }
  bool ShiftDown() const { return m_shiftDown; }

  bool LeftDown() const { return m_eventType == wxEVT_LEFT_DOWN; }
  bool MiddleDown() const { return m_eventType == wxEVT_MIDDLE_DOWN; }
  bool RightDown() const { return m_eventType == wxEVT_RIGHT_DOWN; }
  bool LeftUp() const { return m_eventType == wxEVT_LEFT_UP; }
  bool MiddleUp() const { return m_eventType == wxEVT_MIDDLE_UP; }
  bool RightUp() const { return m_eventType == wxEVT_RIGHT_UP; }
  bool LeftDClick() const { return m_eventType == wxEVT_LEFT_DCLICK; }
  bool MiddleDClick() const { return m_eventType == wxEVT_MIDDLE_DCLICK; }
  bool RightDClick() const { return m_eventType == wxEVT_RIGHT_DCLICK; }
  bool LeftIsDown() const { return m_leftDown; }
  bool MiddleIsDown() const { return m_middleDown; }
  bool RightIsDown() const { return m_rightDown; }
  bool Dragging() const { return m_eventType == wxEVT_MOTION && ButtonIsDown(wxMOUSE_BTN_ANY); }
  bool Moving() const { return m_eventType == wxEVT_MOTION; }
  bool Entering() const { return m_eventType == wxEVT_ENTER_WINDOW; }
  bool Leaving() const { return m_eventType == wxEVT_LEAVE_WINDOW; }

  wxCoord GetX() const { return m_x; }
  wxCoord GetY() const { return m_y; }
  int GetWheelRotation() const { return m_wheelRotation; }
  int GetWheelDelta() const { return m_wheelDelta; }
  int GetLinesPerAction() const { return m_linesPerAction; }
  bool IsPageScroll() const { return static_cast<unsigned int>(m_linesPerAction) == UINT_MAX; }

  wxCoord m_x = 0;
  wxCoord m_y = 0;
  bool m_leftDown = false;
  bool m_middleDown = false;
  bool m_rightDown = false;
  bool m_controlDown = false;
  bool m_shiftDown = false;
  bool m_altDown = false;
  bool m_metaDown = false;
  int m_wheelRotation = 0;
  int m_wheelDelta = 0;
  int m_linesPerAction = 0;
};

class wxDC;

// The window events the application shell handles. The window system (issue #256) sends them.
class wxPaintEvent : public wxEvent
{
public:
  explicit wxPaintEvent(const int id = 0)
    : wxEvent(id, wxEVT_PAINT)
  {}
};

class wxEraseEvent : public wxEvent
{
public:
  explicit wxEraseEvent(const int id = 0, wxDC* const dc = nullptr)
    : wxEvent(id, wxEVT_ERASE_BACKGROUND)
    , m_dc(dc)
  {}

  wxDC* GetDC() const { return m_dc; }

  wxDC* m_dc = nullptr;
};

class wxSizeEvent : public wxEvent
{
public:
  wxSizeEvent() : wxEvent(0, wxEVT_SIZE) {}
  wxSizeEvent(const int width, const int height, const int id = 0)
    : wxEvent(id, wxEVT_SIZE)
    , m_width(width)
    , m_height(height)
  {}

  int m_width = 0;
  int m_height = 0;
};

class wxMoveEvent : public wxEvent
{
public:
  wxMoveEvent() : wxEvent(0, wxEVT_MOVE) {}
  wxMoveEvent(const int x, const int y, const int id = 0)
    : wxEvent(id, wxEVT_MOVE)
    , m_x(x)
    , m_y(y)
  {}

  int m_x = 0;
  int m_y = 0;
};

class wxCloseEvent : public wxEvent
{
public:
  explicit wxCloseEvent(const wxEventType type = wxEVT_CLOSE_WINDOW, const int id = 0)
    : wxEvent(id, type)
  {}

  void SetCanVeto(const bool canVeto) { m_canVeto = canVeto; }
  bool CanVeto() const { return m_canVeto; }
  void Veto(const bool veto = true) { m_veto = veto; }
  bool GetVeto() const { return m_veto; }

  bool m_canVeto = true;
  bool m_veto = false;
};

typedef void (wxObject::*wxObjectEventFunction)(wxEvent&);
typedef void (wxEvtHandler::*wxEventFunction)(wxEvent&);
typedef void (wxEvtHandler::*wxCharEventFunction)(wxKeyEvent&);
typedef void (wxEvtHandler::*wxMouseEventFunction)(wxMouseEvent&);
typedef void (wxEvtHandler::*wxPaintEventFunction)(wxPaintEvent&);
typedef void (wxEvtHandler::*wxEraseEventFunction)(wxEraseEvent&);
typedef void (wxEvtHandler::*wxSizeEventFunction)(wxSizeEvent&);
typedef void (wxEvtHandler::*wxMoveEventFunction)(wxMoveEvent&);
typedef void (wxEvtHandler::*wxCloseEventFunction)(wxCloseEvent&);

struct wxEventTableEntry
{
  int m_eventType;
  int m_id;
  int m_lastId;
  wxObjectEventFunction m_fn;
  wxObject* m_callbackUserData;
};

struct wxEventTable
{
  const wxEventTable* baseTable;
  const wxEventTableEntry* entries;
};

class wxEvtHandler : public wxObject
{
public:
  wxEvtHandler() = default;
  ~wxEvtHandler() override;

  wxEvtHandler* GetNextHandler() const { return m_nextHandler; }
  wxEvtHandler* GetPreviousHandler() const { return m_previousHandler; }
  void SetNextHandler(wxEvtHandler* const handler) { m_nextHandler = handler; }
  void SetPreviousHandler(wxEvtHandler* const handler) { m_previousHandler = handler; }
  void SetEvtHandlerEnabled(const bool enabled) { m_enabled = enabled; }
  bool GetEvtHandlerEnabled() const { return m_enabled; }

  /**
   * src/common/event.cpp 2.4.2: this handler's tables, from its class up to wxEvtHandler, then
   * the next handler in the chain. True when a handler took the event without skipping it.
   */
  virtual bool ProcessEvent(wxEvent& event);

  bool SearchEventTable(const wxEventTable& table, wxEvent& event);

protected:
  static const wxEventTable sm_eventTable;
  virtual const wxEventTable* GetEventTable() const;

private:
  static const wxEventTableEntry sm_eventTableEntries[];

  wxEvtHandler* m_nextHandler = nullptr;
  wxEvtHandler* m_previousHandler = nullptr;
  bool m_enabled = true;
};

#define DECLARE_EVENT_TABLE_ENTRY(type, id, idLast, fn, obj) {type, id, idLast, fn, obj}

#define DECLARE_EVENT_TABLE()                              \
private:                                                   \
  static const wxEventTableEntry sm_eventTableEntries[];   \
                                                           \
protected:                                                 \
  static const wxEventTable sm_eventTable;                 \
  const wxEventTable* GetEventTable() const override;

#define BEGIN_EVENT_TABLE(theClass, baseClass)                                                   \
  const wxEventTable* theClass::GetEventTable() const { return &theClass::sm_eventTable; }      \
  const wxEventTable theClass::sm_eventTable = {&baseClass::sm_eventTable,                      \
                                                &theClass::sm_eventTableEntries[0]};            \
  const wxEventTableEntry theClass::sm_eventTableEntries[] = {

#define END_EVENT_TABLE() DECLARE_EVENT_TABLE_ENTRY(wxEVT_NULL, 0, 0, nullptr, nullptr)};

#define wxFAF_EVT_ENTRY(type, castType, func) \
  DECLARE_EVENT_TABLE_ENTRY(type, wxID_ANY, wxID_ANY, (wxObjectEventFunction)(wxEventFunction)(castType)&func, nullptr),

#define EVT_CHAR(func) wxFAF_EVT_ENTRY(wxEVT_CHAR, wxCharEventFunction, func)
#define EVT_KEY_DOWN(func) wxFAF_EVT_ENTRY(wxEVT_KEY_DOWN, wxCharEventFunction, func)
#define EVT_KEY_UP(func) wxFAF_EVT_ENTRY(wxEVT_KEY_UP, wxCharEventFunction, func)

#define EVT_LEFT_DOWN(func) wxFAF_EVT_ENTRY(wxEVT_LEFT_DOWN, wxMouseEventFunction, func)
#define EVT_LEFT_UP(func) wxFAF_EVT_ENTRY(wxEVT_LEFT_UP, wxMouseEventFunction, func)
#define EVT_MIDDLE_DOWN(func) wxFAF_EVT_ENTRY(wxEVT_MIDDLE_DOWN, wxMouseEventFunction, func)
#define EVT_MIDDLE_UP(func) wxFAF_EVT_ENTRY(wxEVT_MIDDLE_UP, wxMouseEventFunction, func)
#define EVT_RIGHT_DOWN(func) wxFAF_EVT_ENTRY(wxEVT_RIGHT_DOWN, wxMouseEventFunction, func)
#define EVT_RIGHT_UP(func) wxFAF_EVT_ENTRY(wxEVT_RIGHT_UP, wxMouseEventFunction, func)
#define EVT_MOTION(func) wxFAF_EVT_ENTRY(wxEVT_MOTION, wxMouseEventFunction, func)
#define EVT_LEFT_DCLICK(func) wxFAF_EVT_ENTRY(wxEVT_LEFT_DCLICK, wxMouseEventFunction, func)
#define EVT_MIDDLE_DCLICK(func) wxFAF_EVT_ENTRY(wxEVT_MIDDLE_DCLICK, wxMouseEventFunction, func)
#define EVT_RIGHT_DCLICK(func) wxFAF_EVT_ENTRY(wxEVT_RIGHT_DCLICK, wxMouseEventFunction, func)
#define EVT_LEAVE_WINDOW(func) wxFAF_EVT_ENTRY(wxEVT_LEAVE_WINDOW, wxMouseEventFunction, func)
#define EVT_ENTER_WINDOW(func) wxFAF_EVT_ENTRY(wxEVT_ENTER_WINDOW, wxMouseEventFunction, func)
#define EVT_MOUSEWHEEL(func) wxFAF_EVT_ENTRY(wxEVT_MOUSEWHEEL, wxMouseEventFunction, func)

#define EVT_PAINT(func) wxFAF_EVT_ENTRY(wxEVT_PAINT, wxPaintEventFunction, func)
#define EVT_ERASE_BACKGROUND(func) wxFAF_EVT_ENTRY(wxEVT_ERASE_BACKGROUND, wxEraseEventFunction, func)
#define EVT_SIZE(func) wxFAF_EVT_ENTRY(wxEVT_SIZE, wxSizeEventFunction, func)
#define EVT_MOVE(func) wxFAF_EVT_ENTRY(wxEVT_MOVE, wxMoveEventFunction, func)
#define EVT_CLOSE(func) wxFAF_EVT_ENTRY(wxEVT_CLOSE_WINDOW, wxCloseEventFunction, func)

// wx 2.4.2: the thirteen mouse event types, all to one sink.
#define EVT_MOUSE_EVENTS(func)  \
  EVT_LEFT_DOWN(func)           \
  EVT_LEFT_UP(func)             \
  EVT_MIDDLE_DOWN(func)         \
  EVT_MIDDLE_UP(func)           \
  EVT_RIGHT_DOWN(func)          \
  EVT_RIGHT_UP(func)            \
  EVT_MOTION(func)              \
  EVT_LEFT_DCLICK(func)         \
  EVT_MIDDLE_DCLICK(func)       \
  EVT_RIGHT_DCLICK(func)        \
  EVT_LEAVE_WINDOW(func)        \
  EVT_ENTER_WINDOW(func)        \
  EVT_MOUSEWHEEL(func)

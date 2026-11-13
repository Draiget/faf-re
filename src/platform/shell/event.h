#pragma once

// Engine addition (issues #255, #407): the shell's events and static event tables. The event type
// numbers are the retail window library's (EVT_FIRST + n), and the table search follows its
// event.cpp. See defs.h.

#include "platform/shell/defs.h"
#include "platform/shell/object.h"
#include "legacy/containers/Layout.h"

#include <cstdint>

class ShellEvent;
class ShellEvtHandler;

enum
{
  SHELL_EVT_NULL = 0,
  SHELL_EVT_FIRST = 10000,

  SHELL_EVT_LEFT_DOWN = SHELL_EVT_FIRST + 100,
  SHELL_EVT_LEFT_UP = SHELL_EVT_FIRST + 101,
  SHELL_EVT_MIDDLE_DOWN = SHELL_EVT_FIRST + 102,
  SHELL_EVT_MIDDLE_UP = SHELL_EVT_FIRST + 103,
  SHELL_EVT_RIGHT_DOWN = SHELL_EVT_FIRST + 104,
  SHELL_EVT_RIGHT_UP = SHELL_EVT_FIRST + 105,
  SHELL_EVT_MOTION = SHELL_EVT_FIRST + 106,
  SHELL_EVT_ENTER_WINDOW = SHELL_EVT_FIRST + 107,
  SHELL_EVT_LEAVE_WINDOW = SHELL_EVT_FIRST + 108,
  SHELL_EVT_LEFT_DCLICK = SHELL_EVT_FIRST + 109,
  SHELL_EVT_MIDDLE_DCLICK = SHELL_EVT_FIRST + 110,
  SHELL_EVT_RIGHT_DCLICK = SHELL_EVT_FIRST + 111,
  SHELL_EVT_MOUSEWHEEL = SHELL_EVT_FIRST + 115,
  SHELL_EVT_SET_FOCUS = SHELL_EVT_FIRST + 112,
  SHELL_EVT_KILL_FOCUS = SHELL_EVT_FIRST + 113,

  SHELL_EVT_SIZE = SHELL_EVT_FIRST + 400,
  SHELL_EVT_MOVE = SHELL_EVT_FIRST + 401,
  SHELL_EVT_CLOSE_WINDOW = SHELL_EVT_FIRST + 402,
  SHELL_EVT_ACTIVATE = SHELL_EVT_FIRST + 409,
  SHELL_EVT_PAINT = SHELL_EVT_FIRST + 416,
  SHELL_EVT_ERASE_BACKGROUND = SHELL_EVT_FIRST + 417,

  SHELL_EVT_CHAR = SHELL_EVT_FIRST + 212,
  SHELL_EVT_CHAR_HOOK = SHELL_EVT_FIRST + 213,
  SHELL_EVT_KEY_DOWN = SHELL_EVT_FIRST + 215,
  SHELL_EVT_KEY_UP = SHELL_EVT_FIRST + 216
};

enum
{
  SHELL_MOUSE_BTN_ANY = -1,
  SHELL_MOUSE_BTN_NONE = -1,
  SHELL_MOUSE_BTN_LEFT = 0,
  SHELL_MOUSE_BTN_MIDDLE = 1,
  SHELL_MOUSE_BTN_RIGHT = 2
};

class ShellEvent : public ShellObject
{
public:
  explicit ShellEvent(
    const int id = 0,
    const ShellEventType eventType = SHELL_EVT_NULL
  )
    : m_eventType(eventType)
    , m_id(id)
  {}

  void SetEventType(
    const ShellEventType type
  )
  {
    m_eventType = type;
  }
  ShellEventType GetEventType() const
  {
    return m_eventType;
  }
  ShellObject* GetEventObject() const
  {
    return m_eventObject;
  }
  void SetEventObject(
    ShellObject* const object
  )
  {
    m_eventObject = object;
  }
  long GetTimestamp() const
  {
    return m_timeStamp;
  }
  void SetTimestamp(
    const long timeStamp = 0
  )
  {
    m_timeStamp = timeStamp;
  }
  int GetId() const
  {
    return m_id;
  }
  void SetId(
    const int id
  )
  {
    m_id = id;
  }
  void Skip(
    const bool skip = true
  )
  {
    m_skipped = skip;
  }
  bool GetSkipped() const
  {
    return m_skipped;
  }
  // The 2.4.2 window library queues copies of events posted across threads; the shell only dispatches
  // directly, so no copy is ever made.
  virtual ShellEvent* Clone() const
  {
    return nullptr;
  }

  ShellObject* m_eventObject = nullptr;
  ShellEventType m_eventType = SHELL_EVT_NULL;
  long m_timeStamp = 0;
  int m_id = 0;
  ShellObject* m_callbackUserData = nullptr;
  bool m_skipped = false;
  bool m_isCommandEvent = false;
};

class ShellKeyEvent : public ShellEvent
{
public:
  explicit ShellKeyEvent(
    const ShellEventType keyType = SHELL_EVT_NULL
  )
    : ShellEvent(0, keyType)
  {}

  bool ControlDown() const
  {
    return m_controlDown;
  }
  bool MetaDown() const
  {
    return m_metaDown;
  }
  bool AltDown() const
  {
    return m_altDown;
  }
  bool ShiftDown() const
  {
    return m_shiftDown;
  }
  bool HasModifiers() const
  {
    return ControlDown() || AltDown();
  }
  int GetKeyCode() const
  {
    return static_cast<int>(m_keyCode);
  }
  ShellUint32 GetRawKeyCode() const
  {
    return m_rawCode;
  }
  ShellUint32 GetRawKeyFlags() const
  {
    return m_rawFlags;
  }
  ShellCoord GetX() const
  {
    return m_x;
  }
  ShellCoord GetY() const
  {
    return m_y;
  }
  long KeyCode() const
  {
    return m_keyCode;
  }

  ShellCoord m_x = 0;
  ShellCoord m_y = 0;
  long m_keyCode = 0;
  bool m_controlDown = false;
  bool m_shiftDown = false;
  bool m_altDown = false;
  bool m_metaDown = false;
  bool m_scanCode = false;
  // On Windows the virtual-key code and the WM_KEYDOWN lParam (bit 30: the key was already
  // down). The window system (issue #256) fills them the same way.
  ShellUint32 m_rawCode = 0;
  ShellUint32 m_rawFlags = 0;
};

class ShellMouseEvent : public ShellEvent
{
public:
  explicit ShellMouseEvent(
    const ShellEventType mouseType = SHELL_EVT_NULL
  )
    : ShellEvent(0, mouseType)
  {}

  // src/common/event.cpp 2.4.2: buttons are numbered 1 (left), 2 (middle), 3 (right) here,
  // -1 for any.
  bool IsButton() const
  {
    return Button(SHELL_MOUSE_BTN_ANY);
  }
  bool ButtonDown(int but = SHELL_MOUSE_BTN_ANY) const;
  bool ButtonDClick(int but = SHELL_MOUSE_BTN_ANY) const;
  bool ButtonUp(int but = SHELL_MOUSE_BTN_ANY) const;
  bool Button(int but) const;
  bool ButtonIsDown(int but) const;
  int GetButton() const;

  bool ControlDown() const
  {
    return m_controlDown;
  }
  bool MetaDown() const
  {
    return m_metaDown;
  }
  bool AltDown() const
  {
    return m_altDown;
  }
  bool ShiftDown() const
  {
    return m_shiftDown;
  }

  bool LeftDown() const
  {
    return m_eventType == SHELL_EVT_LEFT_DOWN;
  }
  bool MiddleDown() const
  {
    return m_eventType == SHELL_EVT_MIDDLE_DOWN;
  }
  bool RightDown() const
  {
    return m_eventType == SHELL_EVT_RIGHT_DOWN;
  }
  bool LeftUp() const
  {
    return m_eventType == SHELL_EVT_LEFT_UP;
  }
  bool MiddleUp() const
  {
    return m_eventType == SHELL_EVT_MIDDLE_UP;
  }
  bool RightUp() const
  {
    return m_eventType == SHELL_EVT_RIGHT_UP;
  }
  bool LeftDClick() const
  {
    return m_eventType == SHELL_EVT_LEFT_DCLICK;
  }
  bool MiddleDClick() const
  {
    return m_eventType == SHELL_EVT_MIDDLE_DCLICK;
  }
  bool RightDClick() const
  {
    return m_eventType == SHELL_EVT_RIGHT_DCLICK;
  }
  bool LeftIsDown() const
  {
    return m_leftDown;
  }
  bool MiddleIsDown() const
  {
    return m_middleDown;
  }
  bool RightIsDown() const
  {
    return m_rightDown;
  }
  bool Dragging() const
  {
    return m_eventType == SHELL_EVT_MOTION && ButtonIsDown(SHELL_MOUSE_BTN_ANY);
  }
  bool Moving() const
  {
    return m_eventType == SHELL_EVT_MOTION;
  }
  bool Entering() const
  {
    return m_eventType == SHELL_EVT_ENTER_WINDOW;
  }
  bool Leaving() const
  {
    return m_eventType == SHELL_EVT_LEAVE_WINDOW;
  }

  ShellCoord GetX() const
  {
    return m_x;
  }
  ShellCoord GetY() const
  {
    return m_y;
  }
  int GetWheelRotation() const
  {
    return m_wheelRotation;
  }
  int GetWheelDelta() const
  {
    return m_wheelDelta;
  }
  int GetLinesPerAction() const
  {
    return m_linesPerAction;
  }
  bool IsPageScroll() const
  {
    return static_cast<unsigned int>(m_linesPerAction) == UINT_MAX;
  }

  ShellCoord m_x = 0;
  ShellCoord m_y = 0;
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

class SHELL_DC;

// The window events the application shell handles. The window system (issue #256) sends them.
class ShellPaintEvent : public ShellEvent
{
public:
  explicit ShellPaintEvent(
    const int id = 0
  )
    : ShellEvent(id, SHELL_EVT_PAINT)
  {}
};

class ShellEraseEvent : public ShellEvent
{
public:
  explicit ShellEraseEvent(
    const int id = 0,
    SHELL_DC* const dc = nullptr
  )
    : ShellEvent(id, SHELL_EVT_ERASE_BACKGROUND)
    , m_dc(dc)
  {}

  SHELL_DC* GetDC() const
  {
    return m_dc;
  }

  SHELL_DC* m_dc = nullptr;
};

class ShellSizeEvent : public ShellEvent
{
public:
  ShellSizeEvent()
    : ShellEvent(0, SHELL_EVT_SIZE)
  {}
  ShellSizeEvent(
    const int width,
    const int height,
    const int id = 0
  )
    : ShellEvent(id, SHELL_EVT_SIZE)
    , m_width(width)
    , m_height(height)
  {}

  int m_width = 0;
  int m_height = 0;
};

class ShellMoveEvent : public ShellEvent
{
public:
  ShellMoveEvent()
    : ShellEvent(0, SHELL_EVT_MOVE)
  {}
  ShellMoveEvent(
    const int x,
    const int y,
    const int id = 0
  )
    : ShellEvent(id, SHELL_EVT_MOVE)
    , m_x(x)
    , m_y(y)
  {}

  int m_x = 0;
  int m_y = 0;
};

class ShellCloseEvent : public ShellEvent
{
public:
  explicit ShellCloseEvent(
    const ShellEventType type = SHELL_EVT_CLOSE_WINDOW,
    const int id = 0
  )
    : ShellEvent(id, type)
  {}

  void SetCanVeto(
    const bool canVeto
  )
  {
    m_canVeto = canVeto;
  }
  bool CanVeto() const
  {
    return m_canVeto;
  }
  void Veto(
    const bool veto = true
  )
  {
    m_veto = veto;
  }
  bool GetVeto() const
  {
    return m_veto;
  }

  bool m_canVeto = true;
  bool m_veto = false;
};

// The 2.4.2 window library ActivateEvent: the top-level window got (true) or lost the keyboard, as Windows'
// WM_ACTIVATEAPP told the frame.
class ShellActivateEvent : public ShellEvent
{
public:
  explicit ShellActivateEvent(
    const bool active = true,
    const int id = 0
  )
    : ShellEvent(id, SHELL_EVT_ACTIVATE)
    , m_active(active)
  {}

  bool GetActive() const
  {
    return m_active;
  }

  bool m_active = true;
};

typedef void (ShellObject::*ShellObjectEventFunction)(ShellEvent&);
typedef void (ShellEvtHandler::*ShellEventFunction)(ShellEvent&);
typedef void (ShellEvtHandler::*ShellCharEventFunction)(ShellKeyEvent&);
typedef void (ShellEvtHandler::*ShellMouseEventFunction)(ShellMouseEvent&);
typedef void (ShellEvtHandler::*ShellPaintEventFunction)(ShellPaintEvent&);
typedef void (ShellEvtHandler::*ShellEraseEventFunction)(ShellEraseEvent&);
typedef void (ShellEvtHandler::*ShellSizeEventFunction)(ShellSizeEvent&);
typedef void (ShellEvtHandler::*ShellMoveEventFunction)(ShellMoveEvent&);
typedef void (ShellEvtHandler::*ShellCloseEventFunction)(ShellCloseEvent&);
typedef void (ShellEvtHandler::*ShellActivateEventFunction)(ShellActivateEvent&);

struct ShellEventTableEntry
{
  int m_eventType;
  int m_id;
  int m_lastId;
  ShellObjectEventFunction m_fn;
  ShellObject* m_callbackUserData;
};

struct ShellEventTable
{
  const ShellEventTable* baseTable;
  const ShellEventTableEntry* entries;
};

class ShellEvtHandler : public ShellObject
{
public:
  ShellEvtHandler() = default;
  ~ShellEvtHandler() override;

  ShellEvtHandler* GetNextHandler() const
  {
    return m_nextHandler;
  }
  ShellEvtHandler* GetPreviousHandler() const
  {
    return m_previousHandler;
  }
  void SetNextHandler(
    ShellEvtHandler* const handler
  )
  {
    m_nextHandler = handler;
  }
  void SetPreviousHandler(
    ShellEvtHandler* const handler
  )
  {
    m_previousHandler = handler;
  }
  void SetEvtHandlerEnabled(
    const bool enabled
  )
  {
    m_enabled = enabled;
  }
  bool GetEvtHandlerEnabled() const
  {
    return m_enabled;
  }

  /**
   * the library's event.cpp: this handler's tables, from its class up to EvtHandler, then
   * the next handler in the chain. True when a handler took the event without skipping it.
   */
  virtual bool ProcessEvent(ShellEvent& event);

  bool SearchEventTable(const ShellEventTable& table, ShellEvent& event);

protected:
  static const ShellEventTable sm_eventTable;
  virtual const ShellEventTable* GetEventTable() const;

private:
  static const ShellEventTableEntry sm_eventTableEntries[];

  ShellEvtHandler* m_nextHandler = nullptr;
  ShellEvtHandler* m_previousHandler = nullptr;
  bool m_enabled = true;
#if FAF_RETAIL_LAYOUT
  // The retail-layout build keeps the size of the class this stands in for, the 2.4.2 window library's
  // wxEvtHandler (0x28 on x86), so the recovered types built on it keep their retail offsets: CUIKeyHandler is
  // 0x28 and CMauiEventMapper's own fields start at 0x28 (moho/ui/UiRuntimeTypes.h). Nothing reads these bytes.
  std::uint8_t m_retailReserved[0x18]{};
#endif
};

#define DECLARE_EVENT_TABLE_ENTRY(type, id, idLast, fn, obj) {type, id, idLast, fn, obj}

#define DECLARE_EVENT_TABLE()                                                                                          \
private:                                                                                                               \
  static const ShellEventTableEntry sm_eventTableEntries[];                                                            \
                                                                                                                       \
protected:                                                                                                             \
  static const ShellEventTable sm_eventTable;                                                                          \
  const ShellEventTable* GetEventTable() const override;

#define BEGIN_EVENT_TABLE(theClass, baseClass)                                                                         \
  const ShellEventTable* theClass::GetEventTable() const                                                               \
  {                                                                                                                    \
    return &theClass::sm_eventTable;                                                                                   \
  }                                                                                                                    \
  const ShellEventTable theClass::sm_eventTable = {&baseClass::sm_eventTable, &theClass::sm_eventTableEntries[0]};     \
  const ShellEventTableEntry theClass::sm_eventTableEntries[] = {

#define END_EVENT_TABLE()                                                                                              \
  DECLARE_EVENT_TABLE_ENTRY(SHELL_EVT_NULL, 0, 0, nullptr, nullptr)                                                    \
  }                                                                                                                    \
  ;

#define SHELL_EVT_ENTRY(type, castType, func)                                                                          \
  DECLARE_EVENT_TABLE_ENTRY(                                                                                           \
    type, SHELL_ID_ANY, SHELL_ID_ANY, (ShellObjectEventFunction)(ShellEventFunction)(castType) & func, nullptr         \
  ),

#define EVT_CHAR(func) SHELL_EVT_ENTRY(SHELL_EVT_CHAR, ShellCharEventFunction, func)
#define EVT_KEY_DOWN(func) SHELL_EVT_ENTRY(SHELL_EVT_KEY_DOWN, ShellCharEventFunction, func)
#define EVT_KEY_UP(func) SHELL_EVT_ENTRY(SHELL_EVT_KEY_UP, ShellCharEventFunction, func)

#define EVT_LEFT_DOWN(func) SHELL_EVT_ENTRY(SHELL_EVT_LEFT_DOWN, ShellMouseEventFunction, func)
#define EVT_LEFT_UP(func) SHELL_EVT_ENTRY(SHELL_EVT_LEFT_UP, ShellMouseEventFunction, func)
#define EVT_MIDDLE_DOWN(func) SHELL_EVT_ENTRY(SHELL_EVT_MIDDLE_DOWN, ShellMouseEventFunction, func)
#define EVT_MIDDLE_UP(func) SHELL_EVT_ENTRY(SHELL_EVT_MIDDLE_UP, ShellMouseEventFunction, func)
#define EVT_RIGHT_DOWN(func) SHELL_EVT_ENTRY(SHELL_EVT_RIGHT_DOWN, ShellMouseEventFunction, func)
#define EVT_RIGHT_UP(func) SHELL_EVT_ENTRY(SHELL_EVT_RIGHT_UP, ShellMouseEventFunction, func)
#define EVT_MOTION(func) SHELL_EVT_ENTRY(SHELL_EVT_MOTION, ShellMouseEventFunction, func)
#define EVT_LEFT_DCLICK(func) SHELL_EVT_ENTRY(SHELL_EVT_LEFT_DCLICK, ShellMouseEventFunction, func)
#define EVT_MIDDLE_DCLICK(func) SHELL_EVT_ENTRY(SHELL_EVT_MIDDLE_DCLICK, ShellMouseEventFunction, func)
#define EVT_RIGHT_DCLICK(func) SHELL_EVT_ENTRY(SHELL_EVT_RIGHT_DCLICK, ShellMouseEventFunction, func)
#define EVT_LEAVE_WINDOW(func) SHELL_EVT_ENTRY(SHELL_EVT_LEAVE_WINDOW, ShellMouseEventFunction, func)
#define EVT_ENTER_WINDOW(func) SHELL_EVT_ENTRY(SHELL_EVT_ENTER_WINDOW, ShellMouseEventFunction, func)
#define EVT_MOUSEWHEEL(func) SHELL_EVT_ENTRY(SHELL_EVT_MOUSEWHEEL, ShellMouseEventFunction, func)

#define EVT_PAINT(func) SHELL_EVT_ENTRY(SHELL_EVT_PAINT, ShellPaintEventFunction, func)
#define EVT_ERASE_BACKGROUND(func) SHELL_EVT_ENTRY(SHELL_EVT_ERASE_BACKGROUND, ShellEraseEventFunction, func)
#define EVT_SIZE(func) SHELL_EVT_ENTRY(SHELL_EVT_SIZE, ShellSizeEventFunction, func)
#define EVT_MOVE(func) SHELL_EVT_ENTRY(SHELL_EVT_MOVE, ShellMoveEventFunction, func)
#define EVT_CLOSE(func) SHELL_EVT_ENTRY(SHELL_EVT_CLOSE_WINDOW, ShellCloseEventFunction, func)
#define EVT_ACTIVATE(func) SHELL_EVT_ENTRY(SHELL_EVT_ACTIVATE, ShellActivateEventFunction, func)

// The 2.4.2 window library: the thirteen mouse event types, all to one sink.
#define EVT_MOUSE_EVENTS(func)                                                                                         \
  EVT_LEFT_DOWN(func)                                                                                                  \
  EVT_LEFT_UP(func)                                                                                                    \
  EVT_MIDDLE_DOWN(func)                                                                                                \
  EVT_MIDDLE_UP(func)                                                                                                  \
  EVT_RIGHT_DOWN(func)                                                                                                 \
  EVT_RIGHT_UP(func)                                                                                                   \
  EVT_MOTION(func)                                                                                                     \
  EVT_LEFT_DCLICK(func)                                                                                                \
  EVT_MIDDLE_DCLICK(func)                                                                                              \
  EVT_RIGHT_DCLICK(func)                                                                                               \
  EVT_LEAVE_WINDOW(func)                                                                                               \
  EVT_ENTER_WINDOW(func)                                                                                               \
  EVT_MOUSEWHEEL(func)

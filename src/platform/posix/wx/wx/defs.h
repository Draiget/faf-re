#pragma once

/**
 * Engine addition (issue #255): the part of wxWindows 2.4.2 the Linux client's game code uses.
 *
 * The Windows client links the real library (dependencies/wxWindows-2.4.2, wxMSW), which has no
 * usable Linux port. Outside the tool windows (script debugger, emitter editor, log window,
 * dialogs) and the application shell (app loop, main frame, viewports), the client's code uses
 * wx only for its event model: event tables, key and mouse events, the input window's handler
 * chain, and wx key codes, which the Lua key bindings also use. These headers declare that part
 * under wx's own names, with wx 2.4.2's field names, key codes and event type numbers, as
 * src/platform/posix/win32 does for the Win32 API. The window system behind them (SDL3) is
 * issue #256; until then nothing produces events.
 *
 * Only the Linux client target puts this folder on the include path (cmake/FafLinuxClient.cmake).
 */

#include <climits>
#include <cstdint>

#define WXDLLEXPORT

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef int wxCoord;
typedef std::uint32_t wxUint32;
typedef wchar_t wxChar;
typedef int wxEventType;
typedef int wxWindowID;

// The Windows engine builds wx and itself with UNICODE.
#define wxT(x) L##x

#define wxID_ANY (-1)

// wx/defs.h 2.4.2: standard identifiers.
enum
{
  wxID_OK = 5100,
  wxID_CANCEL
};

// wx/defs.h 2.4.2: wxDirDialog style.
#define wxDD_NEW_DIR_BUTTON 0x0080

// wx/defs.h 2.4.2, enum wxKeyCode, value for value: the key codes in events and in the Lua key
// tables (/lua/keymap/keyNames.lua).
enum wxKeyCode
{
  WXK_BACK = 8,
  WXK_TAB = 9,
  WXK_RETURN = 13,
  WXK_ESCAPE = 27,
  WXK_SPACE = 32,
  WXK_DELETE = 127,

  WXK_START = 300,
  WXK_LBUTTON,
  WXK_RBUTTON,
  WXK_CANCEL,
  WXK_MBUTTON,
  WXK_CLEAR,
  WXK_SHIFT,
  WXK_ALT,
  WXK_CONTROL,
  WXK_MENU,
  WXK_PAUSE,
  WXK_CAPITAL,
  WXK_PRIOR,
  WXK_NEXT,
  WXK_END,
  WXK_HOME,
  WXK_LEFT,
  WXK_UP,
  WXK_RIGHT,
  WXK_DOWN,
  WXK_SELECT,
  WXK_PRINT,
  WXK_EXECUTE,
  WXK_SNAPSHOT,
  WXK_INSERT,
  WXK_HELP,
  WXK_NUMPAD0,
  WXK_NUMPAD1,
  WXK_NUMPAD2,
  WXK_NUMPAD3,
  WXK_NUMPAD4,
  WXK_NUMPAD5,
  WXK_NUMPAD6,
  WXK_NUMPAD7,
  WXK_NUMPAD8,
  WXK_NUMPAD9,
  WXK_MULTIPLY,
  WXK_ADD,
  WXK_SEPARATOR,
  WXK_SUBTRACT,
  WXK_DECIMAL,
  WXK_DIVIDE,
  WXK_F1,
  WXK_F2,
  WXK_F3,
  WXK_F4,
  WXK_F5,
  WXK_F6,
  WXK_F7,
  WXK_F8,
  WXK_F9,
  WXK_F10,
  WXK_F11,
  WXK_F12,
  WXK_F13,
  WXK_F14,
  WXK_F15,
  WXK_F16,
  WXK_F17,
  WXK_F18,
  WXK_F19,
  WXK_F20,
  WXK_F21,
  WXK_F22,
  WXK_F23,
  WXK_F24,
  WXK_NUMLOCK,
  WXK_SCROLL,
  WXK_PAGEUP,
  WXK_PAGEDOWN,

  WXK_NUMPAD_SPACE,
  WXK_NUMPAD_TAB,
  WXK_NUMPAD_ENTER,
  WXK_NUMPAD_F1,
  WXK_NUMPAD_F2,
  WXK_NUMPAD_F3,
  WXK_NUMPAD_F4,
  WXK_NUMPAD_HOME,
  WXK_NUMPAD_LEFT,
  WXK_NUMPAD_UP,
  WXK_NUMPAD_RIGHT,
  WXK_NUMPAD_DOWN,
  WXK_NUMPAD_PRIOR,
  WXK_NUMPAD_PAGEUP,
  WXK_NUMPAD_NEXT,
  WXK_NUMPAD_PAGEDOWN,
  WXK_NUMPAD_END,
  WXK_NUMPAD_BEGIN,
  WXK_NUMPAD_INSERT,
  WXK_NUMPAD_DELETE,
  WXK_NUMPAD_EQUAL,
  WXK_NUMPAD_MULTIPLY,
  WXK_NUMPAD_ADD,
  WXK_NUMPAD_SEPARATOR,
  WXK_NUMPAD_SUBTRACT,
  WXK_NUMPAD_DECIMAL,
  WXK_NUMPAD_DIVIDE
};

/**
 * wx 2.4.2 src/msw/window.cpp: a Windows virtual-key code to a wx key code, 0 for a key that
 * WM_CHAR reports instead.
 */
int wxCharCodeMSWToWX(int keySym);

/**
 * wx 2.4.2 src/msw/window.cpp: a wx key code to a Windows virtual-key code; `*isVirtual` is
 * false when the code is a character, returned unchanged.
 */
int wxCharCodeWXToMSW(int id, bool* isVirtual);

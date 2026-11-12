#pragma once

/**
 * Engine addition (issues #255, #407, #415): the application shell's basic definitions. The
 * engine's recovered window code uses the shell for its event model (event tables, key and mouse
 * events, the input window's handler chain) and its key codes, which the Lua key bindings also
 * use. The shell keeps the field names, key codes and event type numbers of the window library
 * the retail binary linked (2.4.2), as src/platform/posix/win32 does for the Win32 API, and runs
 * over the window system (platform/Window.h, SDL3) on every platform.
 */

#include <climits>
#include <cstdint>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef int ShellCoord;
typedef std::uint32_t ShellUint32;
typedef wchar_t ShellChar;
typedef int ShellEventType;
typedef int ShellWindowID;

// The retail engine built its window library and itself with UNICODE.
#define SHELL_T(x) L##x

#define SHELL_ID_ANY (-1)

// defs.h 2.4.2: standard identifiers.
enum
{
  SHELL_ID_OK = 5100,
  SHELL_ID_CANCEL
};

// defs.h 2.4.2: DirDialog style.
#define SHELL_DD_NEW_DIR_BUTTON 0x0080

// defs.h 2.4.2, enum KeyCode, value for value: the key codes in events and in the Lua key
// tables (/lua/keymap/keyNames.lua).
enum ShellKeyCode
{
  SHELL_KEY_BACK = 8,
  SHELL_KEY_TAB = 9,
  SHELL_KEY_RETURN = 13,
  SHELL_KEY_ESCAPE = 27,
  SHELL_KEY_SPACE = 32,
  SHELL_KEY_DELETE = 127,

  SHELL_KEY_START = 300,
  SHELL_KEY_LBUTTON,
  SHELL_KEY_RBUTTON,
  SHELL_KEY_CANCEL,
  SHELL_KEY_MBUTTON,
  SHELL_KEY_CLEAR,
  SHELL_KEY_SHIFT,
  SHELL_KEY_ALT,
  SHELL_KEY_CONTROL,
  SHELL_KEY_MENU,
  SHELL_KEY_PAUSE,
  SHELL_KEY_CAPITAL,
  SHELL_KEY_PRIOR,
  SHELL_KEY_NEXT,
  SHELL_KEY_END,
  SHELL_KEY_HOME,
  SHELL_KEY_LEFT,
  SHELL_KEY_UP,
  SHELL_KEY_RIGHT,
  SHELL_KEY_DOWN,
  SHELL_KEY_SELECT,
  SHELL_KEY_PRINT,
  SHELL_KEY_EXECUTE,
  SHELL_KEY_SNAPSHOT,
  SHELL_KEY_INSERT,
  SHELL_KEY_HELP,
  SHELL_KEY_NUMPAD0,
  SHELL_KEY_NUMPAD1,
  SHELL_KEY_NUMPAD2,
  SHELL_KEY_NUMPAD3,
  SHELL_KEY_NUMPAD4,
  SHELL_KEY_NUMPAD5,
  SHELL_KEY_NUMPAD6,
  SHELL_KEY_NUMPAD7,
  SHELL_KEY_NUMPAD8,
  SHELL_KEY_NUMPAD9,
  SHELL_KEY_MULTIPLY,
  SHELL_KEY_ADD,
  SHELL_KEY_SEPARATOR,
  SHELL_KEY_SUBTRACT,
  SHELL_KEY_DECIMAL,
  SHELL_KEY_DIVIDE,
  SHELL_KEY_F1,
  SHELL_KEY_F2,
  SHELL_KEY_F3,
  SHELL_KEY_F4,
  SHELL_KEY_F5,
  SHELL_KEY_F6,
  SHELL_KEY_F7,
  SHELL_KEY_F8,
  SHELL_KEY_F9,
  SHELL_KEY_F10,
  SHELL_KEY_F11,
  SHELL_KEY_F12,
  SHELL_KEY_F13,
  SHELL_KEY_F14,
  SHELL_KEY_F15,
  SHELL_KEY_F16,
  SHELL_KEY_F17,
  SHELL_KEY_F18,
  SHELL_KEY_F19,
  SHELL_KEY_F20,
  SHELL_KEY_F21,
  SHELL_KEY_F22,
  SHELL_KEY_F23,
  SHELL_KEY_F24,
  SHELL_KEY_NUMLOCK,
  SHELL_KEY_SCROLL,
  SHELL_KEY_PAGEUP,
  SHELL_KEY_PAGEDOWN,

  SHELL_KEY_NUMPAD_SPACE,
  SHELL_KEY_NUMPAD_TAB,
  SHELL_KEY_NUMPAD_ENTER,
  SHELL_KEY_NUMPAD_F1,
  SHELL_KEY_NUMPAD_F2,
  SHELL_KEY_NUMPAD_F3,
  SHELL_KEY_NUMPAD_F4,
  SHELL_KEY_NUMPAD_HOME,
  SHELL_KEY_NUMPAD_LEFT,
  SHELL_KEY_NUMPAD_UP,
  SHELL_KEY_NUMPAD_RIGHT,
  SHELL_KEY_NUMPAD_DOWN,
  SHELL_KEY_NUMPAD_PRIOR,
  SHELL_KEY_NUMPAD_PAGEUP,
  SHELL_KEY_NUMPAD_NEXT,
  SHELL_KEY_NUMPAD_PAGEDOWN,
  SHELL_KEY_NUMPAD_END,
  SHELL_KEY_NUMPAD_BEGIN,
  SHELL_KEY_NUMPAD_INSERT,
  SHELL_KEY_NUMPAD_DELETE,
  SHELL_KEY_NUMPAD_EQUAL,
  SHELL_KEY_NUMPAD_MULTIPLY,
  SHELL_KEY_NUMPAD_ADD,
  SHELL_KEY_NUMPAD_SEPARATOR,
  SHELL_KEY_NUMPAD_SUBTRACT,
  SHELL_KEY_NUMPAD_DECIMAL,
  SHELL_KEY_NUMPAD_DIVIDE
};

/**
 * The 2.4.2 window library src/msw/window.cpp: a Windows virtual-key code to a window-library key code, 0 for a key
 * that WM_CHAR reports instead.
 */
int ShellKeyFromVirtualKey(int keySym);

/**
 * The 2.4.2 window library src/msw/window.cpp: a window-library key code to a Windows virtual-key code; `*isVirtual` is
 * false when the code is a character, returned unchanged.
 */
int ShellKeyToVirtualKey(int id, bool* isVirtual);

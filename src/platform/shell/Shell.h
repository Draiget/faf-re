#pragma once

/**
 * The application shell (issues #407, #415): the window, event and application classes the
 * engine's recovered window code is written against, over the window system (platform/Window.h,
 * SDL3) on every platform. The retail binary linked the 2.4.2 window library for them; the shell keeps
 * that library's class shapes, field names, key codes and event numbers, under its own names.
 *
 * <windows.h> first: the engine's window code calls the Win32 API (the POSIX <Windows.h> on
 * other systems) next to the shell.
 */

#include <windows.h>

#include "platform/shell/app.h"
#include "platform/shell/bitmap.h"
#include "platform/shell/dc.h"
#include "platform/shell/defs.h"
#include "platform/shell/event.h"
#include "platform/shell/frame.h"
#include "platform/shell/gdicmn.h"
#include "platform/shell/string.h"
#include "platform/shell/window.h"

#pragma once

/**
 * The application shell's wx-shaped classes (src/platform/shell, issue #407) and <windows.h>, in
 * the order every engine file reads them. The shell keeps wx 2.4.2's class and event names, field
 * names, key codes and event numbers for the code recovered from the retail binary, which linked
 * wxWindows 2.4.2; underneath it is SDL3 (platform/Window.h) on every platform.
 */

#include <wx/defs.h>

#include <windows.h>
#include <wx/msw/winundef.h>

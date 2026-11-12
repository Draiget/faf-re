#pragma once

// Engine addition (issue #255): platform/WxWidgets.h includes wx's <wx/msw/winundef.h> to undo
// <windows.h>'s A/W macros. The POSIX <Windows.h> defines none, so there is nothing to undo.

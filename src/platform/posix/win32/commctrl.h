#pragma once

// Engine addition (issue #255): <commctrl.h> for the Linux client. The Windows common controls
// have nothing to register here.

#include <Windows.h>

inline void InitCommonControls() noexcept {}

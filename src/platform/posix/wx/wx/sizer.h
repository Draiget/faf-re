#pragma once

// Engine addition (issue #255): the Linux client's game code includes wx/sizer.h without using
// it (moho/sim/UserLuaPrivate.h). Layout belongs to the tool windows, which Linux leaves out.

#include <wx/window.h>

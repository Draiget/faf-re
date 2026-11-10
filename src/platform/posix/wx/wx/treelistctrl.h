#pragma once

// Engine addition (issue #255): the Linux client's game code includes wx/treelistctrl.h without
// using it (moho/sim/UserLuaPrivate.h). Tree controls belong to the tool windows, which Linux
// leaves out.

#include <wx/window.h>

#pragma once

// Engine addition (issue #255): wx 2.4.2's root class (wx/object.h), for the Linux client.
// See wx/defs.h in this folder. No run-time class information: the game code doesn't use it.

#include <wx/defs.h>

class wxObject
{
public:
  wxObject() = default;
  virtual ~wxObject() = default;
};

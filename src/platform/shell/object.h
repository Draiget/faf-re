#pragma once

// Engine addition (issues #255, #407): the shell's root class. No run-time class information: the
// game code doesn't use it. See defs.h.

#include "platform/shell/defs.h"

class ShellObject
{
public:
  ShellObject() = default;
  virtual ~ShellObject() = default;
};
